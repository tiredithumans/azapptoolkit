//! Dead-session handling in the long-running fan-outs.
//!
//! A re-auth-fatal failure makes every remaining item fail identically, so a
//! fan-out that only warns returns a partial result the UI presents as
//! complete. Checked per `dispatch_capped` **call site** — see [`call_sites`]
//! for why the whole-file form was unsound.

// The module list this file used to carry is gone: the fan-out modules are now
// whichever modules actually contain a `dispatch_capped` call site, read from
// the source tree by `sources::command_modules()`. A hand-maintained list could
// only ever check the files someone remembered to add.

/// Reads that enumerate **every object of a kind in the tenant**. A loop over
/// one of these runs once per app/SP/site, not once per sub-object of a single
/// app, and that is the whole difference between "bounded by one object the
/// operator is editing" and "a run the operator needs to be able to stop".
const TENANT_WIDE_READS: &[&str] = &[
    "list_applications_all(",
    "list_service_principals_all(",
    "get_application_access_policies(",
    "list_managed_identities_all(",
    "sp_index_cached(",
    "app_name_index_cached(",
    "indexes_cached(",
    "list_all_sites(",
];

/// Method-call fragments that mutate tenant state.
const WRITE_CALLS: &[&str] = &[
    ".create_",
    ".delete_",
    ".patch_",
    ".add_",
    ".remove_",
    ".set_",
    ".assign_",
    ".grant_",
    ".revoke_",
    ".upsert_",
    ".new_management_scope",
    "migrate_one(",
];

/// A command that enumerates the tenant and then **writes once per result** must
/// be stoppable, both by the operator and by a dead session.
///
/// This replaces a one-element `SEQUENTIAL_WRITE_MODULES` list containing only
/// `commands/restore.rs`. That list was the mechanism by which
/// `migrate_application_access_policies` — added in the very PR that introduced
/// the pin — shipped a whole-tenant Exchange + Entra write loop with no cancel
/// token and no dead-session latch, and passed CI: the rule simply never looked
/// at `commands/exchange.rs` (now the `commands/exchange/` directory).
///
/// The rule now derives its own subject. "Tenant-wide writer" is expressed as
/// what the code *does* — reads a tenant-wide collection, then writes inside a
/// loop — so a new command is in scope the moment it is written, and there is no
/// allowlist to forget. Deliberately no escape hatch: the two shapes that look
/// like violations but are not (a loop over one app's own credentials, a loop
/// that only reads) are excluded by the rule itself, not by naming them.
#[test]
fn every_tenant_wide_writer_is_cancellable() {
    let mut offenders: Vec<String> = Vec::new();
    for cmd in super::sources::commands() {
        if !TENANT_WIDE_READS.iter().any(|r| cmd.body.contains(r)) {
            continue;
        }
        let writes_per_result = super::sources::loops(&cmd.body).iter().any(|(_, block)| {
            block.contains(".await") && WRITE_CALLS.iter().any(|w| block.contains(w))
        });
        if !writes_per_result {
            continue;
        }
        // Two accepted shapes, matching the two drivers in `commands/dispatch.rs`:
        // a fan-out gates its spawn closure, a sequential flow breaks on the
        // latch. Both must ALSO claim a cancel token — a dead session is not the
        // same event as an operator pressing Cancel, and only the token answers
        // the second.
        let cancellable = cmd.body.contains(".claim()");
        let stops_on_dead = cmd.body.contains("is_dead()")
            || cmd.body.contains("dispatch_capped(")
            || cmd.body.contains("run_bulk_seq(");
        if !(cancellable && stops_on_dead) {
            offenders.push(format!(
                "{}::{} (claims a token: {cancellable}, stops on a dead session: {stops_on_dead})",
                cmd.module, cmd.name
            ));
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "tenant-wide write loop(s) the operator cannot stop: {offenders:#?}\n\
         This command reads a tenant-wide collection and then writes once per result, so it runs \
         for as long as the tenant is large. Claim a `CancelToken` once before the first write \
         (`state.<flag>_cancel.claim()`), construct a `SessionDead`, and break the loop on both \
         `cancel.is_cancelled()` and `session.is_dead()` — noting failures through `note_code` so \
         `UiError::is_reauth_fatal` stays the single definition. Flag the result as incomplete: a \
         run that stopped early must never render as a finished one."
    );
}

/// Fan-outs that still lack the branch. **Empty, and it must stay that way** —
/// every entry was a command that returned a silently partial result when the
/// session died mid-run. The list is kept (rather than deleted with its last
/// entry) so a NEW fan-out cannot be added without either the branch or an
/// explicit, reviewed admission here.
///
/// Closing the last four needed a root-cause fix, not four local branches:
/// `BearerProvider` returned `Result<String, String>`, so every client flattened
/// a dead session into the code `token_error` and `is_reauth_fatal` could never
/// fire for a Graph/Exchange/Key Vault/ARM call. `core::token::TokenError` now
/// carries the classification across that boundary.
const KNOWN_GAPS: &[&str] = &[];

/// The source of each `callee(` call in `src`, from the identifier to its
/// balanced closing paren.
///
/// A whole-file `contains` cannot express this rule. `commands/bulk.rs` shipped
/// three ungated `dispatch_capped` fan-outs while satisfying a file-level
/// `contains("is_reauth_fatal")` — the string was real, but it lived in
/// `BulkOutcome::session_fatal`, which only the *sequential* driver consults.
/// The rule is about a specific call site, so the check has to be too.
///
/// Double-quoted strings and `//` comments are skipped so a paren inside either
/// cannot unbalance the scan. Char literals are deliberately NOT tracked: `'`
/// also opens a lifetime, and misreading `&'a str` as a literal would swallow
/// the rest of the file.
fn call_sites<'a>(src: &'a str, callee: &str) -> Vec<&'a str> {
    let needle = format!("{callee}(");
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;

    while let Some(hit) = src[from..].find(&needle) {
        let start = from + hit;
        from = start + needle.len();
        // `dispatch_capped(` also appears in prose and in `use` items; a call
        // site is preceded by whitespace or a path separator, never by an
        // identifier character or a backtick.
        if start > 0 {
            let prev = bytes[start - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'`' {
                continue;
            }
        }
        let mut depth = 0usize;
        let mut i = start + needle.len() - 1; // sits on the opening paren
        let (mut in_str, mut in_line_comment) = (false, false);
        while i < bytes.len() {
            let c = bytes[i];
            if in_line_comment {
                if c == b'\n' {
                    in_line_comment = false;
                }
            } else if in_str {
                if c == b'\\' {
                    i += 1; // skip the escaped byte
                } else if c == b'"' {
                    in_str = false;
                }
            } else if c == b'"' {
                in_str = true;
            } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
                in_line_comment = true;
            } else if c == b'(' {
                depth += 1;
            } else if c == b')' {
                depth -= 1;
                if depth == 0 {
                    out.push(&src[start..=i]);
                    from = i + 1;
                    break;
                }
            }
            i += 1;
        }
    }
    out
}

/// A dead session makes every remaining item fail identically, so a fan-out that
/// only warns produces a silently partial result. `UiError::is_reauth_fatal` is
/// the single definition (azapptoolkit-dto, shared by both tiers) — AGENTS.md:
/// "Long-running loops must stop on it".
///
/// Checked **per `dispatch_capped` call site**, not per file: see [`call_sites`]
/// for why the file-level form was unsound. The set of modules is now read from
/// the source tree rather than listed here, so a new fan-out is in scope the
/// moment it compiles.
#[test]
fn every_fan_out_command_honours_is_reauth_fatal() {
    let mut missing: Vec<String> = Vec::new();
    let stale: Vec<&str> = Vec::new();
    let mut checked = 0usize;

    for (name, src) in super::sources::command_modules() {
        let name = name.as_str();
        // The driver module DEFINES `dispatch_capped`; it has no session to
        // gate on and its own doc comments name the call.
        if name == "commands/dispatch.rs" {
            continue;
        }
        if !(src.contains("dispatch_capped(") || src.contains("run_bulk_seq(")) {
            continue;
        }
        checked += 1;

        // `run_bulk_seq` gates centrally, in the driver — every caller inherits
        // it, and `a_dead_session_halts_the_run_instead_of_burning_the_selection`
        // covers it. A module that only drives the sequential path is handled by
        // that, so it has no call sites to check here.
        let sites = call_sites(&src, "dispatch_capped");
        let _handled_by_driver = sites.is_empty() && src.contains("run_bulk_seq(");

        for (n, site) in sites.iter().enumerate() {
            // Two accepted shapes. Either the spawn closure gates on the shared
            // `SessionDead` latch (`session.is_dead()`), or the module runs its
            // own classified latch (`commands/audit.rs`'s `reauth_fatal` flag,
            // read in the spawn closure and set from `classify_audit_failure`).
            // Both must appear INSIDE the call: recording a dead session and
            // dispatching anyway is the bug this rule exists to catch.
            if !(site.contains("is_dead()") || site.contains("reauth_fatal")) {
                missing.push(format!("{name} (dispatch_capped call #{})", n + 1));
            }
        }
    }

    assert!(
        checked >= 5,
        "only {checked} fan-out module(s) found by the source walk — expected at least the audit, \
         bulk, backup, sharepoint and permission-tester drivers. A rule that scans nothing passes \
         vacuously."
    );
    assert!(
        missing.is_empty(),
        "fan-out call site(s) with no dead-session gate: {missing:?}\n\
         A dead session makes every remaining item fail identically — gate the spawn closure \
         on `SessionDead::is_dead()`, note failures through it in the collect arm, and return \
         `session.err(..)` rather than a partial result. See commands/backup.rs for the shape."
    );
    assert!(
        stale.is_empty(),
        "these now handle is_reauth_fatal — drop them from KNOWN_GAPS: {stale:?}"
    );
    // AGENTS.md: KNOWN_GAPS "is empty and must stay so". It was empty, and the
    // test above tolerated entries being ADDED to it — a new fan-out with no
    // dead-session branch could ship by appending one line, and the only
    // pushback would be a staleness message that never fires while the gap is
    // real. An allowlist that can grow is not a ratchet.
    //
    // Deliberately last, so the two diagnostics above (which say what to fix)
    // are reached first when several things are wrong at once.
    assert!(
        KNOWN_GAPS.is_empty(),
        "KNOWN_GAPS must stay empty: {KNOWN_GAPS:?}\n\
         Every fan-out honours is_reauth_fatal today. Fix the new one instead of \
         listing it — a fan-out that warns through a dead session returns a partial \
         result the UI presents as complete."
    );
}

/// The tenant-wide-writer rule must actually FIRE on the shape it exists to
/// catch. Without this, the rule passes for two indistinguishable reasons —
/// "every writer is gated" and "the detector matches nothing" — and the second
/// is how the rule it replaced came to be worthless.
///
/// The unguarded case below is `migrate_application_access_policies` as it
/// shipped: enumerate every Application Access Policy in the tenant, then write
/// per app, with no token and no latch.
#[test]
fn the_tenant_wide_writer_rule_fires_on_an_ungated_loop() {
    fn violates(body: &str) -> bool {
        let reads_tenant = TENANT_WIDE_READS.iter().any(|r| body.contains(r));
        let writes_per_result = super::sources::loops(body)
            .iter()
            .any(|(_, b)| b.contains(".await") && WRITE_CALLS.iter().any(|w| b.contains(w)));
        let gated = body.contains(".claim()")
            && (body.contains("is_dead()")
                || body.contains("dispatch_capped(")
                || body.contains("run_bulk_seq("));
        reads_tenant && writes_per_result && !gated
    }

    let unguarded = r#"{
        let policies = exo.get_application_access_policies().await?;
        for (app_id, batch) in group(policies) {
            exo.remove_application_access_policy(id).await?;
        }
    }"#;
    assert!(violates(unguarded), "the rule must catch an ungated writer");

    let guarded = r#"{
        let policies = exo.get_application_access_policies().await?;
        let cancel = state.audit_cancel.claim();
        let session = SessionDead::new();
        for (app_id, batch) in group(policies) {
            if cancel.is_cancelled() || session.is_dead() { break; }
            exo.remove_application_access_policy(id).await?;
        }
    }"#;
    assert!(!violates(guarded), "a gated writer must pass");

    // A loop over ONE app's own sub-collection is bounded by that app, not by
    // the tenant, and must not be dragged in — this is the shape 25 of the 26
    // awaited write loops in `commands/` actually have.
    let bounded = r#"{
        let app = graph.get_application(&object_id).await?;
        for cred in &app.password_credentials {
            graph.remove_password(&object_id, &cred.key_id).await?;
        }
    }"#;
    assert!(
        !violates(bounded),
        "a per-app loop is not a tenant-wide run"
    );

    // Reading the tenant without writing per result is a listing, not a run.
    let read_only = r#"{
        let sps = sp_index_cached(&cache, &client, &tenant_id).await;
        for sp in &sps { rows.push(project(sp)); }
    }"#;
    assert!(!violates(read_only), "a tenant-wide READ is not a writer");
}

/// `call_sites` is load-bearing for the rule above, so it gets its own cover.
/// Every case here is a shape that actually appears in `commands/`.
#[test]
fn call_sites_extracts_balanced_calls_and_ignores_lookalikes() {
    let src = r#"
        use crate::commands::dispatch::dispatch_capped;
        /// Prose mentioning `dispatch_capped(` in a doc comment.
        let a = dispatch_capped(items, || cap(), |x| spawn(x), |j| collect(j)).await;
        let b = my_dispatch_capped(nested(f(g())), "a string with ) in it", '(');
        let c = dispatch_capped(one, "close ) inside a literal", |x| { h(x) }).await;
    "#;
    let sites = call_sites(src, "dispatch_capped");
    assert_eq!(sites.len(), 2, "got: {sites:#?}");
    assert!(sites[0].starts_with("dispatch_capped(items"));
    assert!(
        sites[0].ends_with("|j| collect(j))"),
        "the scan must stop at the balanced close paren, not the first one"
    );
    // `my_dispatch_capped` is a different function; a preceding identifier
    // character disqualifies the hit.
    assert!(sites.iter().all(|s| !s.contains("my_dispatch")));
    assert!(
        sites[1].contains("close ) inside a literal"),
        "a paren inside a string literal must not close the call"
    );
    // The `use` item and the doc comment are not calls.
    assert!(sites.iter().all(|s| !s.contains("use crate")));
}
