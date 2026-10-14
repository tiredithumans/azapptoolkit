//! Dead-session handling in the long-running fan-outs.
//!
//! A re-auth-fatal failure makes every remaining item fail identically, so a
//! fan-out that only warns returns a partial result the UI presents as
//! complete. Checked per `dispatch_capped` **call site** — see [`call_sites`]
//! for why the whole-file form was unsound. Also the page-size rule for the
//! serial paged Graph reads the fan-outs sit on
//! ([`every_paged_graph_read_sends_a_page_size`]).

// The module list this file used to carry is gone: the fan-out modules are now
// whichever modules actually call a driver (`sources::long_run_drivers`, derived
// from the source tree by `sources::command_modules()`). A hand-maintained list
// could only ever check the files someone remembered to add.

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
    // Recycle-bin reads are tenant-wide too: the restore run pre-reads both
    // deleted collections, so its per-item write loop must carry the same
    // cancel/session-proof as every other tenant-wide fan-out.
    "list_deleted_applications(",
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
///
/// The write loop may sit in a helper the command hands its per-item work to
/// (`bulk::sweep_one`, `aap_migration::run_migration_batches`); see
/// [`is_tenant_wide_writer`]. [`WRITER_FLOOR`] stops that following from
/// silently losing the two commands that need it.
#[test]
fn every_tenant_wide_writer_is_cancellable() {
    let mut offenders: Vec<String> = Vec::new();
    let mut writers: Vec<String> = Vec::new();
    let helpers = Helpers::from_source();
    for cmd in super::sources::commands() {
        if !is_tenant_wide_writer(&cmd.body, &helpers) {
            continue;
        }
        writers.push(cmd.name.clone());
        // Two accepted shapes: the command gates on the latch itself, or it
        // calls a function that does (`Helpers::dead_gated`). Both must ALSO
        // claim a cancel token — a dead session is not the same event as an
        // operator pressing Cancel, and only the token answers the second.
        let (cancellable, stops_on_dead) = stoppable(&cmd.body, &helpers);
        if !(cancellable && stops_on_dead) {
            offenders.push(format!(
                "{}::{} (claims a token: {cancellable}, stops on a dead session: {stops_on_dead})",
                cmd.module, cmd.name
            ));
        }
    }
    for floor in WRITER_FLOOR {
        assert!(
            writers.iter().any(|w| w == floor),
            "`{floor}` is no longer detected as a tenant-wide writer (found {writers:?}) — the \
             detector or the helper derivation is broken"
        );
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

/// Commands the writer detector must keep finding: their write loops sit in a
/// helper (`bulk::sweep_one`; the AAP migration's `migrate_one` closure handed
/// to `run_migration_batches`), so they are the ones a broken helper
/// derivation would drop first.
const WRITER_FLOOR: &[&str] = &[
    "bulk_remove_expired_credentials",
    "migrate_application_access_policies",
];

/// What the tenant-wide-writer rule knows about the helpers a command hands its
/// per-item work to, derived from the source (the self-test derives one from a
/// synthetic source). Shared by the rule and its self-test so the two cannot
/// disagree.
struct Helpers {
    /// `sources::cancel_runners`: the helpers handed a `CancelToken`.
    runners: std::collections::BTreeSet<String>,
    /// Runners with a loop of their own that awaits a write, and their callers.
    writing: std::collections::BTreeSet<String>,
    /// Functions that stop on a dead session themselves: every driver from
    /// `sources::long_run_drivers` (`run_bulk_seq` checks each outcome, and
    /// every `dispatch_capped` call site — the one inside a derived helper
    /// included — is pinned to gate its spawn closure by
    /// [`every_fan_out_command_honours_is_reauth_fatal`]), every runner with
    /// `is_dead()` inside one of its own loops, and their callers. A runner
    /// that only honours Cancel does not count: a cancel token proves nothing
    /// about a dead session.
    dead_gated: std::collections::BTreeSet<String>,
}

impl Helpers {
    fn from_source() -> Self {
        Self::derive(
            &super::sources::command_functions(),
            &super::sources::command_names(),
            super::sources::long_run_drivers(),
            super::sources::cancel_runners(),
        )
    }

    fn derive(
        functions: &[super::sources::Function],
        commands: &std::collections::BTreeSet<String>,
        drivers: Vec<String>,
        runners: std::collections::BTreeSet<String>,
    ) -> Self {
        let loop_in = |name: &String, pred: &dyn Fn(&str) -> bool| {
            functions
                .iter()
                .filter(|f| f.name == *name)
                .any(|f| super::sources::loops(&f.body).iter().any(|(_, b)| pred(b)))
        };
        let writing_seeds = runners
            .iter()
            .filter(|r| loop_in(r, &writes_per_item))
            .cloned()
            .collect();
        let gated_seeds = runners
            .iter()
            .filter(|r| loop_in(r, &|b| b.contains("is_dead()")))
            .cloned()
            .chain(drivers)
            .collect();
        Self {
            writing: super::sources::close_over_callers(functions, commands, writing_seeds),
            dead_gated: super::sources::close_over_callers(functions, commands, gated_seeds),
            runners,
        }
    }
}

/// A loop body that awaits a write.
fn writes_per_item(block: &str) -> bool {
    block.contains(".await") && WRITE_CALLS.iter().any(|w| block.contains(w))
}

/// Whether `body` reads a tenant-wide collection and then writes once per
/// result: in a loop of its own, through a runner whose own loop writes
/// (`bulk::sweep_one`), or by handing a runner a closure that writes (the AAP
/// migration's `migrate_one`, looped by `run_migration_batches`).
fn is_tenant_wide_writer(body: &str, helpers: &Helpers) -> bool {
    let calls_any = |set: &std::collections::BTreeSet<String>| {
        set.iter().any(|n| super::sources::calls(body, n))
    };
    TENANT_WIDE_READS.iter().any(|r| body.contains(r))
        && (super::sources::loops(body)
            .iter()
            .any(|(_, b)| writes_per_item(b))
            || calls_any(&helpers.writing)
            || (calls_any(&helpers.runners) && WRITE_CALLS.iter().any(|w| body.contains(w))))
}

/// Whether a tenant-wide writer's body can be stopped, as `(claims a token,
/// stops on a dead session)`: the latch in the body (`is_dead()`), or a call to
/// a function in [`Helpers::dead_gated`].
fn stoppable(body: &str, helpers: &Helpers) -> (bool, bool) {
    let cancellable = body.contains(".claim()");
    let stops_on_dead = body.contains("is_dead()")
        || helpers
            .dead_gated
            .iter()
            .any(|d| super::sources::calls(body, d));
    (cancellable, stops_on_dead)
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
    let mut checked = 0usize;
    let drivers = super::sources::long_run_drivers();

    for (name, src) in super::sources::command_modules() {
        let name = name.as_str();
        // The driver module DEFINES `dispatch_capped`; it has no session to
        // gate on and its own doc comments name the call.
        if name == "commands/dispatch.rs" {
            continue;
        }
        if !drivers.iter().any(|d| super::sources::calls(&src, d)) {
            continue;
        }
        checked += 1;

        // `run_bulk_seq` gates centrally, in the driver — every caller inherits
        // it, and `a_dead_session_halts_the_run_instead_of_burning_the_selection`
        // covers it. So a module that only drives the sequential path has no
        // `dispatch_capped` sites, and the loop below is empty for it. A
        // derived driver (a helper wrapping `dispatch_capped`, from
        // `sources::long_run_drivers`) gates centrally too: its one
        // `dispatch_capped` call site is checked below like any other, and every
        // command that calls the helper inherits that gate.
        let sites = call_sites(&src, "dispatch_capped");

        for (n, site) in sites.iter().enumerate() {
            // Two accepted shapes. Either the spawn closure gates on the shared
            // `SessionDead` latch (`session.is_dead()`), or the module runs its
            // own classified latch (`commands/audit/run.rs`'s `reauth_fatal` flag,
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
         on `SessionDead::is_dead()`, note failures through it in the collect arm, and then: a \
         read fan-out returns `session.err(..)` rather than a partial result (commands/backup.rs \
         has the shape); a mutating one returns what landed with the fatal code on its failures \
         (commands/bulk.rs). Never a partial read presented as complete."
    );
    // AGENTS.md: KNOWN_GAPS "is empty and must stay so". It was empty, and the
    // test above tolerated entries being ADDED to it — a new fan-out with no
    // dead-session branch could ship by appending one line, and the only
    // pushback would be a staleness message that never fires while the gap is
    // real. An allowlist that can grow is not a ratchet.
    //
    // Deliberately last, so the diagnostics above (which say what to fix) are
    // reached first when several things are wrong at once.
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
    // The helpers a command can hand its per-item work to, in the shapes the
    // command layer has: a per-app write loop gated on both stops
    // (`bulk::sweep_one`), a batch loop gated on both that runs a closure
    // (`run_migration_batches`), the same loop gated on Cancel only, and a
    // derived fan-out driver.
    let helper_src = r#"
async fn sweep_one(client: &GraphClient, cancel: &CancelToken, session: &SessionDead, app: App) {
    for key in keys(&app) {
        if cancel.is_cancelled() || session.is_dead() { break; }
        client.remove_password(&app.id, key).await;
    }
}
async fn run_batches(batches: Vec<u8>, cancel: &CancelToken, session: &SessionDead, migrate: F) {
    while let Some(batch) = next(&mut batches) {
        if cancel.is_cancelled() || session.is_dead() { break; }
        migrate(batch).await;
    }
}
async fn cancel_only_batches(batches: Vec<u8>, cancel: &CancelToken, migrate: F) {
    while let Some(batch) = next(&mut batches) {
        if cancel.is_cancelled() { break; }
        migrate(batch).await;
    }
}
async fn run_capped_helper(cancel: &CancelToken, items: Vec<u8>, per_item: F) {
    dispatch_capped(items, || 4, |x| spawn(x), |j| collect(j)).await;
}
"#;
    let functions = super::sources::functions_in(helper_src);
    let commands = std::collections::BTreeSet::new();
    // The seeds plus the derived helper, standing in for
    // `sources::long_run_drivers` (whose derivation has its own self-test).
    let drivers = ["dispatch_capped", "run_bulk_seq", "run_capped_helper"]
        .iter()
        .map(|d| (*d).to_string())
        .collect();
    let runners = super::sources::derive_cancel_runners(&functions, &commands);
    let helpers = Helpers::derive(&functions, &commands, drivers, runners);
    let violates = |body: &str| {
        let (cancellable, stops_on_dead) = stoppable(body, &helpers);
        is_tenant_wide_writer(body, &helpers) && !(cancellable && stops_on_dead)
    };

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

    // A writer whose per-item work runs through a derived driver is gated by
    // that driver's own `dispatch_capped` call site — but it must still claim.
    let through_helper = r#"{
        let apps = graph.list_applications_all(query, None).await?;
        let cancel = state.bulk_cancel.claim();
        let run = run_capped_helper(&cancel, apps, |app| async move {
            for key in keys(&app) { graph.remove_password(&app.id, key).await; }
        }).await;
    }"#;
    assert!(
        !violates(through_helper),
        "a writer gated by a derived driver must pass"
    );
    assert!(
        violates(&through_helper.replace(".claim()", ".peek()")),
        "a derived driver does not excuse a missing claim"
    );

    // The write loop in a helper the command calls (`bulk::sweep_one`): still
    // a tenant-wide writer, gated by the helper's own latch check.
    let sweep_shape = r#"{
        let cancel = state.bulk_cancel.claim();
        let apps = graph.list_applications_all(query, None).await?;
        let run = run_capped_helper(&cancel, apps, |app| async move {
            sweep_one(&client, &cancel, &session, app).await
        }).await;
    }"#;
    assert!(is_tenant_wide_writer(sweep_shape, &helpers));
    assert!(
        !violates(sweep_shape),
        "a writer whose helper is gated must pass"
    );
    assert!(violates(&sweep_shape.replace(".claim()", ".peek()")));

    // The write handed to a runner as a closure (the AAP migration): a writer,
    // gated only if the runner's own loop checks the latch.
    let migration_shape = r#"{
        let cancel = state.migration_cancel.claim();
        let session = SessionDead::new();
        let policies = exo.get_application_access_policies().await?;
        let run = run_batches(group(policies), &cancel, &session, |id, batch| async move {
            migrate_one(ctx, &id, &batch).await
        }).await;
    }"#;
    assert!(is_tenant_wide_writer(migration_shape, &helpers));
    assert!(
        !violates(migration_shape),
        "a runner gated on both stops passes"
    );
    assert!(
        violates(&migration_shape.replace("run_batches(", "cancel_only_batches(")),
        "a runner that honours only Cancel does not stop on a dead session"
    );

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

// ── Every paged read sends a page size ─────────────────────────────────────

/// The Graph client's paging helpers. Each follows `@odata.nextLink` serially,
/// so the first page's size divides the wall clock of the whole read: without
/// `$top` Graph serves its default of 100, a 10x round-trip multiplier on a
/// large tenant, and nothing fails. The size rides the `nextLink`, so it only
/// has to be on the first request — which the CALLER builds, and which is
/// therefore where the rule looks. (`collect_all_pages(` does not match
/// `collect_all_pages_capped(`, nor `collect_pages_from(` the scoped
/// `collect_pages_from_capped(`, so each capped form is listed on its own.)
const PAGING_HELPERS: &[&str] = &[
    "collect_all_pages(",
    "collect_all_pages_capped(",
    "collect_pages_from(",
    "collect_pages_from_capped(",
    // The partitioned tenant-wide scan (`partition.rs`): its caller's params
    // are page one AND every slice, so they must carry the page size.
    "scan_directory_capped(",
];

/// What counts as asking for a page size: `$top` as a query pair or inline in
/// a URL, the shared constants, or the `Prefer: odata.maxpagesize` header a
/// collection whose `$top` ceiling is too low uses instead.
const PAGE_SIZE_EVIDENCE: &[&str] = &[
    "\"$top\"",
    "$top=",
    "MAX_PAGE_SIZE",
    "DEFAULT_APP_PAGE_SIZE",
    "odata.maxpagesize",
];

/// Paged reads that legitimately send no page size of their own, each with the
/// reason. Every entry must still match a real call site (a stale exemption
/// fails the rule), so this cannot quietly grow into an allowlist.
const PAGE_SIZE_EXEMPT: &[(&str, &str, &str)] = &[
    (
        "applications.rs",
        "list_applications_all",
        "its params come from app_list_params (shared with list_applications), which sends \
         DEFAULT_APP_PAGE_SIZE on page 1 and on every appId slice — pinned by \
         list_applications_pages_at_the_graph_maximum and \
         a_large_application_scan_slices_with_its_projection",
    ),
    (
        "credentials.rs",
        "list_federated_credentials",
        "Graph caps federated credentials at 20 per app, so one default page holds them all",
    ),
];

/// One entry per paging-helper call site in `src`: the enclosing function and
/// whether that function's own body asks for a page size. Comment lines never
/// count either way — `functions_in` drops them, so a doc line that names a
/// helper is not a call and a comment that names `$top` is not a request.
fn paged_read_sites(src: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for f in super::sources::functions_in(src) {
        let calls: usize = PAGING_HELPERS
            .iter()
            .map(|h| {
                f.body
                    .match_indices(h)
                    .filter(|(at, _)| {
                        // A call, not a longer identifier ending in the name.
                        let prev = f.body[..*at].chars().next_back();
                        prev.is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
                    })
                    .count()
            })
            .sum();
        if calls == 0 {
            continue;
        }
        let sized = PAGE_SIZE_EVIDENCE.iter().any(|e| f.body.contains(e));
        out.extend(std::iter::repeat_n((f.name.clone(), sized), calls));
    }
    out
}

/// AGENTS.md: "Every paged read sends `$top`". Scans the Graph client's domain
/// modules (not `tests/`), skipping `transport.rs` and `partition.rs`, where
/// the helpers are defined, and `batch.rs`, whose continuations follow
/// sub-URLs its callers built.
#[test]
fn every_paged_graph_read_sends_a_page_size() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../crates/azapptoolkit-graph/src/client")
        .canonicalize()
        .expect("graph client dir");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&root)
        .expect("read graph client dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "rs"))
        .collect();
    files.sort();

    let mut found = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    let mut exemptions_hit: Vec<(&str, &str)> = Vec::new();
    for path in files {
        let file = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default()
            .to_string();
        // `partition.rs` defines `scan_directory_capped`, which pages each slice
        // with the params its caller passed in.
        if file == "transport.rs" || file == "batch.rs" || file == "partition.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read graph client source");
        for (func, sized) in paged_read_sites(&super::sources::strip_tests(&text)) {
            found += 1;
            if sized {
                continue;
            }
            match PAGE_SIZE_EXEMPT
                .iter()
                .find(|(f, name, _)| *f == file && *name == func)
            {
                Some((f, name, _)) => exemptions_hit.push((f, name)),
                None => offenders.push(format!("{file}::{func}")),
            }
        }
    }

    assert!(
        found >= 20,
        "found only {found} paged Graph reads — the scan is broken, and a rule that scans \
         nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "paged Graph read(s) with no page size: {offenders:#?}\n\
         Paging is serial, so Graph's default page of 100 multiplies the round trips of the whole \
         read. Send `(\"$top\", MAX_PAGE_SIZE)` (or `$top={{MAX_PAGE_SIZE}}` in the URL, or \
         `Prefer: odata.maxpagesize` where `$top` is capped lower), or add a justified entry to \
         `PAGE_SIZE_EXEMPT`."
    );
    for (file, func, _) in PAGE_SIZE_EXEMPT {
        assert!(
            exemptions_hit.contains(&(file, func)),
            "stale page-size exemption `{file}::{func}` — it matches no unsized paged read; \
             remove it"
        );
    }
}

/// The page-size rule must fire on the shape it exists to catch, and not on a
/// sized read or a doc comment that merely names a helper.
#[test]
fn the_page_size_rule_fires_on_a_read_without_top() {
    let unsized_read = r#"
    pub async fn list_things(&self) -> Result<Vec<Thing>> {
        let page = self.get_json("/things", &[], false).await?;
        self.collect_all_pages(page, false).await
    }
"#;
    assert_eq!(
        paged_read_sites(unsized_read),
        vec![("list_things".to_string(), false)]
    );

    let sized_read = r#"
    pub async fn list_things(&self) -> Result<Vec<Thing>> {
        let params: [(&str, &str); 1] = [("$top", MAX_PAGE_SIZE)];
        let page = self.get_json("/things", &params, false).await?;
        self.collect_all_pages(page, false).await
    }
"#;
    assert_eq!(
        paged_read_sites(sized_read),
        vec![("list_things".to_string(), true)]
    );

    let doc_only = r#"
    /// Walks every page via `collect_all_pages(` — prose, not a call.
    pub async fn get_thing(&self) -> Result<Thing> {
        // collect_all_pages(page, false) would be wrong here
        self.get_json("/things/1", &[], false).await
    }
"#;
    assert!(paged_read_sites(doc_only).is_empty());

    // A comment naming `$top` does not satisfy the rule, and the capped helper
    // is a paging helper too.
    let comment_top = r#"
    pub async fn list_capped(&self) -> Result<(Vec<Thing>, bool)> {
        // TODO: send $top= here
        let page = self.get_json("/things", &[], false).await?;
        self.collect_all_pages_capped(page, 10, false).await
    }
"#;
    assert_eq!(
        paged_read_sites(comment_top),
        vec![("list_capped".to_string(), false)]
    );

    // The partitioned scan is a paging helper: its caller must size the read.
    let partitioned = r#"
    pub async fn list_index(&self) -> Result<Vec<Thing>> {
        let params = [("$select", "id")];
        Ok(self.scan_directory_capped("things", "/things", &params, 10).await?.0)
    }
"#;
    assert_eq!(
        paged_read_sites(partitioned),
        vec![("list_index".to_string(), false)]
    );
}

/// The adaptive-throttle observer is attached only through
/// `throttle::FanOutMeter`.
///
/// `FanOutMeter` exists so the tracker, the RAII `ThrottleGuard` and the
/// completion counter are wired once. Its doc claimed `sweep_site_permissions`
/// had already moved onto it while that sweep (and the DR backup) still built
/// the pair by hand — a second copy of the wiring is a second place to get the
/// observer lifetime or the cap re-read wrong, and nothing noticed the drift.
/// So no command module other than `throttle.rs` names `ThrottleGuard::attach`.
#[test]
fn the_throttle_observer_is_attached_only_through_fan_out_meter() {
    let mut offenders: Vec<String> = Vec::new();
    let mut meters = 0usize;
    for (name, src) in super::sources::command_modules() {
        for line in super::sources::code_lines(&src) {
            if line.contains("FanOutMeter::attach(") {
                meters += 1;
            }
            if name != "commands/throttle.rs" && line.contains("ThrottleGuard::attach(") {
                offenders.push(format!("{name}: {}", line.trim()));
            }
        }
    }
    // The bulk commands (3), the audit, the site sweep and the DR backup.
    assert!(
        meters >= 6,
        "found only {meters} `FanOutMeter::attach` call(s) — the scan is broken"
    );
    assert!(
        offenders.is_empty(),
        "hand-rolled throttle wiring — use `FanOutMeter::attach(client, cap)` and \
         `|| meter.limit()`:\n  {}",
        offenders.join("\n  ")
    );
}

/// A command that attaches a [`FanOutMeter`] fans out, so its body must call a
/// driver from `sources::long_run_drivers` — the cross-check on the derivation
/// itself. Were a driver's call unreadable to `sources::calls`, or its header
/// to `sources::is_fn_header`, the command would drop out of the cancel and
/// dead-session rules above with nothing failing; here it fails by name.
#[test]
fn every_metered_command_calls_a_driver() {
    let drivers = super::sources::long_run_drivers();
    let mut metered = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for cmd in super::sources::commands() {
        if !super::sources::code_lines(&cmd.body).any(|l| l.contains("FanOutMeter::attach(")) {
            continue;
        }
        metered += 1;
        if !drivers.iter().any(|d| super::sources::calls(&cmd.body, d)) {
            offenders.push(format!("{}::{}", cmd.module, cmd.name));
        }
    }
    // The same six the throttle rule above counts.
    assert!(
        metered >= 6,
        "found only {metered} metered command(s) — the scan is broken"
    );
    assert!(
        offenders.is_empty(),
        "command(s) that attach a FanOutMeter but call no derived driver: {offenders:#?}\n\
         Either the fan-out moved behind a helper the driver derivation cannot see (a call \
         `sources::calls` cannot read, a header `sources::is_fn_header` cannot parse, a helper \
         outside commands/), or the meter is attached for nothing. Derived drivers: {drivers:?}"
    );
}
