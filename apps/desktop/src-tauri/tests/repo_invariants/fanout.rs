//! Dead-session handling in the long-running fan-outs.
//!
//! A re-auth-fatal failure makes every remaining item fail identically, so a
//! fan-out that only warns returns a partial result the UI presents as
//! complete. Checked per `dispatch_capped` **call site** — see [`call_sites`]
//! for why the whole-file form was unsound.

/// Command modules that drive a long-running fan-out. Kept as literal
/// `include_str!`s because a test binary has no reliable source-tree walk.
const FAN_OUT_MODULES: &[(&str, &str)] = &[
    (
        "commands/audit.rs",
        include_str!("../../src/commands/audit.rs"),
    ),
    (
        "commands/bulk.rs",
        include_str!("../../src/commands/bulk.rs"),
    ),
    (
        "commands/backup.rs",
        include_str!("../../src/commands/backup.rs"),
    ),
    (
        "commands/sharepoint.rs",
        include_str!("../../src/commands/sharepoint.rs"),
    ),
    (
        "commands/keyvault_rbac.rs",
        include_str!("../../src/commands/keyvault_rbac.rs"),
    ),
    (
        "commands/permission_tester.rs",
        include_str!("../../src/commands/permission_tester.rs"),
    ),
];

/// Long-running **sequential** flows: many writes in a row, each degrading to a
/// per-item failure or warning rather than aborting.
///
/// Held separately from [`FAN_OUT_MODULES`] because the rename-guard differs —
/// these dispatch nothing, so `dispatch_capped(`/`run_bulk_seq(` never appears
/// in them — but the hazard is identical and arguably worse: a dead session
/// mid-restore produced one indistinguishable failure per remaining item, so a
/// report full of "permission denied" read as a tenant rejecting the writes
/// rather than as a session that had expired on the first one.
const SEQUENTIAL_WRITE_MODULES: &[(&str, &str)] = &[(
    "commands/restore.rs",
    include_str!("../../src/commands/restore.rs"),
)];

/// The sequential counterpart to [`every_fan_out_command_honours_is_reauth_fatal`].
#[test]
fn every_sequential_write_flow_stops_on_a_dead_session() {
    for (name, src) in SEQUENTIAL_WRITE_MODULES {
        assert!(
            src.contains("SessionDead") && src.contains("session.is_dead()"),
            "{name} performs a long sequence of writes but never latches or gates on a dead \
             session. Construct a `SessionDead`, note each failure through it (`note_code` keeps \
             `UiError::is_reauth_fatal` the single definition), and break out of each pass when \
             `is_dead()` — otherwise every remaining item fails identically and the report reads \
             as a tenant rejection rather than an expired session."
        );
    }
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
/// for why the file-level form was unsound.
#[test]
fn every_fan_out_command_honours_is_reauth_fatal() {
    let mut missing: Vec<String> = Vec::new();
    let mut stale: Vec<&str> = Vec::new();

    for (name, src) in FAN_OUT_MODULES {
        // Guard against a module being renamed out from under this list.
        assert!(
            src.contains("dispatch_capped(") || src.contains("run_bulk_seq("),
            "{name} no longer drives a fan-out — drop it from FAN_OUT_MODULES"
        );

        // `run_bulk_seq` gates centrally, in the driver — every caller inherits
        // it, and `a_dead_session_halts_the_run_instead_of_burning_the_selection`
        // covers it. A module that only drives the sequential path is handled by
        // that, so it has no call sites to check here.
        let sites = call_sites(src, "dispatch_capped");
        let handled_by_driver = sites.is_empty() && src.contains("run_bulk_seq(");

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

        let handled = handled_by_driver || !sites.is_empty();
        match (handled, KNOWN_GAPS.contains(name)) {
            (false, false) => missing.push(format!("{name} (no recognised fan-out driver)")),
            (true, true) => stale.push(name),
            _ => {}
        }
    }

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
