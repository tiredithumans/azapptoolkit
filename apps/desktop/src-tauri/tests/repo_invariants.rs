//! Cross-tree invariants that AGENTS.md could previously only state as prose.
//!
//! Sibling of `dependency_policy.rs` and written the same way: `include_str!` +
//! a small hand-rolled scan, so these run inside `just test` on every platform
//! rather than needing a shell script that `verify` could not portably call
//! (recipe lines run under PowerShell on Windows).
//!
//! Both rules below were enforced by "the docs tell you to", and one had already
//! drifted: `run_audit` warned its way through a dead session and cached the
//! truncated security report as authoritative.

/// The non-comment, non-blank lines of a TOML block, sorted.
///
/// `header` must be the exact table line; the block ends at the next table.
fn table_body(toml_src: &str, header: &str) -> Vec<String> {
    let Some(start) = toml_src.find(header) else {
        return Vec::new();
    };
    let mut out: Vec<String> = toml_src[start + header.len()..]
        .lines()
        .take_while(|line| !line.trim_start().starts_with('['))
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    out.sort();
    out
}

/// web-rs is EXCLUDED from the root workspace (it targets `wasm32` and carries
/// its own lockfile), so it cannot inherit `[workspace.lints]` and restates the
/// block by hand. AGENTS.md says "keep it in sync with the root block"; nothing
/// but this test actually did.
#[test]
fn web_rs_lint_block_matches_the_workspace_block() {
    let root = table_body(
        include_str!("../../../../Cargo.toml"),
        "[workspace.lints.rust]",
    );
    let web = table_body(include_str!("../../web-rs/Cargo.toml"), "[lints.rust]");
    assert!(
        !root.is_empty(),
        "no [workspace.lints.rust] block found in the root Cargo.toml — this test is checking nothing"
    );
    assert_eq!(
        root, web,
        "apps/desktop/web-rs/Cargo.toml's [lints.rust] has drifted from the root \
         [workspace.lints.rust]. web-rs is outside the workspace, so it cannot inherit \
         the block — restate it verbatim."
    );
}

/// Command modules that drive a long-running fan-out. Kept as literal
/// `include_str!`s because a test binary has no reliable source-tree walk.
const FAN_OUT_MODULES: &[(&str, &str)] = &[
    (
        "commands/audit.rs",
        include_str!("../src/commands/audit.rs"),
    ),
    ("commands/bulk.rs", include_str!("../src/commands/bulk.rs")),
    (
        "commands/backup.rs",
        include_str!("../src/commands/backup.rs"),
    ),
    (
        "commands/sharepoint.rs",
        include_str!("../src/commands/sharepoint.rs"),
    ),
    (
        "commands/keyvault_rbac.rs",
        include_str!("../src/commands/keyvault_rbac.rs"),
    ),
    (
        "commands/permission_tester.rs",
        include_str!("../src/commands/permission_tester.rs"),
    ),
];

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

/// A dead session makes every remaining item fail identically, so a fan-out that
/// only warns produces a silently partial result. `UiError::is_reauth_fatal` is
/// the single definition (azapptoolkit-dto, shared by both tiers) — AGENTS.md:
/// "Long-running loops must stop on it".
#[test]
fn every_fan_out_command_honours_is_reauth_fatal() {
    let mut missing: Vec<&str> = Vec::new();
    let mut stale: Vec<&str> = Vec::new();

    for (name, src) in FAN_OUT_MODULES {
        // Guard against a module being renamed out from under this list.
        assert!(
            src.contains("dispatch_capped(") || src.contains("run_bulk_seq("),
            "{name} no longer drives a fan-out — drop it from FAN_OUT_MODULES"
        );
        // Two accepted shapes. Either the module classifies the error itself
        // (`commands/audit.rs::classify_audit_failure`), or it uses the shared
        // `SessionDead` latch — which routes through `UiError::is_reauth_fatal`
        // internally. The latch only counts when the module also *gates* on it:
        // recording a dead session and dispatching anyway is the bug this rule
        // exists to catch.
        let handled = src.contains("is_reauth_fatal")
            || (src.contains("SessionDead") && src.contains("session.is_dead()"));
        match (handled, KNOWN_GAPS.contains(name)) {
            (false, false) => missing.push(name),
            (true, true) => stale.push(name),
            _ => {}
        }
    }

    assert!(
        missing.is_empty(),
        "fan-out command(s) with no is_reauth_fatal branch: {missing:?}\n\
         A dead session makes every remaining item fail identically — stop the loop and \
         do not cache a partial result. See commands/audit.rs::classify_audit_failure."
    );
    assert!(
        stale.is_empty(),
        "these now handle is_reauth_fatal — drop them from KNOWN_GAPS: {stale:?}"
    );
}

/// Every module that writes a **pinned** cache entry, and how many it writes.
///
/// Pinning exempts an entry from LRU, so a pinned per-object key is unevictable
/// junk that crowds out the tenant-wide indexes pinning exists to protect —
/// AGENTS.md: "Never pin a per-object key". The set of legitimately pinned keys
/// is a fixed handful of tenant-wide indexes, so a ratchet is the right shape:
/// adding a pin means editing this list, which is the review the rule wants.
const PINNED_WRITE_SITES: &[(&str, &str, usize)] = &[
    (
        "commands/search.rs",
        include_str!("../src/commands/search.rs"),
        1,
    ),
    (
        "commands/gallery.rs",
        include_str!("../src/commands/gallery.rs"),
        1,
    ),
    (
        "commands/enterprise_application.rs",
        include_str!("../src/commands/enterprise_application.rs"),
        1,
    ),
    (
        "commands/applications/mod.rs",
        include_str!("../src/commands/applications/mod.rs"),
        1,
    ),
    (
        "commands/managed_identity.rs",
        include_str!("../src/commands/managed_identity.rs"),
        1,
    ),
    (
        "commands/applications/cache.rs",
        include_str!("../src/commands/applications/cache.rs"),
        2,
    ),
];

#[test]
fn pinned_cache_writes_stay_on_the_tenant_wide_indexes() {
    for (name, src, expected) in PINNED_WRITE_SITES {
        let found = src.matches("put_index(").count()
            + src.matches("put_typed_index(").count()
            + src.matches("put_typed_index_if_current(").count();
        assert_eq!(
            found, *expected,
            "{name} has {found} pinned cache write(s), expected {expected}. A pinned entry is \
             invisible to LRU, so it must be a tenant-wide INDEX (one per tenant), never a \
             per-object key — those belong in an unpinned `put`. If this is a new tenant-wide \
             index, update PINNED_WRITE_SITES."
        );
    }
}

/// A scope remediation must be gated on a POSITIVE "this resource can be
/// confined" test, never on the negation of a legacy/unscopable test.
///
/// AGENTS.md states this for mailbox, and the SharePoint sibling had already
/// drifted: `Sites.*` on Office 365 SharePoint Online was offered the Graph
/// `Sites.Selected` fix, which strips nothing on that resource and would have
/// left the app org-wide while the audit re-scored it as confined. A negation
/// silently admits every resource nobody has classified yet; the positive form
/// admits only what has been proved confinable.
#[test]
fn scope_fixes_are_gated_on_a_positive_resource_test() {
    let scoring = include_str!("../../../../crates/azapptoolkit-core/src/audit/scoring.rs");
    for positive in [
        "is_scopable_exchange_resource_permission",
        "is_scopable_sharepoint_resource_permission",
    ] {
        assert!(
            scoring.contains(positive),
            "audit/scoring.rs no longer references {positive} — a scope Fix must be gated on the \
             positive resource test, not on the negation of a legacy one"
        );
        assert!(
            !scoring.contains(&format!("!{positive}")),
            "audit/scoring.rs negates {positive}; the gate must stay positive"
        );
    }
    for negated in [
        "!is_unscopable_legacy_exchange_permission",
        "!crate::scoping::is_unscopable_legacy_exchange_permission",
    ] {
        assert!(
            !scoring.contains(negated),
            "audit/scoring.rs gates on {negated}. Negating the legacy test admits every resource \
             nobody has classified — gate on is_scopable_*_resource_permission instead."
        );
    }
}

/// Command modules that own a long-running fan-out, for the cancel-flag rule.
const CANCEL_FLAG_MODULES: &[(&str, &str)] = &[
    (
        "commands/audit.rs",
        include_str!("../src/commands/audit.rs"),
    ),
    ("commands/bulk.rs", include_str!("../src/commands/bulk.rs")),
    (
        "commands/backup.rs",
        include_str!("../src/commands/backup.rs"),
    ),
    (
        "commands/restore.rs",
        include_str!("../src/commands/restore.rs"),
    ),
    (
        "commands/sharepoint.rs",
        include_str!("../src/commands/sharepoint.rs"),
    ),
    (
        "commands/keyvault_rbac.rs",
        include_str!("../src/commands/keyvault_rbac.rs"),
    ),
    (
        "commands/permission_tester.rs",
        include_str!("../src/commands/permission_tester.rs"),
    ),
];

/// Every long-running command must `reset()` its cancel flag at the top.
///
/// The flags are shared (`audit_cancel` by the security audit AND every bulk
/// action; `sweep_cancel` by two sweeps), so a command that forgets is
/// cancelled before it starts by an unrelated earlier run — a failure that only
/// shows up as "the run did nothing" on the second use.
///
/// Splitting on `#[tauri::command]` gives one chunk per handler, which is enough
/// to tell "this handler drives a fan-out" from "this handler resets a flag".
#[test]
fn every_long_running_command_resets_its_cancel_flag() {
    let mut missing: Vec<String> = Vec::new();
    for (name, src) in CANCEL_FLAG_MODULES {
        for chunk in src.split("#[tauri::command]").skip(1) {
            // Stop at the module's test block: fixtures legitimately call the
            // fan-out helpers without being commands.
            let body = chunk.split("#[cfg(test)]").next().unwrap_or(chunk);
            let drives_fan_out =
                body.contains("dispatch_capped(") || body.contains("run_bulk_seq(");
            if drives_fan_out && !body.contains(".reset()") {
                let signature = body
                    .lines()
                    .find(|l| l.contains("pub async fn") || l.contains("pub fn"))
                    .unwrap_or("(unnamed)")
                    .trim();
                missing.push(format!("{name}: {signature}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "long-running command(s) that never reset their cancel flag: {missing:#?}\n\
         The flags are shared between commands, so a stale `true` cancels this run before it \
         starts. Call `state.<flag>_cancel.reset()` at the top."
    );
}

/// `## [X.Y.Z] - YYYY-MM-DD`, exactly — no `v` prefix, ASCII hyphen, one space.
///
/// TWO parsers depend on this and they cannot be merged (one is PowerShell in
/// `release.yml`, one is Rust in `web-rs/build.rs`), so the format contract is
/// checked here instead of by a comment in each. They already differ in
/// tolerance — the PowerShell matches `^##\s+\[` while the Rust requires a
/// single space — so a header the workflow accepts can bake empty in-app.
#[test]
fn changelog_headers_match_what_both_parsers_require() {
    let changelog = include_str!("../../../../CHANGELOG.md");
    let mut bad: Vec<&str> = Vec::new();
    let mut releases = 0usize;
    for line in changelog
        .lines()
        .filter(|l| l.trim_start().starts_with("##"))
    {
        // Section headers inside a release (### Added, …) aren't version rows.
        if !line.starts_with("## [") {
            if line.starts_with("##") && line.contains('[') && !line.starts_with("###") {
                bad.push(line);
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("## [") else {
            bad.push(line);
            continue;
        };
        let Some((version, tail)) = rest.split_once(']') else {
            bad.push(line);
            continue;
        };
        if version.starts_with('v')
            || version.split('.').count() != 3
            || !version
                .split('.')
                .all(|p| p.chars().all(|c| c.is_ascii_digit()))
        {
            // `[Unreleased]` is the one legal non-version header.
            if version != "Unreleased" {
                bad.push(line);
            }
            continue;
        }
        releases += 1;
        // ` - YYYY-MM-DD`, ASCII hyphen both as separator and inside the date.
        let date = tail.trim();
        if !date.starts_with("- ") || date.len() != "- YYYY-MM-DD".len() {
            bad.push(line);
        }
    }
    assert!(
        bad.is_empty(),
        "CHANGELOG.md header(s) that one of the two parsers will mis-read: {bad:#?}\n\
         Required shape: `## [X.Y.Z] - YYYY-MM-DD` (no `v`, ASCII hyphen, single space)."
    );
    assert!(
        releases > 0,
        "no release headers found in CHANGELOG.md — this test is checking nothing"
    );
}

/// AGENTS.md is the index every agent loads on session start, and it documents
/// its own 28 000-byte budget. It had grown past it, which is precisely when the
/// file stops being an index and starts being the manual it tells you not to
/// write — so the budget is enforced rather than advertised.
#[test]
fn agents_md_stays_within_its_own_budget() {
    const BUDGET: usize = 28_000;
    // Measured with `\r` stripped: git checks this file out CRLF on Windows, so
    // a raw byte count would charge the file one extra byte per line and make
    // the budget platform-dependent (it failed on windows-latest alone).
    let size = include_str!("../../../../AGENTS.md")
        .bytes()
        .filter(|b| *b != b'\r')
        .count();
    assert!(
        size <= BUDGET,
        "AGENTS.md is {size} bytes, over its documented {BUDGET}-byte budget by {}. \
         Move the deep detail into docs/architecture/ and leave one invariant + a pointer.",
        size - BUDGET
    );
}
