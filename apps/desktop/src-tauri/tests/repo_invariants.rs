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

/// Fan-outs that still lack the branch. These are the same defect class as the
/// one fixed in `commands/audit.rs` and each needs the same treatment; they are
/// listed rather than ignored so the rule stays honest and so no NEW fan-out can
/// be added without one. Removing a name here is the fix landing.
const KNOWN_GAPS: &[&str] = &[
    "commands/backup.rs",
    "commands/keyvault_rbac.rs",
    "commands/permission_tester.rs",
    "commands/sharepoint.rs",
];

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
        let handled = src.contains("is_reauth_fatal");
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
