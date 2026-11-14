//! Pins the confirmation tiers (`docs/architecture/frontend-workspace.md`,
//! "Confirmation tiers"): an action's guard follows what it does, not which
//! surface it is triggered from.
//!
//! Before this, the same act was guarded differently per surface: admin consent
//! was one click on an app's Permissions tab and a typed "GRANT" in the bulk
//! bar; "Delete forever" (permanent) only relabelled its own button while the
//! recoverable bulk delete asked for a typed "DELETE"; the Exchange section's
//! "Migrate this app" ran without the plan the Security tab's dialog requires.
//!
//! Each row names a source file and a fragment that must stay in it. The scan
//! is textual on purpose: the behaviour is proven by the browser GUI tests
//! (`tests/gui/{deleted_apps,application_detail,confirm_dialog}.rs`); this keeps
//! a guard from being dropped on a surface those tests do not mount.
//!
//! Runs natively under `just web-test`; gated off for wasm32 because it reads
//! the filesystem.

#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::path::Path;

/// `(file under src/, fragment that must be present, the rule it carries)`.
const REQUIRED: &[(&str, &str, &str)] = &[
    (
        "views/dialogs/deleted_apps_dialog.rs",
        "require_keyword=\"DELETE\"",
        "permanent delete is irreversible: typed keyword",
    ),
    (
        "views/application_detail_pane.rs",
        "require_keyword=\"DELETE\"",
        "deleting an app registration: typed keyword, as the bulk delete",
    ),
    (
        "views/tabs/permissions_tab.rs",
        "require_keyword=\"GRANT\"",
        "admin consent is tenant-wide: typed keyword, as the bulk grant",
    ),
    (
        "views/enterprise_application_detail_pane/sso_tab.rs",
        "require_keyword=\"ROTATE\"",
        "an immediate signing-certificate rotation: typed keyword",
    ),
    (
        "views/enterprise_application_detail_pane/sso_tab.rs",
        "title=\"Disable single sign-on?\"",
        "turning SSO off is confirmed",
    ),
    (
        "components/exchange_scoping_section.rs",
        "title=\"Grant scoped access and remove org-wide grants?\"",
        "stripping org-wide grants is confirmed",
    ),
    (
        "components/exchange_scoping_section.rs",
        "title=\"Grant scoped access to these groups and remove org-wide grants?\"",
        "the Advanced block's org-wide strip is confirmed, as the recommended one",
    ),
    (
        "views/tabs/owners_tab.rs",
        "title=\"Replace the owners of this app registration?\"",
        "replacing the owner set removes owners: confirmed, as a single removal",
    ),
    (
        "views/dr.rs",
        "require_keyword=\"RESTORE\"",
        "a restore re-grants permissions tenant-wide: typed keyword",
    ),
    (
        "components/exchange_scoping_section.rs",
        "mig_cmd.busy.get() || !mig_planned.get()",
        "an AAP migration is offered only after its plan was shown",
    ),
    (
        "views/dialogs/migrate_legacy_scope.rs",
        "busy.get() || report.with(|r| r.is_none())",
        "an AAP migration is offered only after its plan was shown",
    ),
];

/// Fragments that must NOT come back: `(file, fragment, why)`.
const FORBIDDEN: &[(&str, &str, &str)] = &[(
    "views/dialogs/deleted_apps_dialog.rs",
    "Confirm permanent delete",
    "the arm-then-click permanent delete (same button, no dialog, no keyword)",
)];

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn every_tiered_action_keeps_its_guard() {
    let mut missing = Vec::new();
    for (file, fragment, rule) in REQUIRED {
        if !read(file).contains(fragment) {
            missing.push(format!("{file}: `{fragment}` — {rule}"));
        }
    }
    assert!(
        missing.is_empty(),
        "confirmation tier dropped (frontend-workspace.md, \"Confirmation tiers\"):\n{}",
        missing.join("\n")
    );
}

#[test]
fn retired_weak_confirmations_stay_retired() {
    let mut found = Vec::new();
    for (file, fragment, why) in FORBIDDEN {
        if read(file).contains(fragment) {
            found.push(format!("{file}: `{fragment}` — {why}"));
        }
    }
    assert!(
        found.is_empty(),
        "weak confirmation reintroduced:\n{}",
        found.join("\n")
    );
}
