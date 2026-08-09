//! GUI tests for the findings-first Security workbench: impact ranking, the
//! Fix-all eligibility rule, the group↔bulk-action pairing (the retired
//! over-privileged→remove-redundant mismatch), the per-row fix↔section pairing
//! (a section offers its own rule's Fix only, deep-links "Open" to its own
//! tab, and applying one fix leaves the others standing), the add-owner /
//! disable-sign-in bulk flows, and the Home-drill routing (severity → All apps
//! pane, finding → expanded group).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_core::audit::{
    AuditPrincipalKind, CredentialStatus, RemediationAction, RemediationKind, RiskLevel, issue,
};
use azapptoolkit_core::models::DirectoryObject;
use azapptoolkit_dto::audit::AuditRunResult;
use azapptoolkit_dto::bulk::{
    BulkAddOwnerResult, BulkDisableOutcome, BulkDisableSignInResult, BulkOwnerOutcome,
};
use azapptoolkit_dto::exchange::{AapMigrationItem, AapMigrationReport};
use azapptoolkit_dto::remediation::RemediationOutcome;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::security_view::SecurityView;

/// A run exercising every behavior under test: ownership (impact 35, must
/// outrank expired's 8), one expired app, one unused app, an org-wide-mailbox
/// group holding an app row AND an SP-only row (Fix-all eligibility), one
/// redundant-permissions app, and one over-privileged (advisory) app.
fn cached_run() -> AuditRunResult {
    let mut owner_a = fixtures::audit_item(
        "No Owner App",
        RiskLevel::Critical,
        &[format!("{} x", issue::NO_OWNERS)],
    );
    owner_a.risk_score = 30;
    let mut owner_b = fixtures::audit_item(
        "Solo Owner App",
        RiskLevel::Low,
        &[format!("{} x", issue::SINGLE_OWNER)],
    );
    owner_b.risk_score = 5;

    let mut expired = fixtures::audit_item("Expired App", RiskLevel::Medium, &[]);
    expired.credential_status = CredentialStatus::Expired;
    expired.risk_score = 8;

    let mut unused = fixtures::audit_item("Idle App", RiskLevel::Low, &[]);
    unused.unused = true;
    unused.risk_score = 2;

    let mail_app = fixtures::audit_item(
        "Mail App",
        RiskLevel::Low,
        &[format!("{} Mail.Read", issue::ORG_WIDE_MAILBOX)],
    );
    let mut foreign_sp = fixtures::audit_item(
        "Foreign App",
        RiskLevel::Low,
        &[format!("{} Mail.ReadWrite", issue::ORG_WIDE_MAILBOX)],
    );
    foreign_sp.principal_kind = AuditPrincipalKind::ServicePrincipal;

    let redundant = fixtures::audit_item(
        "Redundant App",
        RiskLevel::Low,
        &[format!(
            "{} Mail.Read (covered by Mail.ReadWrite)",
            issue::REDUNDANT_APP_PERMS
        )],
    );
    let over = fixtures::audit_item(
        "Over App",
        RiskLevel::Low,
        &[format!("{} Mail.ReadWrite", issue::HIGH_RISK_APP_PERMS)],
    );
    // Confined by the deprecated policy: its own group, with the plan-first
    // migration Fix attached. It ALSO holds an expired credential, so it is
    // listed under two groups carrying two unrelated fixes — the cross-section
    // leakage `section_rows_offer_only_their_own_rules_fix` pins.
    let mut legacy = fixtures::audit_item(
        "Legacy Policy App",
        RiskLevel::Low,
        &[format!("{}: Mail.Read", issue::LEGACY_MAILBOX_POLICY)],
    );
    legacy.credential_status = CredentialStatus::Expired;
    legacy.remediations = vec![
        RemediationAction {
            kind: RemediationKind::MigrateApplicationAccessPolicy,
            label: "Migrate to RBAC for Applications".to_string(),
            detail: "Replaces the legacy policy confining 1 permission: Mail.Read".to_string(),
            targets: vec!["Mail.Read".to_string()],
        },
        RemediationAction {
            kind: RemediationKind::RemoveExpiredCredentials,
            label: "Remove 1 expired credential".to_string(),
            detail: "old-secret (expired 2024-01-01)".to_string(),
            targets: Vec::new(),
        },
    ];

    AuditRunResult {
        tenant_id: "tenant-1".to_string(),
        total_apps: 9,
        items: vec![
            owner_a, owner_b, expired, unused, mail_app, foreign_sp, redundant, over, legacy,
        ],
        cancelled: false,
        sign_in_report_available: true,
        sign_in_consent_required: false,
        truncated: false,
        degraded: Vec::new(),
    }
}

async fn mount_security() -> ts::Mounted {
    ts::reset();
    ts::mock_ok("get_cached_audit", &cached_run());
    let m = ts::mount_view(|| view! { <SecurityView /> });
    ts::wait_for(|| ts::body_contains("Missing or single owner")).await;
    m
}

fn click_button(label: &str) {
    for el in ts::query_all("button") {
        if el.text_content().unwrap_or_default().trim() == label {
            let el: web_sys::HtmlElement = el.unchecked_into();
            el.click();
            return;
        }
    }
    panic!("no button labelled `{label}`");
}

/// True once a button with exactly this label exists — body-text waits are not
/// enough here because group blurbs can mention an action's name before the
/// bulk bar's button renders.
fn has_button(label: &str) -> bool {
    ts::query_all("button")
        .iter()
        .any(|el| el.text_content().unwrap_or_default().trim() == label)
}

/// Clicks the "Open" deep-link inside the row for `app_name`. Every row carries
/// one, so the label alone is ambiguous — scope the search to the row.
fn click_row_open(app_name: &str) {
    for row in ts::query_all("tbody tr") {
        if !row.text_content().unwrap_or_default().contains(app_name) {
            continue;
        }
        let buttons = row.query_selector_all("button").unwrap();
        for i in 0..buttons.length() {
            let el: web_sys::HtmlElement = buttons.item(i).unwrap().unchecked_into();
            if el.text_content().unwrap_or_default().trim() == "Open" {
                el.click();
                return;
            }
        }
    }
    panic!("no Open button in a row for `{app_name}`");
}

/// Clicks a button inside the bulk bar's armed panel — the panel's confirm can
/// share its label with the bar's action button, so scope to the panel.
fn click_panel_button(label: &str) {
    for el in ts::query_all(".bulk-action-bar__confirm button") {
        if el.text_content().unwrap_or_default().trim() == label {
            let el: web_sys::HtmlElement = el.unchecked_into();
            el.click();
            return;
        }
    }
    panic!("no armed-panel button labelled `{label}`");
}

#[wasm_bindgen_test]
async fn groups_rank_by_impact_with_counts() {
    let _m = mount_security().await;
    let titles: Vec<String> = ts::query_all(".finding-group__title")
        .iter()
        .map(|el| el.text_content().unwrap_or_default())
        .collect();
    let pos = |t: &str| {
        titles
            .iter()
            .position(|x| x == t)
            .unwrap_or_else(|| panic!("group {t:?} not rendered: {titles:?}"))
    };
    // Ownership (impact 35) outranks expired (8), which outranks unused (2).
    assert!(pos("Missing or single owner") < pos("Expired credentials"));
    assert!(pos("Expired credentials") < pos("Unused applications"));
    assert!(ts::body_contains("2 principals"), "ownership count renders");
    // The healthy section trails as a collapsed disclosure; expanding it
    // reveals the positive groups even at zero count.
    assert!(!ts::body_contains("Mailbox access scoped"));
    ts::click(".finding-group__header--section");
    ts::wait_for(|| ts::body_contains("Mailbox access scoped")).await;
}

#[wasm_bindgen_test]
async fn fix_all_selects_only_application_rows() {
    let m = mount_security().await;
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("orgwide_mailbox".to_string()));
    ts::wait_for(|| ts::body_contains("Fix all 1")).await;
    // The group holds 2 principals (app + SP) but only the app registration is
    // bulk-eligible — Fix all must seed exactly it.
    click_button("Fix all 1");
    ts::wait_for(|| {
        !m.session
            .tenant_ui
            .selected_audit_ids
            .get_untracked()
            .is_empty()
    })
    .await;
    let selected = m.session.tenant_ui.selected_audit_ids.get_untracked();
    assert!(selected.contains("obj-Mail App"));
    assert!(
        !selected.contains("obj-Foreign App"),
        "SP rows must never enter the selection via Fix all"
    );
    assert_eq!(selected.len(), 1);
}

#[wasm_bindgen_test]
async fn group_bar_pairs_each_fix_with_its_own_rule() {
    let m = mount_security().await;
    // The redundant-permissions group offers RemoveRedundant…
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("redundant_perms".to_string()));
    ts::wait_for(|| ts::body_contains("Fix all 1")).await;
    click_button("Fix all 1");
    ts::wait_for(|| ts::body_contains("Remove redundant permissions")).await;

    // …but the over-privileged (advisory) group must NOT — the old
    // audit_bulk_actions mapped a different rule's fix here.
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("high_risk_perms".to_string()));
    ts::wait_for(|| !ts::body_contains("Remove redundant permissions")).await;
    assert!(
        m.session
            .tenant_ui
            .selected_audit_ids
            .get_untracked()
            .is_empty(),
        "switching groups clears the shared selection"
    );
    // Selecting its row offers no bulk bar actions (advisory group).
    let checkbox: web_sys::HtmlElement = ts::query_all("tbody input[type=checkbox]")
        .into_iter()
        .next()
        .expect("advisory group rows are still visible with checkboxes")
        .unchecked_into();
    checkbox.click();
    ts::wait_for(|| {
        !m.session
            .tenant_ui
            .selected_audit_ids
            .get_untracked()
            .is_empty()
    })
    .await;
    assert!(
        !ts::body_contains("Remove redundant permissions"),
        "no cross-rule fix is offered on the advisory group"
    );
}

#[wasm_bindgen_test]
async fn bulk_add_owner_flow_sends_the_picked_principal() {
    let m = mount_security().await;
    ts::mock_ok(
        "search_users",
        &vec![DirectoryObject {
            id: "user-1".to_string(),
            display_name: Some("Dana Admin".to_string()),
            user_principal_name: Some("dana@contoso.com".to_string()),
            mail: None,
            odata_type: Some("#microsoft.graph.user".to_string()),
        }],
    );
    ts::mock_ok(
        "bulk_add_owner",
        &BulkAddOwnerResult {
            outcomes: vec![
                BulkOwnerOutcome {
                    object_id: "obj-No Owner App".to_string(),
                    added: true,
                    skipped: false,
                    error: None,
                },
                BulkOwnerOutcome {
                    object_id: "obj-Solo Owner App".to_string(),
                    added: true,
                    skipped: false,
                    error: None,
                },
            ],
            cancelled: false,
        },
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("ownership".to_string()));
    ts::wait_for(|| ts::body_contains("Fix all 2")).await;
    click_button("Fix all 2");
    ts::wait_for(|| has_button("Add owner")).await;
    click_button("Add owner");
    ts::wait_for(|| ts::query(".bulk-action-bar__confirm input").is_some()).await;
    ts::set_input_value(".bulk-action-bar__confirm input", "dana");
    ts::wait_for(|| ts::query(".add-owner-candidates button").is_some()).await;
    ts::click(".add-owner-candidates button");
    ts::wait_for(|| ts::body_contains("Adding:")).await;
    click_panel_button("Add owner");
    ts::wait_for(|| ts::call_count("bulk_add_owner") == 1).await;

    let call = ts::last_call("bulk_add_owner").unwrap();
    assert_eq!(
        call.args.get("principalId").and_then(|v| v.as_str()),
        Some("user-1")
    );
    assert_eq!(
        call.args
            .get("objectIds")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(2)
    );
}

#[wasm_bindgen_test]
async fn bulk_disable_sign_in_flow_runs_on_the_unused_group() {
    let m = mount_security().await;
    ts::mock_ok(
        "bulk_disable_sign_in",
        &BulkDisableSignInResult {
            outcomes: vec![BulkDisableOutcome {
                object_id: "obj-Idle App".to_string(),
                error: None,
            }],
            cancelled: false,
        },
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("unused".to_string()));
    ts::wait_for(|| ts::body_contains("Fix all 1")).await;
    click_button("Fix all 1");
    ts::wait_for(|| has_button("Disable sign-in")).await;
    click_button("Disable sign-in");
    // Reversible ⇒ plain confirm panel (no typed keyword).
    ts::wait_for(|| ts::query(".bulk-action-bar__confirm").is_some()).await;
    click_panel_button("Disable sign-in");
    ts::wait_for(|| ts::call_count("bulk_disable_sign_in") == 1).await;

    let call = ts::last_call("bulk_disable_sign_in").unwrap();
    assert_eq!(
        call.args
            .get("objectIds")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str()),
        Some("obj-Idle App")
    );
}

/// The legacy-policy migration Fix is plan-first: opening it must run a **dry
/// run** and refuse to commit until that plan has come back. A modal that
/// committed on the first click would perform an Exchange scope build + Entra
/// grant strip before the operator ever saw which mailboxes it covers.
#[wasm_bindgen_test]
async fn legacy_policy_fix_plans_before_it_migrates() {
    let m = mount_security().await;
    ts::mock_ok(
        "migrate_application_access_policies",
        &AapMigrationReport {
            dry_run: true,
            incomplete: false,
            unattempted: Vec::new(),
            items: vec![AapMigrationItem {
                app_id: "Legacy Policy App-appid".to_string(),
                source_policy_identities: vec!["policy-1".to_string()],
                scope_name: Some("app_scope_Legacy Policy App-appid".to_string()),
                scope_filter: Some("MemberOfGroup -eq 'CN=Sales'".to_string()),
                managed_group_name: Some("app_scope_group_Legacy Policy App-appid".to_string()),
                members_copied: vec!["ada@contoso.com".to_string()],
                members_unverified: Vec::new(),
                roles_assigned: vec!["Application Mail.Read".to_string()],
                removed_entra_grants: vec!["Mail.Read".to_string()],
                removed_policies: vec!["policy-1".to_string()],
                retired_groups: Vec::new(),
                status: "planned".to_string(),
                warnings: Vec::new(),
            }],
            failures: Vec::new(),
        },
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("legacy_mailbox_scope".to_string()));
    ts::wait_for(|| has_button("Migrate to RBAC for Applications")).await;
    click_button("Migrate to RBAC for Applications");

    // Opening the modal plans; nothing is committed yet.
    ts::wait_for(|| ts::call_count("migrate_application_access_policies") == 1).await;
    let plan = ts::last_call("migrate_application_access_policies").unwrap();
    assert_eq!(
        plan.args.get("dryRun").and_then(|v| v.as_bool()),
        Some(true)
    );
    // Keyed on the appId (what a policy names), not the audit row's object id.
    assert_eq!(
        plan.arg_str("appId").as_deref(),
        Some("Legacy Policy App-appid")
    );
    ts::wait_for(|| ts::body_contains("Nothing has changed yet")).await;

    // Committing sends the same call with dry_run cleared.
    click_button("Migrate");
    ts::wait_for(|| ts::call_count("migrate_application_access_policies") == 2).await;
    let commit = ts::last_call("migrate_application_access_policies").unwrap();
    assert_eq!(
        commit.args.get("dryRun").and_then(|v| v.as_bool()),
        Some(false)
    );
}

/// A section shows "Open" plus the Fix for **its own** rule and nothing else.
/// The Legacy-policy app also holds an expired credential, so before the
/// `kinds` gate its row rendered "Remove 1 expired credential" inside the
/// legacy-policy section — an action with nothing to do with the finding the
/// operator opened that section for.
#[wasm_bindgen_test]
async fn section_rows_offer_only_their_own_rules_fix() {
    let m = mount_security().await;
    let expand = |key: &str| {
        m.session
            .tenant_ui
            .audit_expanded_group
            .set(Some(key.to_string()))
    };

    expand("legacy_mailbox_scope");
    ts::wait_for(|| has_button("Migrate to RBAC for Applications")).await;
    assert!(
        !has_button("Remove 1 expired credential"),
        "the legacy-policy section must not offer the credential fix"
    );

    // …and symmetrically: the expired section owns the credential fix only.
    expand("expired");
    ts::wait_for(|| has_button("Remove 1 expired credential")).await;
    assert!(
        !has_button("Migrate to RBAC for Applications"),
        "the expired-credentials section must not offer the migration fix"
    );
}

/// "Open" lands on the tab for the section it was clicked in. The Legacy Policy
/// App trips both the legacy-scoping rule and the expired-credential one, and
/// the item-wide scan ranks scoping first — so from Expired credentials, Open
/// used to drop the operator on Permissions.
#[wasm_bindgen_test]
async fn open_deep_links_to_the_section_it_was_clicked_in() {
    let m = mount_security().await;
    let tab = || m.session.tenant_ui.pending_app_tab.get_untracked();

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("expired".to_string()));
    ts::wait_for(|| has_button("Remove 1 expired credential")).await;
    click_row_open("Legacy Policy App");
    assert_eq!(tab().as_deref(), Some("credentials"));

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("legacy_mailbox_scope".to_string()));
    ts::wait_for(|| has_button("Migrate to RBAC for Applications")).await;
    click_row_open("Legacy Policy App");
    assert_eq!(tab().as_deref(), Some("permissions"));
}

/// Applying one section's Fix clears **that** remediation only. Clearing the
/// row's whole set made the credential fix take the legacy-policy section's
/// migration button with it — the operator's next stop vanished, with nothing
/// short of a full re-run to bring it back.
#[wasm_bindgen_test]
async fn applying_one_fix_leaves_the_other_sections_fix_standing() {
    let m = mount_security().await;
    ts::mock_ok(
        "remediate_remove_expired_credentials",
        &RemediationOutcome {
            removed_secrets: 1,
            removed_certificates: 0,
        },
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("expired".to_string()));
    ts::wait_for(|| has_button("Remove 1 expired credential")).await;
    click_button("Remove 1 expired credential");
    ts::wait_for(|| ts::body_contains("Remove expired credentials?")).await;
    click_button("Remove");
    ts::wait_for(|| ts::call_count("remediate_remove_expired_credentials") == 1).await;
    // The applied fix is gone for good.
    ts::wait_for(|| !has_button("Remove 1 expired credential")).await;

    // The legacy-policy section still offers the migration nobody has run.
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("legacy_mailbox_scope".to_string()));
    ts::wait_for(|| has_button("Migrate to RBAC for Applications")).await;
}

#[wasm_bindgen_test]
async fn home_drills_route_severity_to_apps_and_findings_to_groups() {
    let m = mount_security().await;
    // Finding drill → Findings pane with the group expanded.
    m.session.open_posture_with_facet("ownership");
    assert_eq!(m.session.security_tab.get_untracked(), "findings");
    assert_eq!(
        m.session
            .tenant_ui
            .audit_expanded_group
            .get_untracked()
            .as_deref(),
        Some("ownership")
    );
    ts::wait_for(|| ts::body_contains("Adding an owner is purely additive")).await;

    // Severity drill → All apps pane with the severity filter seeded. Scope
    // queries to the apps pane — the findings pane stays keep-alive-mounted
    // (display:none) with its own tables still in the DOM.
    m.session.open_posture_with_facet("critical");
    assert_eq!(m.session.security_tab.get_untracked(), "apps");
    assert_eq!(
        m.session.tenant_ui.audit_severity.get_untracked(),
        "critical"
    );
    ts::wait_for(|| {
        ts::query_all(".audit-apps-pane tbody tr").iter().any(|r| {
            r.text_content()
                .unwrap_or_default()
                .contains("No Owner App")
        })
    })
    .await;
    // The severity filter narrows the table to the one Critical row.
    assert_eq!(
        ts::query_all(".audit-apps-pane tbody tr").len(),
        1,
        "only the Critical row survives the drill filter"
    );
}
