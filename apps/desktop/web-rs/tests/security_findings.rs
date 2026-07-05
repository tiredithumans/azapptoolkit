//! GUI tests for the findings-first Security workbench: impact ranking, the
//! Fix-all eligibility rule, the group↔bulk-action pairing (the retired
//! over-privileged→remove-redundant mismatch), the add-owner / disable-sign-in
//! bulk flows, and the Home-drill routing (severity → All apps pane, finding →
//! expanded group).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_core::audit::{AuditPrincipalKind, CredentialStatus, RiskLevel, issue};
use azapptoolkit_core::models::DirectoryObject;
use azapptoolkit_dto::audit::AuditRunResult;
use azapptoolkit_dto::bulk::{
    BulkAddOwnerResult, BulkDisableOutcome, BulkDisableSignInResult, BulkOwnerOutcome,
};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::security_view::SecurityView;

wasm_bindgen_test_configure!(run_in_browser);

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

    AuditRunResult {
        tenant_id: "tenant-1".to_string(),
        total_apps: 8,
        items: vec![
            owner_a, owner_b, expired, unused, mail_app, foreign_sp, redundant, over,
        ],
        cancelled: false,
        sign_in_report_available: true,
        sign_in_consent_required: false,
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
