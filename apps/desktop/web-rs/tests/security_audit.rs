//! GUI tests for the Security-audit table's SP-only rows — principals scored
//! without a local application object (foreign enterprise apps, managed
//! identities, orphaned SPs). Pins the three behaviors that keep them safe and
//! useful: they never enter the bulk selection (the bulk commands loop
//! app-registration cores), the "No app registration" finding filters to them,
//! and their scope Fix routes to the SP-only command instead of the
//! app-registration remediation wrapper.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_core::audit::{
    AuditPrincipalKind, RemediationAction, RemediationKind, RiskLevel, issue,
};
use azapptoolkit_dto::audit::AuditRunResult;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::audit_view::AuditView;

wasm_bindgen_test_configure!(run_in_browser);

/// One app-registration row + one SP-only row (a foreign enterprise app
/// holding an org-wide mail grant, with the scope-mailbox Fix attached).
fn cached_run() -> AuditRunResult {
    let app = fixtures::audit_item(
        "Local App",
        RiskLevel::Medium,
        &[format!("{} Mail.Read", issue::ORG_WIDE_MAILBOX)],
    );
    let mut sp = fixtures::audit_item(
        "Foreign App",
        RiskLevel::High,
        &[format!("{} Mail.ReadWrite", issue::ORG_WIDE_MAILBOX)],
    );
    sp.principal_kind = AuditPrincipalKind::ServicePrincipal;
    sp.remediations = vec![RemediationAction {
        kind: RemediationKind::ScopeMailboxAccess,
        label: "Scope 1 mailbox permission to specific mailboxes".to_string(),
        detail: "Confines via Exchange RBAC: Mail.ReadWrite".to_string(),
        targets: vec!["Mail.ReadWrite".to_string()],
    }];
    AuditRunResult {
        tenant_id: "tenant-1".to_string(),
        total_apps: 2,
        items: vec![sp, app],
        cancelled: false,
        sign_in_report_available: false,
        sign_in_consent_required: false,
    }
}

async fn mount_audit() -> ts::Mounted {
    ts::reset();
    ts::mock_ok("get_cached_audit", &cached_run());
    let m = ts::mount_view(|| view! { <AuditView /> });
    ts::wait_for(|| ts::body_contains("Foreign App")).await;
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

#[wasm_bindgen_test]
async fn sp_rows_are_excluded_from_selection() {
    let m = mount_audit().await;
    // Only the app-registration row renders a checkbox; the SP row shows the
    // explanatory dash instead.
    assert_eq!(
        ts::query_all("tbody input[type=checkbox]").len(),
        1,
        "exactly the app-registration row is selectable"
    );
    // "Select all visible" covers the filtered set MINUS the SP rows.
    let select_all: web_sys::HtmlElement = ts::query(".app-list__selectall input")
        .expect("select-all bar renders")
        .unchecked_into();
    select_all.click();
    ts::wait_for(|| !m.session.selected_audit_ids.get_untracked().is_empty()).await;
    let selected = m.session.selected_audit_ids.get_untracked();
    assert!(selected.contains("obj-Local App"));
    assert!(
        !selected.contains("obj-Foreign App"),
        "SP row must never enter the bulk selection"
    );
    assert_eq!(selected.len(), 1);
}

#[wasm_bindgen_test]
async fn no_local_app_finding_filters_to_sp_rows() {
    let m = mount_audit().await;
    assert_eq!(ts::query_all("tbody tr").len(), 2);
    m.session.audit_finding.set("no_local_app".to_string());
    ts::wait_for(|| ts::query_all("tbody tr").len() == 1).await;
    let row = &ts::query_all("tbody tr")[0];
    assert!(
        row.text_content()
            .unwrap_or_default()
            .contains("Foreign App"),
        "the SP-only row survives the no_local_app finding filter"
    );
}

#[wasm_bindgen_test]
async fn sp_mailbox_fix_routes_to_the_sp_only_command() {
    let _m = mount_audit().await;
    ts::mock_ok(
        "grant_managed_identity_scoped_exchange_access",
        &fixtures::exchange_access_result(),
    );

    // The SP row's Fix (the app row carries no remediation in this fixture).
    click_button("Scope 1 mailbox permission to specific mailboxes");
    ts::wait_for(|| ts::query(".modal textarea").is_some()).await;
    ts::set_textarea_value(".modal textarea", "Sales Team");
    click_button("Scope access");
    ts::wait_for(|| ts::call_count("grant_managed_identity_scoped_exchange_access") == 1).await;

    // Never the app-registration wrapper — it would 404 resolving the
    // (nonexistent) local application.
    assert_eq!(ts::call_count("remediate_scope_mailbox_access"), 0);
    let call = ts::last_call("grant_managed_identity_scoped_exchange_access").unwrap();
    assert_eq!(
        call.args.get("managedIdentityId").and_then(|v| v.as_str()),
        Some("obj-Foreign App"),
        "the SP object id is the target"
    );
    assert_eq!(
        call.args.get("appId").and_then(|v| v.as_str()),
        Some("Foreign App-appid")
    );
    assert_eq!(
        call.args
            .get("mailPermissions")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(1)
    );
    assert_eq!(
        call.args
            .get("removeUnscopedEntraGrants")
            .and_then(|v| v.as_bool()),
        Some(true),
        "the org-wide grant is stripped so RBAC scoping is effective"
    );
}
