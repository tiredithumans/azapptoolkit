//! GUI tests for the Security workbench's SP-only rows — principals scored
//! without a local application object (foreign enterprise apps, managed
//! identities, orphaned SPs). Pins the three behaviors that keep them safe and
//! useful: they never enter the bulk selection (the bulk commands loop
//! app-registration cores), the "No local app registration" group collects
//! them, and their scope Fix routes to the SP-only command instead of the
//! app-registration remediation wrapper.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_core::audit::{
    AuditPrincipalKind, RemediationAction, RemediationKind, RiskLevel, issue,
};
use azapptoolkit_dto::audit::{AuditCoverageGap, AuditProgress, AuditRunResult};
use azapptoolkit_dto::events as names;
use azapptoolkit_dto::exchange::ExchangeAccessResult;
use azapptoolkit_web_rs::state::SecurityTab;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::security_view::SecurityView;

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
        credential_policy_available: false,
        credential_policy_max_days: None,
        truncated: false,
        degraded: Vec::new(),
        completed_at: None,
        mailbox_scoping_resolved: true,
    }
}

async fn mount_security() -> ts::Mounted {
    ts::reset();
    ts::mock_ok("get_cached_audit", &cached_run());
    let m = ts::mount_view(|| view! { <SecurityView /> });
    // The Findings pane (default tab) renders group headers once hydrated.
    ts::wait_for(|| ts::body_contains("Org-wide mailbox access")).await;
    m
}

#[wasm_bindgen_test]
async fn sp_rows_are_excluded_from_selection_on_the_apps_pane() {
    let m = mount_security().await;
    m.session
        .security_tab
        .set(SecurityTab::Apps.value().to_string());
    ts::wait_for(|| !ts::query_all("tbody tr").is_empty()).await;
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
    ts::wait_for(|| {
        !m.session
            .tenant_ui
            .selected_audit_ids
            .get_untracked()
            .is_empty()
    })
    .await;
    let selected = m.session.tenant_ui.selected_audit_ids.get_untracked();
    assert!(selected.contains("obj-Local App"));
    assert!(
        !selected.contains("obj-Foreign App"),
        "SP row must never enter the bulk selection"
    );
    assert_eq!(selected.len(), 1);
}

#[wasm_bindgen_test]
async fn no_local_app_group_collects_sp_rows_without_checkboxes() {
    let m = mount_security().await;
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("no_local_app".to_string()));
    ts::wait_for(|| !ts::query_all("tbody tr").is_empty()).await;
    let rows = ts::query_all("tbody tr");
    assert_eq!(rows.len(), 1, "only the SP-only principal is in this group");
    assert!(
        rows[0]
            .text_content()
            .unwrap_or_default()
            .contains("Foreign App"),
        "the SP-only row lands in the no_local_app group"
    );
    assert!(
        ts::query_all("tbody input[type=checkbox]").is_empty(),
        "SP rows render no checkbox even in an actionable group"
    );
}

#[wasm_bindgen_test]
async fn sp_mailbox_fix_routes_to_the_sp_only_command() {
    let m = mount_security().await;
    ts::mock_ok(
        "grant_managed_identity_scoped_exchange_access",
        &fixtures::exchange_access_result(),
    );
    // Expand the org-wide mailbox group; the SP row's Fix lives there (the app
    // row carries no remediation in this fixture).
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("orgwide_mailbox".to_string()));
    ts::wait_for(|| ts::body_contains("Scope 1 mailbox permission")).await;

    ts::click_button_labelled("Scope 1 mailbox permission to specific mailboxes");
    ts::wait_for(|| ts::query(".modal textarea").is_some()).await;
    ts::set_textarea_value(".modal textarea", "Sales Team");
    ts::click_button_labelled("Scope access");
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

/// A missing Exchange admin-API consent used to leave the mailbox Fix with a
/// raw message and no way forward, while its SharePoint twin offered consent.
/// It now swaps the primary action for "Grant consent" on the `exchange`
/// feature, and the modal stays open for the retry.
#[wasm_bindgen_test]
async fn sp_mailbox_fix_offers_exchange_consent_on_consent_required() {
    let m = mount_security().await;
    ts::mock_err(
        "grant_managed_identity_scoped_exchange_access",
        &fixtures::ui_error("consent_required", "consent required (AADSTS65001)"),
    );
    ts::mock_ok("request_scope_consent", &());
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("orgwide_mailbox".to_string()));
    ts::wait_for(|| ts::body_contains("Scope 1 mailbox permission")).await;

    ts::click_button_labelled("Scope 1 mailbox permission to specific mailboxes");
    ts::wait_for(|| ts::query(".modal textarea").is_some()).await;
    ts::set_textarea_value(".modal textarea", "Sales Team");
    ts::click_button_labelled("Scope access");
    ts::wait_for(|| ts::body_contains("Exchange.Manage")).await;

    ts::click_button_labelled("Grant consent");
    ts::wait_for(|| ts::call_count("request_scope_consent") == 1).await;
    let call = ts::last_call("request_scope_consent").unwrap();
    assert_eq!(call.arg_str("feature").as_deref(), Some("exchange"));
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert!(
        ts::query(".modal").is_some(),
        "the modal stays open so the operator can retry the scoping"
    );
}

/// A grant Exchange answered with a warning did not necessarily do what was
/// asked (the common one: an existing scope with a different group set, so the
/// requested groups were NOT applied). The modal stays open with the notes and
/// the row keeps its Fix, rather than a success toast reading a no-op as done.
#[wasm_bindgen_test]
async fn sp_mailbox_fix_keeps_a_warned_grant_open() {
    let m = mount_security().await;
    ts::mock_ok(
        "grant_managed_identity_scoped_exchange_access",
        &ExchangeAccessResult {
            warnings: vec![
                "A management scope already exists for this app with a different group set".into(),
            ],
            ..fixtures::exchange_access_result()
        },
    );
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("orgwide_mailbox".to_string()));
    ts::wait_for(|| ts::body_contains("Scope 1 mailbox permission")).await;

    ts::click_button_labelled("Scope 1 mailbox permission to specific mailboxes");
    ts::wait_for(|| ts::query(".modal textarea").is_some()).await;
    ts::set_textarea_value(".modal textarea", "Sales Team");
    ts::click_button_labelled("Scope access");
    ts::wait_for(|| ts::body_contains("with a different group set")).await;

    assert!(
        ts::query(".modal").is_some(),
        "a warned grant keeps the modal open"
    );
    assert!(
        ts::body_contains("may not have been applied"),
        "the warning is explained, not counted"
    );
    assert!(
        ts::body_contains("Scope 1 mailbox permission to specific mailboxes"),
        "the row keeps its Fix"
    );
}

fn audit_progress(done: usize, total: usize, current: &str, cap: usize) -> AuditProgress {
    AuditProgress {
        done,
        total,
        current_app: Some(current.to_string()),
        in_flight_cap: cap,
        cancelled: false,
    }
}

/// The tenant-wide prefetch is the longest phase of a large run and knows no
/// app count yet: it reads as a phase label, never as "0 / 0 apps". Once the
/// count lands the fraction takes over, and the rate-limit notice still keys
/// off the live cap dropping below its peak.
#[wasm_bindgen_test]
async fn audit_progress_reads_as_a_phase_until_the_app_count_is_known() {
    let _m = mount_security().await;
    // Let `use_progress_stream` register its listener before we emit.
    ts::tick().await;
    ts::tick().await;

    ts::emit_event(
        names::AUDIT_PROGRESS,
        &audit_progress(0, 0, "Reading tenant-wide directory data…", 8),
    );
    ts::wait_for(|| ts::body_contains("Reading tenant-wide directory data")).await;
    assert!(
        !ts::body_contains("0 / 0 apps"),
        "the preparation phase must not read as a stalled 0 / 0 fraction"
    );

    ts::emit_event(names::AUDIT_PROGRESS, &audit_progress(3, 10, "App X", 8));
    ts::wait_for(|| ts::body_contains("3 / 10 apps")).await;
    assert!(ts::body_contains("App X"));
    assert!(
        !ts::body_contains("Reading tenant-wide directory data"),
        "the phase label gives way to the fraction"
    );
    assert!(
        ts::query(".audit-progress__notice").is_none(),
        "no back-off notice while the cap is at its peak"
    );

    ts::emit_event(names::AUDIT_PROGRESS, &audit_progress(4, 10, "App Y", 4));
    ts::wait_for(|| ts::query(".audit-progress__notice").is_some()).await;
}

/// A degraded run is never cached backend-side, so exporting it "by reference"
/// either failed with `no_cached_audit` or wrote an EARLIER complete run in its
/// place. It must hand the exporter its own items.
#[wasm_bindgen_test]
async fn a_degraded_run_exports_its_own_items() {
    ts::reset();
    let mut run = cached_run();
    run.degraded = vec![AuditCoverageGap::PerPrincipalScoring];
    ts::mock_ok("get_cached_audit", &run);
    ts::mock_ok("save_audit_to_file", &Option::<String>::None);
    let _m = ts::mount_view(|| view! { <SecurityView /> });
    ts::wait_for(|| ts::body_contains("Org-wide mailbox access")).await;

    ts::click_button_labelled("Export");
    ts::wait_for(|| !ts::query_all("[role=\"menuitem\"]").is_empty()).await;
    ts::click_button_labelled("Export as CSV…");
    ts::wait_for(|| ts::call_count("save_audit_to_file") == 1).await;

    let call = ts::last_call("save_audit_to_file").unwrap();
    assert_eq!(
        call.args
            .get("items")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(2),
        "an uncached run ships its own items instead of exporting by reference"
    );
}
