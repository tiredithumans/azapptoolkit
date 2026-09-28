//! GUI tests for the Home dashboard's Security Posture card.
//!
//! The card reads the backend's counts-only `get_cached_audit_summary`, never
//! the run itself (the Security view holds the only copy), and carries two
//! keep-alive subtleties that regress silently: the "Scanned …" stamp that
//! qualifies every number on it, and the one-click "Run a security audit" that
//! trips the audit controller's `pending_audit_run` one-shot.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::audit::CachedAuditSummary;
use azapptoolkit_web_rs::state::ActiveView;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::home_dashboard::HomeDashboard;

/// The inventory cards' reads, so only the posture card varies per test.
fn mock_inventory() {
    let mut apps = fixtures::apps(&["Payroll API", "HR Sync"]);
    apps[0].password_credential_count = 1;
    ts::mock_ok("list_applications_with_pairing", &apps);
    ts::mock_ok(
        "list_enterprise_applications",
        &fixtures::enterprise_apps(&["Contoso CRM"]),
    );
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-build"]),
    );
    ts::mock_ok(
        "list_credential_expirations",
        &fixtures::credential_expirations(),
    );
}

#[wasm_bindgen_test]
async fn posture_card_renders_the_summary_with_its_age_stamp() {
    ts::reset();
    mock_inventory();
    let five_minutes_ago = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    let summary =
        CachedAuditSummary::from_items(&fixtures::audit_run_result().items, Some(five_minutes_ago));
    assert!(summary.posture.critical > 0, "fixture needs a Critical app");
    ts::mock_ok("get_cached_audit_summary", &Some(summary.clone()));

    let _m = ts::mount_view(|| view! { <HomeDashboard /> });
    ts::wait_for(|| ts::body_contains("Scanned ")).await;

    assert!(
        !ts::query_all(".posture-finding").is_empty(),
        "the ranked Top findings list renders from the summary's tallies"
    );
    let critical = ts::query(".dash-metric--link[title=\"Show Critical\"] .dash-metric__num")
        .expect("Critical drill");
    assert_eq!(
        critical.text_content().unwrap_or_default().trim(),
        summary.posture.critical.to_string()
    );
    // The perf fix: Home asks for the summary, never the whole run.
    assert_eq!(ts::call_count("get_cached_audit"), 0);
    let call = ts::last_call("get_cached_audit_summary").expect("summary read");
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
}

#[wasm_bindgen_test]
async fn no_cached_run_trips_pending_audit_run_in_one_click() {
    ts::reset();
    mock_inventory();
    ts::mock_ok("get_cached_audit_summary", &None::<CachedAuditSummary>);

    let m = ts::mount_view(|| view! { <HomeDashboard /> });
    ts::wait_for(|| ts::body_contains("No audit run in this session.")).await;

    ts::click_button_labelled("Run a security audit");
    ts::tick().await;

    assert!(
        m.session.tenant_ui.pending_audit_run.get_untracked(),
        "one click must start the scan on arrival, not just navigate"
    );
    assert_eq!(m.session.view.get_untracked(), ActiveView::Security);
    assert_eq!(m.session.security_tab.get_untracked(), "findings");
}

/// "With secrets" was the one number on Home you couldn't click; it now drills
/// into the App Registrations chip of the same name.
#[wasm_bindgen_test]
async fn with_secrets_metric_drills_into_the_apps_facet() {
    ts::reset();
    mock_inventory();
    ts::mock_ok("get_cached_audit_summary", &None::<CachedAuditSummary>);

    let m = ts::mount_view(|| view! { <HomeDashboard /> });
    const WITH_SECRETS: &str = "button.dash-metric--link[title=\"Show With secrets\"]";
    ts::wait_for(|| ts::query(WITH_SECRETS).is_some()).await;
    ts::click(WITH_SECRETS);
    ts::tick().await;

    assert_eq!(m.session.view.get_untracked(), ActiveView::Apps);
    assert_eq!(m.session.tenant_ui.apps_facet.get_untracked(), "secrets");
    assert_eq!(
        m.session.tenant_ui.pending_open_filters.get_untracked(),
        Some(ActiveView::Apps),
        "the drawer-open one-shot names the App Registrations list"
    );
}
