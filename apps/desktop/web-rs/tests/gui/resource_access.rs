//! GUI tests for the Resource Access reverse lookups' tenant-wide summaries.
//!
//! The per-app panel's partial-sweep wording is pinned in
//! `app_site_access.rs`; this pins the tenant-wide Sites summary, which is
//! also what its export ships — a sweep with failed site reads must never read
//! as the complete answer. It also pins the sweep's dead-session recovery.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::sharepoint::{SiteAppGrantRow, SiteSweepResult};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::resource_access::ResourceAccessView;

#[wasm_bindgen_test]
async fn a_partial_site_sweep_says_coverage_is_partial() {
    ts::reset();
    ts::mock_ok(
        "get_cached_site_sweep",
        &Some(SiteSweepResult {
            tenant_id: "test-tenant".into(),
            total_sites: 10,
            sites_scanned: 8,
            sites_failed: 2,
            rows: vec![],
            cancelled: false,
            truncated: false,
        }),
    );

    let m = ts::mount_view(|| view! { <ResourceAccessView /> });
    m.session.resource_access_tab.set("sites".to_string());

    ts::wait_for(|| ts::body_contains("(2 failed — coverage is partial)")).await;
    assert!(ts::body_contains("scanned 8 of 10 sites"));
}

/// The lenses own their rows for the view's whole life (cleared on a tenant
/// switch), so they tag the export snapshot with the active tenant
/// themselves; an export is refused unless that tag is the active tenant.
/// Pins that a lens's own rows still export.
#[wasm_bindgen_test]
async fn the_site_sweep_exports_its_rows() {
    ts::reset();
    ts::mock_ok(
        "get_cached_site_sweep",
        &Some(SiteSweepResult {
            tenant_id: "test-tenant".into(),
            total_sites: 1,
            sites_scanned: 1,
            sites_failed: 0,
            rows: vec![SiteAppGrantRow {
                site_id: "site-1".into(),
                site_display_name: Some("Finance".into()),
                site_url: Some("https://contoso.sharepoint.com/sites/finance".into()),
                permission_id: "perm-1".into(),
                roles: vec!["read".into()],
                app_id: Some("app-1".into()),
                app_display_name: Some("Payroll API".into()),
            }],
            cancelled: false,
            truncated: false,
        }),
    );
    ts::mock_ok("save_site_access_to_file", &Option::<String>::None);

    let m = ts::mount_view(|| view! { <ResourceAccessView /> });
    m.session.resource_access_tab.set("sites".to_string());
    ts::wait_for(|| ts::body_contains("Payroll API")).await;

    // All three lens panels stay mounted (hidden tabs), each with its own
    // "Export"; the other two are disabled with nothing to export.
    ts::query_all("button")
        .into_iter()
        .find(|b| {
            b.text_content().unwrap_or_default().trim() == "Export" && !b.has_attribute("disabled")
        })
        .expect("the Sites panel's enabled Export button")
        .unchecked_into::<web_sys::HtmlElement>()
        .click();
    ts::wait_for(|| !ts::query_all("[role=\"menuitem\"]").is_empty()).await;
    ts::click_button_labelled("Export as CSV…");
    ts::wait_for(|| ts::call_count("save_site_access_to_file") == 1).await;

    let call = ts::last_call("save_site_access_to_file").expect("recorded call");
    assert_eq!(
        call.args
            .get("rows")
            .and_then(|v| v.as_array())
            .map(Vec::len),
        Some(1)
    );
}

/// A sweep that failed on a dead session used to render the raw error inline
/// with no way forward; it now raises the Re-authenticate notification in its
/// place (the DR view's shape).
#[wasm_bindgen_test]
async fn a_dead_session_site_sweep_offers_reauthenticate() {
    ts::reset();
    ts::mock_ok("get_cached_site_sweep", &None::<SiteSweepResult>);
    ts::mock_err(
        "sweep_site_permissions",
        &fixtures::ui_error("refresh_missing", "session expired"),
    );

    let m = ts::mount_view(|| view! { <ResourceAccessView /> });
    m.session.resource_access_tab.set("sites".to_string());
    ts::wait_for(|| ts::button_labelled_enabled("Scan sites")).await;
    ts::click_button_labelled("Scan sites");

    ts::wait_for(|| {
        m.session.toasts.with_untracked(|list| {
            list.iter()
                .any(|t| t.action_label.as_deref() == Some("Re-authenticate"))
        })
    })
    .await;
    ts::wait_for(|| ts::button_labelled_enabled("Scan sites")).await;
    assert!(
        !ts::body_contains("session expired"),
        "the lever replaces the dead-end inline text"
    );
}
