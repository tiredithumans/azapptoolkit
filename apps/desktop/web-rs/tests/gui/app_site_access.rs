//! GUI tests for "Sites this app can reach" (`AppSiteAccessPanel`) — the
//! per-app read of the tenant site-permission sweep, which answers which
//! `Sites.Selected` sites a principal is scoped to *without* the operator
//! knowing a site URL (Graph has no reverse app→sites lookup).
//!
//! Pins the three things that make the answer trustworthy: it asks with the
//! **appId**, an empty result is only reported as "no grants" when the sweep it
//! came from was complete, and picking a row hands the site URL to the existing
//! per-site manage flow rather than re-implementing it.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::sharepoint::{AppSiteAccessDto, SiteAppGrantRow};
use azapptoolkit_web_rs::components::sharepoint_sites_section::SharePointSitesSection;
use azapptoolkit_web_rs::test_support as ts;

const APP_ID: &str = "11111111-2222-3333-4444-555555555555";

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

fn row(site: &str, roles: &[&str]) -> SiteAppGrantRow {
    SiteAppGrantRow {
        site_id: format!("id-{site}"),
        site_display_name: Some(site.to_string()),
        site_url: Some(format!("https://contoso.sharepoint.com/sites/{site}")),
        permission_id: format!("perm-{site}"),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        app_id: Some(APP_ID.to_string()),
        app_display_name: Some("Payroll API".to_string()),
    }
}

/// Mounts the section (collapsed by default) and expands it, with
/// `get_app_site_access` answering `access`.
async fn mount_with(access: Option<AppSiteAccessDto>) -> ts::Mounted {
    ts::reset();
    match access {
        Some(a) => ts::mock_ok("get_app_site_access", &Some(a)),
        None => ts::mock_ok("get_app_site_access", &Option::<AppSiteAccessDto>::None),
    }
    ts::mock_ok("list_site_permissions", &Vec::<serde_json::Value>::new());
    let m = ts::mount_view(|| {
        view! {
            <SharePointSitesSection
                app_id=Signal::derive(|| APP_ID.to_string())
                app_display_name=Signal::derive(|| "Payroll API".to_string())
            />
        }
    });
    ts::wait_for(|| ts::body_contains("SharePoint site access")).await;
    // The section is a collapsed disclosure and renders no body until expanded,
    // so the panel doesn't exist — and costs no IPC — before this click.
    assert_eq!(
        ts::call_count("get_app_site_access"),
        0,
        "a collapsed section must cost no IPC"
    );
    click_button("Show");
    m
}

#[wasm_bindgen_test]
async fn cached_sweep_lists_this_apps_sites_with_their_roles() {
    let _m = mount_with(Some(AppSiteAccessDto {
        sites: vec![row("Marketing", &["read"]), row("Projects", &["write"])],
        total_sites: 42,
        sites_scanned: 42,
        sites_failed: 0,
        cancelled: false,
    }))
    .await;

    ts::wait_for(|| ts::body_contains("Marketing")).await;
    // The roles per site are the point — "which sites" alone doesn't say what
    // the app can do there.
    assert!(ts::body_contains("read"));
    assert!(ts::body_contains("write"));
    assert!(ts::body_contains("Projects"));
    // Coverage is stated, and a complete sweep says so without hedging.
    assert!(ts::body_contains("2 sites"));
    assert!(ts::body_contains("42 scanned sites"));
    assert!(!ts::body_contains("coverage is partial"));

    // Asked with the appId — a site grant records the client id, not the
    // directory object id.
    let call = ts::last_call("get_app_site_access").expect("panel asked for its sites");
    assert_eq!(call.arg_str("appId").as_deref(), Some(APP_ID));
}

#[wasm_bindgen_test]
async fn a_partial_sweep_never_reports_no_access() {
    // Zero rows, but two sites failed to read: "this app reaches nothing" is
    // NOT a conclusion available here, and the empty state must not draw it.
    let _m = mount_with(Some(AppSiteAccessDto {
        sites: Vec::new(),
        total_sites: 42,
        sites_scanned: 40,
        sites_failed: 2,
        cancelled: false,
    }))
    .await;

    ts::wait_for(|| ts::body_contains("coverage is partial")).await;
    assert!(
        ts::body_contains("not proof the app has none"),
        "a partial scan must not read as 'no grants'"
    );
    assert!(!ts::body_contains("This app reaches no site"));
}

#[wasm_bindgen_test]
async fn no_cached_sweep_offers_a_scan_instead_of_an_empty_table() {
    let _m = mount_with(None).await;
    ts::wait_for(|| ts::body_contains("No site scan has run for this tenant yet")).await;
    // The scan is tenant-wide, so its cost is stated before it is offered.
    assert!(ts::body_contains("can be cancelled anytime"));
    assert_eq!(ts::call_count("sweep_site_permissions"), 0);

    ts::mock_ok(
        "sweep_site_permissions",
        &azapptoolkit_dto::sharepoint::SiteSweepResult {
            tenant_id: "tenant-1".to_string(),
            total_sites: 3,
            sites_scanned: 3,
            sites_failed: 0,
            rows: vec![
                row("Marketing", &["read"]),
                // Another app's grant on the same sweep — must not appear here.
                SiteAppGrantRow {
                    app_id: Some("other-app".to_string()),
                    ..row("Finance", &["write"])
                },
            ],
            cancelled: false,
        },
    );
    click_button("Scan sites");
    ts::wait_for(|| ts::body_contains("Marketing")).await;
    assert!(
        !ts::body_contains("Finance"),
        "the fresh sweep must be projected to THIS app's rows"
    );
}

#[wasm_bindgen_test]
async fn picking_a_site_loads_it_into_the_per_site_flow() {
    let _m = mount_with(Some(AppSiteAccessDto {
        sites: vec![row("Marketing", &["read"])],
        total_sites: 1,
        sites_scanned: 1,
        sites_failed: 0,
        cancelled: false,
    }))
    .await;
    ts::wait_for(|| ts::body_contains("Marketing")).await;

    // "Manage" hands the URL to the existing grant/list/revoke section instead
    // of duplicating those mutations — so the site's permissions get listed.
    click_button("Manage");
    ts::wait_for(|| ts::call_count("list_site_permissions") >= 1).await;
    let call = ts::last_call("list_site_permissions").expect("listed the picked site");
    assert_eq!(
        call.arg_str("siteUrl").as_deref(),
        Some("https://contoso.sharepoint.com/sites/Marketing")
    );
}
