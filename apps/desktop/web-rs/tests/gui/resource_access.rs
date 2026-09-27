//! GUI tests for the Resource Access reverse lookups' tenant-wide summaries.
//!
//! The per-app panel's partial-sweep wording is pinned in
//! `app_site_access.rs`; this pins the tenant-wide Sites summary, which is
//! also what its export ships — a sweep with failed site reads must never read
//! as the complete answer.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::sharepoint::SiteSweepResult;
use azapptoolkit_web_rs::test_support as ts;
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
