//! Mount-smoke for the interaction-heavy views (multi-tab / progress-driven).
//! Their full flows need step sequences whose exact selectors are best verified
//! against a running browser; until those land, these prove each view *mounts
//! and renders* under the harness (catching Thaw-in-headless crashes, missing
//! context, and panics) without coupling to fragile internal markup. `reset()`
//! installs the mock so any demand-driven call rejects gracefully rather than
//! hitting an absent IPC bridge.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support as ts;
use azapptoolkit_web_rs::views::bulk_actions_view::BulkActionsView;
use azapptoolkit_web_rs::views::dr::DisasterRecoveryView;
use azapptoolkit_web_rs::views::permission_tester_view::PermissionTesterView;
use azapptoolkit_web_rs::views::resource_access::ResourceAccessView;

wasm_bindgen_test_configure!(run_in_browser);

async fn assert_renders_interactive() {
    ts::tick().await;
    assert!(!ts::body_text().is_empty(), "view rendered no content");
    assert!(
        !ts::query_all("button").is_empty(),
        "view rendered no interactive controls"
    );
}

#[wasm_bindgen_test]
async fn bulk_actions_view_mounts() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <BulkActionsView /> });
    assert_renders_interactive().await;
}

#[wasm_bindgen_test]
async fn disaster_recovery_view_mounts() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <DisasterRecoveryView /> });
    assert_renders_interactive().await;
}

#[wasm_bindgen_test]
async fn resource_access_view_mounts() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <ResourceAccessView /> });
    assert_renders_interactive().await;
}

#[wasm_bindgen_test]
async fn permission_tester_view_mounts() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <PermissionTesterView /> });
    assert_renders_interactive().await;
}
