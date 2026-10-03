//! Nothing-mocked mount smoke for Bulk actions, Permission tester and Resource
//! Access. `reset()` installs the mock IPC bridge with no routes, so every call
//! these views make rejects; each test proves the view still *mounts and
//! renders* on that path (catching Thaw-in-headless crashes, missing context,
//! and panics on a rejected load) without coupling to internal markup.
//!
//! The permission tester and Resource Access behaviour modules
//! (`permission_tester.rs`, `resource_access.rs`) mock their reads, so this is
//! the one place the reject-everything path runs for them. Bulk actions' Create
//! apps tab has its behaviour module in `bulk_create.rs`; its `BulkActionBar`
//! is exercised through `security_findings.rs`. The Disaster-recovery smoke was retired in favour of
//! `dr.rs` (shard 4), whose real tests supersede it.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support as ts;
use azapptoolkit_web_rs::views::bulk_actions_view::BulkActionsView;
use azapptoolkit_web_rs::views::permission_tester_view::PermissionTesterView;
use azapptoolkit_web_rs::views::resource_access::ResourceAccessView;

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
