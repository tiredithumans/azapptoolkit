//! GUI test for the enterprise app's Access tab load failure.
//!
//! A throttled or dropped assignment read used to leave a bare
//! `error [code]: message` line with no way back short of switching tabs; it
//! now renders the shared `DetailLoadError` (message first, code muted) whose
//! Retry refetches the list in place.
//!
//! Mounts `AccessContent` directly, like `provisioning_tab` mounts its tab
//! (same shard, same linked pane).
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::enterprise_application_detail_pane::access::AccessContent;

fn mount() -> ts::Mounted {
    let detail = Arc::new(fixtures::enterprise_application_detail(
        "sp-demo",
        "Contoso SSO Portal",
    ));
    ts::mount_view(move || {
        let d = detail.clone();
        view! { <AccessContent signal=Signal::derive(move || d.clone()) /> }
    })
}

#[wasm_bindgen_test]
async fn a_failed_assignment_load_offers_retry() {
    ts::reset();
    ts::mock_err(
        "list_enterprise_app_assignments",
        &fixtures::throttled_error(),
    );
    ts::mock_ok(
        "list_sp_group_memberships",
        &Vec::<serde_json::Value>::new(),
    );
    let _m = mount();

    ts::wait_for(|| ts::query(".ui-load-error").is_some()).await;
    assert!(ts::body_contains(fixtures::THROTTLED_MESSAGE));
    assert!(
        !ts::body_contains("error ["),
        "the wire code no longer leads the message"
    );

    ts::mock_ok(
        "list_enterprise_app_assignments",
        &Vec::<serde_json::Value>::new(),
    );
    ts::click_button_labelled_in(".ui-load-error", "Retry");
    ts::wait_for(|| ts::call_count("list_enterprise_app_assignments") == 2).await;
    ts::wait_for(|| ts::body_contains("No users or groups are assigned")).await;
    assert!(ts::query(".ui-load-error").is_none());
}
