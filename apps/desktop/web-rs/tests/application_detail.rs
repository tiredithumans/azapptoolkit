//! GUI tests for the App Registration detail pane. Driven by an `object_id`
//! prop; auto-loads `get_application_detail` on mount.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::application_detail_pane::ApplicationDetailPane;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn loads_and_renders_detail() {
    ts::reset();
    ts::mock_ok(
        "get_application_detail",
        &fixtures::application_detail("obj-1", "app-1", "Contoso CRM"),
    );

    let _m = ts::mount_view(
        || view! { <ApplicationDetailPane object_id=Signal::derive(|| "obj-1".to_string()) /> },
    );

    ts::wait_for(|| ts::body_contains("Contoso CRM")).await;
    let call = ts::last_call("get_application_detail").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert_eq!(call.arg_str("objectId").as_deref(), Some("obj-1"));
}

#[wasm_bindgen_test]
async fn error_state_offers_retry_that_reloads() {
    ts::reset();
    ts::mock_err(
        "get_application_detail",
        &fixtures::ui_error("not_found", "Application not found in this tenant"),
    );

    let _m = ts::mount_view(
        || view! { <ApplicationDetailPane object_id=Signal::derive(|| "obj-1".to_string()) /> },
    );

    ts::wait_for(|| ts::body_contains("Application not found")).await;
    // The Err branch is no longer a dead-end: a Retry button re-runs the load.
    ts::wait_for(|| ts::query(".detail-load-error button").is_some()).await;
    let before = ts::call_count("get_application_detail");
    ts::click(".detail-load-error button");
    ts::wait_for(|| ts::call_count("get_application_detail") > before).await;
}
