//! GUI tests for the Managed Identities list. Unlike the App/Enterprise lists
//! this view has no result-count line, so assertions key off the shared
//! `.app-list__row` rows, the command recorder, and `body_contains`.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::managed_identities::ManagedIdentitiesView;

#[wasm_bindgen_test]
async fn loads_and_renders_rows() {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-prod-api", "mi-staging-worker"]),
    );

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });

    ts::wait_for(|| ts::query_all(".app-list__row").len() == 2).await;
    assert_eq!(
        ts::last_call("list_managed_identities")
            .unwrap()
            .arg_str("tenantId")
            .as_deref(),
        Some("test-tenant")
    );
}

#[wasm_bindgen_test]
async fn error_state_renders_message() {
    ts::reset();
    ts::mock_err(
        "list_managed_identities",
        &fixtures::ui_error("forbidden", "Directory read permission required"),
    );

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });

    ts::wait_for(|| ts::body_contains("Directory read permission required")).await;
}

#[wasm_bindgen_test]
async fn retry_after_error_refetches() {
    ts::reset();
    ts::mock_err(
        "list_managed_identities",
        &fixtures::ui_error("throttled", "Too many requests"),
    );

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });
    // The MI list now renders its load failure via the shared `DetailLoadError`
    // (raw `UiError` message, no "Failed to load:" prefix) — see the P3 grammar.
    ts::wait_for(|| ts::body_contains("Too many requests")).await;

    // The transient failure clears: Retry refetches in place (no remount).
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-recovered"]),
    );
    ts::click(".app-list__error button");

    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;
    assert_eq!(ts::call_count("list_managed_identities"), 2);
}

#[wasm_bindgen_test]
async fn empty_list_renders_no_rows() {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &Vec::<azapptoolkit_dto::managed_identity::ManagedIdentityDto>::new(),
    );

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });

    ts::wait_for(|| ts::call_count("list_managed_identities") == 1).await;
    ts::tick().await;
    assert_eq!(ts::query_all(".app-list__row").len(), 0);
}

#[wasm_bindgen_test]
async fn refresh_invokes_invalidate_list_cache() {
    ts::reset();
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-solo"]),
    );
    ts::mock_ok("invalidate_list_cache", &());

    let _m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;

    ts::click("button[aria-label=\"Refresh managed identities\"]");

    ts::wait_for(|| ts::call_count("invalidate_list_cache") >= 1).await;
    let call = ts::last_call("invalidate_list_cache").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    // ListCacheKindDto is `rename_all = "snake_case"` → ManagedIdentities.
    assert_eq!(call.arg_str("kind").as_deref(), Some("managed_identities"));
}
