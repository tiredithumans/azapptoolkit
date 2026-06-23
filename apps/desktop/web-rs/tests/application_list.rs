//! GUI functionality tests for the App Registrations list — the anchor view
//! that proves the harness. These mount the *real* `ApplicationList` component
//! in a headless browser with the Tauri backend mocked (no tenant, no Graph),
//! and assert on what a user would see and do: rows render, the filter narrows
//! them, the error/empty states show, and the Refresh button fires the right
//! command.
//!
//! `#![cfg(target_arch = "wasm32")]` keeps these out of the host `just web-test`
//! run (they only execute under `just web-itest` via wasm-bindgen-test in a
//! browser). Build/run requires the `test-support` feature.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::application_list::ApplicationList;

wasm_bindgen_test_configure!(run_in_browser);

/// The text input the list filters on (the only non-checkbox input in the pane;
/// row + select-all controls are checkboxes).
const SEARCH: &str = ".app-list input:not([type=checkbox])";
/// Result-count line from `SelectAllBar` — reflects the filtered total
/// independent of row virtualization, so it's the robust assertion target.
const COUNT: &str = ".app-list__count";

#[wasm_bindgen_test]
async fn loads_and_renders_rows() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });

    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 3);
}

#[wasm_bindgen_test]
async fn search_narrows_rows() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;

    // Typing is debounced (~300ms) then applied in memory; wait_for polls past it.
    ts::set_input_value(SEARCH, "contoso");
    ts::wait_for(|| ts::text(COUNT) == "1 of 3 app registrations").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 1);
}

#[wasm_bindgen_test]
async fn error_state_renders_message() {
    ts::reset();
    ts::mock_err(
        "list_applications_with_pairing",
        &fixtures::ui_error(
            "consent_required",
            "Admin consent is required for Microsoft Graph",
        ),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });

    ts::wait_for(|| ts::query(".app-list__error").is_some()).await;
    assert!(ts::text(".app-list__error").contains("Admin consent is required"));
}

#[wasm_bindgen_test]
async fn empty_tenant_shows_create_cta() {
    ts::reset();
    ts::mock_ok("list_applications_with_pairing", &fixtures::no_apps());

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });

    ts::wait_for(|| ts::text(COUNT) == "0 app registrations").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 0);
    // A genuinely empty tenant gets an onboarding CTA, not the "adjust your
    // filters" copy meant for a filtered-empty list.
    ts::wait_for(|| ts::query(".ui-empty__title").is_some()).await;
    assert_eq!(ts::text(".ui-empty__title"), "No app registrations yet");
    assert!(ts::text(".ui-empty").contains("+ New app"));
}

#[wasm_bindgen_test]
async fn refresh_invokes_invalidate_list_cache() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Solo App"]),
    );
    ts::mock_ok("invalidate_list_cache", &()); // command returns ()

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "1 app registrations").await;

    ts::click("button[aria-label=\"Refresh App Registrations\"]");

    ts::wait_for(|| ts::call_count("invalidate_list_cache") >= 1).await;
    let call = ts::last_call("invalidate_list_cache").expect("recorded call");
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    // The per-page Refresh scopes invalidation to this list's kind only.
    assert_eq!(call.arg_str("kind").as_deref(), Some("apps"));
}
