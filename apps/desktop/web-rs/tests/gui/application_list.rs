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

use azapptoolkit_core::audit::ListCredentialStatus;
use chrono::{Duration, Utc};
use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::application_list::ApplicationList;

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

/// SCL-01: an operator pastes the appId out of a sign-in log or a ticket. The
/// list printed that id on every row while matching only the display name.
#[wasm_bindgen_test]
async fn search_matches_the_app_id() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;

    // `fixtures::app_row` derives the appId from the object id (`obj-1-appid`).
    ts::set_input_value(SEARCH, "obj-1-appid");
    ts::wait_for(|| ts::text(COUNT) == "1 of 3 app registrations").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 1);
}

/// SCL-02: the credential state the list already filters on now reaches the row.
#[wasm_bindgen_test]
async fn rows_show_credential_state_and_expiry() {
    ts::reset();
    let mut rows = fixtures::apps(&["Expiring App"]);
    rows[0].credential_status = ListCredentialStatus::Expiring;
    // Plus an hour so the render's own `Utc::now()`, taken a few ms later,
    // still truncates to 9 whole days rather than 8.
    rows[0].soonest_credential_expiry = Some(Utc::now() + Duration::days(9) + Duration::hours(1));
    ts::mock_ok("list_applications_with_pairing", &rows);

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::query(".app-list__row").is_some()).await;

    assert_eq!(ts::text(".app-list__row .badge"), "Expiring");
    assert_eq!(ts::text(".app-list__row-expiry"), "9d left");
}

/// SCL-02: rows arrive in whatever order Graph returned; the sort is applied
/// between the filtered set and the virtualized window.
#[wasm_bindgen_test]
async fn sorting_by_name_reorders_the_rows() {
    ts::reset();
    // Deliberately a fixture whose Graph order heads with neither the A→Z nor
    // the Z→A row, so all three steps of the cycle are distinguishable.
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Mike", "Alpha", "Zulu"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;
    assert_eq!(ts::text(".app-list__row-title"), "Mike");

    // Name: A→Z, then reversed, then back to the order Graph returned.
    ts::click(".app-list__sortbar button");
    ts::wait_for(|| ts::text(".app-list__row-title") == "Alpha").await;
    ts::click(".app-list__sortbar button");
    ts::wait_for(|| ts::text(".app-list__row-title") == "Zulu").await;
    ts::click(".app-list__sortbar button");
    ts::wait_for(|| ts::text(".app-list__row-title") == "Mike").await;
    assert_eq!(ts::query_all(".app-list__row").len(), 3);
}

/// A11Y-06: the pairing arrow is a SIBLING of the row button, not a button
/// nested inside one — which is invalid HTML and put the arrow's label in the
/// middle of the row's accessible name.
#[wasm_bindgen_test]
async fn the_pair_arrow_is_not_nested_in_the_row_button() {
    ts::reset();
    let mut rows = fixtures::apps(&["Paired App"]);
    rows[0].paired_service_principal_id = Some("sp-0".to_string());
    ts::mock_ok("list_applications_with_pairing", &rows);

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::query(".pair-arrow").is_some()).await;

    assert!(ts::query(".app-list__row-btn .pair-arrow").is_none());
    assert!(ts::query(".app-list__row > .pair-arrow").is_some());
}

/// A11Y-02: crossing the inventory by Tab alone costs ~2 presses per row. The
/// rendered window carries a roving tabindex and Arrow/Home/End move it.
#[wasm_bindgen_test]
async fn arrow_keys_move_focus_between_rows() {
    ts::reset();
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["First App", "Second App", "Third App"]),
    );

    let _mounted = ts::mount_view(|| view! { <ApplicationList /> });
    ts::wait_for(|| ts::text(COUNT) == "3 app registrations").await;
    // Exactly one row is in the tab order at a time (the roving tabindex).
    ts::wait_for(|| ts::query_all(".app-list__row[tabindex='0']").len() == 1).await;

    // The tab stop rides along with focus, so it is what the move is read from.
    ts::focus(".app-list__row");
    ts::press_key(".app-list__row", "ArrowDown");
    assert!(ts::text(".app-list__row[tabindex='0']").contains("Second App"));
    ts::press_key(".app-list__row[tabindex='0']", "ArrowUp");
    assert!(ts::text(".app-list__row[tabindex='0']").contains("First App"));
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
    assert!(ts::text(".ui-empty").contains("New app"));
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
