//! GUI tests for the Enterprise Applications list — same shape as the App
//! Registrations list (load / filter / error / empty / Refresh→command).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::enterprise_application_list::EnterpriseApplicationList;

const SEARCH: &str = ".app-list input:not([type=checkbox])";

#[wasm_bindgen_test]
async fn loads_and_renders_rows() {
    ts::reset();
    ts::mock_ok(
        "list_enterprise_applications",
        &fixtures::enterprise_apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _m = ts::mount_view(|| view! { <EnterpriseApplicationList /> });

    ts::wait_for(|| ts::query_all(".app-list__row").len() == 3).await;
    assert_eq!(ts::call_count("list_enterprise_applications"), 1);
    assert_eq!(
        ts::last_call("list_enterprise_applications")
            .unwrap()
            .arg_str("tenantId")
            .as_deref(),
        Some("test-tenant")
    );
}

#[wasm_bindgen_test]
async fn search_narrows_rows() {
    ts::reset();
    ts::mock_ok(
        "list_enterprise_applications",
        &fixtures::enterprise_apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _m = ts::mount_view(|| view! { <EnterpriseApplicationList /> });
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 3).await;

    ts::set_input_value(SEARCH, "contoso");
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;
}

/// SCL-01: pasting the appId from a sign-in log or a ticket has to find the
/// row that prints it.
#[wasm_bindgen_test]
async fn search_matches_the_app_id() {
    ts::reset();
    ts::mock_ok(
        "list_enterprise_applications",
        &fixtures::enterprise_apps(&["Contoso CRM", "Fabrikam API", "Northwind Portal"]),
    );

    let _m = ts::mount_view(|| view! { <EnterpriseApplicationList /> });
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 3).await;

    // `fixtures::enterprise_app` derives the appId from the SP id (`sp-1-appid`).
    ts::set_input_value(SEARCH, "sp-1-appid");
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;
}

/// A11Y-06: the pairing arrow is a SIBLING of the row button, not a button
/// nested inside one — which is invalid HTML and put the arrow's label in the
/// middle of the row's accessible name.
#[wasm_bindgen_test]
async fn the_pair_arrow_is_not_nested_in_the_row_button() {
    ts::reset();
    let mut rows = fixtures::enterprise_apps(&["Paired SP"]);
    rows[0].paired_app_registration_id = Some("obj-0".to_string());
    ts::mock_ok("list_enterprise_applications", &rows);

    let _m = ts::mount_view(|| view! { <EnterpriseApplicationList /> });
    ts::wait_for(|| ts::query(".pair-arrow").is_some()).await;

    assert!(ts::query(".app-list__row-btn .pair-arrow").is_none());
    assert!(ts::query(".app-list__row > .pair-arrow").is_some());
}

#[wasm_bindgen_test]
async fn error_state_renders_message() {
    ts::reset();
    ts::mock_err(
        "list_enterprise_applications",
        &fixtures::ui_error(
            "forbidden",
            "Insufficient privileges to list service principals",
        ),
    );

    let _m = ts::mount_view(|| view! { <EnterpriseApplicationList /> });

    ts::wait_for(|| ts::body_contains("Insufficient privileges")).await;
}

#[wasm_bindgen_test]
async fn empty_list_renders_no_rows() {
    ts::reset();
    ts::mock_ok(
        "list_enterprise_applications",
        &Vec::<azapptoolkit_dto::enterprise_application::EnterpriseApplicationDto>::new(),
    );

    let _m = ts::mount_view(|| view! { <EnterpriseApplicationList /> });

    ts::wait_for(|| ts::call_count("list_enterprise_applications") == 1).await;
    ts::tick().await;
    assert_eq!(ts::query_all(".app-list__row").len(), 0);
}

#[wasm_bindgen_test]
async fn refresh_invokes_invalidate_list_cache() {
    ts::reset();
    ts::mock_ok(
        "list_enterprise_applications",
        &fixtures::enterprise_apps(&["Solo SP"]),
    );
    ts::mock_ok("invalidate_list_cache", &());

    let _m = ts::mount_view(|| view! { <EnterpriseApplicationList /> });
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;

    ts::click("button[aria-label=\"Refresh Enterprise Applications\"]");

    ts::wait_for(|| ts::call_count("invalidate_list_cache") >= 1).await;
    let call = ts::last_call("invalidate_list_cache").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert_eq!(call.arg_str("kind").as_deref(), Some("enterprise"));
}
