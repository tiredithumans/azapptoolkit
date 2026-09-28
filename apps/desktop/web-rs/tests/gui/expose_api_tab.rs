//! GUI tests for the Expose an API tab: the load-failure Retry, the one-URI
//! delta writes (the backend merges them into live state), and the
//! pre-authorized clients' names + directory picker.
//!
//! Mounts `ExposeApiTab` directly, like `authentication_tab.rs`: the tab owns
//! its own load, so it stands alone without driving the detail pane to it.
#![cfg(target_arch = "wasm32")]

use std::collections::BTreeMap;
use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_core::models::{OAuth2PermissionScope, PreAuthorizedApplication};
use azapptoolkit_web_rs::bindings::expose_api::ExposeApiDto;
use azapptoolkit_web_rs::bindings::search::{GlobalSearchResults, SearchHit};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::expose_api_tab::ExposeApiTab;

const RESOLVED_CLIENT: &str = "11111111-1111-1111-1111-111111111111";
const UNRESOLVED_CLIENT: &str = "22222222-2222-2222-2222-222222222222";
const PICKED_CLIENT: &str = "33333333-3333-3333-3333-333333333333";

fn scope(id: &str, value: &str) -> OAuth2PermissionScope {
    OAuth2PermissionScope {
        id: id.into(),
        value: value.into(),
        admin_consent_display_name: Some(format!("{value} (admin)")),
        admin_consent_description: Some(format!("Allows {value}.")),
        user_consent_display_name: None,
        user_consent_description: None,
        r#type: Some("User".into()),
        is_enabled: Some(true),
    }
}

fn dto() -> ExposeApiDto {
    let mut names = BTreeMap::new();
    names.insert(RESOLVED_CLIENT.to_string(), "Contoso Portal".to_string());
    ExposeApiDto {
        identifier_uris: vec!["api://app-1".into()],
        scopes: vec![scope("scope-1", "Files.Read")],
        pre_authorized_applications: vec![
            PreAuthorizedApplication {
                app_id: RESOLVED_CLIENT.into(),
                delegated_permission_ids: vec!["scope-1".into()],
            },
            PreAuthorizedApplication {
                app_id: UNRESOLVED_CLIENT.into(),
                delegated_permission_ids: vec!["scope-1".into()],
            },
        ],
        client_display_names: names,
    }
}

fn mount() -> ts::Mounted {
    let detail = Arc::new(fixtures::application_detail(
        "obj-1",
        "app-1",
        "Contoso API",
    ));
    ts::mount_view(move || {
        let d = detail.clone();
        view! {
            <ExposeApiTab
                detail=Signal::derive(move || d.clone())
                on_changed=Callback::new(|_| ())
            />
        }
    })
}

#[wasm_bindgen_test]
async fn a_failed_load_offers_retry() {
    ts::reset();
    ts::mock_err("get_expose_api", &fixtures::throttled_error());
    let _m = mount();

    ts::wait_for(|| ts::query(".ui-load-error").is_some()).await;
    assert!(ts::body_contains(fixtures::THROTTLED_MESSAGE));

    ts::mock_ok("get_expose_api", &dto());
    ts::click_button_labelled_in(".ui-load-error", "Retry");
    ts::wait_for(|| ts::call_count("get_expose_api") == 2).await;
    ts::wait_for(|| ts::body_contains("api://app-1")).await;
    assert!(ts::query(".ui-load-error").is_none());
}

#[wasm_bindgen_test]
async fn adding_a_uri_sends_only_that_uri() {
    ts::reset();
    ts::mock_ok("get_expose_api", &dto());
    ts::mock_ok("add_identifier_uri", &());
    let _m = mount();
    ts::wait_for(|| ts::body_contains("api://app-1")).await;

    ts::click_button_labelled_in(".expose-api", "+ Add URI");
    ts::wait_for(|| ts::query(".modal input").is_some()).await;
    ts::set_input_value(".modal input", "https://contoso.com/api");
    ts::click_button_labelled_in(".modal", "Save");

    ts::wait_for(|| ts::call_count("add_identifier_uri") == 1).await;
    let call = ts::last_call("add_identifier_uri").unwrap();
    assert_eq!(call.arg_str("objectId").as_deref(), Some("obj-1"));
    assert_eq!(
        call.arg_str("uri").as_deref(),
        Some("https://contoso.com/api")
    );
    // A delta, never the tab's loaded list: the backend merges into live state.
    assert!(call.args.get("uris").is_none());
}

#[wasm_bindgen_test]
async fn removing_a_uri_sends_only_that_uri() {
    ts::reset();
    ts::mock_ok("get_expose_api", &dto());
    ts::mock_ok("remove_identifier_uri", &());
    let _m = mount();
    ts::wait_for(|| ts::body_contains("api://app-1")).await;

    // The first row "Remove" is the URI table's (it renders first).
    ts::click_button_labelled_in(".expose-api table", "Remove");
    ts::wait_for(|| ts::query(".confirm-dialog__subject").is_some()).await;
    assert_eq!(ts::text(".confirm-dialog__subject"), "api://app-1");
    ts::click_button_labelled_in(".modal", "Remove");

    ts::wait_for(|| ts::call_count("remove_identifier_uri") == 1).await;
    let call = ts::last_call("remove_identifier_uri").unwrap();
    assert_eq!(call.arg_str("uri").as_deref(), Some("api://app-1"));
    assert!(call.args.get("uris").is_none());
}

#[wasm_bindgen_test]
async fn pre_authorized_rows_show_the_client_name() {
    ts::reset();
    ts::mock_ok("get_expose_api", &dto());
    let _m = mount();

    ts::wait_for(|| ts::body_contains("Contoso Portal")).await;
    assert!(ts::body_contains("Client application"));
    assert!(ts::body_contains(RESOLVED_CLIENT));
    // An unresolved client still shows its bare application id.
    assert!(ts::body_contains(UNRESOLVED_CLIENT));
}

#[wasm_bindgen_test]
async fn picking_a_client_from_search_fills_the_client_id() {
    ts::reset();
    ts::mock_ok("get_expose_api", &dto());
    ts::mock_ok("set_pre_authorized_app", &());
    ts::mock_ok(
        "global_search",
        &GlobalSearchResults {
            query: "fab".into(),
            enterprise_apps: vec![SearchHit {
                id: "sp-9".into(),
                app_id: Some(PICKED_CLIENT.into()),
                display_name: "Fabrikam Mobile".into(),
            }],
            ..Default::default()
        },
    );
    let _m = mount();
    ts::wait_for(|| ts::body_contains("Contoso Portal")).await;

    ts::click_button_labelled_in(".expose-api", "+ Add a client application");
    ts::wait_for(|| ts::query(".modal input").is_some()).await;
    // The first input in the dialog is the directory search box.
    ts::set_input_value(".modal input", "fab");
    ts::wait_for(|| ts::query(".candidates li").is_some()).await;
    assert!(ts::text(".candidates li").contains("Fabrikam Mobile"));
    ts::click_button_labelled_in(".candidates li", "Select");

    ts::wait_for(|| ts::body_contains("Selected: Fabrikam Mobile")).await;
    let call = ts::last_call("global_search").unwrap();
    assert_eq!(call.arg_str("query").as_deref(), Some("fab"));

    ts::click(".modal .checkbox-row input");
    ts::click_button_labelled_in(".modal", "Save");

    ts::wait_for(|| ts::call_count("set_pre_authorized_app") == 1).await;
    let call = ts::last_call("set_pre_authorized_app").unwrap();
    assert_eq!(
        call.args["input"]["clientAppId"].as_str(),
        Some(PICKED_CLIENT)
    );
    assert_eq!(
        call.args["input"]["scopeIds"],
        serde_json::json!(["scope-1"])
    );
}
