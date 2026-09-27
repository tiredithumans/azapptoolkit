//! GUI tests for the enterprise app's Provisioning tab consent path.
//!
//! The backend pre-acquires the `Synchronization.Read.All` token, so a missing
//! consent arrives typed as `consent_required`; the tab must turn that into a
//! "Grant consent & retry" round trip for the `sync` feature and reload, while a
//! 403 (a role / license gap no consent can fix) offers no such button.
//!
//! Mounts `ProvisioningContent` directly, like `sso_claims` mounts the SSO tab
//! (same shard, same linked pane).
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::enterprise_application_detail_pane::panels::ProvisioningContent;

const GRANT: &str = "Grant consent & retry";

fn mount() -> ts::Mounted {
    let detail = Arc::new(fixtures::enterprise_application_detail(
        "sp-demo",
        "Contoso SSO Portal",
    ));
    ts::mount_view(move || {
        let d = detail.clone();
        view! { <ProvisioningContent signal=Signal::derive(move || d.clone()) /> }
    })
}

fn button(label: &str) -> web_sys::HtmlButtonElement {
    ts::query_all("button")
        .into_iter()
        .find(|el| el.text_content().unwrap_or_default().trim() == label)
        .unwrap_or_else(|| panic!("no button labelled `{label}`"))
        .unchecked_into()
}

#[wasm_bindgen_test]
async fn a_missing_consent_offers_the_sync_grant_and_reloads() {
    ts::reset();
    ts::mock_err(
        "get_enterprise_app_provisioning",
        &fixtures::ui_error("consent_required", "consent needed"),
    );
    let _m = mount();

    ts::wait_for(|| ts::body_contains(GRANT)).await;
    assert!(ts::body_contains("SCIM provisioning"));

    ts::mock_ok("request_scope_consent", &());
    ts::mock_ok(
        "get_enterprise_app_provisioning",
        &Vec::<serde_json::Value>::new(),
    );
    button(GRANT).click();
    ts::wait_for(|| ts::call_count("request_scope_consent") == 1).await;
    assert_eq!(
        ts::last_call("request_scope_consent")
            .unwrap()
            .arg_str("feature")
            .as_deref(),
        Some("sync")
    );
    ts::wait_for(|| ts::body_contains("no SCIM provisioning configured")).await;
    assert_eq!(ts::call_count("get_enterprise_app_provisioning"), 2);
}

#[wasm_bindgen_test]
async fn a_403_names_the_role_gap_without_a_consent_button() {
    ts::reset();
    ts::mock_err(
        "get_enterprise_app_provisioning",
        &fixtures::ui_error("forbidden", "Insufficient privileges"),
    );
    let _m = mount();

    ts::wait_for(|| ts::body_contains("Provisioning status is unavailable")).await;
    assert!(!ts::body_contains(GRANT));
}
