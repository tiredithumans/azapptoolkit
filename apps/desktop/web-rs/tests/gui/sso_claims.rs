//! GUI tests for the SSO tab's "Attributes & claims" save guard.
//!
//! The behaviour worth pinning: **an unread claims policy is never saved
//! over.** When the backend couldn't read the assigned claims-mapping policy
//! (consent not granted yet, a 403, a transient failure), the editor renders
//! empty — and a save from it would replace the app's real claims with
//! whatever the operator typed. Save must stay off until a read succeeds, and
//! "Load claims" must consent and re-read.
//!
//! Mounts `SsoContent` directly, exactly like `sso_rollover` (same shard, same
//! linked view subtree).
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::enterprise_application_detail_pane::sso_tab::SsoContent;

const UNREAD: &str = "Couldn't read this app's current claims policy";

/// Mounts the SSO tab over a SAML app whose claims read did (or didn't) fail.
fn mount(claims_read_failed: bool) -> ts::Mounted {
    let mut cfg = fixtures::sso_config("sp-demo", "app-demo");
    cfg.claims_read_failed = claims_read_failed;
    cfg.rollover = Some(fixtures::signing_cert_rollover_steady(
        "sp-demo", "app-demo",
    ));
    ts::mock_ok("get_sso_config", &cfg);
    ts::mock_ok(
        "get_signing_cert_rollover",
        &fixtures::signing_cert_rollover_steady("sp-demo", "app-demo"),
    );

    let detail = Arc::new(fixtures::enterprise_application_detail(
        "sp-demo",
        "Contoso SSO Portal",
    ));
    ts::mount_view(move || {
        let d = detail.clone();
        view! { <SsoContent signal=Signal::derive(move || d.clone()) /> }
    })
}

/// The first button with exactly this label.
fn button(label: &str) -> web_sys::HtmlButtonElement {
    ts::query_all("button")
        .into_iter()
        .find(|el| el.text_content().unwrap_or_default().trim() == label)
        .unwrap_or_else(|| panic!("no button labelled `{label}`"))
        .unchecked_into()
}

#[wasm_bindgen_test]
async fn an_unreadable_claims_policy_blocks_save_until_it_loads() {
    ts::reset();
    ts::mock_ok("set_claims_mapping", &Option::<String>::None);
    let _m = mount(true);

    ts::wait_for(|| ts::body_contains(UNREAD)).await;
    let save = button("Save claims");
    assert!(
        save.disabled(),
        "Save must be off while the live policy is unknown — a save now would \
         replace claims the operator never saw"
    );
    save.click();
    ts::tick().await;
    assert_eq!(ts::call_count("set_claims_mapping"), 0);

    // Consent makes the next read succeed.
    ts::mock_ok("request_scope_consent", &());
    let mut readable = fixtures::sso_config("sp-demo", "app-demo");
    readable.claims_read_failed = false;
    readable.rollover = Some(fixtures::signing_cert_rollover_steady(
        "sp-demo", "app-demo",
    ));
    ts::mock_ok("get_sso_config", &readable);
    button("Load claims").click();
    ts::wait_for(|| ts::call_count("request_scope_consent") == 1).await;
    let call = ts::last_call("request_scope_consent").unwrap();
    assert_eq!(call.arg_str("feature").as_deref(), Some("policy_write"));
    // Consent lands, then the config is read again — and the guard lifts.
    ts::wait_for(|| ts::call_count("get_sso_config") == 2).await;
    ts::wait_for(|| !ts::body_contains(UNREAD)).await;
    // Tolerate the remount window, when the button is briefly absent.
    ts::wait_for(|| {
        ts::query_all("button").into_iter().any(|el| {
            el.text_content().unwrap_or_default().trim() == "Save claims"
                && !el.unchecked_ref::<web_sys::HtmlButtonElement>().disabled()
        })
    })
    .await;
    button("Save claims").click();
    ts::wait_for(|| ts::call_count("set_claims_mapping") == 1).await;
}

/// F385: the editor's advisory validation. A policy that switched the basic
/// claim set off without defining any claim strips name/email/givenname/
/// surname from every assertion — the editor must warn while it is being
/// edited, and stay advisory: Save keeps working (a deliberate lockdown is
/// legitimate).
#[wasm_bindgen_test]
async fn a_strip_everything_policy_warns_without_blocking_save() {
    // Control: the healthy default (basic set on, nothing defined) renders no
    // advisory at all.
    ts::reset();
    ts::mock_ok("set_claims_mapping", &Option::<String>::None);
    let m1 = mount(false);
    ts::wait_for(|| ts::body_contains("Save claims")).await;
    assert!(
        ts::query(".claims-editor .alert--warn").is_none(),
        "the healthy default shows no advisory"
    );
    drop(m1);

    // Same view over a policy that switched the basic set off with no claims
    // defined: the editor warns.
    ts::reset();
    ts::mock_ok("set_claims_mapping", &Option::<String>::None);
    let mut broken = fixtures::sso_config("sp-demo", "app-demo");
    broken.rollover = Some(fixtures::signing_cert_rollover_steady(
        "sp-demo", "app-demo",
    ));
    broken.claims_policy = Some(azapptoolkit_dto::sso::ClaimsPolicyDto {
        include_basic_claim_set: false,
        ..Default::default()
    });
    ts::mock_ok("get_sso_config", &broken);
    ts::mock_ok(
        "get_signing_cert_rollover",
        &fixtures::signing_cert_rollover_steady("sp-demo", "app-demo"),
    );

    let detail = Arc::new(fixtures::enterprise_application_detail(
        "sp-demo",
        "Contoso SSO Portal",
    ));
    let _m2 = ts::mount_view(move || {
        let d = detail.clone();
        view! { <SsoContent signal=Signal::derive(move || d.clone()) /> }
    });

    ts::wait_for(|| ts::body_contains("no identity claims at all")).await;
    assert!(ts::query(".claims-editor .alert--warn").is_some());

    // Advisory only: Save is still enabled and still sends.
    let save = button("Save claims");
    assert!(!save.disabled());
    save.click();
    ts::wait_for(|| ts::call_count("set_claims_mapping") == 1).await;
}

#[wasm_bindgen_test]
async fn a_read_claims_policy_can_be_saved() {
    ts::reset();
    ts::mock_ok("set_claims_mapping", &Option::<String>::None);
    let _m = mount(false);

    ts::wait_for(|| ts::body_contains("Save claims")).await;
    assert!(
        !ts::body_contains(UNREAD),
        "a policy that was read needs no warning"
    );
    let save = button("Save claims");
    assert!(!save.disabled());
    save.click();
    ts::wait_for(|| ts::call_count("set_claims_mapping") == 1).await;
}
