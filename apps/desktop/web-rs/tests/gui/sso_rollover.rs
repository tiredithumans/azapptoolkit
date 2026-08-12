//! GUI tests for the SSO tab's staged signing-certificate rollover panel.
//!
//! Mounts `SsoContent` directly rather than clicking through the enterprise
//! detail pane, mirroring `authentication_tab`: the pane resolves its initial
//! tab during setup, and driving it elsewhere needs machinery this behaviour
//! doesn't warrant.
//!
//! The behaviour worth pinning is the one the whole feature exists for:
//! **staging must not activate.** A staged certificate that silently went live
//! would be exactly the big-bang rotation the staged flow replaced, and nothing
//! else in the suite would notice — the panel would still render, the toast
//! would still say "staged", and sign-in would break for every app whose
//! service provider hadn't picked the new certificate up.
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::enterprise_application_detail_pane::sso_tab::SsoContent;

/// Mounts the SSO tab over a SAML app whose rollover state is `rollover`.
fn mount(rollover: &azapptoolkit_dto::sso::SigningCertRolloverDto) -> ts::Mounted {
    ts::mock_ok(
        "get_sso_config",
        &fixtures::sso_config("sp-demo", "app-demo"),
    );
    ts::mock_ok(
        "get_sso_summary",
        &fixtures::saml_sso_summary("sp-demo", "app-demo"),
    );
    ts::mock_ok("get_signing_cert_rollover", rollover);

    let detail = Arc::new(fixtures::enterprise_application_detail(
        "sp-demo",
        "Contoso SSO Portal",
    ));
    ts::mount_view(move || {
        let d = detail.clone();
        view! { <SsoContent signal=Signal::derive(move || d.clone()) /> }
    })
}

#[wasm_bindgen_test]
async fn staging_a_certificate_does_not_activate_it() {
    ts::reset();
    ts::mock_ok(
        "stage_saml_signing_certificate",
        &fixtures::staged_cert_result(),
    );
    // Mocked so that if the panel ever *did* call it, the call would succeed and
    // be recorded rather than erroring — the assertion below has to fail because
    // the call happened, not because it blew up.
    ts::mock_ok(
        "activate_saml_signing_certificate",
        &fixtures::signing_cert_rollover("sp-demo", "app-demo"),
    );

    let _m = mount(&fixtures::signing_cert_rollover_steady(
        "sp-demo", "app-demo",
    ));
    ts::wait_for(|| ts::body_contains("Stage new certificate")).await;

    ts::click(".cert-rollover button");
    ts::wait_for(|| ts::call_count("stage_saml_signing_certificate") == 1).await;

    assert_eq!(
        ts::call_count("activate_saml_signing_certificate"),
        0,
        "staging must leave the new certificate INACTIVE — activation is a \
         separate, explicit step",
    );
}

#[wasm_bindgen_test]
async fn a_staged_replacement_surfaces_entras_activation_deadline() {
    ts::reset();
    // Staged phase: the ACTIVE certificate's expiry is the deadline, because
    // Entra promotes the staged one on its own once it passes.
    let _m = mount(&fixtures::signing_cert_rollover("sp-demo", "app-demo"));

    ts::wait_for(|| ts::body_contains("Activate staged certificate")).await;
    assert!(
        ts::body_contains("2027-04-30"),
        "the active certificate's expiry is the activation deadline and must be \
         on screen; body was: {}",
        ts::body_text()
    );
    assert!(
        ts::body_contains("Entra promotes it on its own"),
        "the panel must say WHY that date is a deadline, not just show it",
    );
}

#[wasm_bindgen_test]
async fn a_steady_app_offers_no_activate_button() {
    ts::reset();
    let _m = mount(&fixtures::signing_cert_rollover_steady(
        "sp-demo", "app-demo",
    ));

    ts::wait_for(|| ts::body_contains("Stage new certificate")).await;
    assert!(
        !ts::body_contains("Activate staged certificate"),
        "nothing is staged, so there is nothing to activate — offering the \
         button would invite a no-op the backend then rejects",
    );
    assert!(
        !ts::body_contains("Revert to previous certificate"),
        "with no superseded certificate there is no rollback target",
    );
}
