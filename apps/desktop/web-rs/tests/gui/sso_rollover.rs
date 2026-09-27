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
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::enterprise_application_detail_pane::sso_tab::SsoContent;

/// Clicks the first button whose trimmed text matches exactly.
fn click_button(label: &str) {
    for el in ts::query_all("button") {
        if el.text_content().unwrap_or_default().trim() == label {
            let el: web_sys::HtmlElement = el.unchecked_into();
            el.click();
            return;
        }
    }
    let seen: Vec<String> = ts::query_all("button")
        .iter()
        .map(|e| e.text_content().unwrap_or_default().trim().to_string())
        .collect();
    panic!("no button labelled `{label}`; saw {seen:?}");
}

/// Whether some `pre.secret-reveal` block holds `needle`.
fn revealed(needle: &str) -> bool {
    ts::query_all("pre.secret-reveal")
        .iter()
        .any(|e| e.text_content().unwrap_or_default().contains(needle))
}

/// Mounts the SSO tab over a SAML app whose rollover state is `rollover`.
/// `get_sso_config` carries the initial state; `get_signing_cert_rollover`
/// answers the panel's re-reads after its own actions.
fn mount(rollover: &azapptoolkit_dto::sso::SigningCertRolloverDto) -> ts::Mounted {
    let mut cfg = fixtures::sso_config("sp-demo", "app-demo");
    cfg.rollover = Some(rollover.clone());
    ts::mock_ok("get_sso_config", &cfg);
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

    // The show-once public certificate is revealed in the shared copy block —
    // labelled, with a Copy button — not a bare `pre` the operator has to
    // select by hand. (Copy itself isn't clicked: headless clipboard writes are
    // unreliable.)
    ts::wait_for(|| revealed("MIIC-demo-newly-staged-certificate-body")).await;
    assert!(ts::body_contains("Staged signing certificate (Base64)"));
    assert!(
        ts::query_all("button")
            .iter()
            .any(|b| b.text_content().unwrap_or_default().trim() == "Copy"),
        "the staged certificate must come with a Copy button",
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
    assert!(
        ts::query(".cert-rollover__remove").is_none(),
        "nothing is expired, so no row may offer Remove — the active \
         certificate must never grow a delete button",
    );
}

/// An expired certificate that is no longer nominated is dead weight: the
/// backend has always been willing to remove it, but no UI offered the action —
/// the retire button only appeared for a superseded (rollback) certificate, so
/// expired leftovers accumulated forever. The portal's equivalent is "Delete
/// certificate" on an inactive cert.
#[wasm_bindgen_test]
async fn an_expired_inactive_certificate_offers_remove() {
    ts::reset();
    let mut roll = fixtures::signing_cert_rollover_steady("sp-demo", "app-demo");
    roll.certs.push(azapptoolkit_dto::sso::SigningCertDto {
        key_id: "key-expired".to_string(),
        thumbprint: "00B2C3D4E5F60718293A4B5C6D7E8F9012345678".to_string(),
        display_name: Some("CN=Contoso SSO 2023".to_string()),
        start_date_time: Some("2020-05-01T00:00:00Z".to_string()),
        end_date_time: Some("2023-05-01T00:00:00Z".to_string()),
        is_active: false,
        days_to_expiry: Some(-1200),
        status: azapptoolkit_dto::sso::CertStatus::Expired,
    });
    ts::mock_ok(
        "retire_saml_signing_certificate",
        &fixtures::signing_cert_rollover_steady("sp-demo", "app-demo"),
    );

    let _m = mount(&roll);
    ts::wait_for(|| ts::query(".cert-rollover__remove").is_some()).await;

    ts::click(".cert-rollover__remove");
    ts::wait_for(|| ts::call_count("retire_saml_signing_certificate") == 1).await;

    assert_eq!(
        ts::call_count("activate_saml_signing_certificate"),
        0,
        "removing an expired leftover must not touch the nomination",
    );
}

/// Opening the SSO tab is ONE backend read. The owner summary and the rollover
/// panel's initial state ride on `get_sso_config`; before, the tab re-ran the
/// whole service-principal → application chain for the summary and read the
/// service principal a third time for the panel.
#[wasm_bindgen_test]
async fn the_sso_tab_fills_from_one_config_read() {
    ts::reset();
    let _m = mount(&fixtures::signing_cert_rollover_steady(
        "sp-demo", "app-demo",
    ));

    ts::wait_for(|| ts::body_contains("Details for the application owner")).await;
    ts::wait_for(|| ts::body_contains("Stage new certificate")).await;
    assert!(
        ts::body_contains("/saml2"),
        "the owner summary's login URL must render; body was: {}",
        ts::body_text()
    );
    assert_eq!(ts::call_count("get_sso_config"), 1);
    assert_eq!(
        ts::call_count("get_signing_cert_rollover"),
        0,
        "the rollover panel must render the state get_sso_config carried, not \
         read the service principal again",
    );
}

/// Opens the immediate-rotation confirmation, types the keyword and confirms.
async fn confirm_rotation() {
    click_button("Rotate and activate immediately");
    assert_eq!(
        ts::call_count("rotate_saml_signing_certificate"),
        0,
        "the button only asks — an immediate rotation breaks sign-in for \
         static-certificate apps, so it must never run on one click",
    );
    ts::wait_for(|| ts::query(".confirm-dialog__keyword input").is_some()).await;
    ts::set_input_value(".confirm-dialog__keyword input", "ROTATE");
    // The typed keyword enables the confirm button on the next render pass.
    ts::wait_for(|| {
        ts::query_all("button").into_iter().any(|el| {
            let b: web_sys::HtmlButtonElement = el.unchecked_into();
            b.text_content().unwrap_or_default().trim() == "Rotate now" && !b.disabled()
        })
    })
    .await;
    click_button("Rotate now");
}

/// The rotated certificate is show-once (`SsoCertResult::base64`), and the
/// rotation reloads the SSO config, which remounts the whole editor. The reveal
/// used to live in that editor and vanished with the reload it triggered — the
/// same teardown class `certificate_reveal.rs` (`mount_tab_counting`) pins for
/// the Credentials tab.
#[wasm_bindgen_test]
async fn a_rotated_certificate_survives_the_reload_it_triggers() {
    ts::reset();
    ts::mock_ok(
        "rotate_saml_signing_certificate",
        &azapptoolkit_dto::sso::SsoCertResult {
            thumbprint: "ROT0C3D4E5F60718293A4B5C6D7E8F9012345678".to_string(),
            base64: Some("MIIC-rotated-certificate-body".to_string()),
            expiry: Some("2029-09-01T00:00:00Z".to_string()),
        },
    );
    let steady = fixtures::signing_cert_rollover_steady("sp-demo", "app-demo");
    let _m = mount(&steady);
    ts::wait_for(|| ts::body_contains("Rotate and activate immediately")).await;

    // The reload's answer carries a marker only a REMOUNTED editor can show,
    // so the wait below proves the refetch resolved and rebuilt the editor —
    // the call count alone rises at invoke time, before the rebuild.
    let mut reloaded = fixtures::sso_config("sp-demo", "app-demo");
    reloaded.rollover = Some(steady);
    reloaded.claims_read_failed = true;
    ts::mock_ok("get_sso_config", &reloaded);

    confirm_rotation().await;
    ts::wait_for(|| ts::call_count("rotate_saml_signing_certificate") == 1).await;
    ts::wait_for(|| ts::body_contains("Couldn't read this app's current claims policy")).await;

    assert!(
        revealed("MIIC-rotated-certificate-body"),
        "the new certificate must still be on screen after the reload; body was: {}",
        ts::body_text()
    );
    assert!(ts::body_contains("New signing certificate (Base64)"));
    assert!(
        ts::query_all("button")
            .iter()
            .any(|b| b.text_content().unwrap_or_default().trim() == "Copy"),
        "the rotated certificate must come with a Copy button",
    );
}

#[wasm_bindgen_test]
async fn rotating_immediately_asks_first_and_cancel_does_nothing() {
    ts::reset();
    ts::mock_ok(
        "rotate_saml_signing_certificate",
        &fixtures::staged_cert_result(),
    );
    let _m = mount(&fixtures::signing_cert_rollover_steady(
        "sp-demo", "app-demo",
    ));
    ts::wait_for(|| ts::body_contains("Rotate and activate immediately")).await;

    click_button("Rotate and activate immediately");
    ts::wait_for(|| ts::body_contains("Rotate the signing certificate now?")).await;
    click_button("Cancel");
    ts::wait_for(|| !ts::body_contains("Rotate the signing certificate now?")).await;

    assert_eq!(
        ts::call_count("rotate_saml_signing_certificate"),
        0,
        "cancelling the confirmation must not rotate",
    );
}

/// Retiring the superseded certificate ends the ability to revert, so it asks
/// before it runs — and then retires exactly the superseded key.
#[wasm_bindgen_test]
async fn retiring_the_previous_certificate_asks_first() {
    ts::reset();
    // Pending retire: the staged certificate went live, the old one is kept as
    // the rollback target.
    let mut roll = fixtures::signing_cert_rollover("sp-demo", "app-demo");
    for c in &mut roll.certs {
        if c.key_id == "key-staged" {
            c.is_active = true;
            c.status = azapptoolkit_dto::sso::CertStatus::Active;
        } else if c.key_id == "key-active" {
            c.is_active = false;
            c.status = azapptoolkit_dto::sso::CertStatus::Superseded;
        }
    }
    roll.active_thumbprint = Some("FE09D8C7B6A5948372615F4E3D2C1B0A98765432".to_string());
    roll.staged_thumbprint = None;
    roll.phase = azapptoolkit_dto::sso::RolloverPhase::PendingRetire;
    roll.auto_promote_deadline = None;
    ts::mock_ok(
        "retire_saml_signing_certificate",
        &fixtures::signing_cert_rollover_steady("sp-demo", "app-demo"),
    );

    let _m = mount(&roll);
    ts::wait_for(|| ts::body_contains("Retire previous certificate")).await;

    click_button("Retire previous certificate");
    ts::wait_for(|| ts::body_contains("Retire the previous signing certificate?")).await;
    assert_eq!(
        ts::call_count("retire_saml_signing_certificate"),
        0,
        "retire removes the only rollback — it must not run on one click",
    );

    click_button("Retire");
    ts::wait_for(|| ts::call_count("retire_saml_signing_certificate") == 1).await;
    assert_eq!(
        ts::last_call("retire_saml_signing_certificate")
            .unwrap()
            .arg_str("keyId")
            .as_deref(),
        Some("key-active"),
        "retire must target the superseded certificate",
    );
}
