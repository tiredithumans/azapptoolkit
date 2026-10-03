//! GUI tests for the SSO tab's signed-AuthnRequest visibility (F265).
//!
//! The control itself (the `requestSignatureVerification` toggle) is
//! portal-only — v1.0 documents the property on reads but not as a PATCH
//! property — so what this tab owes the operator is the *state*: required /
//! required-but-weak / off, with a warn for the unsafe shapes and strict
//! silence on "unknown". These four tests pin exactly that contract: an
//! unverified app must not render as healthy, `rsaSha1` must be named while
//! verification is on, a healthy app informs without alarming, and a missing
//! property renders nothing at all.
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::enterprise_application_detail_pane::sso_tab::SsoContent;

/// The SSO tab's SAML section for a given signature-verification state. The
/// fixture itself carries `Some(true)` (healthy demo posture), so every case
/// below restates BOTH fields — a leftover `rsaSha1` from the fixture would
/// otherwise flag a case that means "no weak algorithm".
fn mount_saml(requires: Option<bool>, weak: Option<&str>) -> ts::Mounted {
    let mut cfg = fixtures::sso_config("sp-1", "app-1");
    cfg.signed_requests_required = requires;
    cfg.allowed_weak_signature_algorithms = weak.map(str::to_string);
    ts::mock_ok("get_sso_config", &cfg);
    ts::mock_ok(
        "get_signing_cert_rollover",
        &fixtures::signing_cert_rollover_steady("sp-1", "app-1"),
    );

    let detail = Arc::new(fixtures::enterprise_application_detail(
        "sp-1",
        "Contoso SSO Portal",
    ));
    ts::mount_view(move || {
        let d = detail.clone();
        view! { <SsoContent signal=Signal::derive(move || d.clone()) /> }
    })
}

/// Wait for the SAML section to be on screen (the editor renders it before any
/// signature-verification markup, so this only says "the tab mounted").
async fn wait_for_saml_section() {
    ts::wait_for(|| ts::body_contains("Identifiers (Entity IDs)")).await;
    // One tick more so the derived `SsoEditor` children have flushed.
    ts::tick().await;
}

fn alert_class(needle: &str) -> Option<String> {
    ts::query_all(".alert")
        .iter()
        .find(|e| e.text_content().unwrap_or_default().contains(needle))
        .map(|e| e.class_name())
}

#[wasm_bindgen_test]
async fn an_unverified_app_shows_as_a_risk_not_an_all_clear() {
    ts::reset();
    let _m = mount_saml(Some(false), None);
    wait_for_saml_section().await;
    assert!(
        ts::body_contains("Entra checks nothing"),
        "an app accepting unsigned AuthnRequests must be flagged; body was: {}",
        ts::body_text()
    );
    let cls = alert_class("Entra checks nothing").expect("the flag must be a Callout");
    assert!(
        cls.contains("alert--warn"),
        "verification-off is a risk, not a neutral fact: {cls}"
    );
    assert!(ts::body_contains("Not verified"));
}

#[wasm_bindgen_test]
async fn a_weak_algorithm_is_named_even_while_verification_is_on() {
    ts::reset();
    // The exact case F265 was raised for: `isSignedRequestRequired: true`
    // alongside `allowedWeakAlgorithms: rsaSha1` reads as "hardened" until you
    // look at the second field — a SHA-1-signed request is spoofable anyway.
    let _m = mount_saml(Some(true), Some("rsaSha1"));
    wait_for_saml_section().await;
    assert!(
        ts::body_contains("Required, but allows rsaSha1"),
        "the weak algorithm must be named while verification is on; body was: {}",
        ts::body_text()
    );
    let cls = alert_class("spoofable").expect("weak-algorithm allowance must warn");
    assert!(cls.contains("alert--warn"), "{cls}");
}

#[wasm_bindgen_test]
async fn a_healthy_app_informs_without_alarming() {
    ts::reset();
    let _m = mount_saml(Some(true), None);
    wait_for_saml_section().await;
    assert!(ts::body_contains(
        "Entra verifies the signature on every authentication request"
    ));
    // Scoped to the verification Callout itself: the "Rotate now (no staging)"
    // warn Callout is permanent SAML-section furniture and would sink a
    // "no warn anywhere" assertion for reasons unrelated to this feature.
    let cls = alert_class("Entra verifies the signature").expect("the healthy state still informs");
    assert!(
        !cls.contains("alert--warn"),
        "verification on + no weak algorithm must inform, not alarm: {cls}"
    );
}

#[wasm_bindgen_test]
async fn a_missing_signature_state_stays_completely_silent() {
    ts::reset();
    // `None` = the app read carried no `requestSignatureVerification` block.
    // Rendering "Not verified" here would guess: a non-SAML-shaped payload or a
    // Graph quirk would become a false risk flag (the same never-flag-on-unknown
    // contract the credential-lifetime markers pin).
    let _m = mount_saml(None, None);
    wait_for_saml_section().await;
    assert!(
        !ts::body_contains("Signed authentication requests"),
        "unknown must render nothing; body was: {}",
        ts::body_text()
    );
    assert!(!ts::body_contains("authentication request"));
}
