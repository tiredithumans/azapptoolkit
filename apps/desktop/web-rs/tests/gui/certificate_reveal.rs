//! GUI test for the one-shot private-key reveal on the Credentials tab.
//!
//! The generate dialog promises *"shows the private key once"* and the result
//! modal says the key *"is never stored and cannot be retrieved again"*. If the
//! reveal does not render, the operator has irrecoverably lost the key they were
//! told to copy — and the app looks like it succeeded. That promise had no test
//! behind it, which is exactly the shape of gap where a break stays silent.
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::applications::GeneratedCertificateResult;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::credentials_tab::CredentialsTab;

fn generated() -> GeneratedCertificateResult {
    GeneratedCertificateResult {
        thumbprint: "AABBCCDD".to_string(),
        certificate_pem: "-----BEGIN CERTIFICATE-----\nPUBLICPART\n-----END CERTIFICATE-----"
            .to_string(),
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nPRIVATEPART\n-----END PRIVATE KEY-----"
            .to_string(),
        expires: "2027-01-01T00:00:00Z".to_string(),
    }
}

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

fn mount_tab() -> ts::Mounted {
    ts::reset();
    ts::mock_ok("generate_self_signed_certificate", &generated());
    let detail = Arc::new(fixtures::application_detail(
        "obj-1",
        "app-1",
        "Contoso CRM",
    ));
    ts::mount_view(move || {
        let detail = detail.clone();
        let detail = Signal::derive(move || detail.clone());
        view! { <CredentialsTab detail=detail on_changed=Callback::new(|()| {}) /> }
    })
}

#[wasm_bindgen_test]
async fn a_generated_certificate_reveals_its_private_key_once() {
    let _m = mount_tab();

    ts::wait_for(|| ts::body_contains("Generate certificate…")).await;
    click_button("Generate certificate…");

    // The dialog states the promise this test exists to hold it to.
    ts::wait_for(|| ts::body_contains("shows the private key once")).await;
    click_button("Generate");
    ts::wait_for(|| ts::call_count("generate_self_signed_certificate") == 1).await;

    // The reveal itself.
    ts::wait_for(|| ts::body_contains("Certificate generated")).await;
    assert!(
        ts::body_contains("PRIVATEPART"),
        "the private key must be shown — it cannot be retrieved again"
    );
    assert!(ts::body_contains("AABBCCDD"), "thumbprint");
    assert!(ts::body_contains("PUBLICPART"), "certificate PEM");

    // And inside the copyable reveal block, not merely somewhere in the DOM:
    // the "Copy private key" affordance is what the operator is told to use.
    let revealed: Vec<String> = ts::query_all("pre.secret-reveal")
        .iter()
        .map(|e| e.text_content().unwrap_or_default())
        .collect();
    assert!(
        revealed.iter().any(|t| t.contains("PRIVATEPART")),
        "expected the key inside a .secret-reveal block, got {revealed:?}"
    );
    assert!(
        ts::query_all("button")
            .iter()
            .any(|e| e.text_content().unwrap_or_default().trim() == "Copy private key"),
        "the copy affordance the modal points at must be present"
    );
}
