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
        thumbprint: "SHA1THUMB".to_string(),
        thumbprint_sha256: "SHA256THUMB".to_string(),
        certificate_pem: "-----BEGIN CERTIFICATE-----\nPUBLICPART\n-----END CERTIFICATE-----"
            .to_string(),
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nPRIVATEPART\n-----END PRIVATE KEY-----"
            .to_string(),
        pfx_base64: "PFXCIPHERTEXT".to_string(),
        pfx_password: "PFXPASSWORD".to_string(),
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

/// Mounts the tab, returning a counter of `on_changed` calls alongside it.
///
/// `on_changed` is not cosmetic here: in the real pane it is `bump_reload`,
/// which re-runs the `LocalResource` this whole subtree — including the local
/// `gencert_result` signal — is rendered from. Firing it while the reveal is up
/// unmounts the reveal. A no-op callback cannot catch that, so the counter is
/// the stand-in for the teardown.
fn mount_tab_counting() -> (ts::Mounted, RwSignal<u32>) {
    ts::reset();
    ts::mock_ok("generate_self_signed_certificate", &generated());
    ts::mock_ok(
        "save_generated_certificate_pfx",
        &Some("/tmp/contoso.pfx".to_string()),
    );
    let detail = Arc::new(fixtures::application_detail(
        "obj-1",
        "app-1",
        "Contoso CRM",
    ));
    let changes = RwSignal::new(0_u32);
    let mounted = ts::mount_view(move || {
        let detail = detail.clone();
        let detail = Signal::derive(move || detail.clone());
        let on_changed = Callback::new(move |()| changes.update(|n| *n += 1));
        view! { <CredentialsTab detail=detail on_changed=on_changed /> }
    });
    (mounted, changes)
}

fn mount_tab() -> ts::Mounted {
    mount_tab_counting().0
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
    // Both thumbprints, each labelled by algorithm. The SHA-1 one is the value
    // the Credentials tab and the Entra portal show for this same certificate;
    // an unlabelled or SHA-256-only reveal sent the operator looking for a
    // thumbprint that exists nowhere else.
    assert!(
        ts::body_contains("Thumbprint (SHA-1): SHA1THUMB"),
        "SHA-1 thumbprint, labelled"
    );
    assert!(
        ts::body_contains("SHA-256: SHA256THUMB"),
        "SHA-256 thumbprint, labelled"
    );
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

    // The .pfx half. Its password is as unrecoverable as the key itself — the
    // bundle is useless without it — so it has to be on screen, not merely
    // available to a command.
    assert!(
        ts::body_contains("PFXPASSWORD"),
        "the one-time .pfx password must be shown beside the bundle it opens"
    );
    assert!(
        ts::query_all("button")
            .iter()
            .any(|e| e.text_content().unwrap_or_default().trim() == "Save .pfx…"),
        "the .pfx save affordance the modal points at must be present"
    );
}

/// Saving the .pfx must not release the deferred reload.
///
/// Same failure as `the_reveal_defers_the_detail_reload_until_it_is_dismissed`,
/// one button along: `on_changed` re-runs the resource this subtree is built
/// from, so firing it here would unmount the reveal mid-save and destroy the
/// private key the operator has not finished with. A save is not a mutation of
/// the application — nothing behind the modal went stale — so it has no reason
/// to reload anything.
#[wasm_bindgen_test]
async fn saving_the_pfx_leaves_the_reveal_standing() {
    let (_m, changes) = mount_tab_counting();

    ts::wait_for(|| ts::body_contains("Generate certificate…")).await;
    click_button("Generate certificate…");
    ts::wait_for(|| ts::body_contains("shows the private key once")).await;
    click_button("Generate");
    ts::wait_for(|| ts::body_contains("PRIVATEPART")).await;

    click_button("Save .pfx…");
    ts::wait_for(|| ts::call_count("save_generated_certificate_pfx") == 1).await;
    ts::wait_for(|| ts::body_contains("/tmp/contoso.pfx")).await;

    assert_eq!(
        changes.get_untracked(),
        0,
        "saving the bundle is not a mutation — it must not reload the detail"
    );
    assert!(
        ts::body_contains("PRIVATEPART"),
        "the private key must survive the save"
    );
    assert!(ts::body_contains("PFXPASSWORD"), "and so must the password");

    click_button("Done");
    ts::wait_for(|| !ts::body_contains("PRIVATEPART")).await;
    assert_eq!(changes.get_untracked(), 1);
}

/// A FAILED save must say why, inside the reveal.
///
/// The tab-body error banner renders *behind* the modal backdrop (the 0.28.0
/// bug), and this modal is the one screen where "the app appears to have done
/// nothing" costs an unrecoverable private key: the operator dismisses it
/// believing the file was written.
#[wasm_bindgen_test]
async fn a_failed_pfx_save_explains_itself_inside_the_reveal() {
    let (_m, changes) = mount_tab_counting();
    ts::mock_err(
        "save_generated_certificate_pfx",
        &azapptoolkit_dto::UiError::io("disk full"),
    );

    ts::wait_for(|| ts::body_contains("Generate certificate…")).await;
    click_button("Generate certificate…");
    ts::wait_for(|| ts::body_contains("shows the private key once")).await;
    click_button("Generate");
    ts::wait_for(|| ts::body_contains("PRIVATEPART")).await;

    click_button("Save .pfx…");
    ts::wait_for(|| ts::body_contains("disk full")).await;

    let in_modal = ts::query_all(".modal .form-error")
        .iter()
        .any(|e| e.text_content().unwrap_or_default().contains("disk full"));
    assert!(
        in_modal,
        "the failure must render inside the modal; behind the backdrop it is invisible"
    );
    // The key is still there to try again with, and nothing was reloaded.
    assert!(ts::body_contains("PRIVATEPART"));
    assert_eq!(changes.get_untracked(), 0);
}

/// A FAILED generate must say why, inside the dialog.
///
/// The reported symptom — "it doesn't display the private key like the popup
/// says" — is what this produces. On failure the dialog stays open (only success
/// closes it) and no key appears, while the reason went to the tab-body banner
/// **behind the modal backdrop**, where it is invisible. From the operator's
/// side the app silently did nothing.
#[wasm_bindgen_test]
async fn a_failed_generate_explains_itself_inside_the_dialog() {
    ts::reset();
    ts::mock_err(
        "generate_self_signed_certificate",
        &azapptoolkit_dto::UiError::validation(
            "cert_generation_failed",
            "Subject contains an unsupported character.",
        ),
    );
    let detail = Arc::new(fixtures::application_detail(
        "obj-1",
        "app-1",
        "Contoso CRM",
    ));
    let _m = ts::mount_view(move || {
        let detail = detail.clone();
        let detail = Signal::derive(move || detail.clone());
        view! { <CredentialsTab detail=detail on_changed=Callback::new(|()| {}) /> }
    });

    ts::wait_for(|| ts::body_contains("Generate certificate…")).await;
    click_button("Generate certificate…");
    ts::wait_for(|| ts::body_contains("shows the private key once")).await;
    click_button("Generate");
    ts::wait_for(|| ts::call_count("generate_self_signed_certificate") == 1).await;

    ts::wait_for(|| ts::body_contains("unsupported character")).await;
    // The reason must be INSIDE the still-open dialog, not on the page behind it.
    let in_modal = ts::query_all(".modal .form-error").iter().any(|e| {
        e.text_content()
            .unwrap_or_default()
            .contains("unsupported character")
    });
    assert!(
        in_modal,
        "the failure reason must render inside the modal; behind the backdrop it is invisible"
    );
    // And the dialog is still open, so the operator can correct and retry.
    assert!(ts::body_contains("shows the private key once"));
}

/// The reload must NOT fire while the one-time key is on screen.
///
/// Regression: the success handler called `on_changed` immediately, which in the
/// real detail pane re-runs the resource the tab is built from. The tab — and
/// with it `gencert_result` — was torn down and rebuilt empty, so the "shows the
/// private key once" modal never painted and the key was gone for good. The
/// sibling secret-create flow already defers the reload for exactly this reason;
/// the certificate flow did not, and the isolated test above (a no-op
/// `on_changed`) could not see the difference.
#[wasm_bindgen_test]
async fn the_reveal_defers_the_detail_reload_until_it_is_dismissed() {
    let (_m, changes) = mount_tab_counting();

    ts::wait_for(|| ts::body_contains("Generate certificate…")).await;
    click_button("Generate certificate…");
    ts::wait_for(|| ts::body_contains("shows the private key once")).await;
    click_button("Generate");
    ts::wait_for(|| ts::call_count("generate_self_signed_certificate") == 1).await;
    ts::wait_for(|| ts::body_contains("PRIVATEPART")).await;

    assert_eq!(
        changes.get_untracked(),
        0,
        "reloading the detail here unmounts the subtree that owns the reveal"
    );

    // Dismissing it is what releases the reload — the app now holds a new
    // public certificate, so the list behind the modal is stale until then.
    click_button("Done");
    ts::wait_for(|| !ts::body_contains("PRIVATEPART")).await;
    assert_eq!(
        changes.get_untracked(),
        1,
        "the deferred reload must still happen once the operator is done"
    );
}
