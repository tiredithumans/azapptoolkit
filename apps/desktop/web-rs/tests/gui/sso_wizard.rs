//! GUI tests for the end of the "New SSO application" wizard.
//!
//! Two behaviours worth pinning:
//! - **a partial SAML create never reads as a clean success.** The claims and
//!   notification-email steps are best-effort; when one fails the backend says
//!   so in `SamlSsoSummary.warnings`, and the summary must show it.
//! - **the wizard hands the operator to the app it just created** ("Open
//!   application" → the enterprise app on its SSO tab), instead of leaving them
//!   to find it in the list.
//!
//! Lives in the same shard as `sso_claims` / `sso_rollover`: it links the same
//! `sso_summary` + `claims_editor` subtree.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::sso_summary::SamlSummaryView;
use azapptoolkit_web_rs::state::OpenItemKind;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::dialogs::sso_wizard_dialog::SsoWizardDialog;

const PARTIAL: &str = "not everything you asked for was applied";

#[wasm_bindgen_test]
async fn a_partial_saml_create_says_what_was_not_applied() {
    ts::reset();
    let partial = ts::mount_view(|| {
        view! {
            <SamlSummaryView summary=fixtures::saml_sso_summary_partial("sp-demo", "app-demo") />
        }
    });
    ts::wait_for(|| ts::body_contains(PARTIAL)).await;
    assert!(
        ts::query(".sso-summary .alert--warn").is_some(),
        "the partial create is a warn Callout, not plain text"
    );
    assert!(ts::body_contains("Custom claims were not applied"));

    // A clean create shows no warning at all.
    drop(partial);
    ts::reset();
    let _m = ts::mount_view(|| {
        view! { <SamlSummaryView summary=fixtures::saml_sso_summary("sp-demo", "app-demo") /> }
    });
    ts::wait_for(|| ts::body_contains("Share these values")).await;
    assert!(ts::query(".sso-summary .alert--warn").is_none());
    assert!(!ts::body_contains(PARTIAL));
}

/// The `n`th `<input>` in the open modal: `ts::set_input_value` only reaches
/// the first match, and each wizard step has several.
fn set_nth_input(n: usize, value: &str) {
    let input: web_sys::HtmlInputElement = ts::query_all(".modal input")
        .into_iter()
        .nth(n)
        .unwrap_or_else(|| panic!("no input #{n} in the modal"))
        .unchecked_into();
    input.set_value(value);
    input
        .dispatch_event(&web_sys::Event::new("input").unwrap())
        .unwrap();
}

/// The first button with exactly this label, if rendered.
fn button(label: &str) -> Option<web_sys::HtmlElement> {
    ts::query_all("button")
        .into_iter()
        .find(|el| el.text_content().unwrap_or_default().trim() == label)
        .map(|el| el.unchecked_into())
}

/// Waits until the button labelled `label` is rendered and enabled — its
/// `disabled` binding updates on the next reactive tick after an input — then
/// clicks it.
async fn click_button(label: &str) {
    ts::wait_for(|| button(label).is_some_and(|b| !b.has_attribute("disabled"))).await;
    button(label)
        .unwrap_or_else(|| panic!("no button labelled `{label}`"))
        .click();
}

/// F382: a mistyped lifetime used to fall through `parse().ok()` into the
/// default — "3650" became a quiet 365-day cert. Now the field gates Next and
/// says why; a blank stays a legitimate "use the default".
#[wasm_bindgen_test]
async fn an_invalid_certificate_lifetime_blocks_next_until_fixed() {
    ts::reset();
    ts::mock_ok("get_tenant_defaults", &fixtures::tenant_defaults());
    ts::mock_ok(
        "create_saml_sso_application",
        &fixtures::saml_sso_summary("sp-demo", "app-demo"),
    );

    let _m = ts::mount_view(|| {
        view! {
            <SsoWizardDialog
                open=Signal::derive(|| true)
                on_close=Callback::new(|()| {})
                on_created=Callback::new(|()| {})
            />
        }
    });

    ts::wait_for(|| ts::body_contains("Step 1 of 3")).await;
    set_nth_input(0, "Contoso SSO");
    click_button("Next").await;
    ts::wait_for(|| ts::body_contains("Step 2 of 3")).await;

    // Entity + reply set, lifetime still at its valid default: Next is on.
    set_nth_input(0, "https://saml.contoso.com/sp");
    set_nth_input(1, "https://saml.contoso.com/acs");
    ts::wait_for(|| button("Next").is_some_and(|b| !b.has_attribute("disabled"))).await;

    // Mistype the cert lifetime (input #5 on this step): Next drops out and
    // the reason shows under the field.
    set_nth_input(4, "3650");
    ts::tick().await;
    assert!(ts::body_contains("out of range"));
    assert!(
        button("Next")
            .unwrap_or_else(|| panic!("no Next on step 2"))
            .has_attribute("disabled"),
        "an impossible lifetime must not fall through to Create"
    );

    // Fixing the number lifts the gate; the create then really runs.
    set_nth_input(4, "180");
    click_button("Next").await;
    ts::wait_for(|| ts::body_contains("Step 3 of 3")).await;
    click_button("Create").await;
    ts::wait_for(|| ts::call_count("create_saml_sso_application") == 1).await;
}

#[wasm_bindgen_test]
async fn the_wizard_opens_the_created_app_on_its_sso_tab() {
    ts::reset();
    ts::mock_ok("get_tenant_defaults", &fixtures::tenant_defaults());
    ts::mock_ok(
        "create_saml_sso_application",
        &fixtures::saml_sso_summary_partial("sp-demo", "app-demo"),
    );

    let m = ts::mount_view(|| {
        view! {
            <SsoWizardDialog
                open=Signal::derive(|| true)
                on_close=Callback::new(|()| {})
                on_created=Callback::new(|()| {})
            />
        }
    });

    // Step 1 of 3: name (SAML is the default protocol).
    ts::wait_for(|| ts::body_contains("Step 1 of 3")).await;
    set_nth_input(0, "Contoso SSO");
    click_button("Next").await;
    // Step 2 of 3: entity id + reply URL.
    ts::wait_for(|| ts::body_contains("Step 2 of 3")).await;
    set_nth_input(0, "https://saml.contoso.com/sp");
    set_nth_input(1, "https://saml.contoso.com/acs");
    click_button("Next").await;
    // Step 3 of 3: create.
    ts::wait_for(|| ts::body_contains("Step 3 of 3")).await;
    click_button("Create").await;

    // The backend's warning reaches the wizard's summary end to end.
    ts::wait_for(|| ts::body_contains(PARTIAL)).await;
    assert_eq!(ts::call_count("create_saml_sso_application"), 1);

    ts::click(".sso-wizard-open");
    ts::wait_for(|| {
        m.session.open_items.with_untracked(|v| {
            v.iter()
                .any(|i| i.kind == OpenItemKind::Enterprise && i.entity_id == "sp-demo")
        })
    })
    .await;
    assert_eq!(
        m.session
            .tenant_ui
            .pending_enterprise_tab
            .get_untracked()
            .as_deref(),
        Some("sso"),
        "a SAML app opens where its setup (and any retry) continues"
    );
}
