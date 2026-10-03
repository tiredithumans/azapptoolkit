//! GUI tests for the app-management-policy surface on the Credentials tab:
//! the secret-lifetime Callout, the per-row "Over cap" marker, and the
//! add-secret dialog's pre-emptive warning.
//!
//! The invariant these tests hold is the *never-flag-on-unknown* contract the
//! tab's Last-used column already follows: a policy that could not be read,
//! and a tenant that enforces no lifetime cap, must render **nothing** — the
//! app never claims "no cap enforced" on evidence that only shows "couldn't
//! read". The mirror half is that a *known* cap does speak: a 430-day secret
//! on a 90-day-cap tenant reads "OK" to the expiry badge alone, and without
//! the marker the tab hides the one thing the operator can still act on.
//!
//! The over-cap set is folded once (`policy_ctx`) with
//! `credential_over_cap` — the same predicate the audit's lifetime advisory
//! uses — and expired secrets are excluded by design: they already carry
//! their own, louder status signal.
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_core::models::PasswordCredential;
use azapptoolkit_dto::credentials::AppCredentialPolicyDto;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::credentials_tab::CredentialsTab;

/// A secret whose lifetime is `start_days_ago + end_days_from_now` days.
/// Negative `end_days_from_now` means already expired.
fn secret(key_id: &str, start_days_ago: i64, end_days_from_now: i64) -> PasswordCredential {
    PasswordCredential {
        key_id: key_id.to_string(),
        display_name: Some(key_id.to_string()),
        start_date_time: Some(chrono::Utc::now() - chrono::Duration::days(start_days_ago)),
        end_date_time: Some(chrono::Utc::now() + chrono::Duration::days(end_days_from_now)),
        ..Default::default()
    }
}

/// Mounts the tab with an explicit policy answer beside the always-mocked
/// healthy Last-used path (see credential_sweep.rs for why that one is mocked
/// rather than left to reject).
fn mount(secrets: Vec<PasswordCredential>, policy: AppCredentialPolicyDto) -> ts::Mounted {
    ts::reset();
    ts::mock_ok("list_credential_usage", &fixtures::credential_usage_empty());
    ts::mock_ok("get_app_credential_policy", &policy);
    let mut d = fixtures::application_detail("obj-1", "app-1", "Contoso CRM");
    d.application.password_credentials = secrets;
    let detail = Arc::new(d);
    ts::mount_view(move || {
        let detail = detail.clone();
        let detail = Signal::derive(move || detail.clone());
        view! { <CredentialsTab detail=detail on_changed=Callback::new(|()| {}) /> }
    })
}

/// The over-cap `Badge`s currently in the document (label-exact, so the
/// expiry-state badge can't be miscounted as one).
fn over_cap_badges() -> Vec<web_sys::Element> {
    ts::query_all(".badge")
        .into_iter()
        .filter(|e| e.text_content().unwrap_or_default().trim() == "Over cap")
        .collect()
}

/// A known cap with a provably-over secret must say so twice: once as the
/// section notice, once on the row itself. Expired secrets are deliberately
/// in the fixture — the marker is for *valid* illegal secrets; an expired
/// one already wears its Expired badge, and double-marking it trains the
/// operator to skim past both.
#[wasm_bindgen_test]
async fn a_known_cap_warns_and_marks_only_the_valid_over_cap_secrets() {
    let _m = mount(
        vec![
            // 430-day lifetime, still valid → the one that gets marked.
            secret("over-active", 250, 180),
            // 430-day lifetime, already expired → no second marker.
            secret("over-expired", 460, -30),
            // 60-day lifetime → legal, untouched.
            secret("legal", 30, 30),
        ],
        fixtures::credential_policy_cap(90, &["Contoso strict"]),
    );

    ts::wait_for(|| ts::body_contains("caps secret lifetimes at 90 days")).await;
    let callout = ts::query_all(".alert")
        .into_iter()
        .find(|e| {
            e.text_content()
                .unwrap_or_default()
                .contains("caps secret lifetimes")
        })
        .expect("the section Callout");
    assert!(
        callout.class_list().contains("alert--warn"),
        "violations must raise the notice to warn tone"
    );
    assert!(
        callout
            .text_content()
            .unwrap_or_default()
            .contains("(assigned policy: Contoso strict)"),
        "the assigned override must be named, not just the number"
    );

    let marked = over_cap_badges();
    assert_eq!(
        marked.len(),
        1,
        "only the valid over-cap secret is marked, got {} markers",
        marked.len()
    );
    assert_eq!(
        marked[0].get_attribute("title").as_deref(),
        Some("Longer than the 90-day secret-lifetime policy on this app"),
        "the marker must state the rule it violates on hover"
    );
}

/// A known cap with NO violations still informs, but must not alarm: warn
/// tone with nothing to act on is the "cry wolf" notice operators learn to
/// ignore, and per-row there is nothing to mark.
#[wasm_bindgen_test]
async fn a_cap_with_no_violations_informs_without_alarming() {
    let _m = mount(
        vec![secret("legal", 30, 30)],
        fixtures::credential_policy_cap(90, &[]),
    );

    ts::wait_for(|| ts::body_contains("caps secret lifetimes at 90 days")).await;
    let callout = ts::query_all(".alert")
        .into_iter()
        .find(|e| {
            e.text_content()
                .unwrap_or_default()
                .contains("caps secret lifetimes")
        })
        .expect("the section Callout");
    assert!(
        !callout.class_list().contains("alert--warn"),
        "a compliant app must not render in warn tone"
    );
    assert!(
        !ts::body_contains("Over cap"),
        "nothing is over the cap, so nothing may be marked"
    );
}

/// The negative half of the locked wording: an unread policy renders nothing,
/// and the app never says "no cap enforced" (or any lifetime-policy text) on
/// evidence that only shows "couldn't read". The table must still render —
/// silence is about the policy surface, not the whole tab.
#[wasm_bindgen_test]
async fn an_unknown_policy_says_nothing_at_all() {
    let _m = mount(
        vec![secret("over-active", 250, 180)],
        fixtures::credential_policy_unknown(),
    );

    ts::wait_for(|| ts::body_contains("Secret ID")).await;
    let body = ts::body_text();
    assert!(
        !body.contains("secret lifetimes"),
        "an unknown policy must not render a lifetime notice: {body:?}"
    );
    assert!(
        !body.contains("Over cap"),
        "no known cap means no marker: {body:?}"
    );
    assert!(
        !body.contains("no cap"),
        "the app must never claim absence of a cap from unknown evidence"
    );
}

/// The add-secret dialog warns BEFORE the request goes out (F260's other
/// half: a policy-driven rejection should not arrive as an opaque 400 after
/// the operator already chose a lifetime). It warns and does NOT block —
/// only Graph decides whether the add lands.
#[wasm_bindgen_test]
async fn the_add_dialog_flags_a_lifetime_the_policy_would_reject() {
    let _m = mount(
        vec![secret("legal", 30, 30)],
        fixtures::credential_policy_cap(90, &[]),
    );

    ts::wait_for(|| ts::body_contains("caps secret lifetimes at 90 days")).await;
    ts::wait_for(|| ts::body_contains("+ New secret")).await;
    ts::click_button_labelled("+ New secret");
    ts::wait_for(|| ts::body_contains("New client secret")).await;

    // The default preset is 180 days — over the tenant's 90-day cap.
    ts::wait_for(|| ts::body_contains("would be rejected")).await;
    let in_modal = ts::query_all(".modal .alert--warn").iter().any(|e| {
        e.text_content()
            .unwrap_or_default()
            .contains("exceeds the 90-day")
    });
    assert!(
        in_modal,
        "the lifetime warning must render inside the dialog, not behind the backdrop"
    );
    assert!(
        ts::button_labelled_enabled("Create"),
        "the policy decides rejection — the dialog only warns, it never blocks"
    );
}

/// Mirror case: with a cap the chosen lifetime satisfies, the dialog shows
/// no warning — the check is per-chosen-lifetime, not a permanent plaque.
#[wasm_bindgen_test]
async fn the_add_dialog_stays_quiet_under_a_generous_cap() {
    let _m = mount(
        vec![secret("legal", 30, 30)],
        fixtures::credential_policy_cap(365, &[]),
    );

    ts::wait_for(|| ts::body_contains("caps secret lifetimes at 365 days")).await;
    ts::wait_for(|| ts::body_contains("+ New secret")).await;
    ts::click_button_labelled("+ New secret");
    ts::wait_for(|| ts::body_contains("New client secret")).await;
    ts::tick().await;
    assert!(
        !ts::body_contains("would be rejected"),
        "a 180-day add under a 365-day cap is legal and must be silent"
    );
}
