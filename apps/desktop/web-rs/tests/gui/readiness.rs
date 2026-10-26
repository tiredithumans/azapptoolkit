//! GUI tests for the readiness checklist. Auto-loads on mount (tenant preset by
//! the harness), so the load + render assertions need no interaction.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::toast::ToastHost;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::readiness_view::ReadinessView;

#[wasm_bindgen_test]
async fn loads_and_renders_checklist() {
    ts::reset();
    ts::mock_ok("check_readiness", &fixtures::readiness_report());

    let _m = ts::mount_view(|| view! { <ReadinessView /> });

    ts::wait_for(|| ts::body_contains("Manage app registrations")).await;
    assert_eq!(
        ts::last_call("check_readiness")
            .unwrap()
            .arg_str("tenantId")
            .as_deref(),
        Some("test-tenant")
    );
    // The report's second item + its remediation hint render too.
    assert!(ts::body_contains("Read Key Vault secrets"));
    assert!(ts::body_contains("Assign the Key Vault Secrets User role."));
    // A Missing role links to PIM so an eligible operator can activate it.
    assert!(ts::body_contains("Open PIM (My roles)"));
}

#[wasm_bindgen_test]
async fn token_refresh_reruns_the_check() {
    ts::reset();
    ts::mock_ok("check_readiness", &fixtures::readiness_report());

    let m = ts::mount_view(|| view! { <ReadinessView /> });

    ts::wait_for(|| ts::call_count("check_readiness") == 1).await;
    // A token refresh bumps the shared readiness-reload signal (the shell does
    // this on a successful refresh / re-auth) — the checklist re-runs in place,
    // which replaces the old standalone "Re-check" button.
    m.session.bump_readiness_reload();
    ts::wait_for(|| ts::call_count("check_readiness") == 2).await;
}

#[wasm_bindgen_test]
async fn error_state_renders_message() {
    ts::reset();
    ts::mock_err(
        "check_readiness",
        &fixtures::ui_error("forbidden", "Cannot evaluate directory roles"),
    );

    let _m = ts::mount_view(|| view! { <ReadinessView /> });

    ts::wait_for(|| ts::body_contains("Cannot evaluate directory roles")).await;
}

/// An unreadable roles list names its real cause — the read rides the sign-in
/// scopes, so "a missing Directory.Read.All consent" was never it — and a dead
/// session behind it gets the Re-authenticate lever instead of a dead end.
#[wasm_bindgen_test]
async fn a_dead_session_behind_the_roles_read_offers_reauthentication() {
    ts::reset();
    let mut report = fixtures::readiness_report();
    report.directory_roles_indeterminate = true;
    report.directory_roles_error = Some(fixtures::ui_error(
        "refresh_missing",
        "Your sign-in has expired; sign in again.",
    ));
    ts::mock_ok("check_readiness", &report);

    let _m = ts::mount_view(|| {
        view! {
            <ToastHost />
            <ReadinessView />
        }
    });

    ts::wait_for(|| ts::query(".readiness__roles-error").is_some()).await;
    let banner = ts::text(".readiness__roles-error");
    assert!(banner.contains("Your sign-in has expired"), "{banner}");
    assert!(banner.contains("[refresh_missing]"), "{banner}");
    assert!(!banner.contains("Directory.Read.All"), "{banner}");
    ts::wait_for(|| ts::query(".toast__action").is_some()).await;
    assert_eq!(ts::text(".toast__action"), "Re-authenticate");
}

/// A Conditional Access step-up behind the roles read is not shown as its raw
/// AADSTS text: the banner says what is needed and carries its own Verify
/// identity lever, which re-runs the check once verified — and the sink adds
/// no second lever beside it.
#[wasm_bindgen_test]
async fn a_step_up_behind_the_roles_read_offers_verify_identity_inline() {
    ts::reset();
    let mut report = fixtures::readiness_report();
    report.directory_roles_indeterminate = true;
    report.directory_roles_error = Some(fixtures::ui_error(
        "interaction_required",
        "interaction required (AADSTS50076)",
    ));
    ts::mock_ok("check_readiness", &report);
    ts::mock_ok("request_scope_step_up", &());

    let _m = ts::mount_view(|| {
        view! {
            <ToastHost />
            <ReadinessView />
        }
    });

    ts::wait_for(|| ts::query(".readiness__roles-error").is_some()).await;
    let banner = ts::text(".readiness__roles-error");
    assert!(banner.contains("verify your identity"), "{banner}");
    assert!(!banner.contains("AADSTS50076"), "{banner}");
    assert!(
        ts::query(".toast__action").is_none(),
        "no second lever from the sink"
    );

    ts::click_button_labelled("Verify identity & retry");
    ts::wait_for(|| ts::call_count("request_scope_step_up") == 1).await;
    assert_eq!(
        ts::last_call("request_scope_step_up")
            .unwrap()
            .arg_str("feature")
            .as_deref(),
        Some("write")
    );
    ts::wait_for(|| ts::call_count("check_readiness") == 2).await;
}
