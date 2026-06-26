//! GUI test for the "re-authenticate when required" recovery: a command that
//! fails because the session is dead (`refresh_missing` / `not_signed_in`)
//! surfaces an error toast whose action runs the interactive `reauthenticate`
//! flow in place — no manual sign-out. Exercises `report_command_error` and
//! `spawn_reauth` end to end through the real toast UI, the IPC binding, and the
//! serde wire format (the smart Refresh button's fallback shares this path).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::bindings::SignInOutcome;
use azapptoolkit_web_rs::components::toast::ToastHost;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn dead_session_error_offers_reauth_action_that_calls_reauthenticate() {
    ts::reset();
    // The interactive re-auth round trip the toast action triggers.
    ts::mock_ok(
        "reauthenticate",
        &SignInOutcome {
            tenant: ts::test_tenant(),
        },
    );

    let m = ts::mount_view(|| view! { <ToastHost /> });

    // A command failed because the refresh token is dead.
    m.session
        .report_command_error(&fixtures::ui_error("refresh_missing", "session expired"));

    // The error toast offers a "Re-authenticate" action (not a dead-end message).
    ts::wait_for(|| ts::query(".toast__action").is_some()).await;
    assert_eq!(ts::text(".toast__action"), "Re-authenticate");
    assert!(ts::body_contains("session has expired"));

    // Clicking it runs the interactive re-auth in place, pinned to the session's
    // tenant — no sign-out.
    ts::click(".toast__action");
    ts::wait_for(|| ts::call_count("reauthenticate") == 1).await;
    let call = ts::last_call("reauthenticate").expect("reauthenticate called");
    assert_eq!(
        call.args
            .get("tenant")
            .and_then(|t| t.get("tenant_id"))
            .and_then(|v| v.as_str()),
        Some("test-tenant"),
        "re-auth must target the active tenant",
    );
}

#[wasm_bindgen_test]
async fn non_auth_error_shows_plain_toast_without_reauth_action() {
    ts::reset();
    let m = ts::mount_view(|| view! { <ToastHost /> });

    // A normal (non-session) failure: plain error toast, no re-auth action.
    m.session
        .report_command_error(&fixtures::ui_error("network", "request failed"));

    ts::wait_for(|| ts::body_contains("request failed")).await;
    assert!(
        ts::query(".toast__action").is_none(),
        "a non-session error must not offer a re-authenticate action",
    );
}
