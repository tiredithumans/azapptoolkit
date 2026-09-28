//! GUI test for the "re-authenticate when required" recovery: a command that
//! fails because the session is dead (`refresh_missing` / `not_signed_in`)
//! surfaces an error toast whose action runs the interactive `reauthenticate`
//! flow in place — no manual sign-out. Exercises `report_command_error` and
//! `spawn_reauth` end to end through the real toast UI, the IPC binding, and the
//! serde wire format (the smart Refresh button's fallback shares this path).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use azapptoolkit_web_rs::bindings::SignInOutcome;
use azapptoolkit_web_rs::bindings::usage::GraphUsageResult;
use azapptoolkit_web_rs::components::toast::ToastHost;
use azapptoolkit_web_rs::ipc_mock;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::usage_panel::UsagePanel;

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
    let before = m.session.readiness_reload.get_untracked();
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
    // A new session may carry different roles, so it re-runs a mounted Access
    // Readiness checklist — as the top bar's Refresh-token fallback does.
    ts::wait_for(|| ts::body_contains("Re-authenticated")).await;
    assert_eq!(
        m.session.readiness_reload.get_untracked(),
        before + 1,
        "re-auth from the toast must re-check Access Readiness"
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

/// A rejected access token (`unauthorized`, a client 401 — e.g. a CAE claims
/// challenge the silent re-mint couldn't satisfy) used to be a bare
/// "unauthorized (401)" toast. It now offers the top bar's "Refresh token" lever
/// in place, which re-mints silently for the active tenant.
#[wasm_bindgen_test]
async fn unauthorized_error_offers_refresh_token_action() {
    ts::reset();
    ts::mock_ok("refresh_session", &());
    let m = ts::mount_view(|| view! { <ToastHost /> });

    m.session
        .report_command_error(&fixtures::ui_error("unauthorized", "unauthorized (401)"));

    ts::wait_for(|| ts::query(".toast__action").is_some()).await;
    assert_eq!(ts::text(".toast__action"), "Refresh token");

    ts::click(".toast__action");
    ts::wait_for(|| ts::call_count("refresh_session") == 1).await;
    let call = ts::last_call("refresh_session").expect("refresh_session called");
    assert_eq!(
        call.arg_str("tenantId").as_deref(),
        Some("test-tenant"),
        "the refresh must target the active tenant",
    );
    ts::wait_for(|| ts::body_contains("Token refreshed")).await;
    assert_eq!(
        ts::call_count("reauthenticate"),
        0,
        "a successful silent refresh needs no interactive round trip",
    );
}

/// The 401 toast shares `Session::refresh_token_in_place` with the top bar, so
/// a refresh that finds the session dead falls back to ONE interactive
/// re-authentication in place — never a sign-out.
#[wasm_bindgen_test]
async fn unauthorized_refresh_falls_back_to_reauth_on_a_dead_session() {
    ts::reset();
    ts::mock_err(
        "refresh_session",
        &fixtures::ui_error("refresh_missing", "gone"),
    );
    ts::mock_ok(
        "reauthenticate",
        &SignInOutcome {
            tenant: ts::test_tenant(),
        },
    );
    let m = ts::mount_view(|| view! { <ToastHost /> });

    m.session
        .report_command_error(&fixtures::ui_error("unauthorized", "unauthorized (401)"));

    ts::wait_for(|| ts::query(".toast__action").is_some()).await;
    let before = m.session.readiness_reload.get_untracked();
    ts::click(".toast__action");
    ts::wait_for(|| ts::call_count("reauthenticate") == 1).await;
    assert_eq!(ts::call_count("refresh_session"), 1);
    assert_eq!(ts::call_count("sign_out"), 0, "never a sign-out");
    ts::wait_for(|| ts::body_contains("Re-authenticated")).await;
    assert_eq!(m.session.readiness_reload.get_untracked(), before + 1);
}

/// A Conditional Access step-up (`interaction_required` — MFA for one resource)
/// used to purge the whole session. It now offers "Verify identity", which runs
/// the scope-targeted step-up for the caller's feature — never a re-auth or a
/// sign-out.
#[wasm_bindgen_test]
async fn interaction_required_toast_runs_the_scope_step_up() {
    ts::reset();
    ts::mock_ok("request_scope_step_up", &());
    let m = ts::mount_view(|| view! { <ToastHost /> });

    m.session.report_command_error(&fixtures::ui_error(
        "interaction_required",
        "additional verification required for this resource (interaction_required (AADSTS50076))",
    ));

    ts::wait_for(|| ts::query(".toast__action").is_some()).await;
    assert_eq!(ts::text(".toast__action"), "Verify identity");
    assert!(ts::body_contains("verify your identity"));

    ts::click(".toast__action");
    ts::wait_for(|| ts::call_count("request_scope_step_up") == 1).await;
    let call = ts::last_call("request_scope_step_up").expect("request_scope_step_up called");
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    // The caller's declared feature crosses as-is; the backend
    // (`step_up_where_required`) steps up every Graph feature on the sign-in
    // read scopes, so the "write" default never shows a consent screen.
    assert_eq!(
        call.arg_str("feature").as_deref(),
        Some("write"),
        "the shared sink offers the caller's declared feature",
    );
    ts::wait_for(|| ts::body_contains("Verified")).await;
    assert_eq!(ts::call_count("reauthenticate"), 0);
    assert_eq!(ts::call_count("sign_out"), 0, "never a sign-out");
}

/// Surfaces that render their own error never reach the toast sink, so an
/// Azure / Log Analytics MFA policy used to print the raw AADSTS text with no
/// way forward. Observed Graph activity now offers "Verify identity & retry",
/// which steps up BOTH audiences its query acquires (Log Analytics, then ARM
/// for workspace discovery — the backend opens the browser only for the one
/// that needs it) and re-runs the query. Never a re-auth or a sign-out.
#[wasm_bindgen_test]
async fn an_inline_surface_offers_the_resource_step_up_and_retries() {
    ts::reset();
    ts::mock_err(
        "get_app_graph_usage",
        &fixtures::ui_error(
            "interaction_required",
            "additional verification required for this resource (interaction_required (AADSTS50076))",
        ),
    );
    let features = Rc::new(RefCell::new(Vec::<String>::new()));
    let seen = features.clone();
    ipc_mock::mock_each("request_scope_step_up", move |args| {
        seen.borrow_mut()
            .push(args["feature"].as_str().unwrap_or_default().to_string());
    });
    let detail = Arc::new(fixtures::application_detail("obj-1", "app-1", "Payroll"));
    let _m = ts::mount_view(move || {
        view! { <UsagePanel detail=Signal::derive(move || detail.clone()) /> }
    });

    ts::click_button_labelled("Check observed usage (90d)");
    ts::wait_for(|| ts::body_contains("Verify identity & retry")).await;
    assert!(ts::body_contains("verify your identity"));
    assert!(!ts::body_contains("AADSTS"), "our wording, not AAD's code");
    assert!(!ts::body_contains("Grant consent & retry"));

    ts::mock_ok(
        "get_app_graph_usage",
        &GraphUsageResult {
            app_id: "app-1".into(),
            days: 90,
            workspace_name: "law-prod".into(),
            rows: Vec::new(),
            truncated: false,
        },
    );
    ts::click_button_labelled("Verify identity & retry");
    ts::wait_for(|| ts::body_contains("law-prod")).await;

    assert_eq!(*features.borrow(), ["log_analytics", "arm"]);
    assert_eq!(
        ts::call_count("get_app_graph_usage"),
        2,
        "re-ran after verifying"
    );
    assert_eq!(ts::call_count("reauthenticate"), 0);
    assert_eq!(ts::call_count("sign_out"), 0, "never a sign-out");
}

/// A failed step-up keeps the surface and says why, instead of retrying.
#[wasm_bindgen_test]
async fn a_failed_inline_step_up_says_so_and_does_not_retry() {
    ts::reset();
    ts::mock_err(
        "get_app_graph_usage",
        &fixtures::ui_error("interaction_required", "verify"),
    );
    ts::mock_err(
        "request_scope_step_up",
        &fixtures::ui_error("cancelled", "the browser sign-in was closed"),
    );
    let detail = Arc::new(fixtures::application_detail("obj-1", "app-1", "Payroll"));
    let _m = ts::mount_view(move || {
        view! { <UsagePanel detail=Signal::derive(move || detail.clone()) /> }
    });

    ts::click_button_labelled("Check observed usage (90d)");
    ts::wait_for(|| ts::body_contains("Verify identity & retry")).await;
    ts::click_button_labelled("Verify identity & retry");
    ts::wait_for(|| ts::body_contains("Couldn't complete verification")).await;

    assert_eq!(
        ts::call_count("request_scope_step_up"),
        1,
        "stops at the first failure"
    );
    assert_eq!(
        ts::call_count("get_app_graph_usage"),
        1,
        "no retry without verification"
    );
}

/// A step-up on the Graph read scopes (tenant-wide MFA or sign-in frequency)
/// comes back from the silent refresh as `interaction_required`; the in-place
/// `reauthenticate` (`prompt=login` on exactly those scopes) is its step-up.
#[wasm_bindgen_test]
async fn a_refresh_needing_verification_falls_back_to_reauth() {
    ts::reset();
    ts::mock_err(
        "refresh_session",
        &fixtures::ui_error("interaction_required", "verify"),
    );
    ts::mock_ok(
        "reauthenticate",
        &SignInOutcome {
            tenant: ts::test_tenant(),
        },
    );
    let m = ts::mount_view(|| view! { <ToastHost /> });

    m.session
        .report_command_error(&fixtures::ui_error("unauthorized", "unauthorized (401)"));

    ts::wait_for(|| ts::query(".toast__action").is_some()).await;
    let before = m.session.readiness_reload.get_untracked();
    ts::click(".toast__action");
    ts::wait_for(|| ts::call_count("reauthenticate") == 1).await;
    assert_eq!(ts::call_count("refresh_session"), 1);
    assert_eq!(ts::call_count("sign_out"), 0, "never a sign-out");
    ts::wait_for(|| ts::body_contains("Re-authenticated")).await;
    assert_eq!(m.session.readiness_reload.get_untracked(), before + 1);
}

/// The in-flight guard lives on the session, not on a trigger: two 401 toasts
/// (e.g. from parallel loads) clicked together start ONE refresh — never two
/// racing `refresh_session` calls (or, on a dead session, two browser flows).
#[wasm_bindgen_test]
async fn concurrent_refresh_token_actions_start_one_refresh() {
    ts::reset();
    ts::mock_ok("refresh_session", &());
    let m = ts::mount_view(|| view! { <ToastHost /> });

    for _ in 0..2 {
        m.session
            .report_command_error(&fixtures::ui_error("unauthorized", "unauthorized (401)"));
    }
    ts::wait_for(|| ts::query_all(".toast__action").len() == 2).await;
    // Fire both toasts' actions, then the top bar's entry, in one synchronous
    // turn — before the first refresh's task runs. (Read from the session, not
    // the DOM: a click dismisses its toast and re-renders the stack, which
    // would detach the other button and make a second DOM click a no-op.)
    let actions: Vec<_> = m
        .session
        .toasts
        .with_untracked(|list| list.iter().filter_map(|t| t.action.clone()).collect());
    assert_eq!(actions.len(), 2);
    for action in actions {
        action();
    }
    m.session.spawn_refresh_token();
    ts::wait_for(|| ts::body_contains("Token refreshed")).await;
    assert_eq!(
        ts::call_count("refresh_session"),
        1,
        "a second trigger while a refresh is in flight must be a no-op",
    );
    // ...and the guard releases, so the next refresh is not locked out.
    ts::wait_for(|| !m.session.token_refreshing.get_untracked()).await;
    m.session.spawn_refresh_token();
    ts::wait_for(|| ts::call_count("refresh_session") == 2).await;
}
