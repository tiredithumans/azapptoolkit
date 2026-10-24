//! GUI tests for the Activity and Conditional Access tabs' failure levers.
//!
//! Both read a premium Graph surface on an on-demand token the backend
//! pre-acquires, so a missing consent arrives typed as `consent_required` and
//! must turn into a "Grant consent & retry" round trip for the tab's own
//! feature (`audit_log` / `policy`), a dead session must raise the session's
//! Re-authenticate lever, a step-up must offer "Verify identity & retry", and
//! only the backend's `*_unavailable` notice (license / role) stays a plain
//! message. The sign-in summary above the change log reads on the same token
//! and holds no lever of its own, so each lever appears once. Mounts the
//! shared panels directly, like `provisioning_tab` mounts its content.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::activity::SignInActivityDto;
use azapptoolkit_dto::conditional_access::ConditionalAccessPolicyDto;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::activity_tab::ActivityPanel;
use azapptoolkit_web_rs::views::tabs::conditional_access_tab::ConditionalAccessPanel;

const GRANT: &str = "Grant consent & retry";
const VERIFY: &str = "Verify identity & retry";

fn mount_ca() -> ts::Mounted {
    ts::mount_view(|| {
        view! { <ConditionalAccessPanel app_id=Signal::derive(|| "app-1".to_string()) /> }
    })
}

fn mount_activity() -> ts::Mounted {
    ts::mount_view(|| {
        view! {
            <ActivityPanel
                app_id=Signal::derive(|| "app-1".to_string())
                primary_id=Signal::derive(|| "obj-1".to_string())
                secondary_id=Signal::derive(|| Some("sp-1".to_string()))
            />
        }
    })
}

/// The sign-in summary above the change log, answered "available, no sign-in".
fn mock_sign_in_ok() {
    ts::mock_ok(
        "get_app_sign_in_activity",
        &SignInActivityDto {
            available: true,
            consent_required: false,
            last_sign_in_date_time: None,
            message: None,
        },
    );
}

/// How many buttons carry exactly `label` — the tab must offer each lever once.
fn buttons_labelled(label: &str) -> usize {
    ts::query_all("button")
        .into_iter()
        .filter(|b| b.text_content().unwrap_or_default().trim() == label)
        .count()
}

/// Every toast's action label, in order.
fn toast_actions(m: &ts::Mounted) -> Vec<Option<String>> {
    m.session
        .toasts
        .with_untracked(|l| l.iter().map(|t| t.action_label.clone()).collect())
}

#[wasm_bindgen_test]
async fn the_ca_tab_grants_the_policy_consent_and_reloads() {
    ts::reset();
    ts::mock_err(
        "list_conditional_access_for_app",
        &fixtures::ui_error("consent_required", "consent required (AADSTS65001)"),
    );
    let _m = mount_ca();

    ts::wait_for(|| ts::has_button_labelled(GRANT)).await;
    assert!(ts::body_contains("Policy.Read.All"));
    // Our wording, not the AADSTS text.
    assert!(!ts::body_contains("AADSTS65001"));

    ts::mock_ok("request_scope_consent", &());
    ts::mock_ok(
        "list_conditional_access_for_app",
        &Vec::<ConditionalAccessPolicyDto>::new(),
    );
    ts::click_button_labelled(GRANT);
    ts::wait_for(|| ts::call_count("request_scope_consent") == 1).await;
    assert_eq!(
        ts::last_call("request_scope_consent")
            .unwrap()
            .arg_str("feature")
            .as_deref(),
        Some("policy")
    );
    ts::wait_for(|| ts::body_contains("No Conditional Access policies target this app.")).await;
    assert_eq!(ts::call_count("list_conditional_access_for_app"), 2);
}

#[wasm_bindgen_test]
async fn a_ca_role_gap_is_a_notice_without_a_grant_button() {
    ts::reset();
    ts::mock_err(
        "list_conditional_access_for_app",
        &fixtures::ui_error(
            "ca_unavailable",
            "Microsoft Graph refused Conditional Access for your account. Conditional Access \
             visibility needs the Policy.Read.All scope and a role that can read policies \
             (Security Reader or Global Reader), plus an Entra ID P1/P2 license.",
        ),
    );
    let _m = mount_ca();

    ts::wait_for(|| ts::body_contains("Microsoft Graph refused Conditional Access")).await;
    assert!(ts::body_contains("Security Reader"));
    assert!(!ts::has_button_labelled(GRANT));
    assert!(!ts::has_button_labelled(VERIFY));
}

#[wasm_bindgen_test]
async fn a_ca_step_up_offers_verify_identity() {
    ts::reset();
    ts::mock_err(
        "list_conditional_access_for_app",
        &fixtures::ui_error(
            "interaction_required",
            "additional verification required for this resource (AADSTS50076)",
        ),
    );
    let _m = mount_ca();

    ts::wait_for(|| ts::has_button_labelled(VERIFY)).await;
    assert!(!ts::body_contains("AADSTS50076"));

    ts::mock_ok("request_scope_step_up", &());
    ts::mock_ok(
        "list_conditional_access_for_app",
        &Vec::<ConditionalAccessPolicyDto>::new(),
    );
    ts::click_button_labelled(VERIFY);
    ts::wait_for(|| ts::call_count("request_scope_step_up") == 1).await;
    assert_eq!(
        ts::last_call("request_scope_step_up")
            .unwrap()
            .arg_str("feature")
            .as_deref(),
        Some("policy")
    );
    ts::wait_for(|| ts::body_contains("No Conditional Access policies target this app.")).await;
}

/// A token endpoint that stayed busy (B1's `service_unavailable`) is not
/// Entra's verdict on the tenant: the tab shows the sign-in card's shared hint
/// and keeps Retry, never a consent or license claim.
#[wasm_bindgen_test]
async fn a_busy_token_endpoint_reads_the_shared_hint_and_keeps_retry() {
    ts::reset();
    ts::mock_err(
        "list_conditional_access_for_app",
        &fixtures::ui_error(
            "service_unavailable",
            "the sign-in service is throttling or temporarily unavailable (HTTP 503: x)",
        ),
    );
    let _m = mount_ca();

    ts::wait_for(|| ts::body_contains("busy or unavailable — wait a minute, then retry.")).await;
    assert!(ts::has_button_labelled("Retry"));
    assert!(!ts::has_button_labelled(GRANT));
}

#[wasm_bindgen_test]
async fn a_dead_session_on_the_activity_tab_raises_reauthenticate() {
    ts::reset();
    // Both halves read on the one token, so both fail.
    ts::mock_err(
        "get_app_sign_in_activity",
        &fixtures::ui_error("refresh_missing", "refresh token missing"),
    );
    ts::mock_err(
        "list_directory_audits_for_app",
        &fixtures::ui_error("refresh_missing", "refresh token missing"),
    );
    let m = mount_activity();

    // The session's lever, not "needs admin consent" …
    ts::wait_until("the Re-authenticate toast", || {
        toast_actions(&m).contains(&Some("Re-authenticate".to_string()))
    })
    .await;
    // … and the change log keeps its Retry — once: the summary only names the
    // cause — with no grant button.
    ts::wait_for(|| ts::body_contains("until your session is renewed")).await;
    ts::wait_for(|| ts::has_button_labelled("Retry")).await;
    assert_eq!(buttons_labelled("Retry"), 1);
    assert!(!ts::has_button_labelled(GRANT));
}

#[wasm_bindgen_test]
async fn the_activity_tab_grants_the_audit_log_consent_and_reloads() {
    ts::reset();
    // Both halves lack the consent: the summary's DTO says so, the change log
    // fails typed.
    ts::mock_ok(
        "get_app_sign_in_activity",
        &SignInActivityDto {
            available: false,
            consent_required: true,
            last_sign_in_date_time: None,
            message: Some("Sign-in activity needs admin consent for AuditLog.Read.All.".into()),
        },
    );
    ts::mock_err(
        "list_directory_audits_for_app",
        &fixtures::ui_error("consent_required", "consent required (AADSTS65001)"),
    );
    let m = mount_activity();

    ts::wait_for(|| ts::has_button_labelled(GRANT)).await;
    ts::wait_for(|| ts::body_contains("Needs AuditLog.Read.All consent — grant it below.")).await;
    // One lever for the one missing consent, on the change log.
    assert_eq!(buttons_labelled(GRANT), 1);
    // A consent gap has its own button; the sink adds no second lever.
    assert!(
        toast_actions(&m).iter().flatten().next().is_none(),
        "{:?}",
        toast_actions(&m)
    );

    ts::mock_ok("request_scope_consent", &());
    mock_sign_in_ok();
    ts::mock_ok(
        "list_directory_audits_for_app",
        &Vec::<serde_json::Value>::new(),
    );
    ts::click_button_labelled(GRANT);
    ts::wait_for(|| ts::call_count("request_scope_consent") == 1).await;
    assert_eq!(
        ts::last_call("request_scope_consent")
            .unwrap()
            .arg_str("feature")
            .as_deref(),
        Some("audit_log")
    );
    // The shared reload re-runs both halves.
    ts::wait_for(|| ts::body_contains("No recent changes recorded in the audit window.")).await;
    ts::wait_for(|| ts::body_contains("No sign-in recorded in the reporting window.")).await;
    assert_eq!(ts::call_count("get_app_sign_in_activity"), 2);
}
