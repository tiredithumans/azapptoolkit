//! GUI tests for the readiness checklist. Auto-loads on mount (tenant preset by
//! the harness), so the load + render assertions need no interaction.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

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
