//! GUI tests for the Credential-expiry dashboard — the shared `AuditDashboard`
//! scaffold's error → Retry recovery path (all three lenses ride this code).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::credentials_dashboard::CredentialsDashboard;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn loads_and_renders_rows() {
    ts::reset();
    ts::mock_ok(
        "list_credential_expirations",
        &fixtures::credential_expirations(),
    );

    let _m = ts::mount_view(|| view! { <CredentialsDashboard /> });

    ts::wait_for(|| ts::body_contains("Contoso CRM")).await;
    assert_eq!(
        ts::last_call("list_credential_expirations")
            .unwrap()
            .arg_str("tenantId")
            .as_deref(),
        Some("test-tenant")
    );
}

#[wasm_bindgen_test]
async fn retry_after_error_refetches() {
    ts::reset();
    ts::mock_err(
        "list_credential_expirations",
        &fixtures::ui_error("throttled", "Too many requests"),
    );

    let _m = ts::mount_view(|| view! { <CredentialsDashboard /> });
    // The error carries a load context, not just the raw backend message.
    ts::wait_for(|| ts::body_contains("Failed to load: Too many requests")).await;

    // The transient failure clears: Retry refetches in place (no remount).
    ts::mock_ok(
        "list_credential_expirations",
        &fixtures::credential_expirations(),
    );
    ts::click(".app-list__error button");

    ts::wait_for(|| ts::body_contains("Contoso CRM")).await;
    assert_eq!(ts::call_count("list_credential_expirations"), 2);
}
