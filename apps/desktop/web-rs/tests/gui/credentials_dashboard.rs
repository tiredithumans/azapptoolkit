//! GUI tests for the Credential-expiry dashboard — the shared `AuditDashboard`
//! scaffold's error → Retry recovery path (all three lenses ride this code).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::credentials_dashboard::CredentialsDashboard;

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
    // This lens now renders its load failure via the shared `DetailLoadError`
    // (raw `UiError` message + the muted error code, no "Failed to load:"
    // prefix) — the same grammar the Managed Identities list already asserts.
    // The code is what carries the context the bespoke prefix used to.
    ts::wait_for(|| ts::body_contains("Too many requests")).await;
    assert!(
        ts::body_contains("[throttled]"),
        "the error code should be surfaced alongside the message"
    );

    // The transient failure clears: Retry refetches in place (no remount).
    ts::mock_ok(
        "list_credential_expirations",
        &fixtures::credential_expirations(),
    );
    ts::click(".app-list__error button");

    ts::wait_for(|| ts::body_contains("Contoso CRM")).await;
    assert_eq!(ts::call_count("list_credential_expirations"), 2);
}
