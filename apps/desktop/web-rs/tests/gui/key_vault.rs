//! GUI tests for the Key Vault secret browser. The list is demand-driven: type
//! a vault name and click List, which invokes `kv_list_secrets`.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::state::ActiveView;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::key_vault_view::KeyVaultView;

const VAULT_INPUT: &str = "input[placeholder=\"myvault\"]";
const LIST_BTN: &str = ".row button";

#[wasm_bindgen_test]
async fn lists_secrets_for_named_vault() {
    ts::reset();
    ts::mock_ok(
        "kv_list_secrets",
        &fixtures::kv_secrets(&["db-password", "api-key"]),
    );

    let _m = ts::mount_view(|| view! { <KeyVaultView /> });
    ts::tick().await;

    ts::set_input_value(VAULT_INPUT, "myvault");
    ts::click(LIST_BTN);

    ts::wait_for(|| ts::call_count("kv_list_secrets") >= 1).await;
    let call = ts::last_call("kv_list_secrets").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert_eq!(call.arg_str("vaultName").as_deref(), Some("myvault"));

    ts::wait_for(|| ts::body_contains("db-password")).await;
}

#[wasm_bindgen_test]
async fn empty_vault_renders_empty_state() {
    ts::reset();
    ts::mock_ok(
        "kv_list_secrets",
        &Vec::<azapptoolkit_dto::keyvault::KvSecretItemDto>::new(),
    );

    let _m = ts::mount_view(|| view! { <KeyVaultView /> });
    ts::tick().await;

    ts::set_input_value(VAULT_INPUT, "myvault");
    ts::click(LIST_BTN);

    ts::wait_for(|| ts::body_contains("No secrets")).await;
}

#[wasm_bindgen_test]
async fn list_error_renders_message() {
    ts::reset();
    ts::mock_err(
        "kv_list_secrets",
        &fixtures::ui_error("forbidden", "Caller lacks Key Vault Secrets User"),
    );

    let _m = ts::mount_view(|| view! { <KeyVaultView /> });
    ts::tick().await;

    ts::set_input_value(VAULT_INPUT, "myvault");
    ts::click(LIST_BTN);

    ts::wait_for(|| ts::body_contains("Caller lacks Key Vault Secrets User")).await;
}

/// A dead session used to render its raw message inline with no way forward;
/// it now raises the Re-authenticate notification instead (the DR view's shape:
/// the recovery lever replaces the dead-end line).
#[wasm_bindgen_test]
async fn a_dead_session_list_error_offers_reauthenticate() {
    ts::reset();
    ts::mock_err(
        "kv_list_secrets",
        &fixtures::ui_error("refresh_missing", "session expired"),
    );

    let m = ts::mount_view(|| view! { <KeyVaultView /> });
    ts::tick().await;

    ts::set_input_value(VAULT_INPUT, "myvault");
    ts::click(LIST_BTN);

    ts::wait_for(|| {
        m.session.toasts.with_untracked(|list| {
            list.iter()
                .any(|t| t.action_label.as_deref() == Some("Re-authenticate"))
        })
    })
    .await;
    assert!(
        !ts::body_contains("session expired"),
        "the lever replaces the dead-end inline text"
    );
}

#[wasm_bindgen_test]
async fn tenant_switch_clears_listed_secrets_and_vault_name() {
    // The view stays mounted across a tenant switch (keep-alive), so tenant A's
    // listing and vault name must not survive into tenant B's Key Vault page.
    ts::reset();
    ts::mock_ok("kv_list_secrets", &fixtures::kv_secrets(&["db-password"]));

    let m = ts::mount_view(|| view! { <KeyVaultView /> });
    ts::tick().await;

    ts::set_input_value(VAULT_INPUT, "myvault");
    ts::click(LIST_BTN);
    ts::wait_for(|| ts::body_contains("db-password")).await;

    let mut other = ts::test_tenant();
    other.tenant_id = "other-tenant".into();
    m.session.set_active_tenant(Some(other));
    ts::tick().await;

    assert!(!ts::body_contains("db-password"), "listing must be wiped");
    let input: web_sys::HtmlInputElement = ts::query(VAULT_INPUT)
        .expect("vault input")
        .dyn_into()
        .expect("input element");
    assert_eq!(input.value(), "", "vault name must be wiped");
    assert!(
        ts::body_contains("Enter a vault name"),
        "back to the pre-load state"
    );
}

/// Lists `db-password`, reveals it, and waits for the value on screen. The
/// session is put on the Key Vault view first: the wipe fires when the view
/// CHANGES away from it.
async fn reveal_db_password() -> ts::Mounted {
    ts::reset();
    ts::mock_ok("kv_list_secrets", &fixtures::kv_secrets(&["db-password"]));
    ts::mock_ok(
        "kv_get_secret",
        &fixtures::kv_secret_value("db-password", "s3cr3t-value"),
    );

    let m = ts::mount_view(|| view! { <KeyVaultView /> });
    m.session.set_view(ActiveView::KeyVault);
    ts::tick().await;

    ts::set_input_value(VAULT_INPUT, "myvault");
    ts::click(LIST_BTN);
    ts::wait_for(|| ts::body_contains("db-password")).await;

    ts::click("td.cell-mid button");
    ts::wait_for(|| ts::body_contains("s3cr3t-value")).await;
    m
}

/// The module's security promise: the page stays mounted (keep-alive), yet a
/// revealed secret exists only while the page is on screen.
#[wasm_bindgen_test]
async fn reveal_is_wiped_when_the_view_changes() {
    let m = reveal_db_password().await;

    m.session.set_view(ActiveView::Home);
    ts::tick().await;
    assert!(
        !ts::body_contains("s3cr3t-value"),
        "the revealed value must be wiped when the view leaves Key Vault"
    );
    // `CopyableId` also carries the value in a `title` attribute.
    assert!(ts::query("[title=\"s3cr3t-value\"]").is_none());

    // Coming back does not bring it back; the (non-secret) listing survives.
    m.session.set_view(ActiveView::KeyVault);
    ts::tick().await;
    assert!(!ts::body_contains("s3cr3t-value"));
    assert!(ts::query("[title=\"s3cr3t-value\"]").is_none());
    assert!(ts::body_contains("db-password"), "only the secret is wiped");
}

#[wasm_bindgen_test]
async fn hide_puts_a_revealed_secret_away() {
    let _m = reveal_db_password().await;
    let hide = ts::query_all("button")
        .into_iter()
        .find(|el| el.text_content().unwrap_or_default().trim() == "Hide")
        .expect("Hide button");
    hide.unchecked_into::<web_sys::HtmlElement>().click();
    ts::tick().await;
    assert!(!ts::body_contains("s3cr3t-value"));
    assert!(ts::query("[title=\"s3cr3t-value\"]").is_none());
}
