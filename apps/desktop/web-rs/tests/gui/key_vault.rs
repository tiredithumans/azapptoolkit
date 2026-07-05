//! GUI tests for the Key Vault secret browser. The list is demand-driven: type
//! a vault name and click List, which invokes `kv_list_secrets`.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

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
