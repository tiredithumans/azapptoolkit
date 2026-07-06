//! Azure Key Vault IPC bindings: list / get / set secrets. DTOs come from the
//! shared `azapptoolkit-dto` crate (re-exported here for callers).

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::keyvault::{
    KvSecretItemDto, KvSecretMetadataDto, KvSecretValueDto, KvSetSecretInput,
    RotateCredentialInput, RotateCredentialResult,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListArgs<'a> {
    tenant_id: &'a str,
    vault_name: &'a str,
}

pub async fn kv_list_secrets(
    tenant_id: &str,
    vault_name: &str,
) -> Result<Vec<KvSecretItemDto>, UiError> {
    invoke_result(
        "kv_list_secrets",
        ListArgs {
            tenant_id,
            vault_name,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetArgs<'a> {
    tenant_id: &'a str,
    vault_name: &'a str,
    secret_name: &'a str,
}

pub async fn kv_get_secret(
    tenant_id: &str,
    vault_name: &str,
    secret_name: &str,
) -> Result<KvSecretValueDto, UiError> {
    invoke_result(
        "kv_get_secret",
        GetArgs {
            tenant_id,
            vault_name,
            secret_name,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetArgs<'a> {
    tenant_id: &'a str,
    input: &'a KvSetSecretInput,
}

pub async fn kv_set_secret(
    tenant_id: &str,
    input: &KvSetSecretInput,
) -> Result<KvSecretMetadataDto, UiError> {
    invoke_result("kv_set_secret", SetArgs { tenant_id, input }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotateArgs<'a> {
    tenant_id: &'a str,
    input: &'a RotateCredentialInput,
}

pub async fn rotate_app_credential(
    tenant_id: &str,
    input: &RotateCredentialInput,
) -> Result<RotateCredentialResult, UiError> {
    invoke_result("rotate_app_credential", RotateArgs { tenant_id, input }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantArgs<'a> {
    tenant_id: &'a str,
}

/// Names of Key Vaults the signed-in user can see (ARM discovery), for the vault
/// picker. Returns an error when ARM consent is missing — callers degrade to
/// free-text entry.
pub async fn list_available_key_vaults(tenant_id: &str) -> Result<Vec<String>, UiError> {
    invoke_result("list_available_key_vaults", TenantArgs { tenant_id }).await
}
