//! Key Vault IPC DTOs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvSecretItemDto {
    pub name: String,
    pub id: String,
    pub enabled: Option<bool>,
    pub expires: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvSecretValueDto {
    pub name: String,
    pub value: String,
    pub content_type: Option<String>,
    pub expires: Option<String>,
}

/// Returned by `kv_set_secret` — metadata only, never the secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvSecretMetadataDto {
    pub name: String,
    pub content_type: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvSetSecretInput {
    pub vault_name: String,
    pub secret_name: String,
    pub value: String,
    pub content_type: Option<String>,
    /// RFC3339 timestamp.
    pub expires: Option<String>,
}

/// Input for rotating an application's client secret into Key Vault: mint a
/// fresh app secret, store it as a new version of the named vault secret, then
/// optionally remove the previous credential(s). An empty `remove_key_ids` is
/// the "overlap" strategy (old secrets kept); passing the current key ids is
/// the "immediate" strategy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateCredentialInput {
    /// Application object id whose secret is being rotated.
    pub object_id: String,
    pub vault_name: String,
    pub secret_name: String,
    /// Validity of the new app secret in days (default 180, clamped 1..=730).
    pub lifetime_days: Option<u32>,
    /// Previous password-credential key ids to remove after a successful store.
    pub remove_key_ids: Vec<String>,
}

/// Result of `rotate_app_credential`. The secret value is never returned — it
/// lives only in Key Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateCredentialResult {
    pub new_key_id: String,
    pub vault_name: String,
    pub secret_name: String,
    pub expires: Option<String>,
    pub removed_key_ids: Vec<String>,
    pub warnings: Vec<String>,
}
