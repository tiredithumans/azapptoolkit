//! Key Vault IPC DTOs.

use serde::{Deserialize, Serialize};

/// Progress for the Key Vault RBAC reverse-lookup sweep — one tick per vault
/// scanned. Mirrors `SiteSweepProgress`; camelCase for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyVaultSweepProgress {
    pub done: usize,
    pub total: usize,
    pub current_vault: Option<String>,
    pub cancelled: bool,
}

/// One direct Azure-RBAC role assignment on a Key Vault — the reverse-lookup's
/// row unit ("which principal holds which role on which vault"). `principal_id`
/// resolves to `principal_display_name` for service principals (apps + managed
/// identities); users/groups carry only `principal_type` + the id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyVaultAccessRow {
    pub vault_id: String,
    pub vault_name: Option<String>,
    /// The ARM scope the assignment sits at (the vault resource path).
    pub scope: String,
    pub role_name: String,
    pub principal_id: String,
    /// `ServicePrincipal` / `User` / `Group` from ARM, when present.
    pub principal_type: Option<String>,
    /// Resolved display name — filled for service principals; `None` otherwise.
    pub principal_display_name: Option<String>,
    /// True for broadly-privileged roles (Owner, Key Vault Administrator, …).
    pub high_privilege: bool,
}

/// Result of a tenant-wide Key Vault RBAC sweep, with coverage so the UI can
/// warn when a scan was partial — a vault with "no rows" that actually failed
/// to read must never read as "no access".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyVaultSweepResult {
    pub tenant_id: String,
    pub total_vaults: usize,
    pub vaults_scanned: usize,
    pub vaults_failed: usize,
    pub rows: Vec<KeyVaultAccessRow>,
    pub cancelled: bool,
}

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
