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

/// One Azure-RBAC role assignment that applies to a Key Vault — made on the
/// vault itself or inherited from its resource group / subscription /
/// management group (`inherited`) — the reverse-lookup's row unit (which
/// principal, which role, which vault). `principal_id` resolves to
/// `principal_display_name` for service principals (apps + managed
/// identities); users/groups carry only `principal_type` + the id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyVaultAccessRow {
    pub vault_id: String,
    pub vault_name: Option<String>,
    /// The ARM scope the assignment was made at (the vault path, or an
    /// ancestor's when `inherited`).
    pub scope: String,
    pub role_name: String,
    pub principal_id: String,
    /// `ServicePrincipal` / `User` / `Group` from ARM, when present.
    pub principal_type: Option<String>,
    /// Resolved display name — filled for service principals; `None` otherwise.
    pub principal_display_name: Option<String>,
    /// True for broadly-privileged roles (Owner, Key Vault Administrator, …).
    pub high_privilege: bool,
    /// True when the assignment was made at an ancestor scope (resource group,
    /// subscription, management group, root), not on the vault itself.
    #[serde(default)]
    pub inherited: bool,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct KvSecretValueDto {
    pub name: String,
    pub value: String,
    pub content_type: Option<String>,
    pub expires: Option<String>,
}
// Hand-written rather than derived: a derived `Debug` on a secret is a defect
// in this workspace — any `?dto` in a `tracing` macro puts the plaintext
// straight into the daily rolling log file. Mirrors
// `dto::backup::RegeneratedSecret`, `core::models::PasswordCredential`,
// `auth::AccessToken`, `keyvault::SecretValue` and `cert::GeneratedCert`.
impl std::fmt::Debug for KvSecretValueDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvSecretValueDto")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("content_type", &self.content_type)
            .field("expires", &self.expires)
            .finish()
    }
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
    /// Application (client) id — used to remember the vault binding per app so a
    /// later rotation pre-selects the same vault. Optional for wire-compat.
    #[serde(default)]
    pub app_id: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A derived `Debug` on a secret-bearing DTO is a defect in this workspace:
    /// any `?dto` in a `tracing` macro puts the plaintext straight into the
    /// daily rolling log file. Pinned rather than left to convention (that is
    /// what let four of these opt out).
    #[test]
    fn secret_bearing_dtos_redact_their_secret_in_debug() {
        let read = KvSecretValueDto {
            name: "app-secret".into(),
            value: "s3cr3t-value".into(),
            content_type: None,
            expires: None,
        };
        let dbg = format!("{read:?}");
        assert!(!dbg.contains("s3cr3t-value"), "{dbg}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
        // Non-secret fields stay useful for diagnosis.
        assert!(dbg.contains("app-secret"), "{dbg}");
    }
}
