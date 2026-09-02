//! Key Vault Azure-RBAC reverse-lookup IPC bindings. DTOs come from the shared
//! `azapptoolkit-dto` crate (re-exported here for callers). Cancellation reuses
//! `sharepoint::cancel_resource_sweep` (the backend shares one `sweep_cancel`).

use azapptoolkit_dto::UiError;
use tauri_sys::core::invoke_result;

use crate::bindings::TenantArg;
pub use azapptoolkit_dto::keyvault::{
    KeyVaultAccessRow, KeyVaultSweepProgress, KeyVaultSweepResult,
};

/// Runs the tenant-wide Key Vault RBAC sweep (long-running; progress arrives via
/// the `keyvault-sweep-progress` event stream — see `bindings::events`).
pub async fn sweep_key_vault_access(tenant_id: &str) -> Result<KeyVaultSweepResult, UiError> {
    invoke_result("sweep_key_vault_access", TenantArg { tenant_id }).await
}

/// The cached Key Vault sweep for this tenant, if one completed within the TTL.
pub async fn get_cached_key_vault_access(
    tenant_id: &str,
) -> Result<Option<KeyVaultSweepResult>, UiError> {
    invoke_result("get_cached_key_vault_access", TenantArg { tenant_id }).await
}

// ---------------- Vault-access export ----------------

/// The panel's own coverage sentence rides along with the rows: a vault whose
/// role read failed contributes none, so an export that dropped
/// "(N failed — coverage is partial)" would read as a complete answer.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveKeyVaultAccessArgs<'a> {
    rows: &'a [KeyVaultAccessRow],
    summary: &'a str,
    format: &'a str,
}

/// Exports the (filtered) vault-access rows to a CSV/JSON file via the OS save
/// dialog. Returns the chosen path, or `None` if the user cancelled.
pub async fn save_key_vault_access_to_file(
    rows: &[KeyVaultAccessRow],
    summary: &str,
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "save_key_vault_access_to_file",
        SaveKeyVaultAccessArgs {
            rows,
            summary,
            format,
        },
    )
    .await
}
