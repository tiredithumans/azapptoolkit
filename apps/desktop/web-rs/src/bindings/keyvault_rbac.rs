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
