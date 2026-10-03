//! Credential-expiry dashboard IPC bindings.

use super::ipc::invoke_result;
use azapptoolkit_dto::UiError;
use serde::Serialize;

use crate::bindings::TenantArg;
pub use azapptoolkit_dto::credentials::{CredentialRowDto, CredentialUsageDto};

/// Lists every app-registration credential in the tenant, soonest-to-expire
/// first. The backend reads it through its `{tenant}|credential_expirations`
/// cache (`CacheKind::Lists`), which `invalidate_app_credentials`
/// (rotate/remove) and `invalidate_app_lists` (create/delete) clear on `Ok`, so
/// a just-rotated credential is never shown as still-expiring.
pub async fn list_credential_expirations(
    tenant_id: &str,
) -> Result<Vec<CredentialRowDto>, UiError> {
    invoke_result("list_credential_expirations", TenantArg { tenant_id }).await
}

/// Tenant-wide per-credential last-used map from the beta
/// `appCredentialSignInActivities` report (**Global cloud only**), read-through
/// cached in the backend (`{tenant}|app_credential_sign_in_activities` under
/// `CacheKind::Permissions`). Join rows client-side on `(app_id, key_id)`:
/// an absent row is *unknown*, never "unused", and `available = false` means
/// the report was unreadable (no `AuditLog.Read.All`, a sovereign cloud, or a
/// failed read) — the command never fails on those, it degrades.
pub async fn list_credential_usage(tenant_id: &str) -> Result<CredentialUsageDto, UiError> {
    invoke_result("list_credential_usage", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveArgs<'a> {
    rows: &'a [CredentialRowDto],
    format: &'a str,
}

/// Opens an OS save dialog and writes the credential list in `format` (`csv`).
/// Returns the chosen path on success, `None` if the user cancelled.
pub async fn save_credentials_to_file(
    rows: &[CredentialRowDto],
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result("save_credentials_to_file", SaveArgs { rows, format }).await
}
