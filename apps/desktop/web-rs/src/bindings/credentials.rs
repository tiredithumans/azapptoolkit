//! Credential-expiry dashboard IPC bindings.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

use crate::bindings::TenantArg;
pub use azapptoolkit_dto::credentials::CredentialRowDto;

/// Lists every app-registration credential in the tenant, soonest-to-expire
/// first. Always fetched fresh (no cache) so a just-rotated credential isn't
/// shown as still-expiring.
pub async fn list_credential_expirations(
    tenant_id: &str,
) -> Result<Vec<CredentialRowDto>, UiError> {
    invoke_result("list_credential_expirations", TenantArg { tenant_id }).await
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
