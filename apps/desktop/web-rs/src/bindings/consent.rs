//! Consent / OAuth2 permission-grant audit IPC bindings.

use super::ipc::invoke_result;
use azapptoolkit_dto::UiError;
use serde::Serialize;

use crate::bindings::TenantArg;
pub use azapptoolkit_dto::consent::{
    AppPermissionGrantDto, OAuth2GrantDto, TenantConsentPostureDto,
};

/// Lists every delegated permission grant in the tenant, risk-classified and
/// sorted risky-first. Always fetched fresh.
pub async fn list_oauth2_grants_audit(tenant_id: &str) -> Result<Vec<OAuth2GrantDto>, UiError> {
    invoke_result("list_oauth2_grants_audit", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveArgs<'a> {
    rows: &'a [OAuth2GrantDto],
    format: &'a str,
}

/// Opens an OS save dialog and writes the grant list as CSV. Returns the chosen
/// path on success, `None` if the user cancelled.
pub async fn save_oauth2_grants_to_file(
    rows: &[OAuth2GrantDto],
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result("save_oauth2_grants_to_file", SaveArgs { rows, format }).await
}

/// Lists every application permission held tenant-wide on the high-value
/// resource APIs (Microsoft Graph, Exchange, SharePoint), risk-classified.
pub async fn list_app_permission_grants(
    tenant_id: &str,
) -> Result<Vec<AppPermissionGrantDto>, UiError> {
    invoke_result("list_app_permission_grants", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveAppPermsArgs<'a> {
    rows: &'a [AppPermissionGrantDto],
    format: &'a str,
}

pub async fn save_app_permission_grants_to_file(
    rows: &[AppPermissionGrantDto],
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "save_app_permission_grants_to_file",
        SaveAppPermsArgs { rows, format },
    )
    .await
}

/// Reads the tenant consent-setting posture (user self-consent policies, risky
/// app consent, admin consent workflow). Best-effort: the backend always
/// answers, with `available: false` when the policy pair could not be read —
/// unknown renders nothing.
pub async fn get_tenant_consent_posture(
    tenant_id: &str,
) -> Result<TenantConsentPostureDto, UiError> {
    invoke_result("get_tenant_consent_posture", TenantArg { tenant_id }).await
}
