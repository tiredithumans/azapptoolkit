//! Shared Microsoft Graph app-role IPC bindings.

use azapptoolkit_dto::UiError;
use azapptoolkit_dto::managed_identity::AppRoleGrantDto;
use serde::Serialize;
use tauri_sys::core::invoke_result;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeldGrantsArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
}

/// Lists the application permissions a service principal **holds** (its granted
/// app-role assignments). One call for every service-principal type — enterprise
/// applications and managed identities alike.
pub async fn list_held_app_role_grants(
    tenant_id: &str,
    service_principal_id: &str,
) -> Result<Vec<AppRoleGrantDto>, UiError> {
    invoke_result(
        "list_held_app_role_grants",
        HeldGrantsArgs {
            tenant_id,
            service_principal_id,
        },
    )
    .await
}
