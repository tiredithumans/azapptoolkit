//! Managed-identity IPC bindings: discover managed identities and grant/list
//! their application permissions. DTOs come from the shared `azapptoolkit-dto`
//! crate (re-exported here for callers).

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::managed_identity::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantArgs<'a> {
    tenant_id: &'a str,
}

pub async fn list_managed_identities(tenant_id: &str) -> Result<Vec<ManagedIdentityDto>, UiError> {
    invoke_result("list_managed_identities", TenantArgs { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantArgs<'a> {
    tenant_id: &'a str,
    managed_identity_id: &'a str,
    resource_app_id: &'a str,
    roles: &'a [String],
}

pub async fn grant_managed_identity_permission(
    tenant_id: &str,
    managed_identity_id: &str,
    resource_app_id: &str,
    roles: &[String],
) -> Result<GrantManagedIdentityResult, UiError> {
    invoke_result(
        "grant_managed_identity_permission",
        GrantArgs {
            tenant_id,
            managed_identity_id,
            resource_app_id,
            roles,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AzureRolesArgs<'a> {
    tenant_id: &'a str,
    principal_id: &'a str,
}

/// Azure RBAC role assignments held by a managed identity (via ARM). Best
/// effort: an error means ARM consent/licensing is unavailable.
pub async fn list_managed_identity_azure_roles(
    tenant_id: &str,
    principal_id: &str,
) -> Result<AzureRolesResult, UiError> {
    invoke_result(
        "list_managed_identity_azure_roles",
        AzureRolesArgs {
            tenant_id,
            principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignAzureRoleArgs<'a> {
    tenant_id: &'a str,
    scope: &'a str,
    role_definition_id: &'a str,
    principal_id: &'a str,
}

/// Creates an Azure RBAC role assignment for a managed identity at `scope` (a
/// `/subscriptions/{id}/…` path); `role_definition_id` is a built-in/custom role
/// GUID. Requires Owner or User Access Administrator on the scope; a
/// missing-consent or 403 surfaces as a typed error the caller renders.
pub async fn assign_managed_identity_azure_role(
    tenant_id: &str,
    scope: &str,
    role_definition_id: &str,
    principal_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "assign_managed_identity_azure_role",
        AssignAzureRoleArgs {
            tenant_id,
            scope,
            role_definition_id,
            principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveManagedIdentitiesArgs<'a> {
    rows: &'a [ManagedIdentityDto],
    format: &'a str,
}

/// Exports the (filtered) managed-identity list to a CSV/JSON file via the OS
/// save dialog. Returns the chosen path, or `None` if the user cancelled.
pub async fn save_managed_identities_to_file(
    rows: &[ManagedIdentityDto],
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "save_managed_identities_to_file",
        SaveManagedIdentitiesArgs { rows, format },
    )
    .await
}
