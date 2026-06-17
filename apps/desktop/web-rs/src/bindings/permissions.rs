//! Permissions catalog & admin-consent IPC bindings.

use azapptoolkit_core::models::RequiredResourceAccess;
use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::permissions::*;

pub async fn list_catalog_resources() -> Result<Vec<CatalogResourceSummary>, UiError> {
    invoke_result("list_catalog_resources", ()).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantArg<'a> {
    tenant_id: &'a str,
}

/// Live permission counts per resource, used to enrich the dropdown labels.
pub async fn list_resource_permission_counts(
    tenant_id: &str,
) -> Result<Vec<CatalogResourceSummary>, UiError> {
    invoke_result("list_resource_permission_counts", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceArgs<'a> {
    tenant_id: &'a str,
    resource_app_id: &'a str,
}

pub async fn list_resource_permissions(
    tenant_id: &str,
    resource_app_id: &str,
) -> Result<ResourcePermissions, UiError> {
    invoke_result(
        "list_resource_permissions",
        ResourceArgs {
            tenant_id,
            resource_app_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateRequiredResourceArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    required_resource_access: &'a [RequiredResourceAccess],
}

pub async fn update_required_resource_access(
    tenant_id: &str,
    object_id: &str,
    required_resource_access: &[RequiredResourceAccess],
) -> Result<(), UiError> {
    invoke_result(
        "update_required_resource_access",
        UpdateRequiredResourceArgs {
            tenant_id,
            object_id,
            required_resource_access,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantConsentArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
}

pub async fn grant_admin_consent(tenant_id: &str, object_id: &str) -> Result<GrantResult, UiError> {
    invoke_result(
        "grant_admin_consent",
        GrantConsentArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantSinglePermissionArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    resource_app_id: &'a str,
    permission_id: &'a str,
    kind: PermissionKind,
}

pub async fn grant_single_permission(
    tenant_id: &str,
    object_id: &str,
    resource_app_id: &str,
    permission_id: &str,
    kind: PermissionKind,
) -> Result<GrantResult, UiError> {
    invoke_result(
        "grant_single_permission",
        GrantSinglePermissionArgs {
            tenant_id,
            object_id,
            resource_app_id,
            permission_id,
            kind,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DowngradePermissionArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    resource_app_id: &'a str,
    broad_value: &'a str,
    narrow_value: &'a str,
}

/// Swaps a broad application permission for a documented narrower alternative
/// (grant-narrow-before-strip-broad). Admin-judged: the caller is responsible
/// for confirming the broader capability is genuinely unused.
pub async fn downgrade_application_permission(
    tenant_id: &str,
    object_id: &str,
    resource_app_id: &str,
    broad_value: &str,
    narrow_value: &str,
) -> Result<DowngradeOutcome, UiError> {
    invoke_result(
        "downgrade_application_permission",
        DowngradePermissionArgs {
            tenant_id,
            object_id,
            resource_app_id,
            broad_value,
            narrow_value,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveDeclaredPermissionArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    resource_app_id: &'a str,
    permission_id: &'a str,
    kind: PermissionKind,
}

/// Removes a single declared permission from the app's `requiredResourceAccess`
/// manifest. Used for not-granted (declared-only) rows, where there is no
/// runtime grant to revoke.
pub async fn remove_declared_permission(
    tenant_id: &str,
    object_id: &str,
    resource_app_id: &str,
    permission_id: &str,
    kind: PermissionKind,
) -> Result<(), UiError> {
    invoke_result(
        "remove_declared_permission",
        RemoveDeclaredPermissionArgs {
            tenant_id,
            object_id,
            resource_app_id,
            permission_id,
            kind,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeAppRoleArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    assignment_id: &'a str,
}

pub async fn revoke_app_role_assignment(
    tenant_id: &str,
    service_principal_id: &str,
    assignment_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "revoke_app_role_assignment",
        RevokeAppRoleArgs {
            tenant_id,
            service_principal_id,
            assignment_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeOauth2ScopeArgs<'a> {
    tenant_id: &'a str,
    grant_id: &'a str,
    scope_value: &'a str,
}

pub async fn revoke_oauth2_scope(
    tenant_id: &str,
    grant_id: &str,
    scope_value: &str,
) -> Result<RevokeScopeOutcome, UiError> {
    invoke_result(
        "revoke_oauth2_scope",
        RevokeOauth2ScopeArgs {
            tenant_id,
            grant_id,
            scope_value,
        },
    )
    .await
}
