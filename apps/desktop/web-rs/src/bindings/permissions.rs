//! Permissions catalog & admin-consent IPC bindings.

use super::ipc::invoke_result;
use azapptoolkit_dto::UiError;
use serde::Serialize;

use crate::bindings::{ObjectIdArgs, TenantArg};
pub use azapptoolkit_dto::permissions::*;

pub async fn list_catalog_resources() -> Result<Vec<CatalogResourceSummary>, UiError> {
    invoke_result("list_catalog_resources", ()).await
}

/// Live permission counts per resource, used to enrich the dropdown labels.
pub async fn list_resource_permission_counts(
    tenant_id: &str,
) -> Result<Vec<CatalogResourceSummary>, UiError> {
    invoke_result("list_resource_permission_counts", TenantArg { tenant_id }).await
}

/// Tenant-owned app registrations / SPs that expose Application app roles, for
/// the picker's "Tenant app registrations" resource group. `role_count` is the
/// grantable-role count for the dropdown label; the roles themselves resolve via
/// [`list_resource_permissions`] when the resource is selected.
pub async fn list_app_role_resources(
    tenant_id: &str,
) -> Result<Vec<CatalogResourceSummary>, UiError> {
    invoke_result("list_app_role_resources", TenantArg { tenant_id }).await
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

pub async fn grant_admin_consent(tenant_id: &str, object_id: &str) -> Result<GrantResult, UiError> {
    invoke_result(
        "grant_admin_consent",
        ObjectIdArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

/// One permission on one app — what grant, declare and remove-declared all
/// take.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PermissionRefArgs<'a> {
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
        PermissionRefArgs {
            tenant_id,
            object_id,
            resource_app_id,
            permission_id,
            kind,
        },
    )
    .await
}

/// Declares a permission in the app's `requiredResourceAccess` manifest
/// **without** creating any runtime grant — the manifest half of
/// `grant_single_permission`. The scoped-mailbox wizard uses this so the
/// permission is declared (visible + scopable) while access comes solely from a
/// scoped Exchange RBAC role assignment, never an org-wide Entra grant.
pub async fn declare_app_permission(
    tenant_id: &str,
    object_id: &str,
    resource_app_id: &str,
    permission_id: &str,
    kind: PermissionKind,
) -> Result<(), UiError> {
    invoke_result(
        "declare_app_permission",
        PermissionRefArgs {
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
        PermissionRefArgs {
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
