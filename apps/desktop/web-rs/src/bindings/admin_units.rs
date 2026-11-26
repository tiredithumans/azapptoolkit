//! Admin-unit scoping (C1) IPC bindings: admin units, directory roles, and
//! limiting a directory write to an admin unit.

use super::ipc::invoke_result;
use azapptoolkit_dto::UiError;
use serde::Serialize;

use crate::bindings::TenantArg;

pub use azapptoolkit_dto::admin_units::{
    AdminUnitDto, DirectoryRoleDto, DirectoryRoleScopeDto, DirectoryWriteScopeResult,
};

/// The tenant's administrative units.
pub async fn list_admin_units(tenant_id: &str) -> Result<Vec<AdminUnitDto>, UiError> {
    invoke_result("list_admin_units", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NewUnitArgs<'a> {
    tenant_id: &'a str,
    display_name: &'a str,
    membership_rule: &'a str,
}

/// Creates an admin unit whose members come from `membership_rule`.
pub async fn create_admin_unit_by_rule(
    tenant_id: &str,
    display_name: &str,
    membership_rule: &str,
) -> Result<AdminUnitDto, UiError> {
    invoke_result(
        "create_admin_unit_by_rule",
        NewUnitArgs {
            tenant_id,
            display_name,
            membership_rule,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpArgs<'a> {
    tenant_id: &'a str,
    sp_object_id: &'a str,
}

/// The principal's direct, active directory role assignments.
pub async fn list_directory_roles(
    tenant_id: &str,
    sp_object_id: &str,
) -> Result<Vec<DirectoryRoleDto>, UiError> {
    invoke_result(
        "list_directory_roles",
        SpArgs {
            tenant_id,
            sp_object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveRoleArgs<'a> {
    tenant_id: &'a str,
    sp_object_id: &'a str,
    assignment_id: &'a str,
}

/// Removes one admin-unit-scoped role assignment the principal holds.
pub async fn remove_admin_unit_role(
    tenant_id: &str,
    sp_object_id: &str,
    assignment_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_admin_unit_role",
        RemoveRoleArgs {
            tenant_id,
            sp_object_id,
            assignment_id,
        },
    )
    .await
}

/// What a "limit writes to an admin unit" run is applied to.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDirectoryWriteArgs<'a> {
    pub tenant_id: &'a str,
    /// The service principal; `None` resolves it from `app_id`.
    pub sp_object_id: Option<&'a str>,
    /// The app registration, `None` for an SP-only principal.
    pub object_id: Option<&'a str>,
    pub app_id: &'a str,
    pub permission_value: &'a str,
    pub admin_unit_id: &'a str,
    /// The unit was created in this same run.
    pub created_now: bool,
    /// Refuse unless the app holds the tenant-wide write (the audit's Fix).
    pub require_held: bool,
}

/// Limits a tenant-wide directory write to an admin unit (assign the role at
/// the unit, ensure tenant-wide read, then strip the tenant-wide write when
/// safe).
pub async fn scope_directory_write(
    args: ScopeDirectoryWriteArgs<'_>,
) -> Result<DirectoryWriteScopeResult, UiError> {
    // Rebuilt as a literal so the IPC pin can read the wire keys.
    let ScopeDirectoryWriteArgs {
        tenant_id,
        sp_object_id,
        object_id,
        app_id,
        permission_value,
        admin_unit_id,
        created_now,
        require_held,
    } = args;
    invoke_result(
        "scope_directory_write",
        ScopeDirectoryWriteArgs {
            tenant_id,
            sp_object_id,
            object_id,
            app_id,
            permission_value,
            admin_unit_id,
            created_now,
            require_held,
        },
    )
    .await
}
