//! Admin-unit scoping (C1): the IPC shapes for admin units, directory roles
//! and limiting a directory write to an admin unit.

use serde::{Deserialize, Serialize};

/// An administrative unit, as the picker shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUnitDto {
    pub id: String,
    pub display_name: String,
    /// Members come from a dynamic rule (users or devices only).
    pub dynamic: bool,
    pub membership_rule: Option<String>,
    /// A dynamic unit's rule is processing (`On`); always true for an
    /// assigned unit.
    pub rule_processing_on: bool,
    /// A restricted-management unit.
    pub restricted: bool,
}

/// Where a directory role assignment applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DirectoryRoleScopeDto {
    Tenant,
    AdminUnit {
        id: String,
        name: String,
    },
    /// Scoped to one directory object (an app, say).
    Object {
        id: String,
    },
}

/// One direct, active directory role assignment a principal holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryRoleDto {
    pub assignment_id: String,
    pub role_template_id: String,
    pub role_name: String,
    pub scope: DirectoryRoleScopeDto,
}

/// What limiting a directory write to an admin unit did, step by step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryWriteScopeResult {
    /// The role was assigned at the unit's scope now.
    pub role_assigned: bool,
    /// The principal already held that role at that unit.
    pub role_already_held: bool,
    /// The tenant-wide read permission was granted now.
    pub read_granted: bool,
    /// The principal could already read tenant-wide.
    pub read_already_held: bool,
    /// The tenant-wide write permission was removed.
    pub orgwide_removed: bool,
    /// Why the tenant-wide write permission was kept, when it was.
    pub kept_reason: Option<String>,
    /// A tenant-scope role that still lets the app write everywhere.
    pub covering_role: Option<String>,
    pub warnings: Vec<String>,
}
