//! Admin-unit scoping (C1): a tenant-wide directory-write permission replaced
//! by the matching Microsoft Entra admin role assigned at administrative-unit
//! scope.
//!
//! Sources (verified 2026-11-25): Microsoft Entra built-in roles
//! (`learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference`)
//! and "Assign Microsoft Entra roles with administrative unit scope"
//! (`…/admin-units-assign-roles`). A service principal can hold these roles at
//! admin-unit scope, but uses them only if it can also read the objects
//! tenant-wide; directory reads can't be limited to an admin unit.

use super::MICROSOFT_GRAPH_APP_ID;

/// What an admin unit must contain for a mapping's role to reach anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminUnitMemberKind {
    User,
    Group,
    Device,
}

/// One tenant-wide Microsoft Graph write permission and the admin role that
/// replaces it at admin-unit scope.
#[derive(Debug)]
pub struct DirectoryWriteMapping {
    /// The Microsoft Graph application permission it replaces.
    pub permission: &'static str,
    pub role_name: &'static str,
    pub role_template_id: &'static str,
    /// The tenant-wide read the role needs to be usable.
    pub read_permission: &'static str,
    pub member_kind: AdminUnitMemberKind,
    /// What the role allows that the permission doesn't (shown before the
    /// operator confirms).
    pub also_allows: &'static [&'static str],
    /// What the app can no longer do once the tenant-wide permission goes.
    pub no_longer: &'static [&'static str],
}

/// Global Administrator: covers every mapping at tenant scope.
pub const GLOBAL_ADMIN_ROLE_TEMPLATE_ID: &str = "62e90394-69f5-4237-9190-012177145e10";

/// The curated table: one row per permission, Microsoft Graph only.
pub const DIRECTORY_WRITE_MAPPINGS: &[DirectoryWriteMapping] = &[
    DirectoryWriteMapping {
        permission: "User.ReadWrite.All",
        role_name: "User Administrator",
        role_template_id: "fe930be7-5e62-47db-91af-98c3a49a38b1",
        read_permission: "User.Read.All",
        member_kind: AdminUnitMemberKind::User,
        also_allows: &[
            "Reset the passwords of users in the unit (not admins')",
            "Disable and enable users in the unit, and sign them out",
            "Create and manage groups in the unit",
        ],
        no_longer: &[
            "Change users outside the unit",
            "Change users who hold admin roles",
            "Create new users, unless Microsoft allows it at admin-unit scope (it doesn't document this)",
        ],
    },
    DirectoryWriteMapping {
        permission: "Group.ReadWrite.All",
        role_name: "Groups Administrator",
        role_template_id: "fdd7a751-b60b-444a-984c-02652fe8fa1c",
        read_permission: "Group.Read.All",
        member_kind: AdminUnitMemberKind::Group,
        also_allows: &[
            "Change group settings, including naming and expiration policies",
            "Restore and permanently delete groups in the unit",
            "Assign licences to groups in the unit",
        ],
        no_longer: &[
            "Change groups outside the unit",
            "Change role-assignable groups",
        ],
    },
    DirectoryWriteMapping {
        permission: "Device.ReadWrite.All",
        role_name: "Cloud Device Administrator",
        role_template_id: "7698a772-787b-4ac8-901f-60d6b08affd2",
        read_permission: "Device.Read.All",
        member_kind: AdminUnitMemberKind::Device,
        also_allows: &[
            "Read the BitLocker recovery keys of devices in the unit",
            "Read the backed-up local administrator passwords of devices in the unit",
            "Restore and permanently delete devices in the unit",
        ],
        no_longer: &[
            "Change devices outside the unit",
            "Change device properties other than enabling, disabling and deleting",
        ],
    },
];

/// The mapping for `value` on `resource_app_id` (Microsoft Graph only).
pub fn directory_write_mapping(
    resource_app_id: Option<&str>,
    value: &str,
) -> Option<&'static DirectoryWriteMapping> {
    if resource_app_id != Some(MICROSOFT_GRAPH_APP_ID) {
        return None;
    }
    DIRECTORY_WRITE_MAPPINGS
        .iter()
        .find(|m| m.permission == value)
}

/// The positive gate for the mechanism: a tenant-wide directory write this
/// toolkit can limit to an admin unit.
pub fn is_scopable_directory_write_resource_permission(
    resource_app_id: Option<&str>,
    value: &str,
) -> bool {
    directory_write_mapping(resource_app_id, value).is_some()
}

/// Whether holding `value` on `resource_app_id` gives `mapping`'s role the
/// tenant-wide read it needs: its own read, or `Directory.Read(Write).All`.
pub fn satisfies_tenant_read(
    mapping: &DirectoryWriteMapping,
    resource_app_id: Option<&str>,
    value: &str,
) -> bool {
    resource_app_id == Some(MICROSOFT_GRAPH_APP_ID)
        && (value == mapping.read_permission
            || value == "Directory.Read.All"
            || value == "Directory.ReadWrite.All")
}

/// Whether a tenant-scope assignment of `held_role_template_id` voids a unit
/// limit for `mapping`: the same role, or Global Administrator.
pub fn covers_tenant_wide(mapping: &DirectoryWriteMapping, held_role_template_id: &str) -> bool {
    held_role_template_id.eq_ignore_ascii_case(mapping.role_template_id)
        || held_role_template_id.eq_ignore_ascii_case(GLOBAL_ADMIN_ROLE_TEMPLATE_ID)
}

/// The user attributes the create-by-rule builder offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRuleAttribute {
    Department,
    CompanyName,
    OfficeLocation,
    Country,
    JobTitle,
    EmployeeType,
}

impl UserRuleAttribute {
    pub const ALL: [UserRuleAttribute; 6] = [
        UserRuleAttribute::Department,
        UserRuleAttribute::CompanyName,
        UserRuleAttribute::OfficeLocation,
        UserRuleAttribute::Country,
        UserRuleAttribute::JobTitle,
        UserRuleAttribute::EmployeeType,
    ];

    /// The attribute's name in a membership rule.
    pub fn property(self) -> &'static str {
        match self {
            UserRuleAttribute::Department => "department",
            UserRuleAttribute::CompanyName => "companyName",
            UserRuleAttribute::OfficeLocation => "physicalDeliveryOfficeName",
            UserRuleAttribute::Country => "country",
            UserRuleAttribute::JobTitle => "jobTitle",
            UserRuleAttribute::EmployeeType => "employeeType",
        }
    }

    /// Operator-facing label.
    pub fn label(self) -> &'static str {
        match self {
            UserRuleAttribute::Department => "Department",
            UserRuleAttribute::CompanyName => "Company name",
            UserRuleAttribute::OfficeLocation => "Office location",
            UserRuleAttribute::Country => "Country",
            UserRuleAttribute::JobTitle => "Job title",
            UserRuleAttribute::EmployeeType => "Employee type",
        }
    }
}

/// The membership rule "users whose `attribute` equals `value`" (trimmed,
/// with `"` escaped).
pub fn user_rule(attribute: UserRuleAttribute, value: &str) -> String {
    let quoted = value.trim().replace('\\', "\\\\").replace('"', "\\\"");
    format!("(user.{} -eq \"{quoted}\")", attribute.property())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoping::{MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID};

    const GRAPH: Option<&str> = Some(MICROSOFT_GRAPH_APP_ID);

    #[test]
    fn mapping_carries_the_resource() {
        let m = directory_write_mapping(GRAPH, "User.ReadWrite.All").expect("mapped");
        assert_eq!(m.role_name, "User Administrator");
        assert_eq!(m.role_template_id, "fe930be7-5e62-47db-91af-98c3a49a38b1");
        assert_eq!(m.read_permission, "User.Read.All");
        assert_eq!(m.member_kind, AdminUnitMemberKind::User);
        assert!(
            directory_write_mapping(Some(OFFICE365_EXCHANGE_ONLINE_APP_ID), "User.ReadWrite.All")
                .is_none()
        );
        assert!(directory_write_mapping(None, "User.ReadWrite.All").is_none());
        assert!(directory_write_mapping(GRAPH, "Directory.ReadWrite.All").is_none());
        assert_eq!(
            directory_write_mapping(GRAPH, "Group.ReadWrite.All").map(|m| m.member_kind),
            Some(AdminUnitMemberKind::Group)
        );
        assert_eq!(
            directory_write_mapping(GRAPH, "Device.ReadWrite.All").map(|m| m.role_name),
            Some("Cloud Device Administrator")
        );
        assert!(is_scopable_directory_write_resource_permission(
            GRAPH,
            "Group.ReadWrite.All"
        ));
        assert!(!is_scopable_directory_write_resource_permission(
            None,
            "Group.ReadWrite.All"
        ));
    }

    #[test]
    fn every_mapping_discloses_both_ways() {
        assert_eq!(DIRECTORY_WRITE_MAPPINGS.len(), 3);
        for m in DIRECTORY_WRITE_MAPPINGS {
            assert!(!m.also_allows.is_empty(), "{}", m.permission);
            assert!(!m.no_longer.is_empty(), "{}", m.permission);
            assert!(crate::guid::is_guid(m.role_template_id), "{}", m.permission);
        }
    }

    #[test]
    fn tenant_read_accepts_broader_reads() {
        let m = directory_write_mapping(GRAPH, "User.ReadWrite.All").unwrap();
        for ok in [
            "User.Read.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
        ] {
            assert!(satisfies_tenant_read(m, GRAPH, ok), "{ok}");
        }
        assert!(!satisfies_tenant_read(m, GRAPH, "Group.Read.All"));
        assert!(!satisfies_tenant_read(
            m,
            Some(OFFICE365_EXCHANGE_ONLINE_APP_ID),
            "User.Read.All"
        ));
        assert!(!satisfies_tenant_read(m, None, "User.Read.All"));
    }

    #[test]
    fn covering_roles() {
        let m = directory_write_mapping(GRAPH, "User.ReadWrite.All").unwrap();
        assert!(covers_tenant_wide(
            m,
            "fe930be7-5e62-47db-91af-98c3a49a38b1"
        ));
        assert!(covers_tenant_wide(m, GLOBAL_ADMIN_ROLE_TEMPLATE_ID));
        assert!(covers_tenant_wide(
            m,
            &GLOBAL_ADMIN_ROLE_TEMPLATE_ID.to_uppercase()
        ));
        // Helpdesk Administrator does not cover User Administrator.
        assert!(!covers_tenant_wide(
            m,
            "729827e3-9c14-49f7-bb1b-9608f156bbb8"
        ));
    }

    #[test]
    fn user_rule_quotes() {
        assert_eq!(
            user_rule(UserRuleAttribute::Department, "Finance"),
            r#"(user.department -eq "Finance")"#
        );
        assert_eq!(
            user_rule(UserRuleAttribute::CompanyName, r#"Contoso "EU""#),
            r#"(user.companyName -eq "Contoso \"EU\"")"#
        );
        assert_eq!(
            user_rule(UserRuleAttribute::EmployeeType, " Contractor "),
            r#"(user.employeeType -eq "Contractor")"#,
            "the value is trimmed"
        );
    }
}
