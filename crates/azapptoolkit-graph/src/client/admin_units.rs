//! Administrative units and directory role assignments: the reads behind
//! admin-unit scoping and the Directory roles list, and its writes (creating
//! a unit by rule, assigning and removing a role at unit scope), which ride
//! the on-demand `admin_unit_roles` token.

use super::*;
use azapptoolkit_core::models::{AdministrativeUnit, DirectoryRoleAssignment};
use azapptoolkit_core::scoping::admin_unit::AdminUnitMemberKind;

const ADMIN_UNIT_SELECT: &str = "id,displayName,membershipType,membershipRule,\
membershipRuleProcessingState,isMemberManagementRestricted";
const ROLE_DEFINITION_EXPAND: &str = "roleDefinition($select=id,displayName,templateId)";

/// Refuses anything but a GUID: principal and role ids go into a `$filter` or
/// a request body, where a quote would change the query.
fn require_guid(what: &str, value: &str) -> Result<()> {
    if azapptoolkit_core::guid::is_guid(value) {
        Ok(())
    } else {
        Err(GraphError::Protocol(format!("{what} must be a GUID")))
    }
}

impl GraphClient {
    /// Every administrative unit in the tenant (sign-in read token).
    pub async fn list_admin_units(&self) -> Result<Vec<AdministrativeUnit>> {
        let params: [(&str, &str); 2] = [("$select", ADMIN_UNIT_SELECT), ("$top", MAX_PAGE_SIZE)];
        let page: Paged<AdministrativeUnit> = self
            .get_json("/directory/administrativeUnits", &params, false)
            .await?;
        self.collect_all_pages(page, false).await
    }

    /// One administrative unit, read live.
    pub async fn get_admin_unit(&self, admin_unit_id: &str) -> Result<AdministrativeUnit> {
        validate::require_path_segment("admin unit id", admin_unit_id)?;
        let path = format!("/directory/administrativeUnits/{admin_unit_id}");
        let params: [(&str, &str); 1] = [("$select", ADMIN_UNIT_SELECT)];
        self.get_json(&path, &params, false).await
    }

    /// Creates an administrative unit whose members come from a dynamic
    /// rule (users or devices), processing on.
    pub async fn create_dynamic_admin_unit(
        &self,
        display_name: &str,
        membership_rule: &str,
    ) -> Result<AdministrativeUnit> {
        let token = self.admin_unit_roles_token()?;
        let url = format!("{}/directory/administrativeUnits", self.base_url);
        let body = serde_json::json!({
            "displayName": display_name,
            "membershipType": "Dynamic",
            "membershipRule": membership_rule,
            "membershipRuleProcessingState": "On",
        });
        self.scoped_send_json(token, Method::POST, &url, &body)
            .await
    }

    /// Whether the unit has at least one member of `kind`.
    pub async fn admin_unit_has_members(
        &self,
        admin_unit_id: &str,
        kind: AdminUnitMemberKind,
    ) -> Result<bool> {
        validate::require_path_segment("admin unit id", admin_unit_id)?;
        let cast = match kind {
            AdminUnitMemberKind::User => "microsoft.graph.user",
            AdminUnitMemberKind::Group => "microsoft.graph.group",
            AdminUnitMemberKind::Device => "microsoft.graph.device",
        };
        // `cast` is one of three fixed type names, never input.
        let path = format!("/directory/administrativeUnits/{admin_unit_id}/members/") + cast;
        // One row answers the question; this is a probe, not a paged walk.
        let params: [(&str, &str); 2] = [("$select", "id"), ("$top", "1")];
        let page: Paged<serde_json::Value> = self.get_json(&path, &params, false).await?;
        Ok(!page.items.is_empty())
    }

    /// The direct, active directory role assignments held by `principal_id`,
    /// each with its role definition.
    pub async fn list_role_assignments_for_principal(
        &self,
        principal_id: &str,
    ) -> Result<Vec<DirectoryRoleAssignment>> {
        require_guid("principal id", principal_id)?;
        let filter = format!("principalId eq '{}'", escape_odata(principal_id));
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            ("$expand", ROLE_DEFINITION_EXPAND),
            ("$top", MAX_PAGE_SIZE),
        ];
        let page: Paged<DirectoryRoleAssignment> = self
            .get_json("/roleManagement/directory/roleAssignments", &params, false)
            .await?;
        self.collect_all_pages(page, false).await
    }

    /// Every direct, active directory role assignment in the tenant (tenant
    /// and admin-unit scope): the audit joins them to its principals.
    pub async fn list_directory_role_assignments(&self) -> Result<Vec<DirectoryRoleAssignment>> {
        let params: [(&str, &str); 1] = [("$top", MAX_PAGE_SIZE)];
        let page: Paged<DirectoryRoleAssignment> = self
            .get_json("/roleManagement/directory/roleAssignments", &params, false)
            .await?;
        self.collect_all_pages(page, false).await
    }

    /// Assigns the built-in role `role_template_id` to `principal_id` at the
    /// scope of one administrative unit. The scope is built here, so this can
    /// never assign at tenant scope.
    pub async fn assign_role_at_admin_unit(
        &self,
        principal_id: &str,
        role_template_id: &str,
        admin_unit_id: &str,
    ) -> Result<DirectoryRoleAssignment> {
        require_guid("principal id", principal_id)?;
        require_guid("role id", role_template_id)?;
        validate::require_path_segment("admin unit id", admin_unit_id)?;
        let token = self.admin_unit_roles_token()?;
        let url = format!("{}/roleManagement/directory/roleAssignments", self.base_url);
        let body = serde_json::json!({
            "principalId": principal_id,
            "roleDefinitionId": role_template_id,
            "directoryScopeId": format!("/administrativeUnits/{admin_unit_id}"),
        });
        self.scoped_send_json(token, Method::POST, &url, &body)
            .await
    }

    /// Deletes one directory role assignment.
    pub async fn delete_role_assignment(&self, assignment_id: &str) -> Result<()> {
        validate::require_path_segment("role assignment id", assignment_id)?;
        let token = self.admin_unit_roles_token()?;
        let url = format!(
            "{}/roleManagement/directory/roleAssignments/{assignment_id}",
            self.base_url
        );
        self.scoped_send_no_content::<()>(token, Method::DELETE, &url, None)
            .await
    }
}
