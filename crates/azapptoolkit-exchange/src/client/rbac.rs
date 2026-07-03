//! RBAC for Applications: Exchange service-principal pointers, management
//! scopes, management role assignments, the legacy Application Access Policy
//! (migration) surface, and the two live verification cmdlets.

use serde_json::json;

use super::ExchangeClient;
use super::transport::{all_as, first_as, first_optional_as};
use crate::error::Result;
use crate::models::{
    ExoAppAccessPolicyTestResult, ExoApplicationAccessPolicy, ExoAuthorizationResult,
    ExoManagementScope, ExoRoleAssignment, ExoServicePrincipal,
};

impl ExchangeClient {
    // ---------------- Service principals ----------------

    /// Registers the Entra service principal pointer in Exchange. Idempotent:
    /// returns the existing pointer if one already exists for `app_id`.
    pub async fn ensure_service_principal(
        &self,
        app_id: &str,
        object_id: &str,
        display_name: &str,
    ) -> Result<ExoServicePrincipal> {
        if let Some(existing) = self.get_service_principal(app_id).await? {
            return Ok(existing);
        }
        let values = self
            .invoke_command(
                "New-ServicePrincipal",
                json!({
                    "AppId": app_id,
                    "ObjectId": object_id,
                    "DisplayName": display_name,
                }),
            )
            .await?;
        first_as(values, "New-ServicePrincipal")
    }

    /// Looks up the Exchange service-principal pointer by AppId, ObjectId, or
    /// DisplayName. Returns `None` if no pointer is registered.
    pub async fn get_service_principal(
        &self,
        identity: &str,
    ) -> Result<Option<ExoServicePrincipal>> {
        let values = self
            .invoke_optional("Get-ServicePrincipal", json!({ "Identity": identity }))
            .await?;
        first_optional_as(values)
    }

    /// Every service-principal pointer registered in Exchange (the population
    /// eligible for RBAC-for-Applications role assignments). This is the only
    /// way to discover principals whose mailbox access comes *solely* from
    /// Exchange RBAC — they hold no Graph app-role assignment, so no Graph
    /// query can surface them.
    pub async fn list_service_principals(&self) -> Result<Vec<ExoServicePrincipal>> {
        let values = self
            .invoke_command("Get-ServicePrincipal", json!({}))
            .await?;
        all_as(values)
    }

    // ---------------- Management scopes ----------------

    /// Creates a management scope with the given OPATH recipient filter.
    /// Idempotent: returns the existing scope if `name` already exists.
    pub async fn ensure_management_scope(
        &self,
        name: &str,
        recipient_restriction_filter: &str,
    ) -> Result<ExoManagementScope> {
        if let Some(existing) = self.get_management_scope(name).await? {
            return Ok(existing);
        }
        let values = self
            .invoke_command(
                "New-ManagementScope",
                json!({
                    "Name": name,
                    "RecipientRestrictionFilter": recipient_restriction_filter,
                }),
            )
            .await?;
        first_as(values, "New-ManagementScope")
    }

    pub async fn get_management_scope(&self, name: &str) -> Result<Option<ExoManagementScope>> {
        let values = self
            .invoke_optional("Get-ManagementScope", json!({ "Identity": name }))
            .await?;
        first_optional_as(values)
    }

    // ---------------- Role assignments ----------------

    /// Assigns an Exchange application `role` to the service principal `app`
    /// (AppId/ObjectId/DisplayName), optionally constrained to a management
    /// scope. `custom_resource_scope = None` grants org-wide.
    pub async fn new_role_assignment(
        &self,
        app: &str,
        role: &str,
        custom_resource_scope: Option<&str>,
    ) -> Result<ExoRoleAssignment> {
        let mut params = json!({ "App": app, "Role": role });
        if let Some(scope) = custom_resource_scope {
            params["CustomResourceScope"] = json!(scope);
        }
        let values = self
            .invoke_command("New-ManagementRoleAssignment", params)
            .await?;
        first_as(values, "New-ManagementRoleAssignment")
    }

    /// All management role assignments for the service principal `app`.
    pub async fn get_role_assignments(&self, app: &str) -> Result<Vec<ExoRoleAssignment>> {
        let values = self
            .invoke_optional(
                "Get-ManagementRoleAssignment",
                json!({ "RoleAssignee": app }),
            )
            .await?;
        all_as(values)
    }

    pub async fn remove_role_assignment(&self, identity: &str) -> Result<()> {
        self.invoke_command(
            "Remove-ManagementRoleAssignment",
            json!({ "Identity": identity, "Confirm": false }),
        )
        .await?;
        Ok(())
    }

    // ---------------- Legacy Application Access Policies (migration) ----------------

    pub async fn get_application_access_policies(&self) -> Result<Vec<ExoApplicationAccessPolicy>> {
        let values = self
            .invoke_optional("Get-ApplicationAccessPolicy", json!({}))
            .await?;
        all_as(values)
    }

    pub async fn remove_application_access_policy(&self, identity: &str) -> Result<()> {
        self.invoke_command(
            "Remove-ApplicationAccessPolicy",
            json!({ "Identity": identity, "Confirm": false }),
        )
        .await?;
        Ok(())
    }

    // ---------------- Verification ----------------

    /// Simulates the access a service principal has, optionally against a
    /// specific `resource` mailbox. Bypasses the RBAC propagation cache, so it
    /// is the reliable check immediately after granting access.
    pub async fn test_service_principal_authorization(
        &self,
        identity: &str,
        resource: Option<&str>,
    ) -> Result<Vec<ExoAuthorizationResult>> {
        let mut params = json!({ "Identity": identity });
        if let Some(res) = resource {
            params["Resource"] = json!(res);
        }
        let values = self
            .invoke_command("Test-ServicePrincipalAuthorization", params)
            .await?;
        all_as(values)
    }

    /// Live evaluation of the legacy Application Access Policy gate: can
    /// `app_id`'s **Entra-granted** permissions reach `mailbox`? This is the
    /// complement of [`test_service_principal_authorization`]: AAPs constrain
    /// only the Microsoft Entra ID grants (never Exchange RBAC assignments),
    /// while `Test-ServicePrincipalAuthorization` sees only the RBAC layer —
    /// actual access is the union of the two answers.
    ///
    /// [`test_service_principal_authorization`]: Self::test_service_principal_authorization
    pub async fn test_application_access_policy(
        &self,
        app_id: &str,
        mailbox: &str,
    ) -> Result<ExoAppAccessPolicyTestResult> {
        let values = self
            .invoke_command(
                "Test-ApplicationAccessPolicy",
                json!({ "AppId": app_id, "Identity": mailbox }),
            )
            .await?;
        first_as(values, "Test-ApplicationAccessPolicy")
    }
}
