use super::*;

/// `$select` projections: the exact fields the typed models deserialize, so the
/// (often paged, fanned-out) reads don't pull full objects. `appRoleAssignment`
/// and `oauth2PermissionGrant` are their own entity types (not directoryObject
/// casts), so projecting their fields is lossless.
const APP_ROLE_ASSIGNMENT_SELECT: &str = "id,principalId,resourceId,appRoleId,principalDisplayName,principalType,resourceDisplayName,createdDateTime";
const OAUTH2_GRANT_SELECT: &str = "id,clientId,resourceId,consentType,principalId,scope";

impl GraphClient {
    pub async fn list_app_role_assignments(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<AppRoleAssignment>> {
        let path = format!("/servicePrincipals/{service_principal_id}/appRoleAssignments");
        let params: [(&str, &str); 1] = [("$select", APP_ROLE_ASSIGNMENT_SELECT)];
        let page: Paged<AppRoleAssignment> = self.get_json(&path, &params, false).await?;
        self.collect_all_pages(page).await
    }

    /// Principals (users/groups) assigned **to** this service principal's app
    /// roles — the inbound "who has access" direction (`appRoleAssignedTo`), as
    /// opposed to what the SP itself has been granted (`appRoleAssignments`).
    pub async fn list_app_role_assigned_to(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<AppRoleAssignment>> {
        let path = format!("/servicePrincipals/{service_principal_id}/appRoleAssignedTo");
        let params: [(&str, &str); 1] = [("$select", APP_ROLE_ASSIGNMENT_SELECT)];
        let page: Paged<AppRoleAssignment> = self.get_json(&path, &params, false).await?;
        self.collect_all_pages(page).await
    }

    /// Batched [`Self::list_app_role_assigned_to`]: inbound role assignments for
    /// many SPs in one `$batch` POST per 20. Returns each SP's full assignment
    /// list (paginating the rare overflow outside the batch) in input order. The
    /// DR backup's Pass-2 "who's assigned" read.
    pub async fn batch_list_app_role_assigned_to(
        &self,
        sp_ids: &[String],
    ) -> Result<Vec<Result<Vec<AppRoleAssignment>>>> {
        let urls: Vec<String> = sp_ids
            .iter()
            .map(|id| {
                batch_sub_url(
                    &format!("/servicePrincipals/{id}/appRoleAssignedTo"),
                    &[("$select", APP_ROLE_ASSIGNMENT_SELECT)],
                )
            })
            .collect();
        let pages: Vec<Result<Paged<AppRoleAssignment>>> = self.batch_get_json(&urls).await?;
        self.finish_paged_batch(pages).await
    }

    /// Batched [`Self::list_app_role_assignments`]: the application permissions
    /// **held by** many SPs, one `$batch` POST per 20. The DR backup's Pass-3
    /// managed-identity read.
    pub async fn batch_list_app_role_assignments(
        &self,
        sp_ids: &[String],
    ) -> Result<Vec<Result<Vec<AppRoleAssignment>>>> {
        let urls: Vec<String> = sp_ids
            .iter()
            .map(|id| {
                batch_sub_url(
                    &format!("/servicePrincipals/{id}/appRoleAssignments"),
                    &[("$select", APP_ROLE_ASSIGNMENT_SELECT)],
                )
            })
            .collect();
        let pages: Vec<Result<Paged<AppRoleAssignment>>> = self.batch_get_json(&urls).await?;
        self.finish_paged_batch(pages).await
    }

    /// Assigns a principal (user/group) to a role on `resource_sp_id` — grants
    /// access to the enterprise application. `app_role_id` may be the all-zero
    /// GUID for the "default access" (no-specific-role) assignment. Posts to the
    /// resource side (`appRoleAssignedTo`) so it works for any principal type.
    pub async fn assign_app_role_to(
        &self,
        resource_sp_id: &str,
        principal_id: &str,
        app_role_id: &str,
    ) -> Result<AppRoleAssignment> {
        let path = format!("/servicePrincipals/{resource_sp_id}/appRoleAssignedTo");
        let body = serde_json::json!({
            "principalId": principal_id,
            "resourceId": resource_sp_id,
            "appRoleId": app_role_id,
        });
        self.send_json(Method::POST, &path, &body).await
    }

    /// Removes an `appRoleAssignedTo` assignment from `resource_sp_id` — revokes
    /// a principal's access to the enterprise application.
    pub async fn remove_app_role_assigned_to(
        &self,
        resource_sp_id: &str,
        assignment_id: &str,
    ) -> Result<()> {
        let path = format!("/servicePrincipals/{resource_sp_id}/appRoleAssignedTo/{assignment_id}");
        self.send_no_content::<()>(Method::DELETE, &path, None)
            .await
    }

    pub async fn list_oauth2_grants(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<OAuth2PermissionGrant>> {
        let filter = format!("clientId eq '{}'", escape_odata(service_principal_id));
        let params: [(&str, &str); 2] = [
            ("$filter", filter.as_str()),
            ("$select", OAUTH2_GRANT_SELECT),
        ];
        let page: Paged<OAuth2PermissionGrant> = self
            .get_json("/oauth2PermissionGrants", &params, false)
            .await?;
        self.collect_all_pages(page).await
    }

    /// Every delegated permission grant in the tenant (`/oauth2PermissionGrants`,
    /// unfiltered). Used by the consent-grant audit. Follows `@odata.nextLink`.
    pub async fn list_all_oauth2_grants(&self) -> Result<Vec<OAuth2PermissionGrant>> {
        let params: [(&str, &str); 2] = [("$top", "999"), ("$select", OAUTH2_GRANT_SELECT)];
        let page: Paged<OAuth2PermissionGrant> = self
            .get_json("/oauth2PermissionGrants", &params, false)
            .await?;
        self.collect_all_pages(page).await
    }

    /// Grants an application permission (appRole) on a resource service
    /// principal. Returns the created assignment; Graph returns 201 with the
    /// new row. The `client_sp_id` is the service principal receiving the
    /// permission (the app's own SP); `resource_sp_id` is the API provider
    /// (e.g. Microsoft Graph's SP).
    pub async fn grant_app_role(
        &self,
        client_sp_id: &str,
        resource_sp_id: &str,
        app_role_id: &str,
    ) -> Result<AppRoleAssignment> {
        let path = format!("/servicePrincipals/{client_sp_id}/appRoleAssignments");
        let body = serde_json::json!({
            "principalId": client_sp_id,
            "resourceId": resource_sp_id,
            "appRoleId": app_role_id,
        });
        self.send_json(Method::POST, &path, &body).await
    }

    /// Removes an application-permission assignment from a service principal.
    /// Used to drop the org-wide (unscoped) Entra grant for a mailbox
    /// permission when access is being constrained via Exchange RBAC instead —
    /// without this, the unscoped Entra grant unions with the scoped Exchange
    /// grant and defeats the scoping.
    pub async fn remove_app_role_assignment(
        &self,
        service_principal_id: &str,
        assignment_id: &str,
    ) -> Result<()> {
        let path =
            format!("/servicePrincipals/{service_principal_id}/appRoleAssignments/{assignment_id}");
        self.send_no_content::<()>(Method::DELETE, &path, None)
            .await
    }

    /// Finds an existing admin-consent `oauth2PermissionGrant` matching
    /// `clientId=client_sp_id AND resourceId=resource_sp_id AND
    /// consentType=AllPrincipals`, or `None` if no such grant exists.
    pub async fn find_admin_oauth2_grant(
        &self,
        client_sp_id: &str,
        resource_sp_id: &str,
    ) -> Result<Option<OAuth2PermissionGrant>> {
        let grants = self.list_oauth2_grants(client_sp_id).await?;
        Ok(grants
            .into_iter()
            .find(|g| g.resource_id == resource_sp_id && g.consent_type == "AllPrincipals"))
    }

    pub async fn create_oauth2_grant(
        &self,
        grant: &OAuth2PermissionGrant,
    ) -> Result<OAuth2PermissionGrant> {
        self.send_json(Method::POST, "/oauth2PermissionGrants", grant)
            .await
    }

    /// PATCHes the `scope` field of an existing oauth2PermissionGrant. Used
    /// when admin consent needs to add scopes to a grant that already exists.
    pub async fn update_oauth2_grant_scope(&self, grant_id: &str, scope: &str) -> Result<()> {
        let path = format!("/oauth2PermissionGrants/{grant_id}");
        let body = serde_json::json!({ "scope": scope });
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await
    }

    /// Reads a single oauth2PermissionGrant by id — needed by the per-scope
    /// revoke path which computes the new scope string from the current value.
    pub async fn get_oauth2_grant(&self, grant_id: &str) -> Result<OAuth2PermissionGrant> {
        let path = format!("/oauth2PermissionGrants/{grant_id}");
        self.get_json(&path, &[], false).await
    }

    /// Deletes an oauth2PermissionGrant outright. Used when revoking the last
    /// scope from a delegated grant — Graph keeps the empty grant around
    /// otherwise.
    pub async fn delete_oauth2_grant(&self, grant_id: &str) -> Result<()> {
        let path = format!("/oauth2PermissionGrants/{grant_id}");
        self.send_no_content::<()>(Method::DELETE, &path, None)
            .await
    }

    /// Ensures an admin-consent OAuth2 grant exists for `(client_sp_id,
    /// resource_sp_id)` and covers every scope in `desired_scopes`. Returns
    /// the final grant (either newly created or updated). Idempotent.
    pub async fn upsert_admin_oauth2_grant(
        &self,
        client_sp_id: &str,
        resource_sp_id: &str,
        desired_scopes: &[&str],
    ) -> Result<OAuth2PermissionGrant> {
        if let Some(existing) = self
            .find_admin_oauth2_grant(client_sp_id, resource_sp_id)
            .await?
        {
            let current: std::collections::BTreeSet<&str> =
                existing.scope.split_whitespace().collect();
            let desired: std::collections::BTreeSet<&str> =
                desired_scopes.iter().copied().collect();
            if desired.is_subset(&current) {
                return Ok(existing);
            }
            let merged: std::collections::BTreeSet<&str> =
                current.union(&desired).copied().collect();
            let scope_str = merged.into_iter().collect::<Vec<_>>().join(" ");
            let grant_id = existing
                .id
                .as_ref()
                .ok_or_else(|| GraphError::Api {
                    status: 500,
                    body: "existing grant missing id".to_string(),
                })?
                .clone();
            self.update_oauth2_grant_scope(&grant_id, &scope_str)
                .await?;
            return Ok(OAuth2PermissionGrant {
                scope: scope_str,
                ..existing
            });
        }

        let scope_str = desired_scopes.join(" ");
        let new_grant = OAuth2PermissionGrant {
            id: None,
            client_id: client_sp_id.to_string(),
            resource_id: resource_sp_id.to_string(),
            consent_type: "AllPrincipals".to_string(),
            principal_id: None,
            scope: scope_str,
        };
        self.create_oauth2_grant(&new_grant).await
    }
}
