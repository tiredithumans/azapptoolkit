use super::*;

/// `$select` projections: the exact fields the typed models deserialize, so the
/// (often paged, fanned-out) reads don't pull full objects. `appRoleAssignment`
/// and `oauth2PermissionGrant` are their own entity types (not directoryObject
/// casts), so projecting their fields is lossless.
const APP_ROLE_ASSIGNMENT_SELECT: &str = "id,principalId,resourceId,appRoleId,principalDisplayName,principalType,resourceDisplayName,createdDateTime";
const OAUTH2_GRANT_SELECT: &str = "id,clientId,resourceId,consentType,principalId,scope";

impl GraphClient {
    /// Cache key for the tenant-wide grant matrices. The shared `grants:`
    /// segment is what [`Self::invalidate_grant_cache`] sweeps, so the sweep
    /// cannot reach the sign-in-activity entry that also lives under
    /// `CacheKind::Permissions` (a slow beta report — dumping it on every grant
    /// write would be a bad trade).
    fn grant_cache_key(tenant_id: &str, what: &str) -> String {
        format!("{tenant_id}|grants:{what}")
    }

    /// Drops this tenant's cached grant matrices.
    ///
    /// Lives in the client — NOT in the command aggregators — for the same
    /// reason `CacheKind::ServicePrincipal` self-invalidates: grants are written
    /// from seven different command files (consent, permissions, exchange,
    /// sharepoint, remediation, enterprise_application, bulk), and a cached
    /// security-posture read that outlives a revoke is the worst kind of
    /// staleness — the UI would show access that no longer exists, or hide
    /// access that does. Routing every mutator through here makes the
    /// invalidation correct by construction rather than by remembering.
    fn invalidate_grant_cache(&self) {
        self.cache.invalidate_prefix(
            CacheKind::Permissions,
            &format!("{}|grants:", self.tenant_id),
        );
    }
    pub async fn list_app_role_assignments(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<AppRoleAssignment>> {
        let path = format!("/servicePrincipals/{service_principal_id}/appRoleAssignments");
        // Read-through cache. Pointed at the Microsoft Graph SP this is the
        // heaviest paged read in the app, and BOTH the security audit's
        // `prefetch_graph_app_roles` and the Application-permissions consent lens
        // walk it end to end — so browsing between those two surfaces paid for
        // the same full-tenant scan twice. Every mutator below sweeps this
        // prefix on `Ok`, so a revoked grant can never survive the TTL here (see
        // `invalidate_grant_cache`).
        let cache_key = Self::grant_cache_key(
            &self.tenant_id,
            &format!("assigned_to:{service_principal_id}"),
        );
        if let Some(cached) = self
            .cache
            .get::<Vec<AppRoleAssignment>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let params: [(&str, &str); 2] = [
            ("$select", APP_ROLE_ASSIGNMENT_SELECT),
            ("$top", MAX_PAGE_SIZE),
        ];
        let page: Paged<AppRoleAssignment> = self.get_json(&path, &params, false).await?;
        let all = self.collect_all_pages(page).await?;
        self.cache.put(CacheKind::Permissions, cache_key, &all);
        Ok(all)
    }

    /// Principals (users/groups) assigned **to** this service principal's app
    /// roles — the inbound "who has access" direction (`appRoleAssignedTo`), as
    /// opposed to what the SP itself has been granted (`appRoleAssignments`).
    pub async fn list_app_role_assigned_to(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<AppRoleAssignment>> {
        let path = format!("/servicePrincipals/{service_principal_id}/appRoleAssignedTo");
        // The heaviest paged read in the app: pointed at the Microsoft Graph SP
        // (the audit's `prefetch_graph_app_roles`, the consent view's tenant-wide
        // scan) this collection holds every app-permission grant in the tenant,
        // so the page size decides how many serial round trips run before either
        // surface can score anything. See [`MAX_PAGE_SIZE`].
        let params: [(&str, &str); 2] = [
            ("$select", APP_ROLE_ASSIGNMENT_SELECT),
            ("$top", MAX_PAGE_SIZE),
        ];
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
                    &[
                        ("$select", APP_ROLE_ASSIGNMENT_SELECT),
                        ("$top", MAX_PAGE_SIZE),
                    ],
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
                    &[
                        ("$select", APP_ROLE_ASSIGNMENT_SELECT),
                        ("$top", MAX_PAGE_SIZE),
                    ],
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
        let created = self.send_json(Method::POST, &path, &body).await?;
        self.invalidate_grant_cache();
        Ok(created)
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
            .await?;
        self.invalidate_grant_cache();
        Ok(())
    }

    pub async fn list_oauth2_grants(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<OAuth2PermissionGrant>> {
        let filter = format!("clientId eq '{}'", escape_odata(service_principal_id));
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            ("$select", OAUTH2_GRANT_SELECT),
            ("$top", MAX_PAGE_SIZE),
        ];
        let page: Paged<OAuth2PermissionGrant> = self
            .get_json("/oauth2PermissionGrants", &params, false)
            .await?;
        self.collect_all_pages(page).await
    }

    /// Every delegated permission grant in the tenant (`/oauth2PermissionGrants`,
    /// unfiltered). Used by the consent-grant audit. Follows `@odata.nextLink`.
    pub async fn list_all_oauth2_grants(&self) -> Result<Vec<OAuth2PermissionGrant>> {
        // Read-through cache, same reasoning as `list_app_role_assigned_to`: the
        // audit's `prefetch_admin_consent_grants` and the Delegated-grants lens
        // each walked this tenant-wide collection independently.
        let cache_key = Self::grant_cache_key(&self.tenant_id, "oauth2_all");
        if let Some(cached) = self
            .cache
            .get::<Vec<OAuth2PermissionGrant>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let params: [(&str, &str); 2] = [("$top", MAX_PAGE_SIZE), ("$select", OAUTH2_GRANT_SELECT)];
        let page: Paged<OAuth2PermissionGrant> = self
            .get_json("/oauth2PermissionGrants", &params, false)
            .await?;
        let all = self.collect_all_pages(page).await?;
        self.cache.put(CacheKind::Permissions, cache_key, &all);
        Ok(all)
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
        let created = self.send_json(Method::POST, &path, &body).await?;
        self.invalidate_grant_cache();
        Ok(created)
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
            .await?;
        self.invalidate_grant_cache();
        Ok(())
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
        let created = self
            .send_json(Method::POST, "/oauth2PermissionGrants", grant)
            .await?;
        self.invalidate_grant_cache();
        Ok(created)
    }

    /// PATCHes the `scope` field of an existing oauth2PermissionGrant. Used
    /// when admin consent needs to add scopes to a grant that already exists.
    pub async fn update_oauth2_grant_scope(&self, grant_id: &str, scope: &str) -> Result<()> {
        let path = format!("/oauth2PermissionGrants/{grant_id}");
        let body = serde_json::json!({ "scope": scope });
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await?;
        self.invalidate_grant_cache();
        Ok(())
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
            .await?;
        self.invalidate_grant_cache();
        Ok(())
    }

    /// Ensures an admin-consent OAuth2 grant exists for `(client_sp_id,
    /// resource_sp_id)` and covers every scope in `desired_scopes`. Returns
    /// the final grant (either newly created or updated). Idempotent.
    ///
    /// Reads the client's grant collection itself, so a caller upserting for
    /// **several** resources in a row should read it once and use
    /// [`Self::upsert_admin_oauth2_grant_in`] instead.
    pub async fn upsert_admin_oauth2_grant(
        &self,
        client_sp_id: &str,
        resource_sp_id: &str,
        desired_scopes: &[&str],
    ) -> Result<OAuth2PermissionGrant> {
        let existing = self.list_oauth2_grants(client_sp_id).await?;
        self.upsert_admin_oauth2_grant_in(client_sp_id, resource_sp_id, desired_scopes, &existing)
            .await
    }

    /// [`Self::upsert_admin_oauth2_grant`] against an **already-read** grant
    /// list, so a per-resource upsert loop doesn't re-read the client's whole
    /// `/oauth2PermissionGrants` collection on every iteration — the same hoist
    /// the admin-consent path already applies to `appRoleAssignments` on its
    /// Role branch.
    ///
    /// `existing_grants` may go stale as the loop writes, but only for the
    /// resource just upserted: the match is `resourceId` + `AllPrincipals`, and
    /// an application declares each resource at most once, so no later iteration
    /// reads an entry this one wrote.
    pub async fn upsert_admin_oauth2_grant_in(
        &self,
        client_sp_id: &str,
        resource_sp_id: &str,
        desired_scopes: &[&str],
        existing_grants: &[OAuth2PermissionGrant],
    ) -> Result<OAuth2PermissionGrant> {
        if let Some(existing) = existing_grants
            .iter()
            .find(|g| g.resource_id == resource_sp_id && g.consent_type == "AllPrincipals")
            .cloned()
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
