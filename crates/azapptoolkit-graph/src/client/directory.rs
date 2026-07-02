use super::*;

impl GraphClient {
    /// Lists the SCIM provisioning (synchronization) jobs for a service
    /// principal. Requires a `Synchronization.Read.All` token (see
    /// [`Self::with_sync_token`]). `NotFound` (404) means provisioning isn't
    /// configured; the caller treats that as an empty result.
    pub async fn list_synchronization_jobs(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<SynchronizationJob>> {
        let token = self.sync_token()?;
        let url = format!(
            "{}/servicePrincipals/{service_principal_id}/synchronization/jobs",
            self.base_url
        );
        let page: Paged<SynchronizationJob> = self.scoped_get(token, &url).await?;
        Ok(page.items)
    }

    /// Directory audit-log entries whose `targetResources` include any of
    /// `object_ids` (the app registration's object id, and optionally its paired
    /// service-principal id), most-recent first, capped at `top`. Requires an
    /// `AuditLog.Read.All` token (see [`Self::with_audit_log_token`]).
    ///
    /// The `targetResources/any(...)` lambda filter is not contractually
    /// guaranteed on Graph v1.0; a tenant that rejects it surfaces as
    /// `GraphError::Api { status: 400, .. }`, which the command catches and
    /// retries unfiltered via [`Self::list_directory_audits`], filtering
    /// client-side. The caller sorts the result; ordering is not requested
    /// server-side (combining `$filter` with `$orderby` is the fragile combo).
    pub async fn list_directory_audits_for_app(
        &self,
        object_ids: &[String],
        top: u32,
    ) -> Result<Vec<DirectoryAuditLog>> {
        let token = self.audit_log_token()?;
        let filter = object_ids
            .iter()
            .filter(|id| !id.is_empty())
            .map(|id| {
                format!(
                    "targetResources/any(t:t/id eq '{}')",
                    id.replace('\'', "''")
                )
            })
            .collect::<Vec<_>>()
            .join(" or ");
        let mut url = url::Url::parse(&format!("{}/auditLogs/directoryAudits", self.base_url))
            .map_err(|e| GraphError::Protocol(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            if !filter.is_empty() {
                qp.append_pair("$filter", &filter);
            }
            qp.append_pair("$top", &top.to_string());
        }
        let page: Paged<DirectoryAuditLog> = self.scoped_get(token, url.as_str()).await?;
        Ok(page.items)
    }

    /// Most-recent `top` directory audit-log entries tenant-wide (no filter).
    /// Used both for a tenant-wide activity feed and as the fallback when the
    /// per-app lambda filter is rejected. Requires an `AuditLog.Read.All` token.
    pub async fn list_directory_audits(&self, top: u32) -> Result<Vec<DirectoryAuditLog>> {
        let token = self.audit_log_token()?;
        let mut url = url::Url::parse(&format!("{}/auditLogs/directoryAudits", self.base_url))
            .map_err(|e| GraphError::Protocol(e.to_string()))?;
        url.query_pairs_mut().append_pair("$top", &top.to_string());
        let page: Paged<DirectoryAuditLog> = self.scoped_get(token, url.as_str()).await?;
        Ok(page.items)
    }

    /// All Conditional Access policies in the tenant (a thin fetch — the caller
    /// decides which apply to a given app). Requires a `Policy.Read.All` token
    /// (see [`Self::with_policy_token`]). Follows `@odata.nextLink` with the same
    /// scoped token, refusing any link to a foreign origin.
    ///
    /// A 404 on the *first* request means the endpoint reports no policies →
    /// `Ok(empty)`. A 404 (or any error) while paging propagates instead of
    /// silently truncating an already-partial result, so the caller never
    /// mistakes "lost auth mid-scan" for "no policies".
    pub async fn list_conditional_access_policies(&self) -> Result<Vec<ConditionalAccessPolicy>> {
        let token = self.policy_token()?;
        let url = format!("{}/identity/conditionalAccess/policies", self.base_url);

        match self.scoped_get(token, &url).await {
            Ok(page) => self
                .collect_pages_from(page, |u| async move { self.scoped_get(token, &u).await })
                .await
                .map_err(|e| match e {
                    GraphError::NotFound(_) => {
                        GraphError::NotFound("conditional-access policies".into())
                    }
                    _ => e,
                }),
            Err(GraphError::NotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// The signed-in user's **active** directory roles (display name +
    /// immutable `roleTemplateId`). Reads
    /// `/me/transitiveMemberOf/microsoft.graph.directoryRole` — the OData cast
    /// keeps only directory roles — via the verb-selected read token
    /// (`Directory.Read.All`, in the sign-in bundle). PIM-eligible-but-inactive
    /// roles do **not** appear (only activated assignments are memberships),
    /// which is exactly the signal the readiness checklist wants: a role the
    /// user must still activate reads as absent. Best-effort — callers that
    /// can't read it (e.g. a tenant restricting directory reads) degrade to "?".
    ///
    /// Callers must match on `role_template_id`, not the display name: the
    /// `directoryRole` objects in long-lived tenants carry legacy names
    /// ("SharePoint Service Administrator", "Company Administrator").
    ///
    /// The OData cast is an advanced query on directory objects, so Graph
    /// rejects it with `400 Request_UnsupportedQuery` unless **both**
    /// `ConsistencyLevel: eventual` and `$count=true` are sent. `id` must be
    /// in the `$select` — Graph returns only the selected properties, and
    /// [`ActiveDirectoryRole`] requires `id` to deserialize.
    pub async fn me_active_directory_roles(&self) -> Result<Vec<ActiveDirectoryRole>> {
        let params: [(&str, &str); 2] = [
            ("$select", "id,displayName,roleTemplateId"),
            ("$count", "true"),
        ];
        let page: Paged<ActiveDirectoryRole> = self
            .get_json(
                "/me/transitiveMemberOf/microsoft.graph.directoryRole",
                &params,
                true,
            )
            .await?;
        Ok(page.items)
    }

    pub async fn get_organization(&self) -> Result<Organization> {
        let params: [(&str, &str); 1] = [("$select", "id,displayName,verifiedDomains")];
        let page: Paged<Organization> = self.get_json("/organization", &params, false).await?;
        page.items
            .into_iter()
            .next()
            .ok_or_else(|| GraphError::NotFound("organization".into()))
    }

    /// Prefix search over users by `userPrincipalName` or `displayName`. Used
    /// by the owner-picker UI.
    pub async fn search_users(&self, prefix: &str) -> Result<Vec<DirectoryObject>> {
        let filter = format!(
            "startswith(userPrincipalName,'{esc}') or startswith(displayName,'{esc}')",
            esc = escape_odata(prefix)
        );
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            ("$top", "20"),
            ("$select", "id,displayName,userPrincipalName"),
        ];
        let page: Paged<DirectoryObject> = self.get_json("/users", &params, false).await?;
        Ok(page.items)
    }

    /// The security/M365 groups a service principal is a direct member of
    /// (`/servicePrincipals/{id}/memberOf/microsoft.graph.group`). The OData
    /// cast is an advanced query on directory objects, so — like
    /// [`Self::me_active_directory_roles`] — it needs **both**
    /// `ConsistencyLevel: eventual` and `$count=true`, and `id` must be in the
    /// `$select` or [`GroupSummary`] fails to deserialize. Reads ride the
    /// verb-selected read token (`Directory.Read.All`); no extra scope needed.
    pub async fn list_service_principal_groups(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<GroupSummary>> {
        let path =
            format!("/servicePrincipals/{service_principal_id}/memberOf/microsoft.graph.group");
        let params: [(&str, &str); 2] = [
            ("$select", "id,displayName,securityEnabled,groupTypes"),
            ("$count", "true"),
        ];
        let page: Paged<GroupSummary> = self.get_json(&path, &params, true).await?;
        self.collect_all_pages(page).await
    }

    /// Batched [`Self::list_service_principal_groups`]: the group memberships of
    /// many SPs in one `$batch` POST per 20. The `memberOf/microsoft.graph.group`
    /// cast is an advanced query, so each sub-request carries its own
    /// `ConsistencyLevel: eventual` header (the outer POST's headers don't reach
    /// batched sub-requests) alongside `$count=true`. Returns each SP's group
    /// list in input order; the rare overflow paginates outside the batch. The
    /// caller treats a per-SP `Err` as "no groups" (matching the un-batched
    /// path's degrade-to-empty), so a tenant that rejects `$count` in a batch
    /// loses group data but never fails the backup.
    pub async fn batch_list_service_principal_groups(
        &self,
        sp_ids: &[String],
    ) -> Result<Vec<Result<Vec<GroupSummary>>>> {
        let urls: Vec<String> = sp_ids
            .iter()
            .map(|id| {
                batch_sub_url(
                    &format!("/servicePrincipals/{id}/memberOf/microsoft.graph.group"),
                    &[
                        ("$select", "id,displayName,securityEnabled,groupTypes"),
                        ("$count", "true"),
                    ],
                )
            })
            .collect();
        let pages: Vec<Result<Paged<GroupSummary>>> = self
            .batch_get_json_with_headers(&urls, &[("ConsistencyLevel", "eventual")])
            .await?;
        self.finish_paged_batch(pages).await
    }

    /// Adds a directory object (here: a service principal) as a member of a
    /// group (`POST /groups/{id}/members/$ref`). The `@odata.id` body is built
    /// from the configured base URL so sovereign clouds (and mock tests) point
    /// at the right Graph host. Rides the `GroupMember.ReadWrite.All` token —
    /// the default write bundle does not cover group membership. Graph rejects
    /// adds to dynamic-membership groups (membership is rule-based) with a 400.
    pub async fn add_group_member(&self, group_id: &str, member_object_id: &str) -> Result<()> {
        let token = self.group_member_token()?;
        let url = format!("{}/groups/{group_id}/members/$ref", self.base_url);
        let body = serde_json::json!({
            "@odata.id": format!("{}/directoryObjects/{member_object_id}", self.base_url),
        });
        self.scoped_send_no_content(token, Method::POST, &url, Some(&body))
            .await
    }

    /// Removes a member from a group
    /// (`DELETE /groups/{id}/members/{member-id}/$ref`). Same token contract
    /// as [`Self::add_group_member`].
    pub async fn remove_group_member(&self, group_id: &str, member_object_id: &str) -> Result<()> {
        let token = self.group_member_token()?;
        let url = format!(
            "{}/groups/{group_id}/members/{member_object_id}/$ref",
            self.base_url
        );
        self.scoped_send_no_content::<()>(token, Method::DELETE, &url, None)
            .await
    }

    /// Display-name prefix search over `/groups`. Used to assign groups to an
    /// enterprise application's roles (group-based access).
    pub async fn search_groups(&self, prefix: &str) -> Result<Vec<DirectoryObject>> {
        let filter = format!(
            "startswith(displayName,'{esc}')",
            esc = escape_odata(prefix)
        );
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            ("$top", "20"),
            ("$select", "id,displayName"),
        ];
        let page: Paged<DirectoryObject> = self.get_json("/groups", &params, false).await?;
        Ok(page.items)
    }

    /// Best-effort fetch of the tenant's service-principal sign-in activity
    /// (Entra **beta** `reports/servicePrincipalSignInActivities`). Requires an
    /// `AuditLog.Read.All` token (see [`Self::with_audit_log_token`]) — the
    /// documented least-privileged scope for this report, **not** `Reports.Read.All`
    /// — plus Entra ID P1/P2 and a supported directory role (Reports Reader /
    /// Security Reader / Security Administrator / Global Reader) on the signed-in
    /// user. Returns `Err` when the token / consent / license / role is missing so
    /// callers degrade gracefully (no sign-in data ⇒ no "unused app" flags).
    /// Follows `@odata.nextLink`. Deliberately bypasses the shared retry/throttle
    /// loop: this is an optional report, and a failure is handled, not retried.
    /// The `nextLink` still rides the privileged `AuditLog.Read.All` bearer and is
    /// attacker-influenced server output, so — like [`Self::get_json_absolute`]
    /// and [`Self::list_conditional_access_policies`] — each page is origin-checked
    /// before the token is attached and the loop is bounded against a cyclic link.
    pub async fn list_service_principal_sign_in_activities(
        &self,
    ) -> Result<Vec<ServicePrincipalSignInActivity>> {
        // Read-through cache: this report is a slow, rate-limited beta endpoint
        // (up to 200 pages) that is fetched whole once per app on the Activity
        // tab AND once by every audit run — all reading the same tenant-wide
        // data. Cache the full Vec per tenant so clicking through N apps (and the
        // audit) collapses to one fetch per TTL window. It's read-only telemetry,
        // so the 60-min Permissions TTL + the sign-out tenant sweep are
        // sufficient invalidation — no mutation makes it stale.
        let cache_key = format!("{}|sp_sign_in_activities", self.tenant_id);
        if let Some(cached) = self
            .cache
            .get::<Vec<ServicePrincipalSignInActivity>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let token = self.audit_log_token()?;

        const MAX_PAGES: usize = 200;
        let mut url = format!(
            "{}/reports/servicePrincipalSignInActivities?$select=appId,lastSignInActivity",
            self.beta_base()
        );
        let mut out = Vec::new();
        let mut pages = 0usize;

        loop {
            if !same_origin(&self.base_url, &url) {
                return Err(GraphError::Protocol(
                    "refusing to follow nextLink to a different origin".into(),
                ));
            }
            if pages >= MAX_PAGES {
                return Err(GraphError::Protocol(
                    "sign-in activity paging exceeded the page limit".into(),
                ));
            }
            let page: Paged<ServicePrincipalSignInActivity> = self.scoped_get(token, &url).await?;
            out.extend(page.items);
            pages += 1;
            match page.next_link {
                Some(next) => url = next,
                None => break,
            }
        }
        self.cache.put(CacheKind::Permissions, cache_key, &out);
        Ok(out)
    }
}
