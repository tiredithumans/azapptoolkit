use super::*;

impl GraphClient {
    /// Lists a service principal's SCIM synchronization jobs; a 404 means
    /// provisioning isn't configured (callers treat that as empty). Requires the
    /// `Synchronization.Read.All` token (see [`Self::with_sync_token`]).
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

    /// Directory audit entries whose `targetResources` include any of `object_ids` (the app's
    /// object id, optionally its paired SP id), most-recent first, capped at `top`. Requires the
    /// `AuditLog.Read.All` token (see [`Self::with_audit_log_token`]).
    ///
    /// The `targetResources/any(...)` lambda is not contractually guaranteed on Graph v1.0; a
    /// tenant that rejects it surfaces `GraphError::Api { status: 400, .. }`, which the command
    /// retries unfiltered via [`Self::list_directory_audits`] and filters client-side. The
    /// caller sorts: combining `$filter` with `$orderby` is the fragile combo.
    pub async fn list_directory_audits_for_app(
        &self,
        object_ids: &[String],
        top: u32,
    ) -> Result<Vec<DirectoryAuditLog>> {
        let token = self.audit_log_token()?;
        let filter = object_ids
            .iter()
            .filter(|id| !id.is_empty())
            .map(|id| format!("targetResources/any(t:t/id eq '{}')", escape_odata(id)))
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

    /// Most-recent `top` directory audit entries tenant-wide (no filter) — the activity feed
    /// and the fallback when the per-app lambda filter is rejected. Requires the
    /// `AuditLog.Read.All` token.
    pub async fn list_directory_audits(&self, top: u32) -> Result<Vec<DirectoryAuditLog>> {
        let token = self.audit_log_token()?;
        let mut url = url::Url::parse(&format!("{}/auditLogs/directoryAudits", self.base_url))
            .map_err(|e| GraphError::Protocol(e.to_string()))?;
        url.query_pairs_mut().append_pair("$top", &top.to_string());
        let page: Paged<DirectoryAuditLog> = self.scoped_get(token, url.as_str()).await?;
        Ok(page.items)
    }

    /// All Conditional Access policies (the caller decides which apply to an app). Requires the
    /// `Policy.Read.All` token (see [`Self::with_policy_token`]). Follows `@odata.nextLink` with
    /// the same scoped token, refusing foreign-origin links.
    ///
    /// A 404 on the *first* request means no policies → `Ok(empty)`; a 404 or any error while
    /// paging propagates, so "lost auth mid-scan" is never mistaken for "no policies".
    pub async fn list_conditional_access_policies(&self) -> Result<Vec<ConditionalAccessPolicy>> {
        let token = self.policy_token()?;
        let url = format!(
            "{}/identity/conditionalAccess/policies?$top={MAX_PAGE_SIZE}",
            self.base_url
        );

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

    /// The signed-in user's **active** directory roles (display name + immutable
    /// `roleTemplateId`). Reads `/me/transitiveMemberOf/microsoft.graph.directoryRole` — the
    /// OData cast keeps only directory roles — on the verb-selected read token
    /// (`Directory.Read.All`, in the sign-in bundle). PIM-eligible-but-inactive roles do
    /// **not** appear (only activated assignments are memberships), so a role the user must
    /// still activate reads as absent — exactly the readiness signal. Best-effort: callers
    /// that can't read it (e.g. a tenant restricting directory reads) degrade to "?".
    ///
    /// Match on `role_template_id`, not the display name: long-lived tenants carry legacy names
    /// ("SharePoint Service Administrator", "Company Administrator").
    ///
    /// The OData cast is an advanced query, so Graph rejects it with `400 Request_UnsupportedQuery`
    /// unless **both** `ConsistencyLevel: eventual` and `$count=true` are sent; `id` must be in
    /// the `$select` or [`ActiveDirectoryRole`] fails to deserialize.
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

    /// Exact lookup of one user by `userPrincipalName` (bulk create's Owners
    /// column). A `$filter` rather than `/users/{upn}`: a guest UPN carries
    /// `#EXT#`, which would need path-escaping, and a miss reads as `Ok(None)`
    /// rather than a 404 the caller would have to tell apart from a dead route.
    pub async fn find_user_by_upn(&self, upn: &str) -> Result<Option<DirectoryObject>> {
        let filter = format!("userPrincipalName eq '{}'", escape_odata(upn));
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            ("$top", "1"),
            ("$select", "id,displayName,userPrincipalName"),
        ];
        let page: Paged<DirectoryObject> = self.get_json("/users", &params, false).await?;
        Ok(page.items.into_iter().next())
    }

    /// The security/M365 groups a service principal is a direct member of
    /// (`/servicePrincipals/{id}/memberOf/microsoft.graph.group`). The OData cast is an advanced
    /// query, so — like [`Self::me_active_directory_roles`] — it needs **both**
    /// `ConsistencyLevel: eventual` and `$count=true`, and `id` in the `$select`. Rides the
    /// verb-selected read token (`Directory.Read.All`); no extra scope.
    pub async fn list_service_principal_groups(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<GroupSummary>> {
        let path =
            format!("/servicePrincipals/{service_principal_id}/memberOf/microsoft.graph.group");
        let params: [(&str, &str); 3] = [
            ("$select", "id,displayName,securityEnabled,groupTypes"),
            ("$count", "true"),
            ("$top", MAX_PAGE_SIZE),
        ];
        let page: Paged<GroupSummary> = self.get_json(&path, &params, true).await?;
        self.collect_all_pages(page, true).await
    }

    /// Batched [`Self::list_service_principal_groups`], 20 SPs per `$batch` POST. The cast is an
    /// advanced query, so each sub-request carries its own `ConsistencyLevel: eventual` header
    /// (the outer POST's don't reach batched sub-requests) alongside `$count=true`. Returns each
    /// SP's groups in input order; the rare overflow paginates outside the batch — as an
    /// advanced query too, since Graph does not carry the header into the `nextLink` request.
    /// A per-SP `Err` degrades to "no groups" (matching the un-batched path), so a tenant that
    /// rejects `$count` in a batch loses group data but never fails the backup.
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
                        ("$top", MAX_PAGE_SIZE),
                    ],
                )
            })
            .collect();
        let pages: Vec<Result<Paged<GroupSummary>>> = self
            .batch_get_json_with_headers(&urls, &[("ConsistencyLevel", "eventual")])
            .await?;
        self.finish_paged_batch(pages, true).await
    }

    /// Adds a directory object (here: an SP) to a group (`POST /groups/{id}/members/$ref`);
    /// the `@odata.id` is built from the configured base URL so sovereign clouds (and mocks)
    /// hit the right host. Rides the `GroupMember.ReadWrite.All` token — the default write
    /// bundle does not cover group membership. Graph 400s adds to dynamic-membership groups
    /// (membership is rule-based).
    pub async fn add_group_member(&self, group_id: &str, member_object_id: &str) -> Result<()> {
        let token = self.group_member_token()?;
        let url = format!("{}/groups/{group_id}/members/$ref", self.base_url);
        let body = serde_json::json!({
            "@odata.id": format!("{}/directoryObjects/{member_object_id}", self.base_url),
        });
        self.scoped_send_no_content(token, Method::POST, &url, Some(&body))
            .await
    }

    /// Removes a group member (`DELETE /groups/{id}/members/{member-id}/$ref`); same token
    /// contract as [`Self::add_group_member`].
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

    /// Mail-enabled groups (DLs + mail-enabled security/M365) by display-name prefix, only those
    /// with a mail address — the SSO notification recipient picker. Unlike [`Self::search_groups`],
    /// selects `mail`.
    pub async fn search_distribution_lists(&self, prefix: &str) -> Result<Vec<DirectoryObject>> {
        let filter = format!(
            "mailEnabled eq true and startswith(displayName,'{esc}')",
            esc = escape_odata(prefix)
        );
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            ("$top", "20"),
            ("$select", "id,displayName,mail"),
        ];
        let page: Paged<DirectoryObject> = self.get_json("/groups", &params, false).await?;
        Ok(page
            .items
            .into_iter()
            .filter(|g| g.mail.as_deref().is_some_and(|m| !m.is_empty()))
            .collect())
    }

    /// Best-effort tenant-wide SP sign-in activity (Entra **beta**
    /// `reports/servicePrincipalSignInActivities`). Requires the `AuditLog.Read.All` token (see
    /// [`Self::with_audit_log_token`]) — the documented least-privileged scope, **not**
    /// `Reports.Read.All` — plus Entra ID P1/P2 and a Reports Reader / Security Reader /
    /// Security Administrator / Global Reader role on the signed-in user. `Err` when the token /
    /// consent / license / role is missing, so callers degrade (no data ⇒ no "unused app" flags).
    ///
    /// Deliberately bypasses the shared retry/throttle loop: an optional report — a failure is
    /// handled, not retried. The `nextLink` still rides the privileged bearer and is
    /// attacker-influenced server output, so pages follow via `collect_pages_from` (like
    /// [`Self::get_json_absolute_with`] and [`Self::list_conditional_access_policies`]):
    /// origin-checking each nextLink before the token attaches, bounded at `MAX_PAGES` against
    /// a cyclic link.
    pub async fn list_service_principal_sign_in_activities(
        &self,
    ) -> Result<Vec<ServicePrincipalSignInActivity>> {
        // Read-through cache: a slow, rate-limited beta endpoint (up to 200 pages) fetched whole
        // once per app on the Activity tab AND once by every audit run — the same tenant-wide
        // data. Caching the full Vec per tenant collapses N apps + the audit to one fetch per
        // TTL window; it's read-only telemetry, so the 60-min Permissions TTL + the sign-out
        // sweep are sufficient — no mutation makes it stale.
        let cache_key = format!("{}|sp_sign_in_activities", self.tenant_id);
        if let Some(cached) = self
            .cache
            .get::<Vec<ServicePrincipalSignInActivity>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let token = self.audit_log_token()?;

        // `$top` matters most here: the default page of 100 would make a 10k-SP tenant ~100
        // serial round trips on the slowest, most rate-limited read in the crate. The endpoint
        // documents `$top` support, the size carries into every nextLink, and an over-ask is
        // clamped silently — so it also lifts the shared `MAX_PAGES` ceiling from 20k to ~200k.
        let url = format!(
            "{}/reports/servicePrincipalSignInActivities?$select=appId,lastSignInActivity&$top={MAX_PAGE_SIZE}",
            self.beta_base()
        );
        // `beta_base()` derives from `base_url`, so the first URL is same-origin
        // by construction; the helper checks every nextLink after it.
        let first: Paged<ServicePrincipalSignInActivity> = self.scoped_get(token, &url).await?;
        let out = self
            .collect_pages_from(first, |u| async move { self.scoped_get(token, &u).await })
            .await?;
        self.cache.put(CacheKind::Permissions, cache_key, &out);
        Ok(out)
    }

    /// Tenant-wide **per-credential last-used** report (Entra beta
    /// `reports/appCredentialSignInActivities`, preview, **global cloud only** —
    /// on a sovereign build the host rejects the path and callers degrade, which
    /// is why the capability catalog records the cloud limit). Rides the same
    /// `AuditLog.Read.All` token ([`Self::with_audit_log_token`]) and the same
    /// read-through cache pattern as [`Self::list_service_principal_sign_in_activities`]:
    /// read-only telemetry, one fetch per tenant per TTL window, sign-out sweep
    /// is sufficient staleness handling.
    ///
    /// A credential with no row here is **unknown**, not unused — the preview
    /// report's coverage (does it list never-used credentials?) is not
    /// contractual, and inferring "unused" from absence would flag live
    /// credentials. Callers must only use rows that exist (a present row with a
    /// null date is "no use recorded").
    pub async fn list_app_credential_sign_in_activities(
        &self,
    ) -> Result<Vec<AppCredentialSignInActivity>> {
        let cache_key = format!("{}|app_credential_sign_in_activities", self.tenant_id);
        if let Some(cached) = self
            .cache
            .get::<Vec<AppCredentialSignInActivity>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let token = self.audit_log_token()?;
        // Same `$top` reasoning as the SP report: without it the slow beta
        // endpoint pages at 100/request, and the nextLink cap effectively bounds
        // how much of the report a cold run can read.
        let url = format!(
            "{}/reports/appCredentialSignInActivities?$top={MAX_PAGE_SIZE}",
            self.beta_base()
        );
        let first: Paged<AppCredentialSignInActivity> = self.scoped_get(token, &url).await?;
        let out = self
            .collect_pages_from(first, |u| async move { self.scoped_get(token, &u).await })
            .await?;
        self.cache.put(CacheKind::Permissions, cache_key, &out);
        Ok(out)
    }

    /// Tenant-wide **Identity Protection** risky-service-principal report
    /// (Entra v1.0 `identityProtection/riskyServicePrincipals`). Requires the
    /// `IdentityRiskyServicePrincipal.Read.All` token (see
    /// [`Self::with_risky_sp_token`]) *and* a Workload Identities premium
    /// license — without either the endpoint answers 403, so callers degrade
    /// (no risky data ⇒ no risky-SP audit flags).
    ///
    /// Deliberately one-shot `scoped_get` (no retry) like the other optional
    /// premium reports: a failure is handled by the audit runner, not retried.
    /// Deliberately **not cached**: this is a live security signal — a
    /// compromised-SP flag must be re-read by every audit run, and the payload
    /// is tiny (one row per flagged principal, not the sign-in report's 200
    /// pages), so freshness is cheap here. `nextLink` paging follows via
    /// `collect_pages_from` (origin-checked bearer attachment).
    ///
    /// A 404 on the *first* request means the report is not provisioned →
    /// `Ok(empty)`; errors while paging propagate.
    pub async fn list_risky_service_principals(&self) -> Result<Vec<RiskyServicePrincipal>> {
        let token = self.risky_sp_token()?;
        let url = format!(
            "{}/identityProtection/riskyServicePrincipals?$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        match self.scoped_get(token, &url).await {
            Ok(page) => {
                self.collect_pages_from(page, |u| async move { self.scoped_get(token, &u).await })
                    .await
            }
            Err(GraphError::NotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}
