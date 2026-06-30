use super::*;

/// The security audit's lean SP projection. `score_one` reads only `id` and
/// `accountEnabled` (and matches on `appId`); the full SP for a first-party
/// resource (Microsoft Graph, Office 365 Exchange Online, …) carries hundreds
/// of `appRoles`/`oauth2PermissionScopes` — tens of KB each — so projecting
/// these three fields cuts the audit's largest per-app transfer by 10–100×.
const SP_LEAN_SELECT: &str = "id,appId,accountEnabled";

impl GraphClient {
    /// Returns `None` when the app registration has no backing SP (e.g. a
    /// newly-created single-tenant app before consent).
    pub async fn get_service_principal_by_app_id(
        &self,
        app_id: &str,
    ) -> Result<Option<ServicePrincipal>> {
        let cache_key = self.sp_cache_key(app_id);
        if let Some(cached) = self.cache.get(CacheKind::ServicePrincipal, &cache_key) {
            return Ok(cached);
        }
        let filter = format!("appId eq '{}'", escape_odata(app_id));
        let params: [(&str, &str); 2] = [("$filter", filter.as_str()), ("$top", "1")];
        let page: Paged<ServicePrincipal> =
            self.get_json("/servicePrincipals", &params, false).await?;
        let sp = page.items.into_iter().next();
        self.cache.put(CacheKind::ServicePrincipal, cache_key, &sp);
        Ok(sp)
    }

    /// Lean variant of [`Self::get_service_principal_by_app_id`] for the
    /// security audit: projects only [`SP_LEAN_SELECT`] and caches under a
    /// distinct `|lean` key, so a huge first-party SP is neither transferred
    /// nor cached in full for a scan that needs two fields. The detail pane and
    /// the scoping/tester flows keep the full lookup (and its own cache key),
    /// so the lean object never poisons the full-SP cache.
    pub async fn get_service_principal_by_app_id_lean(
        &self,
        app_id: &str,
    ) -> Result<Option<ServicePrincipal>> {
        let cache_key = self.sp_lean_cache_key(app_id);
        if let Some(cached) = self.cache.get(CacheKind::ServicePrincipal, &cache_key) {
            return Ok(cached);
        }
        let filter = format!("appId eq '{}'", escape_odata(app_id));
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            ("$select", SP_LEAN_SELECT),
            ("$top", "1"),
        ];
        let page: Paged<ServicePrincipal> =
            self.get_json("/servicePrincipals", &params, false).await?;
        let sp = page.items.into_iter().next();
        self.cache.put(CacheKind::ServicePrincipal, cache_key, &sp);
        Ok(sp)
    }

    /// Lists managed-identity service principals in the tenant (system- and
    /// user-assigned). Graph models these as service principals with
    /// `servicePrincipalType eq 'ManagedIdentity'`, so enumerating them for
    /// permission management needs no Azure Resource Graph call.
    pub async fn list_managed_identities(&self) -> Result<Vec<ServicePrincipal>> {
        let params: [(&str, &str); 3] = [
            ("$filter", "servicePrincipalType eq 'ManagedIdentity'"),
            (
                "$select",
                "id,appId,displayName,accountEnabled,servicePrincipalType,alternativeNames",
            ),
            ("$top", "200"),
        ];
        let page: Paged<ServicePrincipal> =
            self.get_json("/servicePrincipals", &params, false).await?;
        self.collect_all_pages(page).await
    }

    /// Tenant-owned service principals that may expose app roles, for the
    /// Grant-access picker's "Tenant app registrations" group. Filters
    /// server-side to `appOwnerOrganizationId == this tenant` — the org's own
    /// apps, excluding Microsoft first-party and foreign multi-tenant SPs (the
    /// same comparison `sp_to_enterprise_dto` uses for `is_foreign_tenant`) —
    /// and projects `appRoles` so the caller can keep only those exposing an
    /// Application role. Sourcing from `/servicePrincipals` (not `/applications`)
    /// guarantees the resource has an SP in the tenant, so the later grant's
    /// `resolve_resource_sp` resolves. `$count=true` + `ConsistencyLevel:
    /// eventual` keep the `eq` filter valid regardless of how the property is
    /// indexed; pagination follows `@odata.nextLink` to exhaustion. Managed
    /// identities match the owner filter but carry no app roles, so the caller's
    /// role filter drops them.
    pub async fn list_tenant_app_role_resources(&self) -> Result<Vec<ServicePrincipal>> {
        // `appOwnerOrganizationId` is an `Edm.Guid`, so its `$filter` literal is
        // **unquoted** (`eq <guid>`) — unlike the `appId` string filter above
        // (`eq '<guid>'`). Quoting a GUID property makes Graph reject the whole
        // request with 400, which the picker silently swallows into an empty
        // group. `self.tenant_id` is the trusted GUID from the auth context.
        let filter = format!("appOwnerOrganizationId eq {}", self.tenant_id);
        let params: [(&str, &str); 4] = [
            ("$filter", filter.as_str()),
            ("$select", "id,appId,displayName,appRoles"),
            ("$count", "true"),
            ("$top", "200"),
        ];
        let page: Paged<ServicePrincipal> =
            self.get_json("/servicePrincipals", &params, true).await?;
        self.collect_all_pages(page).await
    }

    /// Single per-tenant service-principal scan shared by both list views'
    /// pairing joins. Selects the superset of fields the two views need so one
    /// cached enumeration serves the App Registrations list (which joins on
    /// `appId -> id` to render the paired-Enterprise-App arrow) and the
    /// Enterprise Applications list (which renders these rows directly, after
    /// filtering managed identities out client-side).
    ///
    /// Returning *every* SP — rather than a server-side
    /// `servicePrincipalType ne 'ManagedIdentity'` slice — is deliberate: the
    /// App Registrations join needs all SPs, and a single unfiltered result is
    /// what lets both views reuse one cache entry. `$count=true` (and the
    /// `ConsistencyLevel: eventual` it implies) keeps the response shape
    /// identical to the prior index calls; pagination follows
    /// `@odata.nextLink` to exhaustion.
    pub async fn list_service_principals_index(&self) -> Result<Vec<ServicePrincipal>> {
        let params: [(&str, &str); 3] = [
            (
                "$select",
                "id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,createdDateTime",
            ),
            ("$count", "true"),
            ("$top", "999"),
        ];
        let page: Paged<ServicePrincipal> =
            self.get_json("/servicePrincipals", &params, true).await?;
        // The effective first-page size reveals Graph's real `$top` cap for
        // `/servicePrincipals` (documented as 100 in some references, 999 in
        // others): if `first_page` saturates well below 999 while more pages
        // follow, the cap is the smaller value and raising `$top` is a no-op.
        tracing::debug!(
            target = "azapptoolkit::graph",
            first_page = page.items.len(),
            "service-principal index first page"
        );
        // A tenant with more than SP_INDEX_MAX service principals degrades to
        // the first SP_INDEX_MAX rows instead of failing the Enterprise Apps
        // list, the App Registrations pairing join, and global search outright
        // (all three read this one index). Matches the App Registrations list's
        // APPS_MAX bound, so a frontend `len() >= cap` notice reads the same.
        const SP_INDEX_MAX: usize = 10_000;
        let (all, truncated) = self.collect_all_pages_capped(page, SP_INDEX_MAX).await?;
        if truncated {
            tracing::warn!(
                target = "azapptoolkit::graph",
                cap = SP_INDEX_MAX,
                "service-principal index hit the cap; returning the first {SP_INDEX_MAX} \
                 — lists/search cover this subset",
            );
        }
        tracing::debug!(
            target = "azapptoolkit::graph",
            total = all.len(),
            truncated,
            "service-principal index total"
        );
        Ok(all)
    }

    /// Best-effort batch pre-resolution of `app_ids` to their service principals
    /// via Graph `$batch` (one POST per 20), seeding the
    /// [`CacheKind::ServicePrincipal`] cache so a following per-app
    /// [`Self::get_service_principal_by_app_id_lean`] is a cache hit instead of a
    /// round trip — the audit's largest per-app fan-out. Uses the **lean**
    /// projection ([`SP_LEAN_SELECT`]) under the `|lean` cache key, matching the
    /// lean single lookup the audit uses (it never needs the full SP); the
    /// detail pane's full-SP cache is left untouched. Only not-already-cached
    /// ids are fetched, and any error is swallowed: the per-app fallback still
    /// works, so resilience is unchanged.
    pub async fn prewarm_service_principals_lean(&self, app_ids: &[String]) {
        let mut missing: Vec<&String> = app_ids
            .iter()
            .filter(|id| {
                self.cache
                    .get::<Option<ServicePrincipal>>(
                        CacheKind::ServicePrincipal,
                        &self.sp_lean_cache_key(id),
                    )
                    .is_none()
            })
            .collect();
        if missing.is_empty() {
            return;
        }
        // The SP bucket holds at most `max_size` entries (LRU): prewarming past
        // it would evict the earliest entries before the caller's loop reads
        // them, silently re-creating the per-app GETs the prewarm exists to
        // remove. Cap and say so — the remainder resolves per-app, exactly the
        // pre-prewarm behavior.
        let cap = self.cache.config().max_size;
        if missing.len() > cap {
            tracing::info!(
                missing = missing.len(),
                cap,
                "SP prewarm capped at the cache size; the remainder resolves per-app"
            );
            missing.truncate(cap);
        }
        let urls: Vec<String> = missing
            .iter()
            .map(|id| {
                // Build the relative sub-request URL with a properly percent-encoded
                // `$filter` value (spaces/quotes), matching the single lookup's query.
                let mut u = url::Url::parse("https://graph.invalid/servicePrincipals")
                    .expect("static URL parses");
                u.query_pairs_mut()
                    .append_pair("$filter", &format!("appId eq '{}'", escape_odata(id)))
                    .append_pair("$select", SP_LEAN_SELECT)
                    .append_pair("$top", "1");
                format!("/servicePrincipals?{}", u.query().unwrap_or(""))
            })
            .collect();

        let pages: Vec<Result<Paged<ServicePrincipal>>> = match self.batch_get_json(&urls).await {
            Ok(p) => p,
            Err(err) => {
                tracing::debug!(
                    ?err,
                    "SP prewarm batch failed; per-app lookups will resolve"
                );
                return;
            }
        };
        for (id, page) in missing.iter().zip(pages) {
            // A failed sub-request leaves the cache cold; the per-app lookup retries.
            if let Ok(page) = page {
                let sp = page.items.into_iter().next();
                self.cache
                    .put(CacheKind::ServicePrincipal, self.sp_lean_cache_key(id), &sp);
            }
        }
    }

    /// Owners on a service principal — used by the Enterprise Applications
    /// detail pane. Mirrors `list_owners` but targets `/servicePrincipals/{id}`.
    pub async fn list_service_principal_owners(
        &self,
        sp_object_id: &str,
    ) -> Result<Vec<DirectoryObject>> {
        let path = format!("/servicePrincipals/{sp_object_id}/owners");
        let page: Paged<DirectoryObject> = self.get_json(&path, &[], false).await?;
        self.collect_all_pages(page).await
    }

    /// Adds an owner to a service principal (`POST /servicePrincipals/{id}/owners/$ref`).
    /// Mirrors [`add_owner`](Self::add_owner) but targets the SP. Only users can
    /// own a service principal — Graph rejects a group principal here.
    pub async fn add_service_principal_owner(
        &self,
        sp_object_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        let odata_id = format!(
            "{}/directoryObjects/{principal_id}",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({ "@odata.id": odata_id });
        let path = format!("/servicePrincipals/{sp_object_id}/owners/$ref");
        self.send_no_content(Method::POST, &path, Some(&body)).await
    }

    /// Removes an owner from a service principal
    /// (`DELETE /servicePrincipals/{id}/owners/{principal_id}/$ref`).
    pub async fn remove_service_principal_owner(
        &self,
        sp_object_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        let path = format!("/servicePrincipals/{sp_object_id}/owners/{principal_id}/$ref");
        self.send_no_content::<()>(Method::DELETE, &path, None)
            .await
    }

    /// Drops every per-app service-principal cache entry (full **and** `|lean`)
    /// for this client's tenant. The SP cache is keyed by `appId`, but the SP
    /// mutators below only know the SP *object* id, so a targeted single-key
    /// bust isn't possible — sweep the whole `{tenant}|` prefix (the can't-miss
    /// option, matching `commands::applications::invalidate_app_details`). SP
    /// writes are infrequent user-initiated actions and the bucket refills
    /// lazily (the detail pane) or via the batch prewarm (the audit), so the
    /// re-fetch cost is acceptable. Without this, a patched/deleted SP stays
    /// cached up to the 60-min TTL, skewing the audit's `accountEnabled` read and
    /// the app-registration detail pane's paired-SP fields.
    fn invalidate_sp_cache(&self) {
        self.cache
            .invalidate_prefix(CacheKind::ServicePrincipal, &format!("{}|", self.tenant_id));
    }

    /// Creates a service principal for `app_id` if one does not exist. Returns
    /// the SP and whether it was **newly created** — callers bust the Lists
    /// caches (the shared SP index / search corpus) only on first creation,
    /// since that is what adds a row to them. On creation, sweeps this tenant's
    /// SP cache so a `None` cached by an earlier lookup (before the SP existed)
    /// can't survive under the full or `|lean` key.
    pub async fn ensure_service_principal(&self, app_id: &str) -> Result<(ServicePrincipal, bool)> {
        if let Some(existing) = self.get_service_principal_by_app_id(app_id).await? {
            return Ok((existing, false));
        }
        let body = serde_json::json!({ "appId": app_id });
        let sp: ServicePrincipal = self
            .send_json(Method::POST, "/servicePrincipals", &body)
            .await?;
        self.invalidate_sp_cache();
        Ok((sp, true))
    }

    /// Display-name **term** search over `/servicePrincipals` via Graph
    /// `$search` (matches anywhere in the name, not just a prefix), combined
    /// with a `$filter` on the SP kind. When `only_managed_identities` is
    /// `true`, returns only managed-identity SPs; otherwise only enterprise SPs.
    /// `$search` + `$filter` together require the `ConsistencyLevel: eventual`
    /// header, which `get_json(.., true)` sends.
    pub async fn search_service_principals_by_name(
        &self,
        term: &str,
        top: u32,
        only_managed_identities: bool,
    ) -> Result<Vec<ServicePrincipal>> {
        let kind_clause = if only_managed_identities {
            "servicePrincipalType eq 'ManagedIdentity'"
        } else {
            "servicePrincipalType ne 'ManagedIdentity'"
        };
        let search = format!("\"displayName:{}\"", term.replace('"', " "));
        let top_s = top.to_string();
        let params: [(&str, &str); 5] = [
            ("$search", search.as_str()),
            ("$filter", kind_clause),
            (
                "$select",
                "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,alternativeNames",
            ),
            ("$count", "true"),
            ("$top", top_s.as_str()),
        ];
        let page: Paged<ServicePrincipal> =
            self.get_json("/servicePrincipals", &params, true).await?;
        Ok(page.items)
    }

    /// GET `/servicePrincipals/{id}`. Returns `Ok(None)` for 404.
    pub async fn get_service_principal_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<ServicePrincipal>> {
        let path = format!("/servicePrincipals/{object_id}");
        // Explicit `$select` (directoryObject-derived resource) so the detail
        // view's non-default fields are returned reliably.
        let select = default_service_principal_select().join(",");
        let params: [(&str, &str); 1] = [("$select", select.as_str())];
        match self
            .get_json::<ServicePrincipal>(&path, &params, false)
            .await
        {
            Ok(sp) => Ok(Some(sp)),
            Err(GraphError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Batched [`Self::get_service_principal_by_object_id`]: one `$batch` POST
    /// per 20 ids, each sub-result mapped `404 → Ok(None)` so a principal that
    /// vanished between the index read and the backup is `Ok(None)` (skipped),
    /// not an error. Used by the DR backup for both the enterprise-app SP read
    /// (Pass 2) and the managed-identity resource-SP resolves (Pass 3). Returns
    /// one result per input id, in order.
    pub async fn batch_get_service_principals(
        &self,
        object_ids: &[String],
    ) -> Result<Vec<Result<Option<ServicePrincipal>>>> {
        let select = default_service_principal_select().join(",");
        let urls: Vec<String> = object_ids
            .iter()
            .map(|id| batch_sub_url(&format!("/servicePrincipals/{id}"), &[("$select", &select)]))
            .collect();
        let raw: Vec<Result<ServicePrincipal>> = self.batch_get_json(&urls).await?;
        Ok(raw
            .into_iter()
            .map(|r| match r {
                Ok(sp) => Ok(Some(sp)),
                Err(GraphError::NotFound(_)) => Ok(None),
                Err(e) => Err(e),
            })
            .collect())
    }

    /// GET `/servicePrincipals/{id}` selecting only the SSO-relevant fields, as
    /// raw JSON (`preferredSingleSignOnMode` /
    /// `preferredTokenSigningKeyThumbprint` aren't on the typed
    /// [`ServicePrincipal`]). Returns `Ok(None)` for 404.
    pub async fn get_service_principal_sso_fields(
        &self,
        object_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        let path = format!("/servicePrincipals/{object_id}");
        let params: [(&str, &str); 1] = [(
            "$select",
            "id,appId,preferredSingleSignOnMode,preferredTokenSigningKeyThumbprint,keyCredentials,notificationEmailAddresses",
        )];
        match self
            .get_json::<serde_json::Value>(&path, &params, false)
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(GraphError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Replaces a service principal's `tags` array (full-set PATCH). Used to
    /// toggle the `HideApp` tag that controls My Apps portal visibility.
    pub async fn set_service_principal_tags(&self, object_id: &str, tags: &[String]) -> Result<()> {
        let path = format!("/servicePrincipals/{object_id}");
        let body = serde_json::json!({ "tags": tags });
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await?;
        self.invalidate_sp_cache();
        Ok(())
    }

    /// DELETE `/servicePrincipals/{id}`. Removes the enterprise application's
    /// service principal from the tenant. Destructive — deleting a first-party
    /// or foreign-tenant SP can break sign-in or orphan consent, so callers
    /// must guard this behind explicit confirmation.
    pub async fn delete_service_principal(&self, object_id: &str) -> Result<()> {
        let path = format!("/servicePrincipals/{object_id}");
        self.send_no_content::<()>(Method::DELETE, &path, None)
            .await?;
        self.invalidate_sp_cache();
        Ok(())
    }

    /// PATCH `/servicePrincipals/{id}` with a caller-built body. Used to set
    /// `preferredSingleSignOnMode` and `preferredTokenSigningKeyThumbprint`
    /// during SSO setup. Accepts any `Serialize` body (a typed patch struct or
    /// a `serde_json::Value`).
    pub async fn patch_service_principal<B: serde::Serialize>(
        &self,
        object_id: &str,
        body: &B,
    ) -> Result<()> {
        let path = format!("/servicePrincipals/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(body))
            .await?;
        self.invalidate_sp_cache();
        Ok(())
    }

    /// GET `/servicePrincipals/{id}?$select=appRoles`, returning the raw
    /// `appRoles` array. `appRoles` is a full-collection PATCH (see
    /// [`Self::set_service_principal_app_roles`]), and gallery/enterprise SPs
    /// publish a default role (`msiam_access`) with `value: null` plus a
    /// read-only `origin`, so entries are kept as raw JSON to round-trip every
    /// field losslessly for the roles a caller isn't editing. Empty when the SP
    /// exposes no roles.
    pub async fn get_service_principal_app_roles_raw(
        &self,
        object_id: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let path = format!("/servicePrincipals/{object_id}");
        let params: [(&str, &str); 1] = [("$select", "appRoles")];
        let v: serde_json::Value = self.get_json(&path, &params, false).await?;
        Ok(v.get("appRoles")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// PATCH `/servicePrincipals/{id}` replacing the whole `appRoles` collection
    /// (Graph treats `appRoles` as a full replacement, not a delta).
    pub async fn set_service_principal_app_roles(
        &self,
        object_id: &str,
        roles: &[serde_json::Value],
    ) -> Result<()> {
        let body = serde_json::json!({ "appRoles": roles });
        self.patch_service_principal(object_id, &body).await
    }

    /// Looks up a resource SP by app id to resolve permission display names
    /// (appRoles + oauth2PermissionScopes). Result is cached under
    /// [`CacheKind::Permissions`] with the matching TTL.
    pub async fn resolve_resource_sp(
        &self,
        resource_app_id: &str,
    ) -> Result<Option<ServicePrincipal>> {
        let cache_key = self.sp_cache_key(resource_app_id);
        if let Some(cached) = self
            .cache
            .get::<Option<ServicePrincipal>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let filter = format!("appId eq '{}'", escape_odata(resource_app_id));
        let select = "id,appId,displayName,appRoles,oauth2PermissionScopes";
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            ("$select", select),
            ("$top", "1"),
        ];
        let page: Paged<ServicePrincipal> =
            self.get_json("/servicePrincipals", &params, false).await?;
        let sp = page.items.into_iter().next();
        self.cache.put(CacheKind::Permissions, cache_key, &sp);
        Ok(sp)
    }
}
