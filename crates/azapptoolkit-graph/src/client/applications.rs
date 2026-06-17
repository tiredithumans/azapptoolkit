use super::*;

impl GraphClient {
    pub async fn list_applications(&self, q: AppListQuery) -> Result<Paged<Application>> {
        let select = q
            .select
            .unwrap_or_else(|| default_application_select().to_vec())
            .join(",");
        let top = q.top.unwrap_or(50).to_string();

        let mut params: Vec<(&str, String)> = vec![
            ("$select", select),
            ("$top", top),
            ("$count", "true".into()),
        ];
        if let Some(s) = &q.search {
            // Neutralize double quotes so a term like `Test"App` can't break the
            // `$search` phrase (matches search_applications_by_name).
            params.push((
                "$search",
                format!("\"displayName:{}\"", s.replace('"', " ")),
            ));
        } else if q.expand.is_none() {
            // Graph rejects `$orderby` together with `$expand` on `/applications`
            // ("Request_UnsupportedQuery: Sorting not supported for 'Application'"),
            // so skip ordering when expanding. Callers that expand (e.g. the
            // security audit, which expands `owners`) sort client-side anyway.
            params.push(("$orderby", "displayName".into()));
        }
        if let Some(expand) = q.expand {
            params.push(("$expand", expand.to_string()));
        }
        // `$orderby` and `$count` on `/applications` are advanced query
        // parameters and require `ConsistencyLevel: eventual`. Without it,
        // Graph returns `Request_UnsupportedQuery: Sorting not supported
        // for 'Application'`.
        let eventual = true;
        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.get_json("/applications", &params_ref, eventual).await
    }

    pub async fn get_application(&self, object_id: &str) -> Result<Application> {
        let path = format!("/applications/{object_id}");
        // Project only the typed model's fields. `application` is a
        // directoryObject-derived resource, so an explicit `$select` is required
        // to reliably return properties outside Graph's limited default subset.
        let select = default_application_select().join(",");
        let params: [(&str, &str); 1] = [("$select", select.as_str())];
        self.get_json(&path, &params, false).await
    }

    /// One `GET /applications/{id}` for the DR backup: selects the full backup
    /// projection (the typed-model fields **plus** the Authentication
    /// `web`/`spa`/`publicClient` and Expose-an-API `identifierUris`/`api`
    /// blocks the tabs otherwise fetch separately) and `$expand`s owners,
    /// returned as raw JSON. This lets the backup capture an app's entire
    /// configuration in a single round trip instead of the four reads
    /// (`get_application` + auth-fields + expose-api + owners) the per-tab paths
    /// make — cutting the backup's Graph call volume (and the throttling it
    /// triggers) sharply. A single-item GET, so no `$orderby`/`ConsistencyLevel`
    /// concerns.
    pub async fn get_application_backup_json(&self, object_id: &str) -> Result<serde_json::Value> {
        let path = format!("/applications/{object_id}");
        let select = "id,appId,displayName,description,signInAudience,publisherDomain,\
                      createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess,\
                      isFallbackPublicClient,web,spa,publicClient,identifierUris,api";
        let params: [(&str, &str); 2] = [("$select", select), ("$expand", "owners")];
        self.get_json(&path, &params, false).await
    }

    /// Fetches every application in the tenant by following `@odata.nextLink`
    /// until exhausted. A safety `cap` argument prevents unbounded memory in
    /// pathological tenants; pass `None` to disable.
    pub async fn list_applications_all(
        &self,
        q: AppListQuery,
        cap: Option<usize>,
    ) -> Result<Vec<Application>> {
        let page = self.list_applications(q).await?;
        // `None` disables the cap: `collect_all_pages_capped` with `usize::MAX`
        // paginates to exhaustion (never reaching the bound) without the
        // hard-error past page limit that `collect_all_pages` raises — the right
        // degradation for a tenant-wide scan.
        let (items, _truncated) = self
            .collect_all_pages_capped(page, cap.unwrap_or(usize::MAX))
            .await?;
        Ok(items)
    }

    /// Returns `(app_id, object_id)` pairs for every app registration in the
    /// tenant, used by the Enterprise Applications list to resolve each SP's
    /// paired App Registration object id. A bare `$select` projection with no
    /// `$orderby`/`$count`: the result feeds a `HashMap`, so a server-side sort
    /// (and the `ConsistencyLevel: eventual` it would require) is wasted work.
    /// `cap` bounds memory in pathological tenants; pass `None` to disable.
    pub async fn list_application_index(
        &self,
        cap: Option<usize>,
    ) -> Result<Vec<(String, String)>> {
        let params: [(&str, &str); 2] = [("$select", "id,appId"), ("$top", "999")];
        let page: Paged<Application> = self.get_json("/applications", &params, false).await?;
        let (items, _truncated) = self
            .collect_all_pages_capped(page, cap.unwrap_or(usize::MAX))
            .await?;
        Ok(items.into_iter().map(|a| (a.app_id, a.id)).collect())
    }

    /// Like [`Self::list_application_index`] but keeps each app registration's
    /// `displayName` alongside `id`/`appId` — the projection the global search
    /// substring-matches client-side. Graph OData has no `contains()` for
    /// directory objects, so "match anywhere in the name / a partial GUID" is
    /// done in memory over this enumeration. `cap` bounds memory in pathological
    /// tenants; pass `None` to disable.
    pub async fn list_application_index_named(
        &self,
        cap: Option<usize>,
    ) -> Result<Vec<Application>> {
        let params: [(&str, &str); 2] = [("$select", "id,appId,displayName"), ("$top", "999")];
        let page: Paged<Application> = self.get_json("/applications", &params, false).await?;
        let (items, _truncated) = self
            .collect_all_pages_capped(page, cap.unwrap_or(usize::MAX))
            .await?;
        Ok(items)
    }

    pub async fn list_owners(&self, object_id: &str) -> Result<Vec<DirectoryObject>> {
        let path = format!("/applications/{object_id}/owners");
        let page: Paged<DirectoryObject> = self.get_json(&path, &[], false).await?;
        self.collect_all_pages(page).await
    }

    pub async fn create_application(&self, body: &CreateApplicationRequest) -> Result<Application> {
        self.send_json(Method::POST, "/applications", body).await
    }

    pub async fn update_application(&self, object_id: &str, patch: &AppPatch) -> Result<()> {
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(patch))
            .await
    }

    pub async fn delete_application(&self, object_id: &str) -> Result<()> {
        let path = format!("/applications/{object_id}");
        self.send_no_content::<()>(Method::DELETE, &path, None)
            .await
    }

    pub async fn add_owner(&self, object_id: &str, principal_id: &str) -> Result<()> {
        let odata_id = format!(
            "{}/directoryObjects/{principal_id}",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({ "@odata.id": odata_id });
        let path = format!("/applications/{object_id}/owners/$ref");
        self.send_no_content(Method::POST, &path, Some(&body)).await
    }

    pub async fn remove_owner(&self, object_id: &str, principal_id: &str) -> Result<()> {
        let path = format!("/applications/{object_id}/owners/{principal_id}/$ref");
        self.send_no_content::<()>(Method::DELETE, &path, None)
            .await
    }

    /// Display-name **term** search over `/applications` via Graph `$search`,
    /// so a term matches anywhere in the name (e.g. "smith" finds "John Smith"),
    /// not just as a prefix. `top` caps the rows returned. Requires the
    /// `ConsistencyLevel: eventual` header, which `get_json(.., true)` sends.
    pub async fn search_applications_by_name(
        &self,
        term: &str,
        top: u32,
    ) -> Result<Vec<Application>> {
        let search = format!("\"displayName:{}\"", term.replace('"', " "));
        let top_s = top.to_string();
        let params: [(&str, &str); 4] = [
            ("$search", search.as_str()),
            ("$select", "id,appId,displayName"),
            ("$count", "true"),
            ("$top", top_s.as_str()),
        ];
        let page: Paged<Application> = self.get_json("/applications", &params, true).await?;
        Ok(page.items)
    }

    /// GET `/applications/{appId-or-objectId}`. Returns `Ok(None)` when Graph
    /// returns 404 (used by the GUID branch of global search).
    pub async fn find_application_by_app_id(&self, app_id: &str) -> Result<Option<Application>> {
        let filter = format!("appId eq '{}'", escape_odata(app_id));
        let params: [(&str, &str); 2] = [("$filter", filter.as_str()), ("$top", "1")];
        let page: Paged<Application> = self.get_json("/applications", &params, false).await?;
        Ok(page.items.into_iter().next())
    }

    /// GET `/applications/{id}` selecting only the SSO-relevant fields, as raw
    /// JSON. `identifierUris` / `web` / `spa` aren't on the typed [`Application`]
    /// (and aren't in the list `$select`), so the SSO detail tab reads them
    /// directly. Returns `Ok(None)` for 404.
    pub async fn get_application_sso_fields(
        &self,
        object_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        let path = format!("/applications/{object_id}");
        let params: [(&str, &str); 1] = [("$select", "id,appId,identifierUris,web,spa")];
        match self
            .get_json::<serde_json::Value>(&path, &params, false)
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(GraphError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// GET `/applications/{id}` selecting only the Authentication-tab fields, as
    /// raw JSON. `web` / `spa` / `publicClient` carry the per-platform reply
    /// (redirect) URLs, `web.implicitGrantSettings` the implicit-grant flags, and
    /// `isFallbackPublicClient` the "Allow public client flows" toggle. Like
    /// [`Self::get_application_sso_fields`] these aren't on the typed
    /// [`Application`] list shape, so the Authentication tab reads them directly.
    /// Returns `Ok(None)` for 404.
    pub async fn get_application_auth_fields(
        &self,
        object_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        let path = format!("/applications/{object_id}");
        let params: [(&str, &str); 1] = [(
            "$select",
            "id,appId,isFallbackPublicClient,web,spa,publicClient",
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

    /// GET `/applications/{id}` selecting only the Expose-an-API fields
    /// (`identifierUris` + the `api` block), typed. Like
    /// [`Self::get_application_sso_fields`] these aren't on the typed
    /// [`Application`] list shape, so the Expose an API tab reads them live.
    /// Returns `Ok(None)` for 404.
    pub async fn get_application_expose_api(
        &self,
        object_id: &str,
    ) -> Result<Option<ApplicationExposeApi>> {
        let path = format!("/applications/{object_id}");
        let params: [(&str, &str); 1] = [("$select", "id,appId,identifierUris,api")];
        match self
            .get_json::<ApplicationExposeApi>(&path, &params, false)
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(GraphError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// PATCH `/applications/{id}` with Expose-an-API fields. Each array Graph
    /// receives is a full replacement (see [`ApplicationExposeApiPatch`]).
    pub async fn patch_application_expose_api(
        &self,
        object_id: &str,
        body: &ApplicationExposeApiPatch,
    ) -> Result<()> {
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(body)).await
    }

    /// Instantiates a non-gallery application from an application template,
    /// creating a paired application + service principal in one call. The SSO
    /// wizard always uses the generic custom template
    /// (`8adf8e6e-67b2-4cf2-a259-e3dc5476c621`). Newly created objects replicate
    /// asynchronously, so an immediate follow-up read/PATCH can 404 briefly —
    /// callers wrap subsequent steps in a `NotFound`-only retry.
    pub async fn instantiate_application_template(
        &self,
        template_id: &str,
        display_name: &str,
    ) -> Result<ApplicationServicePrincipal> {
        let body = serde_json::json!({ "displayName": display_name });
        let path = format!("/applicationTemplates/{template_id}/instantiate");
        self.send_json(Method::POST, &path, &body).await
    }

    /// PATCH `/applications/{id}` with a caller-built body carrying the SSO
    /// fields (`identifierUris`, `web.redirectUris`, `web.logoutUrl`,
    /// `spa.redirectUris`). Kept separate from the typed `AppPatch` so the
    /// widely-used struct stays untouched. Accepts any `Serialize` body (an
    /// `ApplicationSsoPatch` or a `serde_json::Value`).
    pub async fn patch_application_web<B: serde::Serialize>(
        &self,
        object_id: &str,
        body: &B,
    ) -> Result<()> {
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(body)).await
    }
}
