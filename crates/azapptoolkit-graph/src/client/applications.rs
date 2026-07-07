use super::*;

#[derive(Debug, Default, Clone)]
pub struct AppListQuery {
    pub search: Option<String>,
    pub top: Option<u32>,
    pub select: Option<Vec<&'static str>>,
    /// `$expand` clause (e.g. `"owners($select=id)"`). Only the audit uses this
    /// (to count owners inline without a per-app round trip); the list views
    /// leave it `None` to keep page payloads lean.
    pub expand: Option<&'static str>,
}

impl AppListQuery {
    pub fn with_search(mut self, s: impl Into<String>) -> Self {
        self.search = Some(s.into());
        self
    }

    pub fn with_top(mut self, n: u32) -> Self {
        self.top = Some(n);
        self
    }

    pub fn with_expand(mut self, expand: &'static str) -> Self {
        self.expand = Some(expand);
        self
    }

    pub fn with_select(mut self, fields: Vec<&'static str>) -> Self {
        self.select = Some(fields);
        self
    }
}

/// Body for `POST /applications`. Only fields set on the request are sent
/// (Graph tolerates missing optional fields).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApplicationRequest {
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Partial update for `PATCH /applications/{id}`. Only fields set on the
/// patch are sent, matching the PS `Update-AzApp` semantics.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Free-text internal notes (the portal's "Internal notes"). An empty string
    /// clears it; `None` leaves it untouched. `skip_serializing_if` means this
    /// can't send an explicit JSON `null`, so callers clear via `Some("")`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Full replacement of the application's declared permissions. Graph
    /// treats this as a set-operation — every call overwrites the existing
    /// array, so callers must send the full desired state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_resource_access: Option<Vec<RequiredResourceAccess>>,
}

/// `implicitGrantSettings` under an application's `web` block: whether the
/// authorization endpoint may issue access / ID tokens directly (the implicit
/// flow). Unset fields are omitted so a partial patch only touches what it sets.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImplicitGrantSettingsPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_access_token_issuance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_id_token_issuance: Option<bool>,
}

/// `web` block of an application patch: reply (redirect) URLs, an optional
/// logout URL, and the implicit-grant flags. Unset fields are omitted so a
/// partial patch only touches what it sets.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationWebPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logout_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implicit_grant_settings: Option<ImplicitGrantSettingsPatch>,
}

/// `spa` block of an application SSO patch: single-page-app redirect URLs.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSpaPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
}

/// `PATCH /applications/{id}` carrying SSO fields (`identifierUris`, `web`,
/// `spa`). Replaces the previously hand-built JSON in the SSO commands; unset
/// fields are omitted so each caller patches only what it provides.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSsoPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<ApplicationWebPatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spa: Option<ApplicationSpaPatch>,
}

/// `api` block of an Expose-an-API patch. Graph treats each array as a **full
/// replacement** — every PATCH overwrites the existing list — so callers
/// re-read live state and send the complete desired set. Unset fields are
/// omitted so a scopes-only patch leaves `preAuthorizedApplications` (and the
/// unmodeled `api` properties) untouched.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiApplicationPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth2_permission_scopes: Option<Vec<OAuth2PermissionScope>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_authorized_applications: Option<Vec<PreAuthorizedApplication>>,
}

/// `PATCH /applications/{id}` carrying the Expose-an-API fields
/// (`identifierUris` + the `api` block). Kept distinct from
/// [`ApplicationSsoPatch`] (which also writes `identifierUris`, but with SAML
/// entity-id semantics); unset fields are omitted so each call patches only
/// what it provides.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationExposeApiPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiApplicationPatch>,
}

/// `publicClient` block of an application patch: mobile / desktop reply
/// (redirect) URLs. Unset fields are omitted so a partial patch only touches
/// what it sets.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationPublicClientPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
}

/// `PATCH /applications/{id}` carrying the Authentication-tab fields: the `web`
/// block (reply URLs + logout URL + implicit-grant flags), the `spa` reply
/// URLs, the `publicClient` (mobile/desktop) reply URLs, and
/// `isFallbackPublicClient` (the portal's "Allow public client flows" toggle).
/// Kept distinct from [`ApplicationSsoPatch`] (which is SSO-semantic and used by
/// the SSO commands); unset fields are omitted so each save patches only what it
/// provides.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationAuthenticationPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<ApplicationWebPatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spa: Option<ApplicationSpaPatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_client: Option<ApplicationPublicClientPatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_fallback_public_client: Option<bool>,
}

fn default_application_select() -> &'static [&'static str] {
    &[
        "id",
        "appId",
        "displayName",
        "description",
        "signInAudience",
        "publisherDomain",
        "createdDateTime",
        "passwordCredentials",
        "keyCredentials",
        "requiredResourceAccess",
        "verifiedPublisher",
        "servicePrincipalLockConfiguration",
        "isFallbackPublicClient",
        "notes",
    ]
}

/// `$select` for the DR backup's single-shot app read: the typed-model fields
/// **plus** the Authentication (`web`/`spa`/`publicClient`) and Expose-an-API
/// (`identifierUris`/`api`) blocks the per-tab paths fetch separately, so one
/// GET (or one `$batch` sub-request) captures an app's whole configuration.
/// Shared by the single and batched backup reads so their projections can't drift.
const APP_BACKUP_SELECT: &str = "id,appId,displayName,description,signInAudience,publisherDomain,\
     createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess,\
     isFallbackPublicClient,web,spa,publicClient,identifierUris,api";

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
            params.push(("$search", search_phrase("displayName", s)));
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
        let params: [(&str, &str); 2] = [("$select", APP_BACKUP_SELECT), ("$expand", "owners")];
        self.get_json(&path, &params, false).await
    }

    /// Batched [`Self::get_application_backup_json`]: one `$batch` POST per 20
    /// object ids instead of an individual GET each, returning one
    /// `Result<serde_json::Value>` per input id **in order**. The DR backup's
    /// Pass-1 fan-out; cuts the round-trip count (and the throttling it triggers)
    /// ~20×. A per-id failure is one `Err` in the vec (the caller skips that
    /// app); a whole-batch failure surfaces as the outer `Err` so the caller can
    /// fall back to per-id reads.
    pub async fn batch_get_applications_backup_json(
        &self,
        object_ids: &[String],
    ) -> Result<Vec<Result<serde_json::Value>>> {
        let urls: Vec<String> = object_ids
            .iter()
            .map(|id| {
                batch_sub_url(
                    &format!("/applications/{id}"),
                    &[("$select", APP_BACKUP_SELECT), ("$expand", "owners")],
                )
            })
            .collect();
        self.batch_get_json(&urls).await
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
        let search = search_phrase("displayName", term);
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

    /// GET `/applications/{id}?$select=appRoles`, returning the raw `appRoles`
    /// array. Entries are kept as raw JSON for the same reason as the service
    /// principal variant (`get_service_principal_app_roles_raw`): `appRoles`
    /// round-trips through a full-collection PATCH and the SAML default role
    /// carries a `value: null` that a typed shape would mangle.
    pub async fn get_application_app_roles_raw(
        &self,
        object_id: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let path = format!("/applications/{object_id}");
        let params: [(&str, &str); 1] = [("$select", "appRoles")];
        let v: serde_json::Value = self.get_json(&path, &params, false).await?;
        Ok(v.get("appRoles")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// PATCH `/applications/{id}` replacing the whole `appRoles` collection. For
    /// an enterprise app backed by a local app registration this is the
    /// canonical home of the roles — Entra mirrors them onto the paired SP.
    pub async fn set_application_app_roles(
        &self,
        object_id: &str,
        roles: &[serde_json::Value],
    ) -> Result<()> {
        let path = format!("/applications/{object_id}");
        let body = serde_json::json!({ "appRoles": roles });
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await
    }
}
