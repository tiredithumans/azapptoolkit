use super::*;

#[derive(Debug, Default, Clone)]
pub struct AppListQuery {
    pub search: Option<String>,
    pub top: Option<u32>,
    pub select: Option<Vec<&'static str>>,
    /// `$expand` clause (e.g. `"owners($select=id)"`). Only the audit uses it (to count owners
    /// inline, without a per-app round trip); the list views leave it `None` to keep page
    /// payloads lean.
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
    /// Free-form `tags` written at creation. The DR restore stamps its restore
    /// marker here — in the create POST itself, so an app can never exist
    /// without it — which is what lets a re-run find the apps it already
    /// created ([`GraphClient::find_applications_by_tag`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Permissions declared in the create POST itself (bulk create from an
    /// inventory file), so a new app never exists with half its manifest.
    /// Declaration only — no runtime grant is made here.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_resource_access: Vec<RequiredResourceAccess>,
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
    /// Full replacement of the application's declared permissions: Graph overwrites the
    /// existing array on every call, so callers must send the full desired state.
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

/// `PATCH /applications/{id}` carrying SSO fields (`identifierUris`, `web`, `spa`); replaces
/// the previously hand-built JSON in the SSO commands. Unset fields are omitted so each caller
/// patches only what it provides.
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

/// `api` block of an Expose-an-API patch. Graph treats each array as a **full replacement**,
/// so callers re-read live state and send the complete desired set. Unset fields are omitted
/// so a scopes-only patch leaves `preAuthorizedApplications` (and the unmodeled `api`
/// properties) untouched.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiApplicationPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth2_permission_scopes: Option<Vec<OAuth2PermissionScope>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_authorized_applications: Option<Vec<PreAuthorizedApplication>>,
}

/// `PATCH /applications/{id}` carrying the Expose-an-API fields (`identifierUris` + the `api`
/// block). Kept distinct from [`ApplicationSsoPatch`] (which also writes `identifierUris`, but
/// with SAML entity-id semantics). Unset fields are omitted so each call patches only what it
/// provides.
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

/// `PATCH /applications/{id}` carrying the Authentication-tab fields: the `web` block (reply
/// URLs + logout + implicit-grant flags), the `spa` reply URLs, the `publicClient`
/// (mobile/desktop) reply URLs, and `isFallbackPublicClient` (the "Allow public client flows"
/// toggle). Kept distinct from [`ApplicationSsoPatch`] (SSO-semantic, used by the SSO commands);
/// unset fields are omitted so each save patches only what it provides.
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
        // Microsoft's own disable flag (audit Rule 21) — a policy-violation
        // disable is invisible without it, and it is the audit's strongest
        // single signal.
        "disabledByMicrosoftStatus",
        "notes",
    ]
}

/// `$select` for the DR backup's single-shot app read: the typed-model fields **plus** the
/// Authentication (`web`/`spa`/`publicClient`) and Expose-an-API (`identifierUris`/`api`) blocks
/// the per-tab paths fetch separately, so one GET (or one `$batch` sub-request) captures the
/// whole app. Shared by the single and batched backup reads so their projections can't drift.
pub(super) const APP_BACKUP_SELECT: &str = "id,appId,displayName,description,signInAudience,publisherDomain,\
     createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess,\
     isFallbackPublicClient,web,spa,publicClient,identifierUris,api";

/// Page size for `/applications` enumerations. Graph documents the default and **maximum**
/// sizes as 100 and **999**; paging is strictly serial (each request needs the prior
/// response's `@odata.nextLink`), so the page size is a direct divisor of wall-clock time on a
/// full-tenant scan — at the 10 000-app enumeration ceiling, 11 round trips instead of 100.
///
/// Larger pages also *reduce* throttling on the credential-bearing projections: Graph applies a
/// 150-request-per-minute-per-tenant limit specifically to requests that `$select`
/// `keyCredentials`, which the app list, the audit, and the credential dashboard all do.
pub const DEFAULT_APP_PAGE_SIZE: u32 = 999;

/// Safety caps on the two recycle-bin enumerations. Same role as the app-list
/// and SP-index caps: bound memory in pathological tenants and bound the
/// serial paging. Truncation is surfaced (never a silent short list).
pub const DELETED_APPS_MAX: usize = 5_000;
pub const DELETED_SPS_MAX: usize = 10_000;

/// Whether an [`AppListQuery`] is an **advanced query** — i.e. one that must carry
/// `ConsistencyLevel: eventual`.
///
/// Single-sourced because page one and every continuation have to agree: only a `$search` needs
/// it, and `$expand` combined with an advanced query is officially unsupported and "might fail
/// silently" — Graph answers 200 with the expanded property missing. Two copies of this
/// predicate is exactly how page two drifted from page one.
fn is_advanced_query(q: &AppListQuery) -> bool {
    q.search.is_some()
}

impl GraphClient {
    pub async fn list_applications(&self, q: AppListQuery) -> Result<Paged<Application>> {
        let eventual = is_advanced_query(&q);
        let select = q
            .select
            .unwrap_or_else(|| default_application_select().to_vec())
            .join(",");
        let top = q.top.unwrap_or(DEFAULT_APP_PAGE_SIZE).to_string();

        let mut params: Vec<(&str, String)> = vec![("$select", select), ("$top", top)];
        // `$search` on `/applications` is an ADVANCED query: it requires both `$count=true` and
        // `ConsistencyLevel: eventual`. Nothing else here does — so advanced-query mode is
        // scoped to the search path alone.
        //
        // The plain enumerations deliberately send neither:
        //   * `$count` — the `@odata.count` has no reader on this path (the lists report their
        //     own materialized row counts), and it forces every page into advanced-query
        //     handling for a value that is then discarded.
        //   * `$orderby` — sorting is done in the frontend over the cached rows (see
        //     `web-rs/src/views/`), so a server-side sort is wasted work that additionally
        //     conflicts with `$expand`. `list_application_index` omits both for the same reason.
        //
        // This also removes an officially UNSUPPORTED combination on the audit's expanding
        // call: `$expand` is not supported together with advanced queries, and such combinations
        // "might fail silently" rather than erroring.
        if let Some(s) = &q.search {
            // Neutralize double quotes so a term like `Test"App` can't break the
            // `$search` phrase (matches search_applications_by_name).
            params.push(("$search", search_phrase("displayName", s)));
            params.push(("$count", "true".into()));
        }
        if let Some(expand) = q.expand {
            params.push(("$expand", expand.to_string()));
        }
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

    /// One `GET /applications/{id}` for the DR backup: the full backup projection (the
    /// typed-model fields **plus** the Authentication and Expose-an-API blocks the tabs
    /// otherwise fetch separately) and `$expand=owners`, returned as raw JSON. This lets the
    /// backup capture an app's entire configuration in a single round trip instead of the four
    /// reads the per-tab paths make — cutting the backup's Graph call volume (and the throttling
    /// it triggers) sharply. A single-item GET, so no `$orderby`/`ConsistencyLevel` concerns.
    pub async fn get_application_backup_json(&self, object_id: &str) -> Result<serde_json::Value> {
        let path = format!("/applications/{object_id}");
        let params: [(&str, &str); 2] = [("$select", APP_BACKUP_SELECT), ("$expand", "owners")];
        self.get_json(&path, &params, false).await
    }

    /// Batched [`Self::get_application_backup_json`], one `$batch` POST per 20 ids; returns one
    /// `Result<serde_json::Value>` per id **in order**. The DR backup's Pass-1 fan-out; cuts
    /// round trips (and the throttling) ~20×. A per-id failure is one `Err` in the vec (the
    /// caller skips that app); a whole-batch failure is the outer `Err`, so the caller can fall
    /// back to per-id reads.
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

    /// Batched `GET /applications/{id}` projected to what the bulk expired-secret sweep reads
    /// (`id,appId,displayName,passwordCredentials`) — the sweep's **selection** read, so a "Fix
    /// all N" fetches exactly the selected apps instead of walking every page of the tenant and
    /// discarding all but the selection. The projection mirrors the sweep's tenant-walk `$select`
    /// so both read paths see the same fields. One `Result<Application>` per id **in order**; a
    /// per-id failure is one `Err` in the vec, a whole-batch failure the outer `Err` (fall back
    /// to per-id reads).
    pub async fn batch_get_applications_credentials(
        &self,
        object_ids: &[String],
    ) -> Result<Vec<Result<Application>>> {
        let urls: Vec<String> = object_ids
            .iter()
            .map(|id| {
                batch_sub_url(
                    &format!("/applications/{id}"),
                    &[("$select", "id,appId,displayName,passwordCredentials")],
                )
            })
            .collect();
        self.batch_get_json(&urls).await
    }

    /// Every application in the tenant, up to `cap` (a safety against unbounded memory in
    /// pathological tenants; `None` disables), **and whether the cap cut the scan short**.
    ///
    /// The `bool` is deliberately in the return type rather than dropped here: a capped scan is
    /// a partial view of the tenant, and a caller that presents it as complete (a cached "clean"
    /// audit, a bulk sweep reporting how many apps it touched) is making a claim the data does
    /// not support. Forcing each caller to bind the flag makes ignoring it a visible, commented
    /// decision instead of an invisible default — this used to be `let (items, _truncated)`
    /// right here, so no caller could see it at all.
    pub async fn list_applications_all(
        &self,
        q: AppListQuery,
        cap: Option<usize>,
    ) -> Result<(Vec<Application>, bool)> {
        // The SAME predicate page one was issued with. Threading it — rather than letting the
        // paging helper default to `true` — is what stops an `$expand` enumeration silently
        // losing `owners` from page two onward (Graph answers an advanced query that also
        // expands with a 200 and the expanded property simply missing).
        let eventual = is_advanced_query(&q);
        let page = self.list_applications(q).await?;
        // `None` disables the cap: `collect_all_pages_capped` with `usize::MAX` paginates to
        // exhaustion without the hard-error past page limit that `collect_all_pages` raises —
        // the right degradation for a tenant-wide scan.
        self.collect_all_pages_capped(page, cap.unwrap_or(usize::MAX), eventual)
            .await
    }

    /// The tenant's app-registration index: `id`, `appId`, `displayName` for every
    /// registration, paged to exhaustion.
    ///
    /// One projection serves every reader — the pairing joins want `appId -> id`, and the
    /// global search additionally substring-matches the name client-side (Graph OData has no
    /// `contains()` for directory objects, so "match anywhere in the name / a partial GUID" can
    /// only be done in memory over an enumeration like this). One shape is what lets the command
    /// layer cache a single shared entry (`applications::app_name_index_cached`) instead of
    /// re-scanning `/applications` once per surface.
    ///
    /// A bare `$select`, no `$orderby`/`$count`: the result feeds a `HashMap` / in-memory ranker,
    /// so a server-side sort (and the `ConsistencyLevel: eventual` it would require) is wasted
    /// work. `cap` bounds memory in pathological tenants; `None` disables it.
    pub async fn list_application_index_named(
        &self,
        cap: Option<usize>,
    ) -> Result<Vec<Application>> {
        let params: [(&str, &str); 2] =
            [("$select", "id,appId,displayName"), ("$top", MAX_PAGE_SIZE)];
        let page: Paged<Application> = self.get_json("/applications", &params, false).await?;
        // A bare `$select` — not an advanced query, as the `false` above says.
        let (items, _truncated) = self
            .collect_all_pages_capped(page, cap.unwrap_or(usize::MAX), false)
            .await?;
        Ok(items)
    }

    pub async fn list_owners(&self, object_id: &str) -> Result<Vec<DirectoryObject>> {
        let path = format!("/applications/{object_id}/owners");
        let params: [(&str, &str); 1] = [("$top", MAX_PAGE_SIZE)];
        let page: Paged<DirectoryObject> = self.get_json(&path, &params, false).await?;
        self.collect_all_pages(page, false).await
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

    /// Recycle bin: the tenant's deleted app registrations, paged to the cap.
    ///
    /// Returns `(items, truncated)` — a truncated read must never be presented
    /// as the full recycle bin, so the flag crosses to the command layer.
    /// Deliberately NOT cached: the recycle bin is a low-frequency recovery
    /// surface, and a cached stale bin would offer Restore on entries that are
    /// already gone.
    pub async fn list_deleted_applications(
        &self,
        cap: usize,
    ) -> Result<(Vec<DeletedApplication>, bool)> {
        let params: [(&str, &str); 1] = [("$top", MAX_PAGE_SIZE)];
        let page: Paged<DeletedApplication> = self
            .get_json(
                "/directory/deletedItems/microsoft.graph.application",
                &params,
                false,
            )
            .await?;
        self.collect_all_pages_capped(page, cap, false).await
    }

    /// Recycle bin: the tenant's deleted service principals. Only used to pair
    /// the SP cascade onto an app restore (Graph does not cascade-restore the
    /// paired SP), so it rides the same capped collector.
    pub async fn list_deleted_service_principals(
        &self,
        cap: usize,
    ) -> Result<(Vec<DeletedServicePrincipal>, bool)> {
        let params: [(&str, &str); 1] = [("$top", MAX_PAGE_SIZE)];
        let page: Paged<DeletedServicePrincipal> = self
            .get_json(
                "/directory/deletedItems/microsoft.graph.servicePrincipal",
                &params,
                false,
            )
            .await?;
        self.collect_all_pages_capped(page, cap, false).await
    }

    /// Restores one deleted directory object (`POST …/restore`, which answers
    /// 200 with the restored object — discarded here; success is all the
    /// callers need). The `{}` body is deliberate: it carries the
    /// `application/json` Content-Type the documented bodyless-POST form
    /// expects, and a POST is never replayed (`retry_class_for` →
    /// `NonIdempotent`), so a restore can't double-fire.
    pub async fn restore_deleted_item(&self, object_id: &str) -> Result<()> {
        let path = format!("/directory/deletedItems/{object_id}/restore");
        self.send_no_content(Method::POST, &path, Some(&serde_json::json!({})))
            .await
    }

    /// Permanently removes a deleted app (the option the reworded bulk-delete
    /// copy points at). Graph answers 204; the window closes on its own after
    /// ~30 days either way.
    pub async fn purge_deleted_application(&self, object_id: &str) -> Result<()> {
        let path = format!("/directory/deletedItems/microsoft.graph.application/{object_id}");
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

    /// Display-name **term** search over `/applications` via `$search` — matches anywhere in the
    /// name (e.g. "smith" finds "John Smith"), not just as a prefix; `top` caps the rows.
    /// Requires `ConsistencyLevel: eventual`, which `get_json(.., true)` sends.
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

    /// Applications carrying the exact `tag` (`tags/any(t:t eq '…')`, a basic query — no
    /// `ConsistencyLevel` needed). One page capped at 10: callers use this to find an app they
    /// tagged themselves, so more than one hit is an anomaly to refuse, not something to page
    /// through. Selects `createdDateTime` so a caller can prove a hit is its own.
    pub async fn find_applications_by_tag(&self, tag: &str) -> Result<Vec<Application>> {
        let filter = format!("tags/any(t:t eq '{}')", escape_odata(tag));
        let params: [(&str, &str); 3] = [
            ("$filter", filter.as_str()),
            (
                "$select",
                "id,appId,displayName,createdDateTime,passwordCredentials",
            ),
            ("$top", "10"),
        ];
        let page: Paged<Application> = self.get_json("/applications", &params, false).await?;
        Ok(page.items)
    }

    /// GET `/applications/{id}` selecting only the SSO-relevant fields, as raw JSON —
    /// `identifierUris`/`web`/`spa`/`requestSignatureVerification` aren't on the typed
    /// [`Application`] (and aren't in the list `$select`), so the SSO detail tab reads them
    /// directly. `requestSignatureVerification` is the signed-AuthnRequest gate
    /// (`isSignedRequestRequired` + `allowedWeakAlgorithms`); selecting it costs nothing and
    /// its absence is what lets the SSO tab tell "unknown" from "verification off".
    /// `Ok(None)` for 404.
    pub async fn get_application_sso_fields(
        &self,
        object_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        self.get_application_fields_raw(
            object_id,
            "id,appId,identifierUris,web,spa,requestSignatureVerification,groupMembershipClaims",
        )
        .await
    }

    /// GET `/applications/{id}` selecting only the Authentication-tab fields, as raw JSON:
    /// `web`/`spa`/`publicClient` carry the per-platform reply URLs, `web.implicitGrantSettings`
    /// the implicit-grant flags, and `isFallbackPublicClient` the "Allow public client flows"
    /// toggle. Like [`Self::get_application_sso_fields`] these aren't on the typed list shape, so
    /// the Authentication tab reads them directly. `Ok(None)` for 404.
    pub async fn get_application_auth_fields(
        &self,
        object_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        self.get_application_fields_raw(
            object_id,
            "id,appId,isFallbackPublicClient,web,spa,publicClient",
        )
        .await
    }

    /// GET `/applications/{id}` with the given `$select`, as raw JSON; `Ok(None)`
    /// for 404. The one body behind the raw per-tab field readers above.
    async fn get_application_fields_raw(
        &self,
        object_id: &str,
        select: &str,
    ) -> Result<Option<serde_json::Value>> {
        let path = format!("/applications/{object_id}");
        self.get_json_optional(&path, &[("$select", select)]).await
    }

    /// GET `/applications/{id}` selecting only the Expose-an-API fields (`identifierUris` + the
    /// `api` block), typed; like [`Self::get_application_sso_fields`] these aren't on the typed
    /// list shape, so the Expose-an-API tab reads them live. `Ok(None)` for 404.
    pub async fn get_application_expose_api(
        &self,
        object_id: &str,
    ) -> Result<Option<ApplicationExposeApi>> {
        let path = format!("/applications/{object_id}");
        let params: [(&str, &str); 1] = [("$select", "id,appId,identifierUris,api")];
        self.get_json_optional(&path, &params).await
    }

    /// PATCH `/applications/{id}` with Expose-an-API fields. Each array Graph
    /// receives is a full replacement (see [`ApplicationExposeApiPatch`]).
    pub async fn patch_application_expose_api(
        &self,
        object_id: &str,
        body: &ApplicationExposeApiPatch,
    ) -> Result<()> {
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(body))
            .await?;
        // `oauth2PermissionScopes` published here are what the permission
        // picker offers for this resource. Only on the success path.
        self.invalidate_resource_sp_cache();
        Ok(())
    }

    /// Instantiates a non-gallery application from a template, creating a paired application +
    /// service principal in one call. The SSO wizard uses the configured cloud's generic custom
    /// template (`CloudEnvironment::custom_app_template_id` in `azapptoolkit-core`; the id
    /// differs per sovereign cloud). Newly created objects replicate asynchronously, so an
    /// immediate follow-up read/PATCH can 404 briefly — callers wrap subsequent steps in a
    /// `NotFound`-only retry.
    pub async fn instantiate_application_template(
        &self,
        template_id: &str,
        display_name: &str,
    ) -> Result<ApplicationServicePrincipal> {
        let body = serde_json::json!({ "displayName": display_name });
        let path = format!("/applicationTemplates/{template_id}/instantiate");
        self.send_json(Method::POST, &path, &body).await
    }

    /// Fetches the **entire** Entra application gallery (`GET /applicationTemplates`, no
    /// `$filter`) in a handful of round trips, so the caller can cache it once and match
    /// subsequent queries in memory instead of paying a non-indexable `contains(tolower(…))`
    /// server scan per keystroke. (The per-query server-side search this replaced is gone —
    /// `commands::enterprise_application::search_application_templates` ranks against this
    /// cached corpus.)
    ///
    /// Unfiltered, the endpoint honors `Prefer: odata.maxpagesize=2800` (its documented ceiling —
    /// a *filtered* read is capped at 200/page, which is why the per-query path can't page
    /// cheaply), so the ~tens-of-thousands-row catalog arrives in ≈`ceil(total / 2800)` pages.
    /// `$select` trims each row to the picker's fields. Reading needs only a valid Graph token,
    /// and the gallery is tenant-independent.
    pub async fn list_all_application_templates(&self) -> Result<Vec<ApplicationTemplate>> {
        let params: [(&str, &str); 1] = [(
            "$select",
            "id,displayName,publisher,description,categories,logoUrl,supportedSingleSignOnModes",
        )];
        let page: Paged<ApplicationTemplate> = self
            .get_json_prefer("/applicationTemplates", &params, "odata.maxpagesize=2800")
            .await?;
        // `get_json_prefer` issues page 1 as a plain read; so do the rest.
        self.collect_all_pages(page, false).await
    }

    /// PATCH `/applications/{id}` with a caller-built body carrying the SSO fields
    /// (`identifierUris`, `web.redirectUris`, `web.logoutUrl`, `spa.redirectUris`). Kept
    /// separate from the typed `AppPatch` so the widely-used struct stays untouched; accepts any
    /// `Serialize` body (an `ApplicationSsoPatch` or a `serde_json::Value`).
    pub async fn patch_application_web<B: serde::Serialize + Sync>(
        &self,
        object_id: &str,
        body: &B,
    ) -> Result<()> {
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(body)).await
    }

    /// GET `/applications/{id}?$select=appRoles`, returning the raw `appRoles` array. Entries
    /// stay raw JSON for the same reason as the SP variant (`get_service_principal_app_roles_raw`):
    /// `appRoles` round-trips through a full-collection PATCH and the SAML default role carries a
    /// `value: null` that a typed shape would mangle.
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
            .await?;
        // Entra mirrors these onto the paired SP, which is what
        // `resolve_resource_sp` caches. Only on the success path.
        self.invalidate_resource_sp_cache();
        Ok(())
    }
}
