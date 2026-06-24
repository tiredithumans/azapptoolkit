use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{
    AppRoleAssignment, Application, ApplicationExposeApi, ApplicationServicePrincipal,
    ClaimsMappingPolicy, ConditionalAccessPolicy, DirectoryAuditLog, DirectoryObject,
    FederatedIdentityCredential, GroupSummary, KeyCredential, NewKeyCredential,
    OAuth2PermissionGrant, OAuth2PermissionScope, Organization, Paged, PasswordCredential,
    PreAuthorizedApplication, RequiredResourceAccess, SelfSignedCertificate, ServicePrincipal,
    ServicePrincipalSignInActivity, Site, SitePermission, SynchronizationJob,
};

use azapptoolkit_core::http_retry::{
    BASE_DELAY_MS, MAX_RETRIES, next_backoff_ms, parse_retry_after_seconds, sleep_before_retry,
    sleep_with_jitter,
};
use azapptoolkit_core::token::BearerProvider;

use crate::error::{GraphError, Result};

/// Microsoft Graph v1 base URL. Overridable for tests.
pub const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";

const CONSISTENCY_LEVEL: HeaderName = HeaderName::from_static("consistencylevel");

/// Observer fired on every 429 (or 5xx retry) the client handles. Consumers
/// use this to back off concurrency when a tenant is under pressure; the
/// retry middleware inside `send_core` still honors `Retry-After` on a
/// per-request basis independently.
pub trait ThrottleObserver: Send + Sync {
    fn on_throttle(&self, retry_after_secs: Option<u64>);
}

mod applications;
mod batch;
mod credentials;
mod directory;
mod policies;
mod roles_grants;
mod service_principals;
mod sharepoint;
#[cfg(test)]
mod tests;

pub struct GraphClient {
    http: reqwest::Client,
    /// Tenant this client talks to. Used to scope cache keys: the
    /// `ServicePrincipal` and `Permissions` caches live in the single
    /// `Arc<Cache>` shared by every per-tenant client (see `AppState`), but a
    /// service principal's object `id` is tenant-specific and is used to join
    /// runtime grants — so those entries must be tenant-prefixed or they
    /// mis-join across tenants. Mirrors the `"{tenant}|…"` convention the list
    /// caches already use.
    tenant_id: String,
    /// Read-only token (`Directory.Read.All`), used for every GET.
    read_token: Arc<dyn BearerProvider>,
    /// Read-write token, used for every mutating request (POST/PATCH/DELETE).
    /// Acquired on demand so a browse-only session never holds write scopes.
    write_token: Arc<dyn BearerProvider>,
    cache: Arc<Cache>,
    base_url: String,
    /// Optional `Synchronization.Read.All` token for the provisioning (SCIM) job
    /// status, acquired on demand. Same graceful-degradation contract as
    /// `audit_log_token`.
    sync_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `AuditLog.Read.All` token for the directory activity / change
    /// log **and** the service-principal sign-in-activity report (the unused-app
    /// audit), acquired on demand. `None`, or a token the tenant hasn't consented
    /// to / lacks the license for, makes those calls fail so the feature degrades
    /// gracefully (no sign-in data ⇒ no "unused app" detection).
    audit_log_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `Policy.Read.All` token for reading Conditional Access policies,
    /// acquired on demand. Same graceful-degradation contract as `audit_log_token`.
    policy_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `Policy.ReadWrite.ApplicationConfiguration` token for creating
    /// and assigning claims-mapping policies (SAML attribute & claim
    /// customization). The default `write_token` (`Application.ReadWrite.All`)
    /// does NOT cover `/policies/claimsMappingPolicies`, so those writes must
    /// ride this scope; acquired on demand (incremental consent).
    policy_write_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `Sites.FullControl.All` token for the SharePoint `Sites.Selected`
    /// model (list/grant/revoke a site's per-app permissions). The verb-selected
    /// `read_token` (`Directory.Read.All`) cannot read `/sites/{id}/permissions`,
    /// and this scope is admin-consent-only, so the SharePoint site-permission
    /// calls ride this token instead of the default read/write pair; acquired on
    /// demand (incremental consent).
    sharepoint_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `GroupMember.ReadWrite.All` token for adding/removing a service
    /// principal as a member of a security group (the `$ref` member endpoints).
    /// Membership *reads* ride the verb-selected `read_token`
    /// (`Directory.Read.All` covers `memberOf`); only the writes need this
    /// admin-consent scope, so it's acquired on demand (incremental consent).
    group_member_token: Option<Arc<dyn BearerProvider>>,
    throttle_observer: parking_lot::RwLock<Option<Arc<dyn ThrottleObserver>>>,
}

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
    /// Full replacement of the application's declared permissions. Graph
    /// treats this as a set-operation — every call overwrites the existing
    /// array, so callers must send the full desired state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_resource_access: Option<Vec<RequiredResourceAccess>>,
}

/// Body for `POST /applications/{id}/federatedIdentityCredentials`. `audiences`
/// defaults to `["api://AzureADTokenExchange"]` (the value Entra recommends for
/// token exchange; only the "Other issuer" flow may override it). `description`
/// is serialized even when `None` (as JSON `null`), matching the prior
/// hand-built body.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedCredentialRequest {
    pub name: String,
    pub issuer: String,
    pub subject: String,
    pub audiences: Vec<String>,
    pub description: Option<String>,
}

/// Body for `PATCH /applications/{id}/federatedIdentityCredentials/{ficId}`.
/// Graph rejects attempts to change `name` (it is immutable), so the field is
/// deliberately absent. `description: None` serializes as JSON `null` to clear
/// a previously-set description.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedCredentialPatch {
    pub issuer: String,
    pub subject: String,
    pub audiences: Vec<String>,
    pub description: Option<String>,
}

/// `PATCH /servicePrincipals/{id}` setting the single-sign-on mode (e.g. `saml`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipalSsoModePatch {
    pub preferred_single_sign_on_mode: String,
}

/// `PATCH /servicePrincipals/{id}` activating a token-signing certificate (by
/// thumbprint) as the preferred SAML signing key.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipalSigningKeyPatch {
    pub preferred_token_signing_key_thumbprint: String,
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

impl GraphClient {
    pub fn new(
        tenant_id: impl Into<String>,
        read_token: Arc<dyn BearerProvider>,
        write_token: Arc<dyn BearerProvider>,
        cache: Arc<Cache>,
    ) -> Self {
        Self::with_base_url(tenant_id, read_token, write_token, cache, GRAPH_BASE)
    }

    pub fn with_base_url(
        tenant_id: impl Into<String>,
        read_token: Arc<dyn BearerProvider>,
        write_token: Arc<dyn BearerProvider>,
        cache: Arc<Cache>,
        base_url: impl Into<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("azapptoolkit/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest client builds");
        Self {
            http,
            tenant_id: tenant_id.into(),
            read_token,
            write_token,
            cache,
            base_url: base_url.into(),
            sync_token: None,
            audit_log_token: None,
            policy_token: None,
            policy_write_token: None,
            sharepoint_token: None,
            group_member_token: None,
            throttle_observer: parking_lot::RwLock::new(None),
        }
    }

    /// Attaches a `Synchronization.Read.All` token enabling provisioning status.
    pub fn with_sync_token(mut self, token: Arc<dyn BearerProvider>) -> Self {
        self.sync_token = Some(token);
        self
    }

    /// Attaches an `AuditLog.Read.All` token enabling the directory activity log.
    pub fn with_audit_log_token(mut self, token: Arc<dyn BearerProvider>) -> Self {
        self.audit_log_token = Some(token);
        self
    }

    /// Attaches a `Policy.Read.All` token enabling Conditional Access reads.
    pub fn with_policy_token(mut self, token: Arc<dyn BearerProvider>) -> Self {
        self.policy_token = Some(token);
        self
    }

    /// Attaches a `Policy.ReadWrite.ApplicationConfiguration` token enabling
    /// claims-mapping-policy create/assign (SAML claim customization).
    pub fn with_policy_write_token(mut self, token: Arc<dyn BearerProvider>) -> Self {
        self.policy_write_token = Some(token);
        self
    }

    /// Attaches a `Sites.FullControl.All` token enabling the SharePoint
    /// `Sites.Selected` site-permission list/grant/revoke calls.
    pub fn with_sharepoint_token(mut self, token: Arc<dyn BearerProvider>) -> Self {
        self.sharepoint_token = Some(token);
        self
    }

    /// Attaches a `GroupMember.ReadWrite.All` token enabling group-membership
    /// add/remove for service principals.
    pub fn with_group_member_token(mut self, token: Arc<dyn BearerProvider>) -> Self {
        self.group_member_token = Some(token);
        self
    }

    /// GET an absolute URL with an explicit (non-default) bearer token, decoding
    /// the JSON body. Used for optional, separately-scoped reads (provisioning,
    /// reports) that bypass the verb-selected read/write token. Maps HTTP errors
    /// to typed `GraphError`s so callers can degrade gracefully (e.g. 404 =
    /// feature not configured, 403 = missing scope/license).
    async fn scoped_get<T: DeserializeOwned>(
        &self,
        token: &Arc<dyn BearerProvider>,
        url: &str,
    ) -> Result<T> {
        let bearer = token.bearer().await.map_err(GraphError::Token)?;
        let resp = self
            .http
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {bearer}"))
            .send()
            .await
            .map_err(|e| GraphError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(match code {
                401 => GraphError::Unauthorized,
                403 => GraphError::Forbidden(body),
                404 => GraphError::NotFound(body),
                _ => GraphError::Api { status: code, body },
            });
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| GraphError::Network(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// GET an absolute URL with an explicit (non-default) bearer token through
    /// the retrying transport ([`Self::send_core_url_with`]), decoding the JSON
    /// body. High-volume scoped reads — the SharePoint site sweep fans
    /// [`Self::list_site_permissions`] out across thousands of sites against
    /// the throttle-happiest endpoint family — ride this so transient 429s/5xx
    /// are absorbed with `Retry-After` honored exactly, instead of surfacing as
    /// phantom per-site failures. One-off feature probes that prefer to degrade
    /// fast keep using the single-shot [`Self::scoped_get`].
    async fn scoped_get_retried<T: DeserializeOwned>(
        &self,
        token: &Arc<dyn BearerProvider>,
        url: &str,
    ) -> Result<T> {
        let bytes = self
            .send_core_url_with(token, Method::GET, url, &[], false, None)
            .await?;
        serde_json::from_slice(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// POST/PATCH an absolute URL with an explicit (non-default) bearer token,
    /// decoding the JSON response. The non-GET sibling of [`Self::scoped_get`]
    /// — used for writes that need a separately-scoped token (claims-mapping
    /// policies on `policy_write_token`) rather than the verb-selected
    /// read/write token. Maps HTTP errors to typed `GraphError`s. Like
    /// `scoped_get`, this deliberately skips the retry/throttle loop — these are
    /// one-shot configuration writes, not high-volume reads.
    async fn scoped_send_json<B, T>(
        &self,
        token: &Arc<dyn BearerProvider>,
        method: Method,
        url: &str,
        body: &B,
    ) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let bytes = self
            .scoped_send_core(token, method, url, Some(body))
            .await?;
        serde_json::from_slice(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// Scoped POST/PATCH/DELETE with no decoded response (the `$ref` assignment
    /// and `$ref` removal endpoints return 204).
    async fn scoped_send_no_content<B>(
        &self,
        token: &Arc<dyn BearerProvider>,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<()>
    where
        B: Serialize + ?Sized,
    {
        let _ = self.scoped_send_core(token, method, url, body).await?;
        Ok(())
    }

    /// Shared transport for the scoped (explicit-token) write helpers above.
    async fn scoped_send_core<B>(
        &self,
        token: &Arc<dyn BearerProvider>,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<bytes::Bytes>
    where
        B: Serialize + ?Sized,
    {
        let bearer = token.bearer().await.map_err(GraphError::Token)?;
        let mut req = self
            .http
            .request(method, url)
            .header(AUTHORIZATION, format!("Bearer {bearer}"));
        if let Some(b) = body {
            let value =
                serde_json::to_value(b).map_err(|e| GraphError::Deserialize(e.to_string()))?;
            req = req.json(&value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| GraphError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(match code {
                401 => GraphError::Unauthorized,
                403 => GraphError::Forbidden(body),
                404 => GraphError::NotFound(body),
                _ => GraphError::Api { status: code, body },
            });
        }
        resp.bytes()
            .await
            .map_err(|e| GraphError::Network(e.to_string()))
    }

    /// Tenant-scoped cache key for service-principal lookups. See the
    /// `tenant_id` field doc for why these caches must be partitioned by tenant.
    fn sp_cache_key(&self, app_id: &str) -> String {
        format!("{}|{}", self.tenant_id, app_id)
    }

    /// Cache key for the audit's lean SP projection. Distinct `|lean` suffix so
    /// the three-field object never collides with — or overwrites — the full SP
    /// the detail pane caches under [`Self::sp_cache_key`].
    fn sp_lean_cache_key(&self, app_id: &str) -> String {
        format!("{}|{}|lean", self.tenant_id, app_id)
    }

    pub fn set_throttle_observer(&self, observer: Arc<dyn ThrottleObserver>) {
        *self.throttle_observer.write() = Some(observer);
    }

    pub fn clear_throttle_observer(&self) {
        *self.throttle_observer.write() = None;
    }

    /// Follows `@odata.nextLink` from an initial page until exhausted,
    /// concatenating every page's items. Collection endpoints that can exceed
    /// Graph's default page size use this so they don't silently truncate.
    ///
    /// Hard-errors past [`MAX_PAGES`], which is the right guard for the
    /// *small* collections that use it (owners, role assignments, grants,
    /// directory reads) — 200 pages there means a cyclic/pathological
    /// `nextLink`, not a real tenant. The tenant-wide index scans that *can*
    /// legitimately be huge use [`Self::collect_all_pages_capped`] instead, so
    /// a large tenant degrades to a truncated list rather than an outright
    /// failure.
    async fn collect_all_pages<T: DeserializeOwned>(&self, mut page: Paged<T>) -> Result<Vec<T>> {
        // Bound a pathological/cyclic nextLink; legitimate paging is far under
        // this. (Origin safety is enforced by `get_json_absolute`'s same-origin
        // check.) Mirrors `list_conditional_access_policies`.
        const MAX_PAGES: usize = 200;
        let mut out = Vec::new();
        out.append(&mut page.items);
        let mut pages = 1;
        while let Some(next) = page.next_link.take() {
            if pages >= MAX_PAGES {
                return Err(GraphError::Protocol(
                    "paging exceeded the page limit".into(),
                ));
            }
            page = self.get_json_absolute(&next).await?;
            out.append(&mut page.items);
            pages += 1;
        }
        Ok(out)
    }

    /// Like [`Self::collect_all_pages`] but bounds the result to `max_items`
    /// instead of hard-erroring on a high page count. For the tenant-wide
    /// index scans (service principals), a tenant larger than the bound must
    /// degrade to a truncated-but-usable list: failing the Enterprise Apps
    /// list, the App Registrations pairing join, and global search outright is
    /// strictly worse than returning the first N rows. The cap also bounds a
    /// pathological/cyclic `nextLink` (paging stops once `max_items` is
    /// reached), so this needs no separate page guard. Returns
    /// `(items, truncated)` — `truncated` is `true` when rows existed beyond
    /// the cap, so the caller can log/surface that coverage is partial.
    async fn collect_all_pages_capped<T: DeserializeOwned>(
        &self,
        mut page: Paged<T>,
        max_items: usize,
    ) -> Result<(Vec<T>, bool)> {
        let mut out = Vec::new();
        out.append(&mut page.items);
        while out.len() < max_items {
            let Some(next) = page.next_link.take() else {
                // Exhausted within the cap — full coverage.
                return Ok((out, false));
            };
            page = self.get_json_absolute(&next).await?;
            out.append(&mut page.items);
        }
        // Reached the cap. More rows remain iff we overshot the last page or a
        // further nextLink is still pending.
        let truncated = out.len() > max_items || page.next_link.is_some();
        out.truncate(max_items);
        Ok((out, truncated))
    }

    /// Collects all pages from a scoped FETCH closure, following `@odata.nextLink`
    /// until exhausted or the page cap is hit. Each nextLink is origin-checked
    /// before being passed to `fetch_page`, so the bearer token never leaves the
    /// trusted Graph origin.
    async fn collect_pages_from<F, T, Fut>(
        &self,
        mut first_page: Paged<T>,
        mut fetch_page: F,
    ) -> Result<Vec<T>>
    where
        F: FnMut(String) -> Fut + Send,
        Fut: std::future::Future<Output = Result<Paged<T>>> + Send,
        T: DeserializeOwned + Send,
    {
        const MAX_PAGES: usize = 200;
        let mut out = Vec::new();
        out.append(&mut first_page.items);
        let mut page: Paged<T> = first_page;
        let mut pages = 1usize;
        while let Some(next) = page.next_link.take() {
            if !same_origin(&self.base_url, &next) {
                return Err(GraphError::Protocol(
                    "refusing to follow nextLink to a different origin".into(),
                ));
            }
            if pages >= MAX_PAGES {
                return Err(GraphError::Protocol(
                    "paging exceeded the page limit".into(),
                ));
            }
            page = fetch_page(next).await?;
            out.append(&mut page.items);
            pages += 1;
        }
        Ok(out)
    }

    /// Issues a GET against an absolute URL (e.g. an `@odata.nextLink`) and
    /// decodes the response body. All retry + throttle-observer behavior
    /// applies identically to path-relative requests.
    pub async fn get_json_absolute<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        // A `nextLink` is attacker-influenced server output; never send the
        // bearer token to a host other than the one we're already talking to.
        if !same_origin(&self.base_url, url) {
            // Surface only the offending host. The full URL is attacker-
            // influenced (a malicious nextLink in a server response) and may
            // contain tokens, paths, or query material we do not want
            // persisted in logs/audit/error UI.
            let host = url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| "<unparseable>".into());
            return Err(GraphError::Protocol(format!(
                "refusing to follow nextLink to a different origin (host: {host})"
            )));
        }
        // `nextLink` for count/search queries still requires `ConsistencyLevel`
        // so we always attach it — harmless on queries that don't need it.
        let bytes = self
            .send_core_url(Method::GET, url, &[], true, None)
            .await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    // --------- SharePoint Sites.Selected ---------

    /// The `Sites.FullControl.All` token every SharePoint site-permission call
    /// rides (see [`Self::with_sharepoint_token`]). `None` means the optional
    /// scope wasn't wired — surfaced as `Forbidden` so the SharePoint UI can
    /// degrade rather than panic.
    fn sharepoint_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(self.sharepoint_token.as_ref(), "Sites.FullControl.All")
    }

    /// The `GroupMember.ReadWrite.All` token the group-membership writes ride
    /// (see [`Self::with_group_member_token`]). `None` means the optional scope
    /// wasn't wired — surfaced as `Forbidden` so the UI degrades rather than
    /// panics.
    fn group_member_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(
            self.group_member_token.as_ref(),
            "GroupMember.ReadWrite.All",
        )
    }

    /// The `Synchronization.Read.All` token the SCIM provisioning reads ride
    /// (see [`Self::with_sync_token`]). `None` means the optional scope wasn't
    /// wired — surfaced as `Forbidden` so the UI degrades rather than panics.
    fn sync_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(self.sync_token.as_ref(), "Synchronization.Read.All")
    }

    /// The `AuditLog.Read.All` token the directory-audit and sign-in-activity
    /// reads ride (see [`Self::with_audit_log_token`]). `None` means the optional
    /// scope wasn't wired — surfaced as `Forbidden` so the UI degrades rather
    /// than panics.
    fn audit_log_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(self.audit_log_token.as_ref(), "AuditLog.Read.All")
    }

    /// The `Policy.Read.All` token the Conditional Access read rides (see
    /// [`Self::with_policy_token`]). `None` means the optional scope wasn't wired
    /// — surfaced as `Forbidden` so the UI degrades rather than panics.
    fn policy_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(self.policy_token.as_ref(), "Policy.Read.All")
    }

    /// The `Policy.ReadWrite.ApplicationConfiguration` token the claims-mapping
    /// policy writes ride (see [`Self::with_policy_write_token`]). `None` means
    /// the optional scope wasn't wired — surfaced as `Forbidden` so the UI
    /// degrades rather than panics.
    fn policy_write_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(
            self.policy_write_token.as_ref(),
            "Policy.ReadWrite.ApplicationConfiguration",
        )
    }

    /// Unwrap an `Option<&Arc<dyn BearerProvider>>` into a typed error, or return
    /// the inner reference so callers can chain usage.
    fn require_token<'a>(
        &self,
        token: Option<&'a Arc<dyn BearerProvider>>,
        scope_name: &str,
    ) -> Result<&'a Arc<dyn BearerProvider>> {
        token.ok_or_else(|| GraphError::Forbidden(format!("{scope_name} token not configured")))
    }

    /// Beta `reports/servicePrincipalSignInActivities` endpoint, derived from
    /// the configured base so mock tests (which point `base_url` at a local
    /// server) still resolve.
    fn beta_base(&self) -> String {
        if let Some(stripped) = self.base_url.strip_suffix("/v1.0") {
            format!("{stripped}/beta")
        } else {
            self.base_url.clone()
        }
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        consistency_eventual: bool,
    ) -> Result<T> {
        let bytes = self
            .send_core(Method::GET, path, query, consistency_eventual, None)
            .await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// POST/PATCH with a JSON body, returning a decoded response.
    async fn send_json<B, T>(&self, method: Method, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let value =
            serde_json::to_value(body).map_err(|e| GraphError::Deserialize(e.to_string()))?;
        let bytes = self
            .send_core(method, path, &[], false, Some(value))
            .await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// POST/PATCH/DELETE with no response body expected (204 No Content or
    /// empty 200). Returns `Ok(())` on any successful status.
    async fn send_no_content<B>(&self, method: Method, path: &str, body: Option<&B>) -> Result<()>
    where
        B: Serialize + ?Sized,
    {
        let value = match body {
            Some(b) => {
                Some(serde_json::to_value(b).map_err(|e| GraphError::Deserialize(e.to_string()))?)
            }
            None => None,
        };
        let _ = self.send_core(method, path, &[], false, value).await?;
        Ok(())
    }

    async fn send_core(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        consistency_eventual: bool,
        body: Option<serde_json::Value>,
    ) -> Result<bytes::Bytes> {
        let url = format!("{}{path}", self.base_url);
        self.send_core_url(method, &url, query, consistency_eventual, body)
            .await
    }

    /// Like [`send_core`] but operates on a pre-assembled absolute URL. Used
    /// to follow `@odata.nextLink`, which arrives fully qualified. GETs are
    /// read-only; everything else mutates — selecting the token by verb keeps the
    /// least-privilege split (read-only sessions never hold write scopes).
    async fn send_core_url(
        &self,
        method: Method,
        url: &str,
        query: &[(&str, &str)],
        consistency_eventual: bool,
        body: Option<serde_json::Value>,
    ) -> Result<bytes::Bytes> {
        let provider = if method == Method::GET {
            &self.read_token
        } else {
            &self.write_token
        };
        self.send_core_url_with(provider, method, url, query, consistency_eventual, body)
            .await
    }

    /// [`send_core_url`] with an explicit token `provider` — lets a POST that is
    /// semantically a *read* (the `/$batch` endpoint wrapping GET sub-requests)
    /// ride the read token instead of the verb-selected write token.
    async fn send_core_url_with(
        &self,
        provider: &Arc<dyn BearerProvider>,
        method: Method,
        url: &str,
        query: &[(&str, &str)],
        consistency_eventual: bool,
        body: Option<serde_json::Value>,
    ) -> Result<bytes::Bytes> {
        // Fetch the token once: it's valid well past the bounded retry window,
        // so re-fetching on every transient retry would just hammer the auth
        // endpoint. A 401 is non-retryable and surfaces to the caller to re-auth.
        let bearer = provider.bearer().await.map_err(GraphError::Token)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| GraphError::Token(e.to_string()))?,
        );
        if consistency_eventual {
            headers.insert(CONSISTENCY_LEVEL, HeaderValue::from_static("eventual"));
        }
        if body.is_some() {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }

        let mut attempt = 0u32;
        let mut delay_ms = BASE_DELAY_MS;
        // CAE: set once we've re-minted in response to a claims challenge, so a
        // persistent 401 can't loop (the re-mint is outside the transient budget).
        let mut cae_retried = false;
        loop {
            let mut req = self
                .http
                .request(method.clone(), url)
                .headers(headers.clone())
                .query(query);
            if let Some(v) = body.as_ref() {
                req = req.json(v);
            }
            let resp = req.send().await;
            let resp = match resp {
                Ok(r) => r,
                Err(err) => {
                    if attempt < MAX_RETRIES {
                        tracing::warn!(%attempt, ?err, "transport error; retrying");
                        sleep_with_jitter(delay_ms).await;
                        attempt += 1;
                        delay_ms = next_backoff_ms(delay_ms);
                        continue;
                    }
                    return Err(GraphError::Network(err.to_string()));
                }
            };

            let status = resp.status();
            if status.is_success() {
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| GraphError::Network(e.to_string()))?;
                return Ok(bytes);
            }

            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            // Capture the CAE challenge header before the body consumes `resp`.
            let www_authenticate = resp
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let body_text = resp
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            let code = status.as_u16();

            // CAE: a 401 carrying an `insufficient_claims` challenge means the
            // resource now requires a fresher token (e.g. after a revocation or
            // policy change). Re-mint once with the challenge and retry — separate
            // from the transient-retry budget. A non-CAE provider can't satisfy it
            // (its `bearer_with_claims` falls back), so the single-retry guard
            // prevents a loop.
            if code == 401 {
                if !cae_retried
                    && let Some(challenge) =
                        www_authenticate.as_deref().and_then(parse_claims_challenge)
                {
                    match provider.bearer_with_claims(&challenge).await {
                        Ok(bearer) => {
                            headers.insert(
                                AUTHORIZATION,
                                HeaderValue::from_str(&format!("Bearer {bearer}"))
                                    .map_err(|e| GraphError::Token(e.to_string()))?,
                            );
                            cae_retried = true;
                            continue;
                        }
                        Err(e) => tracing::info!(
                            detail = %e,
                            "CAE claims challenge could not be satisfied silently; re-auth needed"
                        ),
                    }
                }
                return Err(GraphError::Unauthorized);
            }
            if code == 403 {
                return Err(GraphError::Forbidden(body_text));
            }
            if code == 404 {
                return Err(GraphError::NotFound(body_text));
            }
            if (400..500).contains(&code) && code != 429 {
                return Err(GraphError::Api {
                    status: code,
                    body: body_text,
                });
            }

            // 429 always notifies the observer, whether or not we end up
            // retrying successfully — the signal is about service pressure.
            if code == 429
                && let Some(observer) = self.throttle_observer.read().as_ref()
            {
                observer.on_throttle(retry_after);
            }

            // Retryable (429, 5xx). An explicit `Retry-After` is waited exactly
            // (no jitter / no 30s clamp); only the no-header path uses backoff.
            if attempt < MAX_RETRIES {
                tracing::warn!(%attempt, status = %status, retry_after_secs = ?retry_after, "transient error; retrying");
                sleep_before_retry(retry_after, delay_ms).await;
                attempt += 1;
                delay_ms = next_backoff_ms(delay_ms);
                continue;
            }

            return if code == 429 {
                Err(GraphError::Throttled {
                    retry_after_secs: retry_after,
                })
            } else {
                Err(GraphError::Server {
                    status: code,
                    body: body_text,
                })
            };
        }
    }
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
    ]
}

/// `$select` projection for a single `ServicePrincipal` read — the full set of
/// fields the typed [`ServicePrincipal`] model deserializes. Directory-object
/// resources (`servicePrincipal` included) need an explicit `$select` to
/// reliably return non-default properties; without it Graph may omit fields the
/// detail view reads (and injects a `@microsoft.graph.tips` nag).
fn default_service_principal_select() -> &'static [&'static str] {
    &[
        "id",
        "appId",
        "displayName",
        "accountEnabled",
        "appRoleAssignmentRequired",
        "servicePrincipalType",
        "passwordCredentials",
        "keyCredentials",
        "appRoles",
        "oauth2PermissionScopes",
        "appOwnerOrganizationId",
        "alternativeNames",
        "tags",
        "createdDateTime",
        "notes",
    ]
}

/// OData single-quoted-string escape: a `'` inside the literal becomes `''`.
/// Applied to every value we interpolate into a `$filter` string literal —
/// both user-typed prefixes (`startswith(...)`) and IDs echoed from Graph
/// (`appId eq '...'`) — as defense-in-depth, even though IDs are GUIDs in
/// practice. Callers should still trust the Graph schema for non-string types.
fn escape_odata(input: &str) -> String {
    input.replace('\'', "''")
}

/// Builds a Graph-version-root-relative sub-request URL (`/applications/{id}?…`)
/// with percent-encoded query values, for the `$batch` helpers. Mirrors the
/// single-call encoding `prewarm_service_principals_lean` does inline, so a
/// batched read's URL is byte-identical to its per-item equivalent. `path` is
/// already-escaped (object ids are GUIDs); only the query values are encoded.
fn batch_sub_url(path: &str, query: &[(&str, &str)]) -> String {
    // A throwaway base just to reuse `url`'s query encoder; the host is never
    // emitted — only `path?query` is returned.
    let mut u = url::Url::parse(&format!("https://graph.invalid{path}"))
        .expect("static base + GUID path parses");
    {
        let mut pairs = u.query_pairs_mut();
        for (k, v) in query {
            pairs.append_pair(k, v);
        }
    }
    match u.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

/// Extracts the base64 CAE claims challenge from a `WWW-Authenticate: Bearer …
/// error="insufficient_claims", claims="<base64>"` header. Returns `None` unless
/// the header signals `insufficient_claims` and carries a non-empty `claims`
/// directive, so an ordinary `401` (expired/invalid token) is not mistaken for a
/// Continuous Access Evaluation challenge.
fn parse_claims_challenge(www_authenticate: &str) -> Option<String> {
    if !www_authenticate.contains("insufficient_claims") {
        return None;
    }
    let after = www_authenticate.split("claims=").nth(1)?.trim_start();
    let value = if let Some(rest) = after.strip_prefix('"') {
        // Quoted form: `claims="<base64>"`.
        rest.split('"').next()?
    } else {
        // Bare form: ends at the next comma/space.
        after.split([',', ' ']).next()?
    }
    .trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// True when `candidate` has the same scheme/host/port as `base`. Used to
/// reject `@odata.nextLink` values that point off the expected Graph origin
/// before the bearer token is attached. Embedded credentials (`user:pass@host`)
/// are rejected outright: `Url::origin()` ignores userinfo, so a link carrying
/// it would otherwise pass the origin compare, and Graph never emits one.
fn same_origin(base: &str, candidate: &str) -> bool {
    match (url::Url::parse(base), url::Url::parse(candidate)) {
        (Ok(b), Ok(c)) => {
            if !c.username().is_empty() || c.password().is_some() {
                return false;
            }
            b.origin() == c.origin()
        }
        _ => false,
    }
}

/// Translates a user-supplied SharePoint URL into the Graph `/sites/...`
/// lookup path used by [`GraphClient::get_site_by_url`].
///
/// A clean site URL (`https://contoso.sharepoint.com/sites/Marketing`) maps to
/// `/sites/{host}:/sites/Marketing`, and the bare tenant root to `/sites/{host}`.
/// But "Copy link" in SharePoint hands users a *document* URL that embeds an app
/// token segment (`/:x:/r/` for Excel, `:w:` Word, `:b:` PDF, `:f:` folder, …),
/// a redirect marker, the document library, the file, and a query string — e.g.
/// `https://contoso.sharepoint.com/:x:/r/sites/Marketing/Shared%20Documents/Book.xlsx?d=w..&web=1`.
/// Passing that through verbatim makes Graph reject the `:x:` segment with
/// `Resource not found for the segment ':x:'`. When an app token is present we
/// strip the decoration and keep only the site collection (managed path + name),
/// which is what the permissions endpoints operate on. URLs without an app token
/// are passed through unchanged so subsite paths keep resolving as before.
fn site_lookup_path(site_url: &str) -> String {
    let trimmed = site_url.trim().trim_end_matches('/');
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    // Drop any query string / fragment (sharing links carry ?d=..&csf=1&web=1&e=..).
    let without_query = without_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let (host, rest) = match without_query.split_once('/') {
        Some((h, p)) => (h, p),
        None => (without_query, ""),
    };
    let mut segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    // A leading `:x:`-style app token marks a document "Copy link" URL.
    if segs
        .first()
        .is_some_and(|s| s.len() >= 2 && s.starts_with(':') && s.ends_with(':'))
    {
        segs.remove(0);
        // Drop the `r` (redirect) / `s` (share) marker that follows the token.
        if segs.first().is_some_and(|s| matches!(*s, "r" | "s")) {
            segs.remove(0);
        }
        // The remaining path runs past the site collection into the document
        // library + file; keep only the managed path and site/personal name.
        if let Some(i) = segs
            .iter()
            .position(|s| matches!(*s, "sites" | "teams" | "personal"))
        {
            segs.truncate(i + 2);
        }
    }
    let rel = segs.join("/");
    if rel.is_empty() {
        format!("/sites/{host}")
    } else {
        format!("/sites/{host}:/{rel}")
    }
}
