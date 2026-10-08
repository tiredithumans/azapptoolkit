use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{
    ActiveDirectoryRole, AdminConsentRequestPolicy, AppCredentialSignInActivity,
    AppManagementPolicy, AppRoleAssignment, Application, ApplicationExposeApi,
    ApplicationServicePrincipal, ApplicationTemplate, ClaimsMappingPolicy, ConditionalAccessPolicy,
    CustomClaimsPolicy, DeletedApplication, DeletedServicePrincipal, DirectoryAuditLog,
    DirectoryObject, Drive, DriveItem, FederatedIdentityCredential, GroupSummary, NewKeyCredential,
    OAuth2PermissionGrant, OAuth2PermissionScope, Organization, Paged, PasswordCredential,
    PreAuthorizedApplication, RequiredResourceAccess, ResolvedSharePointResource,
    RiskyServicePrincipal, SelectedPermission, SelfSignedCertificate, ServicePrincipal,
    ServicePrincipalSignInActivity, Site, SiteList, SitePermission, SynchronizationJob,
    TenantAppManagementPolicy,
};
use azapptoolkit_core::scoping::SelectedScopeLevel;
use url::Url;

use azapptoolkit_core::http_retry::{
    Attempt, RetryClass, RetryReason, parse_retry_after_seconds, with_retries,
};
use azapptoolkit_core::net::same_origin;
use azapptoolkit_core::token::BearerProvider;

use crate::error::{GraphError, Result};

/// Microsoft Graph v1 base URL. Overridable for tests.
pub const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";

/// `$top` for the directory collections this client pages through — Graph's documented
/// maximum for them.
///
/// Omitting `$top` leaves Graph on its **default page size of 100**, and paging is strictly
/// serial, so the page size is a direct divisor of wall-clock time on every tenant-wide or
/// fanned-out read — dominated by `appRoleAssignedTo` on the Microsoft Graph service principal,
/// a tenant-wide collection the audit and the consent view both walk end-to-end before scoring.
///
/// Graph's real per-endpoint caps are not always what the reference pages claim (see
/// [`GraphClient::list_service_principals_index`], which logs its effective first-page size for
/// exactly this reason). Asking for more than an endpoint allows is harmless — Graph silently
/// clamps to its own maximum — so this is the safe request everywhere.
pub(crate) const MAX_PAGE_SIZE: &str = "999";

/// Hard cap on the pages any paging helper follows — the cycle guard: a
/// `{"value": [], "@odata.nextLink": "<same url>"}` loop never advances an item cap, so only a
/// page count bounds it. Legitimate paging is far under it (with [`MAX_PAGE_SIZE`] it bounds a
/// read at about 200k rows). One definition, shared by every helper in `transport` and the
/// domain modules.
pub(crate) const MAX_PAGES: usize = 200;

/// Row cap on the shared per-tenant SP index ([`GraphClient::list_service_principals_index`]).
/// Public because its readers — the Enterprise Applications and Managed Identities lists — are
/// filtered subsets that cannot infer truncation from their own row counts; they compare the
/// *index* length against this.
pub const SP_INDEX_MAX: usize = 10_000;

/// Observer fired on every 429 (or 5xx retry) the client handles — consumers use it to back off
/// concurrency when a tenant is under pressure. The retry middleware inside `send_core` still
/// honors per-request `Retry-After` independently.
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
mod transport;

// Request/patch bodies and wire helpers re-exported at their historical `client::` paths:
// src-tauri's imports (`azapptoolkit_graph::client::AppPatch`, …) and the sibling modules'
// `use super::*` both resolve through here, so the module split isn't a caller-visible move.
pub use applications::{
    ApiApplicationPatch, AppListQuery, AppPatch, ApplicationAuthenticationPatch,
    ApplicationExposeApiPatch, ApplicationPublicClientPatch, ApplicationSpaPatch,
    ApplicationSsoPatch, ApplicationWebPatch, CreateApplicationRequest, DEFAULT_APP_PAGE_SIZE,
    DELETED_APPS_MAX, DELETED_SPS_MAX, ImplicitGrantSettingsPatch,
};
pub use credentials::{FederatedCredentialPatch, FederatedCredentialRequest};
pub use service_principals::{ServicePrincipalSigningKeyPatch, ServicePrincipalSsoModePatch};
pub(crate) use transport::{batch_sub_url, escape_odata, not_found_as_none, search_phrase};

pub struct GraphClient {
    http: reqwest::Client,
    /// Tenant this client talks to; scopes the cache keys. The `ServicePrincipal` and
    /// `Permissions` caches live in the single `Arc<Cache>` shared by every per-tenant client
    /// (see `AppState`), and a service principal's object `id` is tenant-specific and joins
    /// runtime grants — so those entries must be tenant-prefixed or they mis-join across
    /// tenants. Mirrors the `"{tenant}|…"` convention the list caches already use.
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
    /// Optional `AuditLog.Read.All` token for the directory activity / change log **and** the
    /// service-principal sign-in-activity report (the unused-app audit), acquired on demand.
    /// `None` — or a token the tenant hasn't consented to / lacks the license for — makes those
    /// calls fail so the feature degrades (no sign-in data ⇒ no "unused app" detection).
    audit_log_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `Policy.Read.All` token for reading Conditional Access policies,
    /// acquired on demand. Same graceful-degradation contract as `audit_log_token`.
    policy_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `IdentityRiskyServicePrincipal.Read.All` token for the Identity
    /// Protection risky-service-principal report (the audit's compromised-SP
    /// signal), acquired on demand. Same graceful-degradation contract — the
    /// endpoint additionally needs a Workload Identities premium license, so an
    /// un-licensed tenant simply gets no risky-SP data.
    risky_sp_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `Policy.ReadWrite.ApplicationConfiguration` + `Application.ReadWrite.All` token
    /// (one token) for claims-mapping policies. The default `write_token` does NOT cover
    /// `/policies/claimsMappingPolicies`, and the service-principal `$ref` assign/list/remove are
    /// documented as needing both scopes in the same token; acquired on demand (incremental
    /// consent).
    policy_write_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `Sites.FullControl.All` token for the SharePoint `Sites.Selected` model. The
    /// verb-selected `read_token` (`Directory.Read.All`) cannot read `/sites/{id}/permissions`,
    /// and this scope is admin-consent-only, so the site-permission calls ride this token
    /// instead of the default read/write pair; acquired on demand (incremental consent).
    sharepoint_token: Option<Arc<dyn BearerProvider>>,
    /// Optional `GroupMember.ReadWrite.All` + `Application.ReadWrite.All` token (one token —
    /// Learn documents the pair for a `servicePrincipal` member) for adding/removing an SP as a
    /// group member (the `$ref` member endpoints). Membership *reads* ride the verb-selected
    /// `read_token` (`Directory.Read.All` covers `memberOf`); only the writes need this
    /// admin-consent pair, so it's acquired on demand (incremental consent).
    group_member_token: Option<Arc<dyn BearerProvider>>,
    throttle_observer: parking_lot::RwLock<Option<Arc<dyn ThrottleObserver>>>,
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
            // The 60s ceiling is sized for the *slowest legitimate response* — a 999-app page
            // with credential arrays, or a `$batch` POST of 20 sub-requests. The shared connect
            // budget keeps a host that accepts no connection from burning it once per attempt
            // (see `CONNECT_TIMEOUT`).
            .timeout(Duration::from_secs(60))
            .connect_timeout(azapptoolkit_core::http_retry::CONNECT_TIMEOUT)
            // Long fan-outs (audit, DR backup) go quiet between waves; holding idle sockets
            // across the gaps keeps the next wave off a fresh handshake. 90s comfortably spans
            // the throttle back-off window.
            .pool_idle_timeout(Duration::from_secs(90))
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
            risky_sp_token: None,
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

    /// Attaches an `IdentityRiskyServicePrincipal.Read.All` token enabling the
    /// Identity Protection risky-service-principal report.
    pub fn with_risky_sp_token(mut self, token: Arc<dyn BearerProvider>) -> Self {
        self.risky_sp_token = Some(token);
        self
    }

    /// Attaches a `Policy.ReadWrite.ApplicationConfiguration` +
    /// `Application.ReadWrite.All` token enabling claims-mapping-policy
    /// create/update/delete and the service-principal assign/list/remove.
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

    /// Attaches a `GroupMember.ReadWrite.All` + `Application.ReadWrite.All` token
    /// enabling group-membership add/remove for service principals.
    pub fn with_group_member_token(mut self, token: Arc<dyn BearerProvider>) -> Self {
        self.group_member_token = Some(token);
        self
    }

    /// Tenant-scoped cache key for service-principal lookups — see the `tenant_id` field doc
    /// for why these caches are partitioned by tenant.
    fn sp_cache_key(&self, app_id: &str) -> String {
        format!("{}|{}", self.tenant_id, app_id)
    }

    /// Cache key for a **resource** SP's appRoles / oauth2PermissionScopes,
    /// which live under [`CacheKind::Permissions`] rather than
    /// [`CacheKind::ServicePrincipal`].
    ///
    /// Its own `resource:` segment, mirroring how `grants:` separates the tenant-wide grant
    /// matrices in the same bucket. Without it the bucket held two unrelated families under
    /// indistinguishable `{tenant}|{something}` keys, so no prefix could sweep one without the
    /// other — and the mutators that change these definitions consequently swept neither.
    fn resource_sp_cache_key(&self, app_id: &str) -> String {
        format!("{}|resource:{}", self.tenant_id, app_id)
    }

    /// Cache key for the audit's lean SP projection. Distinct `|lean` suffix so
    /// the three-field object never collides with — or overwrites — the full SP
    /// the detail pane caches under [`Self::sp_cache_key`].
    fn sp_lean_cache_key(&self, app_id: &str) -> String {
        format!("{}|{}|lean", self.tenant_id, app_id)
    }

    /// Installs `observer` as the client's single throttle observer. The slot holds one
    /// observer, so a second fan-out on the same per-tenant client displaces the first (logged):
    /// the earlier run then finishes at a fixed cap, with per-request `Retry-After` still in force.
    pub fn set_throttle_observer(&self, observer: Arc<dyn ThrottleObserver>) {
        let prev = self.throttle_observer.write().replace(observer.clone());
        if let Some(prev) = prev
            && !Arc::ptr_eq(&prev, &observer)
        {
            tracing::warn!(
                tenant = %self.tenant_id,
                "throttle: replacing a live observer; concurrent fan-outs on one tenant share a single slot"
            );
        }
    }

    /// Detaches `observer` only if it is the one currently installed, returning whether it
    /// did: a run whose observer was displaced by a concurrent fan-out must not wipe that
    /// run's tracker on its way out — that would leave the survivor at a fixed cap, with no
    /// back-off, for the rest of its life.
    pub fn clear_throttle_observer(&self, observer: &Arc<dyn ThrottleObserver>) -> bool {
        let mut slot = self.throttle_observer.write();
        match slot.as_ref() {
            Some(cur) if Arc::ptr_eq(cur, observer) => {
                *slot = None;
                true
            }
            _ => false,
        }
    }

    // --------- SharePoint Sites.Selected ---------

    /// The `Sites.FullControl.All` token every SharePoint site-permission call rides (see
    /// [`Self::with_sharepoint_token`]); `None` → `Forbidden` so the UI degrades rather than panics.
    fn sharepoint_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(self.sharepoint_token.as_ref(), "Sites.FullControl.All")
    }

    /// The `GroupMember.ReadWrite.All` + `Application.ReadWrite.All` token the group-membership
    /// writes ride (see [`Self::with_group_member_token`]); `None` → `Forbidden` so the UI
    /// degrades rather than panics.
    fn group_member_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(
            self.group_member_token.as_ref(),
            "GroupMember.ReadWrite.All + Application.ReadWrite.All",
        )
    }

    /// The `Synchronization.Read.All` token the SCIM provisioning reads ride (see
    /// [`Self::with_sync_token`]); `None` → `Forbidden` so the UI degrades rather than panics.
    fn sync_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(self.sync_token.as_ref(), "Synchronization.Read.All")
    }

    /// The `AuditLog.Read.All` token the directory-audit and sign-in-activity reads ride (see
    /// [`Self::with_audit_log_token`]); `None` → `Forbidden` so the UI degrades rather than panics.
    fn audit_log_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(self.audit_log_token.as_ref(), "AuditLog.Read.All")
    }

    /// The `Policy.Read.All` token the Conditional Access read rides (see [`Self::with_policy_token`]);
    /// `None` → `Forbidden` so the UI degrades rather than panics.
    fn policy_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(self.policy_token.as_ref(), "Policy.Read.All")
    }

    /// The `IdentityRiskyServicePrincipal.Read.All` token the risky-service-principal
    /// report read rides (see [`Self::with_risky_sp_token`]); `None` → `Forbidden`
    /// so the audit degrades rather than failing.
    fn risky_sp_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(
            self.risky_sp_token.as_ref(),
            "IdentityRiskyServicePrincipal.Read.All",
        )
    }

    /// The `Policy.ReadWrite.ApplicationConfiguration` + `Application.ReadWrite.All` token the
    /// claims-mapping policy calls ride (see [`Self::with_policy_write_token`]); `None` →
    /// `Forbidden` so the UI degrades rather than panics.
    fn policy_write_token(&self) -> Result<&Arc<dyn BearerProvider>> {
        self.require_token(
            self.policy_write_token.as_ref(),
            "Policy.ReadWrite.ApplicationConfiguration + Application.ReadWrite.All",
        )
    }

    /// Unwrap an `Option<&Arc<dyn BearerProvider>>` into a typed error, or return the inner
    /// reference for chaining.
    #[allow(clippy::unused_self)]
    fn require_token<'a>(
        &self,
        token: Option<&'a Arc<dyn BearerProvider>>,
        scope_name: &str,
    ) -> Result<&'a Arc<dyn BearerProvider>> {
        token.ok_or_else(|| GraphError::Forbidden(format!("{scope_name} token not configured")))
    }

    /// Beta endpoint base, derived from the configured base so mock tests (which point
    /// `base_url` at a local server) still resolve.
    fn beta_base(&self) -> String {
        if let Some(stripped) = self.base_url.strip_suffix("/v1.0") {
            format!("{stripped}/beta")
        } else {
            self.base_url.clone()
        }
    }
}
