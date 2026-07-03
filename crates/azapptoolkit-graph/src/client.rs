use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{
    ActiveDirectoryRole, AppRoleAssignment, Application, ApplicationExposeApi,
    ApplicationServicePrincipal, ClaimsMappingPolicy, ConditionalAccessPolicy, DirectoryAuditLog,
    DirectoryObject, FederatedIdentityCredential, GroupSummary, KeyCredential, NewKeyCredential,
    OAuth2PermissionGrant, OAuth2PermissionScope, Organization, Paged, PasswordCredential,
    PreAuthorizedApplication, RequiredResourceAccess, SelfSignedCertificate, ServicePrincipal,
    ServicePrincipalSignInActivity, Site, SitePermission, SynchronizationJob,
};

use azapptoolkit_core::http_retry::{
    BASE_DELAY_MS, MAX_RETRIES, next_backoff_ms, parse_retry_after_seconds, sleep_before_retry,
    sleep_with_jitter,
};
use azapptoolkit_core::net::same_origin;
use azapptoolkit_core::token::BearerProvider;

use crate::error::{GraphError, Result};

/// Microsoft Graph v1 base URL. Overridable for tests.
pub const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";

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
mod transport;

// Request/patch bodies and wire-building helpers re-exported at their
// historical `client::` paths — src-tauri's imports
// (`azapptoolkit_graph::client::AppPatch`, …) and the sibling modules'
// `use super::*` both resolve through here, so the module split isn't a
// caller-visible move.
pub use applications::{
    ApiApplicationPatch, AppListQuery, AppPatch, ApplicationAuthenticationPatch,
    ApplicationExposeApiPatch, ApplicationPublicClientPatch, ApplicationSpaPatch,
    ApplicationSsoPatch, ApplicationWebPatch, CreateApplicationRequest, ImplicitGrantSettingsPatch,
};
pub use credentials::{FederatedCredentialPatch, FederatedCredentialRequest};
pub use service_principals::{ServicePrincipalSigningKeyPatch, ServicePrincipalSsoModePatch};
pub(crate) use transport::{batch_sub_url, escape_odata, search_phrase};

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
}
