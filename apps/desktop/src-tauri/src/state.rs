//! Process-wide state held across Tauri commands.
//!
//! The auth service is singleton (one `EntraAuthService` covering all tenants).
//! Each signed-in tenant gets its own `GraphClient`, lazily created and cached
//! in `graph_clients`. A shared `Cache` (core LRU+TTL) is reused across all
//! clients so SP lookups dedupe across tenant swaps.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;

use azapptoolkit_arm::{ArmClient, LogAnalyticsClient};
use azapptoolkit_auth::EntraAuthService;
use azapptoolkit_core::cache::Cache;
use azapptoolkit_core::settings::UserSettings;
use azapptoolkit_exchange::ExchangeClient;
use azapptoolkit_graph::GraphClient;
use azapptoolkit_keyvault::KeyVaultClient;

use crate::token_adapter::ScopedTokenAdapter;

/// Default client id for the public "azapptoolkit Desktop" app registration.
///
/// Placeholder — replace with the real single-tenant app registration GUID
/// before shipping. Resolution order: runtime `AZAPPTOOLKIT_CLIENT_ID` env
/// var, then the build-time bake from `.env` at the workspace root (see
/// `build.rs`), then this placeholder.
const DEFAULT_CLIENT_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Default tenant id used to construct the OAuth authority
/// (`https://login.microsoftonline.com/{tenant_id}/...`). Placeholder — same
/// resolution order as [`DEFAULT_CLIENT_ID`].
const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Value baked in at build time from `AZAPPTOOLKIT_CLIENT_ID` in `.env` at the
/// workspace root. `None` when no `.env` was present at build time.
const BUILD_CLIENT_ID: Option<&str> = option_env!("AZAPPTOOLKIT_BUILD_CLIENT_ID");
const BUILD_TENANT_ID: Option<&str> = option_env!("AZAPPTOOLKIT_BUILD_TENANT_ID");

/// A cancellation flag shared between a long-running command and its dispatch
/// loop. Wraps an `Arc<AtomicBool>` so the correct memory ordering
/// (`Release` on write, `Acquire` on read) lives in one place instead of at
/// every call site, and so `reset()` — which every long-running command MUST
/// call at the top, the AGENTS.md footgun — is a discoverable method rather
/// than a bare `store(false)`.
#[derive(Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears a possibly-stale flag at the start of a run. A new long-running
    /// command that forgets this would be cancelled by an unrelated prior run.
    pub fn reset(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Signals the run to stop at the next dispatch boundary.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// True once [`Self::cancel`] has been called (until the next
    /// [`Self::reset`]).
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Resolution order for a client/tenant id: a non-empty runtime env var (for
/// MDM/automation overrides), then the user's `settings.json` value (written by
/// the first-run config screen), then the build-time bake from `.env`, then the
/// placeholder default — which makes sign-in fail and the config screen show.
fn resolve(
    env_var: &str,
    settings: Option<&str>,
    baked: Option<&'static str>,
    default: &'static str,
) -> String {
    if let Ok(v) = std::env::var(env_var)
        && !v.is_empty()
    {
        return v;
    }
    if let Some(v) = settings.filter(|s| !s.is_empty()) {
        return v.to_string();
    }
    baked
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| default.to_string())
}

pub struct AppState {
    pub auth: Arc<EntraAuthService>,
    /// The resolved client/tenant IDs the auth service signs in with, kept so
    /// `get_auth_config` can report configuration status to the first-run UI.
    pub client_id: String,
    pub tenant_id: String,
    pub cache: Arc<Cache>,
    pub graph_clients: Mutex<HashMap<String, Arc<GraphClient>>>,
    /// Exchange Online Admin API clients cached per tenant. Built lazily on the
    /// first Exchange RBAC operation; the audience and token are distinct from
    /// the Graph clients (`outlook.office365.com` vs Graph).
    pub exchange_clients: Mutex<HashMap<String, Arc<ExchangeClient>>>,
    /// Key Vault clients cached per `(tenant_id, vault_name)` so the inner
    /// `reqwest` connection pool is reused across calls (mirrors `graph_clients`).
    pub kv_clients: Mutex<HashMap<(String, String), Arc<KeyVaultClient>>>,
    /// Per-tenant ARM clients (Azure Resource Manager), for managed-identity
    /// Azure RBAC. Built on first use; the ARM token is acquired on demand.
    pub arm_clients: Mutex<HashMap<String, Arc<ArmClient>>>,
    /// Per-tenant Azure Monitor Logs query clients (Log Analytics data plane —
    /// its own host + token audience, distinct from ARM). Built on first use
    /// for the granted-vs-used Graph activity analysis.
    pub la_clients: Mutex<HashMap<String, Arc<LogAnalyticsClient>>>,
    /// Flipped by the `cancel_audit` Tauri command; checked by the audit loop
    /// between tasks. Reset to `false` at the top of every run.
    pub audit_cancel: CancelFlag,
    /// Cancel flag for the SharePoint site-permission sweep — deliberately its
    /// own flag (not `audit_cancel`) so cancelling a sweep can't abort a
    /// concurrent audit/bulk run, and vice versa. Reset at the top of every
    /// sweep; flipped by `cancel_site_sweep`.
    pub sweep_cancel: CancelFlag,
    /// Cancel flag for the DR backup/restore fan-out — its own flag (not
    /// `audit_cancel`) so cancelling a long backup or restore can't abort a
    /// concurrent audit/bulk/sweep run, and vice versa. Reset at the top of
    /// every backup/restore; flipped by `cancel_dr`.
    pub dr_cancel: CancelFlag,
}

impl AppState {
    pub fn new() -> Self {
        // The user's persisted IDs (first-run config screen) sit between env
        // vars and the build-time bake in the resolution order.
        let settings = UserSettings::stored(&crate::config_directory());
        let client_id = resolve(
            "AZAPPTOOLKIT_CLIENT_ID",
            settings.client_id.as_deref(),
            BUILD_CLIENT_ID,
            DEFAULT_CLIENT_ID,
        );
        let tenant_id = resolve(
            "AZAPPTOOLKIT_TENANT_ID",
            settings.tenant_id.as_deref(),
            BUILD_TENANT_ID,
            DEFAULT_TENANT_ID,
        );
        if tenant_id == DEFAULT_TENANT_ID {
            tracing::warn!(
                "AZAPPTOOLKIT_TENANT_ID is not set; sign-in will fail until configured (first-run screen)."
            );
        }
        if client_id == DEFAULT_CLIENT_ID {
            tracing::warn!(
                "AZAPPTOOLKIT_CLIENT_ID is not set; sign-in will fail until configured (first-run screen)."
            );
        }
        Self {
            auth: EntraAuthService::new(client_id.clone(), tenant_id.clone()),
            client_id,
            tenant_id,
            cache: Cache::new(),
            graph_clients: Mutex::new(HashMap::new()),
            exchange_clients: Mutex::new(HashMap::new()),
            kv_clients: Mutex::new(HashMap::new()),
            arm_clients: Mutex::new(HashMap::new()),
            la_clients: Mutex::new(HashMap::new()),
            audit_cancel: CancelFlag::new(),
            sweep_cancel: CancelFlag::new(),
            dr_cancel: CancelFlag::new(),
        }
    }

    /// True once both IDs resolve to a real (non-placeholder) value. When
    /// false the frontend shows the first-run config screen instead of sign-in.
    pub fn is_configured(&self) -> bool {
        self.client_id != DEFAULT_CLIENT_ID && self.tenant_id != DEFAULT_TENANT_ID
    }

    /// The client ID for prefilling the config form — the placeholder maps to
    /// an empty string so the field renders blank rather than all-zeros.
    pub fn display_client_id(&self) -> &str {
        if self.client_id == DEFAULT_CLIENT_ID {
            ""
        } else {
            &self.client_id
        }
    }

    /// The tenant ID for prefilling the config form; see [`Self::display_client_id`].
    pub fn display_tenant_id(&self) -> &str {
        if self.tenant_id == DEFAULT_TENANT_ID {
            ""
        } else {
            &self.tenant_id
        }
    }

    pub fn graph_for(&self, tenant_id: &str) -> Arc<GraphClient> {
        let mut clients = self.graph_clients.lock();
        if let Some(existing) = clients.get(tenant_id) {
            return existing.clone();
        }
        let read_token = ScopedTokenAdapter::new_cae(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_graph_read_scopes(),
        );
        let write_token = ScopedTokenAdapter::new_cae(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_graph_write_scopes(),
        );
        let sync_token = ScopedTokenAdapter::new_cae(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_graph_sync_scopes(),
        );
        // AuditLog.Read.All for the directory activity / change log — on demand
        // (incremental consent), graceful degradation when un-consented/unlicensed.
        let audit_log_token = ScopedTokenAdapter::new_cae(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_graph_audit_log_scopes(),
        );
        // Policy.Read.All for Conditional Access visibility — same on-demand,
        // gracefully-degrading contract.
        let policy_token = ScopedTokenAdapter::new_cae(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_graph_policy_scopes(),
        );
        // Policy.ReadWrite.ApplicationConfiguration for claims-mapping policies
        // (SAML claim customization). Same on-demand, incremental-consent
        // contract — never part of the sign-in bundle.
        let policy_write_token = ScopedTokenAdapter::new_cae(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_graph_policy_write_scopes(),
        );
        // Sites.FullControl.All for the SharePoint Sites.Selected tab — on demand
        // (incremental consent), never at sign-in; the site-permission reads as
        // well as writes require it, so the SharePoint calls ride this token.
        let sharepoint_token = ScopedTokenAdapter::new_cae(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_graph_sharepoint_scopes(),
        );
        // GroupMember.ReadWrite.All for adding/removing a service principal as
        // a security-group member (group-gated APIs like Power BI / Fabric).
        // Same on-demand, incremental-consent contract — never at sign-in.
        let group_member_token = ScopedTokenAdapter::new_cae(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_graph_group_member_scopes(),
        );
        let client = Arc::new(
            GraphClient::with_base_url(
                tenant_id.to_string(),
                read_token,
                write_token,
                self.cache.clone(),
                self.auth.cloud().graph_base(),
            )
            .with_sync_token(sync_token)
            .with_audit_log_token(audit_log_token)
            .with_policy_token(policy_token)
            .with_policy_write_token(policy_write_token)
            .with_sharepoint_token(sharepoint_token)
            .with_group_member_token(group_member_token),
        );
        clients.insert(tenant_id.to_string(), client.clone());
        client
    }

    /// Returns a cached Exchange Online Admin API client for `tenant_id`,
    /// building one on first use. `admin_upn` is the signed-in administrator's
    /// UPN, used as the mandatory `X-AnchorMailbox` routing hint; it is stable
    /// for the tenant session, so the cached client reuses it.
    pub fn exchange_for(&self, tenant_id: &str, admin_upn: &str) -> Arc<ExchangeClient> {
        let mut clients = self.exchange_clients.lock();
        if let Some(existing) = clients.get(tenant_id) {
            return existing.clone();
        }
        let token = ScopedTokenAdapter::new(
            self.auth.clone(),
            tenant_id.to_string(),
            self.auth.default_exchange_scopes(),
        );
        let client = Arc::new(ExchangeClient::with_base_url(
            token,
            tenant_id.to_string(),
            admin_upn,
            self.auth.cloud().exchange_resource(),
        ));
        clients.insert(tenant_id.to_string(), client.clone());
        client
    }

    /// Returns a cached Key Vault client for `(tenant_id, vault_name)`, building
    /// one (with vault-name validation) on first use. Errors if the vault name
    /// is invalid.
    pub fn kv_for(
        &self,
        tenant_id: &str,
        vault_name: &str,
    ) -> azapptoolkit_keyvault::Result<Arc<KeyVaultClient>> {
        let key = (tenant_id.to_string(), vault_name.to_string());
        let mut clients = self.kv_clients.lock();
        if let Some(existing) = clients.get(&key) {
            return Ok(existing.clone());
        }
        let scopes =
            EntraAuthService::resource_default_scopes(&self.auth.cloud().keyvault_resource());
        let token = ScopedTokenAdapter::new(self.auth.clone(), tenant_id.to_string(), scopes);
        let client = Arc::new(KeyVaultClient::new_with_dns_suffix(
            token,
            vault_name,
            self.auth.cloud().keyvault_dns_suffix(),
        )?);
        clients.insert(key, client.clone());
        Ok(client)
    }

    /// Scopes requested for interactive incremental consent for `feature`, or
    /// `None` for an unknown feature key. Resolves the cloud-correct resource
    /// audiences via the auth service (single source) rather than spreading host
    /// constants across command handlers; the `request_scope_consent` command
    /// maps a UI feature name to a scope set.
    pub fn consent_scopes_for(&self, feature: &str) -> Option<Vec<String>> {
        Some(match feature {
            "write" => self.auth.default_graph_write_scopes(),
            "sync" => self.auth.default_graph_sync_scopes(),
            "audit_log" => self.auth.default_graph_audit_log_scopes(),
            "policy" => self.auth.default_graph_policy_scopes(),
            "policy_write" => self.auth.default_graph_policy_write_scopes(),
            "sharepoint" => self.auth.default_graph_sharepoint_scopes(),
            "group_membership" => self.auth.default_graph_group_member_scopes(),
            "exchange" => self.auth.default_exchange_scopes(),
            "keyvault" => {
                EntraAuthService::resource_default_scopes(&self.auth.cloud().keyvault_resource())
            }
            "arm" => EntraAuthService::resource_default_scopes(self.auth.cloud().arm_resource()),
            "log_analytics" => EntraAuthService::resource_default_scopes(
                self.auth.cloud().log_analytics_resource(),
            ),
            _ => return None,
        })
    }

    /// Acquires (and caches) the ARM token up front, surfacing a *typed* auth
    /// error — notably [`AuthError::ConsentRequired`] — before any ARM call.
    /// The `BearerProvider` boundary flattens errors to `String`, so a command
    /// that wants the UI to distinguish "needs consent" must probe here first;
    /// on success the token is cached and the subsequent `ArmClient` call reuses
    /// it, so the happy path costs no extra round trip.
    pub async fn ensure_arm_token(&self, tenant_id: &str) -> azapptoolkit_auth::Result<()> {
        let scopes = EntraAuthService::resource_default_scopes(self.auth.cloud().arm_resource());
        self.auth
            .access_token_for_scopes(tenant_id, &scopes)
            .await?;
        Ok(())
    }

    /// Acquires (and caches) the `Policy.ReadWrite.ApplicationConfiguration`
    /// token up front, surfacing a *typed* auth error — notably
    /// [`AuthError::ConsentRequired`] — before any claims-mapping write. The
    /// `ScopedTokenAdapter` boundary flattens errors to `String` (a
    /// `consent_required` raised inside a scoped Graph call would reach the UI as
    /// a generic `token_error`), so an SSO command that wants the UI to show a
    /// "Grant consent" button must probe here first. On success the token is
    /// cached and the subsequent claims Graph call reuses it. Mirrors
    /// [`Self::ensure_arm_token`].
    pub async fn ensure_policy_write_token(
        &self,
        tenant_id: &str,
    ) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_graph_policy_write_scopes();
        self.auth
            .access_token_for_scopes_cae(tenant_id, &scopes, None)
            .await?;
        Ok(())
    }

    /// Acquires (and caches) the `Sites.FullControl.All` token up front, so a
    /// missing-consent rejection surfaces as the typed
    /// [`AuthError::ConsentRequired`] (the SharePoint site access section offers a "Grant
    /// consent" button) instead of being flattened to a generic `token_error`
    /// inside the scoped SharePoint Graph call. Mirrors
    /// [`Self::ensure_policy_write_token`].
    pub async fn ensure_sharepoint_token(&self, tenant_id: &str) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_graph_sharepoint_scopes();
        self.auth
            .access_token_for_scopes_cae(tenant_id, &scopes, None)
            .await?;
        Ok(())
    }

    /// Acquires (and caches) the `GroupMember.ReadWrite.All` token up front, so
    /// a not-yet-consented scope surfaces as the typed
    /// [`AuthError::ConsentRequired`] (the group-membership panel offers a
    /// "Grant consent" button) instead of being flattened to a generic
    /// `token_error` inside the scoped Graph call. Mirrors
    /// [`Self::ensure_sharepoint_token`] (CAE, matching the `new_cae` adapter
    /// that consumes this scope set).
    pub async fn ensure_group_member_token(
        &self,
        tenant_id: &str,
    ) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_graph_group_member_scopes();
        self.auth
            .access_token_for_scopes_cae(tenant_id, &scopes, None)
            .await?;
        Ok(())
    }

    /// Acquires (and caches) the `AuditLog.Read.All` token up front, so the audit
    /// runner can distinguish a missing-consent rejection (typed
    /// [`AuthError::ConsentRequired`] → the audit view offers a "Grant consent"
    /// button to enable unused-app detection) from a license/availability failure.
    /// `AuditLog.Read.All` — not `Reports.Read.All` — is the scope the
    /// `servicePrincipalSignInActivities` report requires. Mirrors
    /// [`Self::ensure_sharepoint_token`]; the cached token is reused by the
    /// subsequent sign-in activity fetch, so the happy path costs no extra round trip.
    pub async fn ensure_audit_log_token(&self, tenant_id: &str) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_graph_audit_log_scopes();
        // Acquire via the CAE path (matching the new_cae Graph adapter that
        // consumes this scope set) so the cached token already advertises cp1 —
        // the token cache key omits CAE-ness, so a non-CAE pre-warm here would
        // make the adapter reuse a non-CAE token. (ARM/Exchange stay non-CAE.)
        self.auth
            .access_token_for_scopes_cae(tenant_id, &scopes, None)
            .await?;
        Ok(())
    }

    /// Acquires (and caches) the `outlook.office365.com/Exchange.Manage` token
    /// up front, so a not-yet-consented Exchange scope surfaces as the typed
    /// [`AuthError::ConsentRequired`] (the Exchange/Permissions views offer a
    /// "Grant consent" button) instead of being flattened to a generic
    /// `token_error` inside the `ScopedTokenAdapter`'s `bearer()` call. Mirrors
    /// [`Self::ensure_sharepoint_token`]; the cached token is reused by the
    /// subsequent Exchange admin-API call, so the happy path costs no extra
    /// round trip. Note a *consented-but-RBAC-blocked* user still passes this
    /// (a token is issued) and instead gets a 403 from the admin API.
    pub async fn ensure_exchange_token(&self, tenant_id: &str) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_exchange_scopes();
        self.auth
            .access_token_for_scopes(tenant_id, &scopes)
            .await?;
        Ok(())
    }

    /// Acquires (and caches) the Log Analytics query token up front
    /// (`https://api.loganalytics.azure.com/.default`, sovereign variants per
    /// cloud), surfacing the typed [`AuthError::ConsentRequired`] before any
    /// usage query so the panel can offer a "Grant consent" button. Mirrors
    /// [`Self::ensure_arm_token`] (non-CAE, like ARM/Exchange).
    pub async fn ensure_log_analytics_token(
        &self,
        tenant_id: &str,
    ) -> azapptoolkit_auth::Result<()> {
        let scopes =
            EntraAuthService::resource_default_scopes(self.auth.cloud().log_analytics_resource());
        self.auth
            .access_token_for_scopes(tenant_id, &scopes)
            .await?;
        Ok(())
    }

    /// Returns a cached Azure Monitor Logs query client for `tenant_id`,
    /// building one on first use (mirrors [`Self::arm_for`] — same lazy
    /// incremental-consent model, different host + token audience).
    pub fn log_analytics_for(&self, tenant_id: &str) -> Arc<LogAnalyticsClient> {
        let mut clients = self.la_clients.lock();
        if let Some(existing) = clients.get(tenant_id) {
            return existing.clone();
        }
        let resource = self.auth.cloud().log_analytics_resource();
        let scopes = EntraAuthService::resource_default_scopes(resource);
        let token = ScopedTokenAdapter::new(self.auth.clone(), tenant_id.to_string(), scopes);
        let client = Arc::new(LogAnalyticsClient::new(token, resource));
        clients.insert(tenant_id.to_string(), client.clone());
        client
    }

    /// Returns a cached ARM client for `tenant_id`, building one on first use.
    /// The `https://management.azure.com/.default` token is acquired on demand
    /// (incremental consent); a tenant without ARM consent simply fails the call
    /// and the managed-identity Azure-RBAC view degrades gracefully.
    pub fn arm_for(&self, tenant_id: &str) -> Arc<ArmClient> {
        let mut clients = self.arm_clients.lock();
        if let Some(existing) = clients.get(tenant_id) {
            return existing.clone();
        }
        let scopes = EntraAuthService::resource_default_scopes(self.auth.cloud().arm_resource());
        let token = ScopedTokenAdapter::new(self.auth.clone(), tenant_id.to_string(), scopes);
        let client = Arc::new(ArmClient::with_base_url(
            token,
            self.auth.cloud().arm_resource(),
        ));
        clients.insert(tenant_id.to_string(), client.clone());
        client
    }
}

#[cfg(test)]
mod tests {
    use super::CancelFlag;

    #[test]
    fn cancel_flag_reset_cancel_roundtrip() {
        let f = CancelFlag::new();
        assert!(!f.is_cancelled());
        f.cancel();
        assert!(f.is_cancelled());
        // reset-at-top clears a stale flag (the AGENTS.md footgun: a new
        // long-running command that forgets reset gets cancelled by a prior run).
        f.reset();
        assert!(!f.is_cancelled());
    }

    #[test]
    fn cancel_flag_clone_shares_state() {
        // The dispatch loop clones the flag into spawned tasks; cancelling via
        // one handle must be visible through the clone.
        let f = CancelFlag::new();
        let g = f.clone();
        f.cancel();
        assert!(g.is_cancelled());
    }

    #[test]
    fn distinct_cancel_flags_are_independent() {
        // The two-flag separation (audit_cancel vs sweep_cancel): cancelling a
        // sweep must not abort a concurrent audit, and vice versa.
        let audit = CancelFlag::new();
        let sweep = CancelFlag::new();
        sweep.cancel();
        assert!(sweep.is_cancelled());
        assert!(!audit.is_cancelled(), "audit flag must be untouched");
    }
}
