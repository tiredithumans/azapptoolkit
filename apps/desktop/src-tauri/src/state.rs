//! Process-wide state held across Tauri commands.
//!
//! The auth service is singleton (one `EntraAuthService` covering all tenants).
//! Each signed-in tenant gets its own `GraphClient`, lazily created and cached
//! in `graph_clients`. A shared `Cache` (core LRU+TTL) is reused across all
//! clients so SP lookups dedupe across tenant swaps.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use azapptoolkit_arm::{ArmClient, LogAnalyticsClient};
use azapptoolkit_auth::{EntraAuthService, TenantContext};
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

/// Shared state behind a [`CancelFlag`] and every [`CancelToken`] it issues.
///
/// Two counters rather than one boolean. The boolean form had no notion of
/// *which* run it referred to, so `reset()` was a destructive write on state a
/// concurrent run was still reading: a second command starting cleared a cancel
/// the first had not yet observed, and that run then continued after the user
/// had stopped it.
#[derive(Default)]
struct CancelInner {
    /// Bumped by every [`CancelFlag::claim`]; the generation of the newest run.
    current: AtomicU64,
    /// Highest generation [`CancelFlag::cancel`] has stopped. Monotonic — it is
    /// never cleared, which is what removes the destructive reset.
    cancelled: AtomicU64,
}

/// A cancellation flag shared between a long-running command and its dispatch
/// loop. Wraps the ordering (`Release` on write, `Acquire` on read) so it lives
/// in one place instead of at every call site.
///
/// A run does not poll the flag directly — it [`claim`](Self::claim)s a
/// [`CancelToken`] first, which is both the run's identity and the AGENTS.md
/// "reset at the top" step, now impossible to forget because the token is the
/// only thing that answers `is_cancelled()`.
#[derive(Clone, Default)]
pub struct CancelFlag(Arc<CancelInner>);

impl CancelFlag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts a run and returns its token. Replaces the old `reset()`: it takes
    /// a fresh generation for *this* run instead of clearing a flag another run
    /// may still be reading.
    pub fn claim(&self) -> CancelToken {
        // `fetch_add` returns the previous value, so the first claim is 1 and a
        // token can never collide with the `cancelled` counter's initial 0.
        let generation = self.0.current.fetch_add(1, Ordering::AcqRel) + 1;
        CancelToken {
            inner: self.0.clone(),
            generation,
        }
    }

    /// Signals the current run — and any older run still in flight — to stop at
    /// the next dispatch boundary.
    ///
    /// Cancelling older generations too is deliberate: the alternative is a
    /// displaced run continuing to write after the operator pressed Cancel.
    /// Stopping a run that was going to be superseded anyway is harmless; the
    /// reverse is not.
    pub fn cancel(&self) {
        let current = self.0.current.load(Ordering::Acquire);
        self.0.cancelled.fetch_max(current, Ordering::AcqRel);
    }

    // Deliberately no `is_cancelled()` on the flag itself. Asking without a
    // token is the question that had no correct answer — "is *something*
    // cancelled?" — and every command that asked it was really asking about its
    // own run. Claim a `CancelToken` and ask that.
}

/// One long-running run's handle on a [`CancelFlag`].
///
/// Cloned into every spawned task. `is_cancelled()` answers for *this* run, so
/// a later run claiming the same flag can neither un-cancel it nor be confused
/// with it.
#[derive(Clone)]
pub struct CancelToken {
    inner: Arc<CancelInner>,
    generation: u64,
}

impl CancelToken {
    /// True once [`CancelFlag::cancel`] has stopped this run's generation (or a
    /// newer one — see [`CancelFlag::cancel`]).
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire) >= self.generation
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

/// Lock → check → build → insert: the shape every per-tenant client cache here
/// repeats. Factored so the memoization contract lives in one place and each
/// getter is left holding only the thing that actually differs — its token
/// scopes and constructor.
///
/// `build` deliberately runs while the map lock is held, exactly as the
/// hand-rolled versions did: every builder is pure construction (a token
/// adapter plus a client struct), with no I/O and no second lock, so the hold is
/// short and cannot deadlock. Two concurrent first-callers therefore get the
/// same client rather than one of them being discarded.
fn try_get_or_build<K, V, E>(
    map: &Mutex<HashMap<K, Arc<V>>>,
    key: K,
    build: impl FnOnce() -> Result<Arc<V>, E>,
) -> Result<Arc<V>, E>
where
    K: Eq + std::hash::Hash,
{
    let mut clients = map.lock();
    if let Some(existing) = clients.get(&key) {
        return Ok(Arc::clone(existing));
    }
    let built = build()?;
    clients.insert(key, Arc::clone(&built));
    Ok(built)
}

/// [`try_get_or_build`] for the builders that cannot fail.
fn get_or_build<K, V>(
    map: &Mutex<HashMap<K, Arc<V>>>,
    key: K,
    build: impl FnOnce() -> Arc<V>,
) -> Arc<V>
where
    K: Eq + std::hash::Hash,
{
    match try_get_or_build::<K, V, std::convert::Infallible>(map, key, || Ok(build())) {
        Ok(client) => client,
        // `Infallible` has no values, so this arm is unreachable by construction.
        Err(never) => match never {},
    }
}

pub struct AppState {
    pub auth: Arc<EntraAuthService>,
    /// The resolved client/tenant IDs the auth service signs in with, kept so
    /// `get_auth_config` can report configuration status to the first-run UI.
    pub client_id: String,
    pub tenant_id: String,
    pub cache: Arc<Cache>,
    /// Single-flight gates, keyed by cache key. See [`AppState::single_flight`].
    inflight: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
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
            inflight: Mutex::new(HashMap::new()),
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

    /// An `AppState` whose Graph client for `tenant_id` points at `base_url`
    /// (a mock server) with a static bearer, so a command's `*_core` body can be
    /// driven end to end: real Graph request/response handling, real cache
    /// invalidation, no network and no Tauri runtime.
    ///
    /// Pre-seeding `graph_clients` is what makes this work — `graph_for` is a
    /// get-or-build, so the seeded client wins and no `ScopedTokenAdapter` is
    /// ever constructed. Nothing here touches `settings.json`.
    #[cfg(test)]
    pub(crate) fn for_test(tenant_id: &str, base_url: &str) -> Self {
        use azapptoolkit_core::token::StaticTokenProvider;

        let cache = Cache::new();
        let client = Arc::new(GraphClient::with_base_url(
            tenant_id.to_string(),
            StaticTokenProvider::new("test-token"),
            StaticTokenProvider::new("test-token"),
            Arc::clone(&cache),
            format!("{}/v1.0", base_url.trim_end_matches('/')),
        ));
        Self {
            auth: EntraAuthService::new("test-client", tenant_id),
            client_id: "test-client".to_string(),
            tenant_id: tenant_id.to_string(),
            cache,
            inflight: Mutex::new(HashMap::new()),
            graph_clients: Mutex::new(HashMap::from([(tenant_id.to_string(), client)])),
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

    /// Records `tenant` in `settings.json` as the account to revive at the next
    /// launch. The refresh token itself is already in the OS keyring; what is
    /// missing across a restart is the `{tenant}:{oid}` key that addresses it,
    /// and an oid is a directory object id, not a credential.
    ///
    /// Best-effort by design: an unwritable settings file costs the operator one
    /// extra sign-in next launch and must never fail the sign-in that just
    /// succeeded. Goes through `mutate` like every other writer — three commands
    /// read-modify-write this file from different threads.
    pub fn remember_account(&self, tenant: &TenantContext) {
        let tenant = tenant.clone();
        if let Err(e) = UserSettings::mutate(&crate::config_directory(), |settings| {
            settings.last_account = Some(tenant);
        }) {
            tracing::warn!(
                target: "auth",
                error = %e,
                "could not remember the signed-in account; the next launch will show sign-in"
            );
        }
    }

    /// Drops the remembered account on sign-out, so the next launch shows the
    /// sign-in card. The keyring token is deleted by `EntraAuthService::sign_out`
    /// in the same command; clearing the pointer too keeps the two from
    /// disagreeing about whether anyone is signed in.
    pub fn forget_account(&self) {
        if let Err(e) = UserSettings::mutate(&crate::config_directory(), |settings| {
            settings.last_account = None;
        }) {
            tracing::warn!(target: "auth", error = %e, "could not clear the remembered account");
        }
    }

    /// The account a previous run remembered, if it belongs to the tenant *this*
    /// run resolved (see `UserSettings::remembered_account_for` for why the
    /// tenant guard is not optional). Read fresh from disk rather than cached at
    /// startup: `AppState::new` snapshots `settings.json` before any sign-in has
    /// happened, so a cached copy would be one launch behind.
    pub fn remembered_account(&self) -> Option<TenantContext> {
        UserSettings::stored(&crate::config_directory())
            .remembered_account_for(&self.tenant_id)
            .cloned()
    }

    /// Returns the single-flight gate for `key` (creating it on first use).
    ///
    /// Read-through caches are `get` → miss → fetch → `put`, which lets two
    /// callers that miss at the same time both do the expensive fetch. Holding
    /// this gate across the fetch — and **re-checking the cache after acquiring
    /// it** — collapses that to one fetch, with the loser reading the winner's
    /// result.
    ///
    /// The concrete case: the gallery picker fires `prefetch_application_gallery`
    /// on dialog open while the operator's first debounced keystroke calls
    /// `search_application_templates`. Both missed, so the prewarm added a
    /// second full-catalog fetch (~39 000 templates) instead of preventing one.
    ///
    /// Gates are keyed by cache key. A handful of keys opt in, but the keys are
    /// **tenant-scoped** (`{tenant_id}|sp_index`, …), so the map grows with
    /// every tenant the session touches and nothing ever removed an entry.
    /// Sweeping idle gates past a threshold bounds it: an `Arc` with no other
    /// holder is a gate nobody is waiting on, so dropping it can never merge or
    /// split an in-flight fetch.
    /// Idle-gate sweep threshold. Generous: a handful of opted-in keys times
    /// the tenants one session realistically visits.
    const MAX_INFLIGHT_GATES: usize = 64;

    pub fn single_flight(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.inflight.lock();
        if map.len() >= Self::MAX_INFLIGHT_GATES && !map.contains_key(key) {
            map.retain(|_, gate| Arc::strong_count(gate) > 1);
        }
        Arc::clone(
            map.entry(key.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    pub fn graph_for(&self, tenant_id: &str) -> Arc<GraphClient> {
        get_or_build(&self.graph_clients, tenant_id.to_string(), || {
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
            Arc::new(
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
            )
        })
    }

    /// Returns a cached Exchange Online Admin API client for `tenant_id`,
    /// building one on first use. `admin_upn` is the signed-in administrator's
    /// UPN, used as the mandatory `X-AnchorMailbox` routing hint; it is stable
    /// for the tenant session, so the cached client reuses it.
    pub fn exchange_for(&self, tenant_id: &str, admin_upn: &str) -> Arc<ExchangeClient> {
        get_or_build(&self.exchange_clients, tenant_id.to_string(), || {
            let token = ScopedTokenAdapter::new(
                self.auth.clone(),
                tenant_id.to_string(),
                self.auth.default_exchange_scopes(),
            );
            Arc::new(ExchangeClient::with_base_url(
                token,
                tenant_id.to_string(),
                admin_upn,
                self.auth.cloud().exchange_resource(),
            ))
        })
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
        try_get_or_build(&self.kv_clients, key, || {
            let scopes =
                EntraAuthService::resource_default_scopes(&self.auth.cloud().keyvault_resource());
            let token = ScopedTokenAdapter::new(self.auth.clone(), tenant_id.to_string(), scopes);
            Ok(Arc::new(KeyVaultClient::new_with_dns_suffix(
                token,
                vault_name,
                self.auth.cloud().keyvault_dns_suffix(),
            )?))
        })
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

    /// Shared core for every `ensure_*_token` probe below: pre-acquires (and
    /// caches) the token for `scopes` so a not-yet-consented scope surfaces as
    /// the typed [`AuthError::ConsentRequired`] (the UI offers a "Grant consent"
    /// button) instead of being flattened to a generic `token_error` deep inside
    /// a `ScopedTokenAdapter`/`BearerProvider` boundary. On success the token is
    /// cached and the subsequent client call reuses it, so the happy path costs
    /// no extra round trip.
    ///
    /// `cae` MUST match the CAE-ness of the adapter that later consumes the same
    /// scope set: the token cache key omits CAE-ness, so a non-CAE pre-warm would
    /// make a `new_cae` adapter reuse a non-CAE token (and vice versa). The Graph
    /// scopes ride `new_cae` (cae = true); ARM / Exchange / Log Analytics stay
    /// non-CAE (cae = false). This is the CAE/adapter pairing each wrapper's doc
    /// comment cross-references — keeping the branch in one place.
    async fn ensure_scoped_token(
        &self,
        tenant_id: &str,
        scopes: Vec<String>,
        cae: bool,
    ) -> azapptoolkit_auth::Result<()> {
        if cae {
            self.auth
                .access_token_for_scopes_cae(tenant_id, &scopes, None)
                .await?;
        } else {
            self.auth
                .access_token_for_scopes(tenant_id, &scopes)
                .await?;
        }
        Ok(())
    }

    /// Acquires (and caches) the ARM token up front, surfacing a *typed* auth
    /// error — notably [`AuthError::ConsentRequired`] — before any ARM call.
    /// The `BearerProvider` boundary flattens errors to `String`, so a command
    /// that wants the UI to distinguish "needs consent" must probe here first;
    /// on success the token is cached and the subsequent `ArmClient` call reuses
    /// it, so the happy path costs no extra round trip. Non-CAE (like the ARM adapter).
    pub async fn ensure_arm_token(&self, tenant_id: &str) -> azapptoolkit_auth::Result<()> {
        let scopes = EntraAuthService::resource_default_scopes(self.auth.cloud().arm_resource());
        self.ensure_scoped_token(tenant_id, scopes, false).await
    }

    /// Acquires (and caches) the `Policy.ReadWrite.ApplicationConfiguration`
    /// token up front, surfacing a *typed* auth error — notably
    /// [`AuthError::ConsentRequired`] — before any claims-mapping write. The
    /// `ScopedTokenAdapter` boundary flattens errors to `String` (a
    /// `consent_required` raised inside a scoped Graph call would reach the UI as
    /// a generic `token_error`), so an SSO command that wants the UI to show a
    /// "Grant consent" button must probe here first. On success the token is
    /// cached and the subsequent claims Graph call reuses it. CAE (Graph adapter).
    pub async fn ensure_policy_write_token(
        &self,
        tenant_id: &str,
    ) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_graph_policy_write_scopes();
        self.ensure_scoped_token(tenant_id, scopes, true).await
    }

    /// Acquires (and caches) the `Sites.FullControl.All` token up front, so a
    /// missing-consent rejection surfaces as the typed
    /// [`AuthError::ConsentRequired`] (the SharePoint site access section offers a "Grant
    /// consent" button) instead of being flattened to a generic `token_error`
    /// inside the scoped SharePoint Graph call. CAE (Graph adapter).
    pub async fn ensure_sharepoint_token(&self, tenant_id: &str) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_graph_sharepoint_scopes();
        self.ensure_scoped_token(tenant_id, scopes, true).await
    }

    /// Acquires (and caches) the `GroupMember.ReadWrite.All` token up front, so
    /// a not-yet-consented scope surfaces as the typed
    /// [`AuthError::ConsentRequired`] (the group-membership panel offers a
    /// "Grant consent" button) instead of being flattened to a generic
    /// `token_error` inside the scoped Graph call. CAE, matching the `new_cae`
    /// adapter that consumes this scope set.
    pub async fn ensure_group_member_token(
        &self,
        tenant_id: &str,
    ) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_graph_group_member_scopes();
        self.ensure_scoped_token(tenant_id, scopes, true).await
    }

    /// Acquires (and caches) the `AuditLog.Read.All` token up front, so the audit
    /// runner can distinguish a missing-consent rejection (typed
    /// [`AuthError::ConsentRequired`] → the audit view offers a "Grant consent"
    /// button to enable unused-app detection) from a license/availability failure.
    /// `AuditLog.Read.All` — not `Reports.Read.All` — is the scope the
    /// `servicePrincipalSignInActivities` report requires. CAE, matching the
    /// `new_cae` Graph adapter that consumes this scope set (so the cached token
    /// already advertises cp1); the cached token is reused by the subsequent
    /// sign-in activity fetch, so the happy path costs no extra round trip.
    pub async fn ensure_audit_log_token(&self, tenant_id: &str) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_graph_audit_log_scopes();
        self.ensure_scoped_token(tenant_id, scopes, true).await
    }

    /// Acquires (and caches) the `outlook.office365.com/Exchange.Manage` token
    /// up front, so a not-yet-consented Exchange scope surfaces as the typed
    /// [`AuthError::ConsentRequired`] (the Exchange/Permissions views offer a
    /// "Grant consent" button) instead of being flattened to a generic
    /// `token_error` inside the `ScopedTokenAdapter`'s `bearer()` call. The
    /// cached token is reused by the subsequent Exchange admin-API call, so the
    /// happy path costs no extra round trip. Note a *consented-but-RBAC-blocked*
    /// user still passes this (a token is issued) and instead gets a 403 from the
    /// admin API. Non-CAE (like the Exchange adapter).
    pub async fn ensure_exchange_token(&self, tenant_id: &str) -> azapptoolkit_auth::Result<()> {
        let scopes = self.auth.default_exchange_scopes();
        self.ensure_scoped_token(tenant_id, scopes, false).await
    }

    /// Acquires (and caches) the Log Analytics query token up front
    /// (`https://api.loganalytics.azure.com/.default`, sovereign variants per
    /// cloud), surfacing the typed [`AuthError::ConsentRequired`] before any
    /// usage query so the panel can offer a "Grant consent" button. Non-CAE
    /// (like ARM/Exchange).
    pub async fn ensure_log_analytics_token(
        &self,
        tenant_id: &str,
    ) -> azapptoolkit_auth::Result<()> {
        let scopes =
            EntraAuthService::resource_default_scopes(self.auth.cloud().log_analytics_resource());
        self.ensure_scoped_token(tenant_id, scopes, false).await
    }

    /// Returns a cached Azure Monitor Logs query client for `tenant_id`,
    /// building one on first use (mirrors [`Self::arm_for`] — same lazy
    /// incremental-consent model, different host + token audience).
    pub fn log_analytics_for(&self, tenant_id: &str) -> Arc<LogAnalyticsClient> {
        get_or_build(&self.la_clients, tenant_id.to_string(), || {
            let resource = self.auth.cloud().log_analytics_resource();
            let scopes = EntraAuthService::resource_default_scopes(resource);
            let token = ScopedTokenAdapter::new(self.auth.clone(), tenant_id.to_string(), scopes);
            Arc::new(LogAnalyticsClient::new(token, resource))
        })
    }

    /// Returns a cached ARM client for `tenant_id`, building one on first use.
    /// The `https://management.azure.com/.default` token is acquired on demand
    /// (incremental consent); a tenant without ARM consent simply fails the call
    /// and the managed-identity Azure-RBAC view degrades gracefully.
    pub fn arm_for(&self, tenant_id: &str) -> Arc<ArmClient> {
        get_or_build(&self.arm_clients, tenant_id.to_string(), || {
            let scopes =
                EntraAuthService::resource_default_scopes(self.auth.cloud().arm_resource());
            let token = ScopedTokenAdapter::new(self.auth.clone(), tenant_id.to_string(), scopes);
            Arc::new(ArmClient::with_base_url(
                token,
                self.auth.cloud().arm_resource(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CancelFlag;

    #[test]
    fn a_claimed_run_starts_uncancelled_and_stops_on_cancel() {
        let f = CancelFlag::new();
        let run = f.claim();
        assert!(!run.is_cancelled());
        f.cancel();
        assert!(run.is_cancelled());
    }

    #[test]
    fn a_token_clone_shares_state() {
        // The dispatch loop clones the token into spawned tasks; cancelling via
        // the flag must be visible through every clone.
        let f = CancelFlag::new();
        let run = f.claim();
        let in_task = run.clone();
        f.cancel();
        assert!(in_task.is_cancelled());
    }

    #[test]
    fn distinct_cancel_flags_are_independent() {
        // The flag separation (audit_cancel vs sweep_cancel vs dr_cancel):
        // cancelling a sweep must not abort a concurrent audit, and vice versa.
        let audit = CancelFlag::new();
        let sweep = CancelFlag::new();
        let audit_run = audit.claim();
        let sweep_run = sweep.claim();
        sweep.cancel();
        assert!(sweep_run.is_cancelled());
        assert!(!audit_run.is_cancelled(), "audit run must be untouched");
    }

    #[test]
    fn a_later_run_cannot_uncancel_an_earlier_one() {
        // The defect this type was rebuilt for. Under the old `AtomicBool`, run
        // B's mandatory `reset()` at the top cleared a cancellation run A had
        // not yet polled, and A carried on writing after the operator stopped
        // it. A generation is per-run, so B starting says nothing about A.
        let f = CancelFlag::new();
        let a = f.claim();
        f.cancel();
        assert!(a.is_cancelled());

        let b = f.claim();
        assert!(
            a.is_cancelled(),
            "starting a second run must not resurrect a cancelled one"
        );
        assert!(!b.is_cancelled(), "the new run starts clean");
    }

    #[test]
    fn cancelling_also_stops_older_runs_still_in_flight() {
        // Conservative direction on purpose: a displaced run stopping is
        // harmless, a cancelled run continuing to write is not. Documented on
        // `CancelFlag::cancel`.
        let f = CancelFlag::new();
        let old = f.claim();
        let new = f.claim();
        f.cancel();
        assert!(new.is_cancelled());
        assert!(old.is_cancelled(), "the displaced run stops too");
    }

    #[test]
    fn a_cancel_issued_before_any_run_does_not_kill_the_next_one() {
        // `cancel_bulk` can fire with nothing running (a stale click, or the UI
        // racing the command's start). That must not poison the next claim.
        let f = CancelFlag::new();
        f.cancel();
        let run = f.claim();
        assert!(!run.is_cancelled());
    }
}
