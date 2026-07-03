//! Entra ID sign-in via OAuth2 authorization code + PKCE.
//!
//! High-level flow:
//!   1. Bind a loopback listener on an ephemeral port.
//!   2. Build the authorize URL (read-only scopes from
//!      `azapptoolkit_core::constants::GRAPH_READ_SCOPES` plus `offline_access`),
//!      open it in the system browser. Write scopes are consented incrementally
//!      the first time a mutating Graph call needs them.
//!   3. Accept requests on the listener until the OAuth redirect arrives,
//!      pull `code` + `state`, reply with a success page, shut down.
//!   4. Exchange the code at `/token` with our own reqwest call so we can read
//!      `id_token` from the response.
//!   5. Resolve tenant id + account oid from the ID token claims.
//!
//! Access tokens are kept in memory only. Callers invoke
//! [`EntraAuthService::access_token_for_scopes`] on every Graph request; it
//! refreshes lazily 60s ahead of expiry under a single shared mutex, and caches
//! per scope set so the read and write tokens coexist.
//!
//! Module layout: [`wire`] (AAD response shapes, error classification and
//! redaction, claims decoding), [`loopback`] (redirect listener + browser
//! launch), [`scopes`] (the per-feature scope catalog). This file keeps the
//! service struct, the token lifecycle, and the interactive/silent flows.

mod loopback;
mod scopes;
mod wire;

use chrono::{Duration, Utc};
use oauth2::{CsrfToken, PkceCodeChallenge, PkceCodeVerifier};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_core::identity::{SignInOutcome, TenantContext};

use crate::error::{AuthError, Result};
use crate::token_cache::{
    AccessToken, TokenCache, delete_refresh_token, load_refresh_token, save_refresh_token,
    scope_key,
};
use loopback::{listen_for_code, open_system_browser};
use wire::{
    IdClaims, TokenErrorBody, TokenResponse, build_cae_claims, classify_token_error,
    parse_id_token, parse_scopes, redacted_aad_error,
};

const REFRESH_LEEWAY_SECS: i64 = 60;

/// Per-`(tenant, scope_key)` refresh locks, created lazily and keyed exactly
/// like the token cache. See the `EntraAuthService::refresh_locks` field.
type RefreshLocks = Mutex<HashMap<(String, String), Arc<AsyncMutex<()>>>>;

pub struct EntraAuthService {
    client_id: String,
    /// Single-tenant authority. The OAuth authorize/token URLs are
    /// constructed as `{auth_root}/{tenant_id}/...`.
    tenant_id: String,
    /// Authority host, derived from [`Self::cloud`] (commercial =
    /// `https://login.microsoftonline.com`). A field (not a const) so tests can
    /// point the token/authorize endpoints at a mock server.
    auth_root: String,
    /// Selected Microsoft cloud — drives the Graph/Exchange scope audiences (and,
    /// via `auth_root`, the login host). Commercial unless `AZAPPTOOLKIT_CLOUD`
    /// selects a sovereign cloud.
    cloud: CloudEnvironment,
    cache: Arc<TokenCache>,
    /// Per-`(tenant, scope_key)` refresh locks, created lazily and keyed exactly
    /// like the token cache. A refresh holds its lock across the token round trip
    /// (up to the 30s HTTP timeout); a single global lock would let a slow Graph
    /// refresh stall an unrelated Key Vault or cross-tenant refresh. Same-key
    /// concurrency still collapses to one network call via the double-checked
    /// cache read taken under the lock.
    refresh_locks: RefreshLocks,
    known_tenants: Mutex<HashMap<String, TenantContext>>,
    http: reqwest::Client,
}

impl EntraAuthService {
    pub fn new(client_id: impl Into<String>, tenant_id: impl Into<String>) -> Arc<Self> {
        let cloud = CloudEnvironment::from_env();
        Arc::new(Self {
            client_id: client_id.into(),
            tenant_id: tenant_id.into(),
            auth_root: cloud.login_authority_root().to_string(),
            cloud,
            cache: TokenCache::new(),
            refresh_locks: Mutex::new(HashMap::new()),
            known_tenants: Mutex::new(HashMap::new()),
            http: reqwest::Client::builder()
                .user_agent(concat!("azapptoolkit/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client builds"),
        })
    }

    /// The Microsoft cloud this service targets (from `AZAPPTOOLKIT_CLOUD`).
    /// Lets `AppState` derive the matching Graph/Exchange/Key Vault/ARM base URLs
    /// from the same source as the scope audiences.
    pub fn cloud(&self) -> CloudEnvironment {
        self.cloud
    }

    // The scope catalog (default_graph_*_scopes, default_exchange_scopes,
    // resource_default_scopes) lives in the `scopes` sibling module.

    // Each parameter maps to a distinct OAuth `/authorize` query param; a
    // params struct would only add indirection for a single private call site.
    #[allow(clippy::too_many_arguments)]
    fn authorize_url(
        &self,
        authority: &str,
        redirect: &str,
        state: &str,
        nonce: &str,
        challenge: &PkceCodeChallenge,
        scope: &str,
        prompt: &str,
        login_hint: Option<&str>,
    ) -> Result<url::Url> {
        let mut url = url::Url::parse(&format!("{authority}/oauth2/v2.0/authorize"))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("client_id", &self.client_id)
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", redirect)
                .append_pair("response_mode", "query")
                .append_pair("scope", scope)
                .append_pair("state", state)
                // OIDC nonce binds the returned id_token to this request: it's
                // echoed in the token's `nonce` claim and verified after exchange
                // (Microsoft marks it required when an id_token is requested).
                .append_pair("nonce", nonce)
                .append_pair("code_challenge", challenge.as_str())
                .append_pair("code_challenge_method", "S256")
                .append_pair("prompt", prompt);
            // Best-effort pre-fill of the consent screen with the signed-in
            // account (absent when the ID token carried no `preferred_username`).
            // This is a UX hint, not the identity guarantee — a consent screen
            // can still switch tenant/account — but the post-exchange tid/oid
            // check in `consent_for_scopes` rejects a token for a different one.
            if let Some(hint) = login_hint {
                pairs.append_pair("login_hint", hint);
            }
        }
        Ok(url)
    }

    async fn post_token(&self, authority: &str, params: &[(&str, &str)]) -> Result<TokenResponse> {
        let url = format!("{authority}/oauth2/v2.0/token");
        let resp = self.http.post(&url).form(params).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            if let Ok(err_body) = serde_json::from_slice::<TokenErrorBody>(&bytes) {
                // Log the OAuth error code, the AADSTS numeric code, and the
                // correlation id for operators, but never the raw
                // error_description: it routinely embeds tenant/user GUIDs and
                // client IPs that should not flow into the UI or audit log.
                tracing::warn!(
                    target: "auth",
                    aad_error = %err_body.error,
                    aad_description = redacted_aad_error(&err_body),
                    correlation_id = err_body.correlation_id.as_deref().unwrap_or(""),
                    "AAD token endpoint rejected request"
                );
                return Err(classify_token_error(&err_body));
            }
            // Body wasn't a TokenErrorBody — log raw, surface generic.
            tracing::warn!(
                target: "auth",
                %status,
                body = %String::from_utf8_lossy(&bytes),
                "AAD token endpoint returned non-success without TokenErrorBody"
            );
            return Err(AuthError::TokenExchange(format!("HTTP {status}")));
        }
        let token: TokenResponse = serde_json::from_slice(&bytes)?;
        Ok(token)
    }
}

impl EntraAuthService {
    /// Runs one loopback authorization-code + PKCE round trip for `scopes`:
    /// binds an ephemeral loopback listener, opens the system browser at the
    /// `/authorize` endpoint (with the given `prompt` and optional
    /// `login_hint`), waits for the redirect, and redeems the code at `/token`.
    /// Returns the redeemed token response plus the parsed ID-token claims.
    /// Shared by [`Self::sign_in`] (read scopes, `prompt=select_account`) and
    /// [`Self::consent_for_scopes`] (incremental scopes, `prompt=consent`).
    async fn run_auth_code_flow(
        &self,
        scopes: &[String],
        prompt: &str,
        login_hint: Option<&str>,
    ) -> Result<(TokenResponse, IdClaims)> {
        let authority = format!("{}/{}", self.auth_root, self.tenant_id);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| AuthError::Loopback(e.to_string()))?;
        let port = listener
            .local_addr()
            .map_err(|e| AuthError::Loopback(e.to_string()))?
            .port();
        let redirect = format!("http://127.0.0.1:{port}");

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let csrf_state = CsrfToken::new_random();
        // Fresh per-request nonce, verified against the id_token's `nonce` claim
        // after the code exchange (reuses the CSPRNG-backed token primitive).
        let nonce = CsrfToken::new_random();

        let scope = scopes.join(" ");
        let auth_url = self.authorize_url(
            &authority,
            &redirect,
            csrf_state.secret(),
            nonce.secret(),
            &pkce_challenge,
            &scope,
            prompt,
            login_hint,
        )?;

        // Log the non-sensitive fields needed to diagnose AAD rejections
        // (missing-scope, wrong-client, wrong-redirect). PKCE `code_challenge`
        // and CSRF `state` stay redacted by stripping the query string for the
        // endpoint URL; scope/client_id/redirect_uri are logged explicitly.
        let mut redacted_url = auth_url.clone();
        redacted_url.set_query(None);
        tracing::info!(
            authorize_endpoint = %redacted_url,
            scope = %scope,
            prompt = %prompt,
            client_id = %self.client_id,
            redirect_uri = %redirect,
            url_length = auth_url.as_str().len(),
            "opening system browser for Entra authorize"
        );
        if let Err(err) = open_system_browser(auth_url.as_str()) {
            tracing::warn!(
                ?err,
                "failed to auto-open browser; user must open URL manually"
            );
        }

        // Bound the wait on the browser redirect so a sleeping machine or a
        // browser that never completes the flow can't hang sign-in forever
        // (the future holds the loopback socket and blocks the caller).
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            listen_for_code(listener, csrf_state.secret()),
        )
        .await
        .map_err(|_| AuthError::Loopback("timed out waiting for the sign-in redirect".into()))??;

        let verifier_secret =
            zeroize::Zeroizing::new(PkceCodeVerifier::secret(&pkce_verifier).to_string());
        let params = [
            ("client_id", self.client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("code_verifier", verifier_secret.as_str()),
            ("scope", scope.as_str()),
        ];
        let token = self.post_token(&authority, &params).await?;
        let claims = parse_id_token(token.id_token.as_deref())?;
        // Bind the id_token to THIS request: its `nonce` must equal the value we
        // sent. An absent/mismatched nonce means the token isn't ours — reject it.
        if claims.nonce.as_deref() != Some(nonce.secret().as_str()) {
            return Err(AuthError::TokenExchange("id_token nonce mismatch".into()));
        }
        Ok((token, claims))
    }

    pub async fn sign_in(&self) -> Result<SignInOutcome> {
        let initial_scopes = self.default_graph_read_scopes();
        let (token, claims) = self
            .run_auth_code_flow(&initial_scopes, "select_account", None)
            .await?;

        let tenant_id = claims
            .tid
            .ok_or_else(|| AuthError::TokenExchange("id token missing tid".into()))?;
        // Defense-in-depth: Entra already enforces the audience server-side
        // for single-tenant registrations, but a local check produces a
        // clearer error if anything ever drifts (e.g. a misconfigured
        // AZAPPTOOLKIT_TENANT_ID against a multi-tenant app reg).
        if tenant_id != self.tenant_id {
            return Err(AuthError::TokenExchange(format!(
                "id token tid {tenant_id} does not match configured tenant {}",
                self.tenant_id
            )));
        }
        let account_oid = claims
            .oid
            .ok_or_else(|| AuthError::TokenExchange("id token missing oid".into()))?;

        let tenant = TenantContext {
            tenant_id: tenant_id.clone(),
            account_oid: account_oid.clone(),
            username: claims.preferred_username,
            display_name: claims.name,
        };

        // Initial sign-in: no requested-scope fallback (matches the original
        // `unwrap_or_default`); the grant response always echoes `scope` here.
        self.store_token_outcome(&tenant_id, &account_oid, &initial_scopes, &[], token)
            .await?;
        self.known_tenants
            .lock()
            .insert(tenant_id.clone(), tenant.clone());
        Ok(SignInOutcome { tenant })
    }

    /// Obtains **interactive incremental consent** for `scopes`: runs a fresh
    /// authorization-code round trip (system browser + loopback) with
    /// `prompt=consent`, pinned to the already-signed-in account, then seeds
    /// the token cache under `scopes` and persists the refreshed refresh token.
    ///
    /// This is the recovery path for [`AuthError::ConsentRequired`]: a silent
    /// `refresh_token` grant can only *use* consent that already exists, never
    /// *obtain* it, so the first use of a scope the tenant hasn't consented to
    /// must take a user through the browser once. After this returns `Ok`, the
    /// next [`Self::access_token_for_scopes`] for the same `scopes` is silent.
    pub async fn consent_for_scopes(&self, tenant_id: &str, scopes: &[String]) -> Result<()> {
        let tenant = self
            .known_tenants
            .lock()
            .get(tenant_id)
            .cloned()
            .ok_or(AuthError::NotSignedIn)?;

        // The round trip needs an ID token (to confirm the same account
        // consented) and a refresh token, so ensure the OIDC/offline scopes are
        // present even for bare resource `.default` scopes (e.g. ARM), which
        // omit them. The access token's audience is still set by the resource
        // scope; these reserved scopes only affect the id/refresh tokens.
        let mut auth_scopes = scopes.to_vec();
        for reserved in ["offline_access", "openid", "profile"] {
            if !auth_scopes.iter().any(|s| s == reserved) {
                auth_scopes.push(reserved.to_string());
            }
        }

        let (token, claims) = self
            .run_auth_code_flow(&auth_scopes, "consent", tenant.username.as_deref())
            .await?;

        // Defense-in-depth: a consent screen can switch tenant/account even
        // with a login_hint. Refuse to cache a token for a different identity.
        ensure_same_identity(&claims, &tenant, "consent")?;

        // Cache under the *requested* `scopes` (not `auth_scopes`) so the next
        // silent acquisition for the same set hits this entry. `scope_key`
        // canonicalizes, so order doesn't matter.
        self.store_token_outcome(
            &tenant.tenant_id,
            &tenant.account_oid,
            scopes,
            scopes,
            token,
        )
        .await?;
        Ok(())
    }

    /// Bearer token for an arbitrary audience. Scopes should be explicit —
    /// e.g. `https://vault.azure.net/.default` for Key Vault. The refresh
    /// token, stored once per `(tenant, account)` in the OS keyring, is
    /// reused across audiences.
    pub async fn access_token_for_scopes(
        &self,
        tenant_id: &str,
        scopes: &[String],
    ) -> Result<AccessToken> {
        self.access_token_inner(tenant_id, scopes, None, false)
            .await
    }

    /// CAE-aware token acquisition for the Graph clients: advertises the `cp1`
    /// client capability so Microsoft Graph issues Continuous Access Evaluation
    /// tokens (which revoke promptly on a policy/credential change). When
    /// `challenge` is set — the base64 claims from a `401 insufficient_claims`
    /// CAE challenge — it's forwarded to the token endpoint and the cache is
    /// bypassed, so the re-minted token satisfies the resource's new claims. The
    /// access-token audience is still set by `scopes`.
    pub async fn access_token_for_scopes_cae(
        &self,
        tenant_id: &str,
        scopes: &[String],
        challenge: Option<&str>,
    ) -> Result<AccessToken> {
        let claims = build_cae_claims(challenge);
        self.access_token_inner(tenant_id, scopes, Some(&claims), challenge.is_some())
            .await
    }

    /// The lazily-created refresh lock for a `(tenant, scope set)`, keyed
    /// identically to the token cache (canonical `scope_key`) so two requests
    /// for the same audience serialize on one lock while unrelated audiences
    /// refresh concurrently.
    fn refresh_lock_for(&self, tenant_id: &str, scopes: &[String]) -> Arc<AsyncMutex<()>> {
        let key = (tenant_id.to_string(), scope_key(scopes));
        self.refresh_locks
            .lock()
            .entry(key)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    /// Shared tail of every token-yielding flow (`sign_in`,
    /// `consent_for_scopes`, `reauthenticate`, `access_token_inner`): computes
    /// expiry, parses the issued scopes (`scope_fallback` covers responses
    /// that omit the `scope` echo), persists a rotated refresh token, and
    /// seeds the access-token cache under `cache_scopes`. The keyring write is
    /// a blocking OS syscall (Windows Credential Manager iterates numbered
    /// chunk entries), so it runs off the async worker via `spawn_blocking` —
    /// centralizing here is what keeps the interactive flows from stalling
    /// other tokio tasks with an inline write.
    async fn store_token_outcome(
        &self,
        tenant_id: &str,
        account_oid: &str,
        cache_scopes: &[String],
        scope_fallback: &[String],
        token: TokenResponse,
    ) -> Result<AccessToken> {
        let expires_at = Utc::now() + Duration::seconds(token.expires_in as i64);
        let scopes = parse_scopes(token.scope.as_deref(), scope_fallback);
        if let Some(refresh) = token.refresh_token {
            let (t, oid) = (tenant_id.to_string(), account_oid.to_string());
            tokio::task::spawn_blocking(move || save_refresh_token(&t, &oid, &refresh))
                .await
                .map_err(|e| AuthError::Keyring(format!("keyring write task failed: {e}")))??;
        }
        let access = AccessToken {
            token: token.access_token,
            expires_at,
            scopes,
        };
        self.cache
            .put(tenant_id.to_string(), cache_scopes, access.clone());
        Ok(access)
    }

    async fn access_token_inner(
        &self,
        tenant_id: &str,
        scopes: &[String],
        claims: Option<&str>,
        bypass_cache: bool,
    ) -> Result<AccessToken> {
        if !bypass_cache
            && let Some(existing) = self.cache.get(tenant_id, scopes)
            && !existing.needs_refresh(REFRESH_LEEWAY_SECS)
        {
            return Ok(existing);
        }

        let lock = self.refresh_lock_for(tenant_id, scopes);
        let _guard = lock.lock().await;
        if !bypass_cache
            && let Some(fresh) = self.cache.get(tenant_id, scopes)
            && !fresh.needs_refresh(REFRESH_LEEWAY_SECS)
        {
            return Ok(fresh);
        }

        let tenant = self
            .known_tenants
            .lock()
            .get(tenant_id)
            .cloned()
            .ok_or(AuthError::NotSignedIn)?;

        // Hold the plaintext refresh secret in a Zeroizing buffer so the copy
        // we POST is wiped from memory when this scope ends, not left on a freed
        // heap page. The keyring read is a blocking OS syscall (Windows
        // Credential Manager iterates numbered chunk entries), so run it off the
        // async worker via spawn_blocking — otherwise it stalls other tokio
        // tasks while this holds the refresh lock.
        let refresh_secret = zeroize::Zeroizing::new({
            let (t, oid) = (tenant.tenant_id.clone(), tenant.account_oid.clone());
            tokio::task::spawn_blocking(move || load_refresh_token(&t, &oid))
                .await
                .map_err(|e| AuthError::Keyring(format!("keyring read task failed: {e}")))??
                .ok_or_else(|| AuthError::RefreshTokenMissing(tenant.tenant_id.clone()))?
        });

        let authority = format!("{}/{}", self.auth_root, tenant.tenant_id);
        let scope = scopes.join(" ");
        let mut params = vec![
            ("client_id", self.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_secret.as_str()),
            ("scope", scope.as_str()),
        ];
        // CAE: advertise cp1 and/or forward a claims challenge to the token endpoint.
        if let Some(c) = claims {
            params.push(("claims", c));
        }
        let token = match self.post_token(&authority, &params).await {
            Ok(t) => t,
            Err(AuthError::InvalidGrant(reason)) => {
                // The stored refresh token is no longer usable. Purge it
                // and drop any cached access tokens for the tenant so the
                // next call surfaces a clean "not signed in" rather than
                // looping on a stale token.
                tracing::warn!(tenant_id = %tenant.tenant_id, %reason, "refresh token rejected, purging");
                let _ = delete_refresh_token(&tenant.tenant_id, &tenant.account_oid);
                self.cache.invalidate_tenant(&tenant.tenant_id);
                self.known_tenants.lock().remove(&tenant.tenant_id);
                return Err(AuthError::RefreshTokenMissing(tenant.tenant_id.clone()));
            }
            Err(AuthError::ConsentRequired(reason)) => {
                // The refresh token is still valid — only these specific scopes
                // lack consent, which a silent grant cannot obtain. Do NOT purge
                // (that would sign the user out over a missing optional scope);
                // surface so the caller can run interactive incremental consent.
                tracing::info!(tenant_id = %tenant.tenant_id, %scope, %reason, "scope needs interactive consent");
                return Err(AuthError::ConsentRequired(reason));
            }
            Err(e) => return Err(e),
        };

        self.store_token_outcome(
            &tenant.tenant_id,
            &tenant.account_oid,
            scopes,
            scopes,
            token,
        )
        .await
    }

    pub async fn sign_out(&self, tenant: &TenantContext) -> Result<()> {
        self.cache.invalidate_tenant(&tenant.tenant_id);
        self.known_tenants.lock().remove(&tenant.tenant_id);
        delete_refresh_token(&tenant.tenant_id, &tenant.account_oid)?;
        Ok(())
    }

    /// Re-mints `tenant_id`'s access tokens *without* ending the session: drops
    /// every cached access token (the keyring refresh token and the known-tenant
    /// entry are left in place) and re-acquires the base read scopes via a
    /// `refresh_token` grant. Entra issues each access token from the user's
    /// *current* directory state, so the new token reflects roles that became
    /// active after sign-in — notably a just-activated PIM role (its `wids`
    /// claim) — letting a user who activates e.g. "Exchange Administrator"
    /// mid-session recover without a full sign-out/sign-in. Every other audience
    /// token (Exchange, write, ARM, …) was dropped too, so each re-mints lazily
    /// on its next use and likewise picks up the new role. Re-acquiring the
    /// (already-consented) read scopes both validates the session and surfaces a
    /// dead refresh token immediately as [`AuthError::RefreshTokenMissing`] —
    /// the same "sign in again" signal a lazy refresh would have produced.
    pub async fn refresh_session(&self, tenant_id: &str) -> Result<()> {
        self.cache.invalidate_tenant(tenant_id);
        self.access_token_for_scopes(tenant_id, &self.default_graph_read_scopes())
            .await?;
        Ok(())
    }

    /// Interactively re-authenticates the already-signed-in account, minting a
    /// fresh refresh + access token *without* ending the session or dropping the
    /// tenant's data caches. This is the recovery path for a **dead** session —
    /// an expired/revoked refresh token (surfaced as [`AuthError::InvalidGrant`],
    /// re-mapped to [`AuthError::RefreshTokenMissing`] after the stale token is
    /// purged) or a missing one — which the silent [`Self::refresh_session`]
    /// can't fix, sparing the user a full sign-out/sign-in (the latter would also
    /// wipe the cached lists + audit run).
    ///
    /// Runs one browser round trip with `prompt=login` (forcing a fresh
    /// credential entry — the right behaviour for a revoked session) pinned to
    /// the current account via `login_hint`. Like [`Self::consent_for_scopes`],
    /// it refuses to cache a token for a different identity: re-authenticating as
    /// another tenant/account would let that operator read this session's
    /// tenant-keyed data caches, so a mismatch errors and the user is told to
    /// Sign Out to switch accounts.
    ///
    /// Takes the full [`TenantContext`] rather than a bare id because the
    /// `InvalidGrant` that sends the user here purges the `known_tenants` entry
    /// (see [`Self::access_token_inner`]), so the caller — which still holds the
    /// context — must supply the `login_hint`/identity to match against.
    pub async fn reauthenticate(&self, tenant: &TenantContext) -> Result<SignInOutcome> {
        let initial_scopes = self.default_graph_read_scopes();
        let (token, claims) = self
            .run_auth_code_flow(&initial_scopes, "login", tenant.username.as_deref())
            .await?;

        // Defense-in-depth (mirrors `consent_for_scopes`): a login screen can
        // switch tenant/account even with a login_hint.
        ensure_same_identity(&claims, tenant, "re-authentication")?;

        self.store_token_outcome(
            &tenant.tenant_id,
            &tenant.account_oid,
            &initial_scopes,
            &initial_scopes,
            token,
        )
        .await?;
        // Restore the (validated) context: a prior `InvalidGrant` removed it, and
        // `tenants()` / consent lookups read `known_tenants`.
        self.known_tenants
            .lock()
            .insert(tenant.tenant_id.clone(), tenant.clone());
        Ok(SignInOutcome {
            tenant: tenant.clone(),
        })
    }

    pub async fn tenants(&self) -> Vec<TenantContext> {
        self.known_tenants.lock().values().cloned().collect()
    }

    /// Synchronous lookup of a single signed-in tenant's context. Returns
    /// `None` if that tenant has not signed in this session. Used by client
    /// factories that need the account (e.g. the admin UPN for the Exchange
    /// `X-AnchorMailbox`) without awaiting.
    pub fn tenant_context(&self, tenant_id: &str) -> Option<TenantContext> {
        self.known_tenants.lock().get(tenant_id).cloned()
    }
}

/// Refuses a token minted for a different identity than the session's. A
/// consent/login screen can switch tenant or account even with a
/// `login_hint`; caching such a token would cross this session's tenant-keyed
/// data caches with another operator's view. One implementation for every
/// interactive post-sign-in flow, so a future one can't check `tid` but
/// forget `oid`. (`sign_in` has a different contract — a tid-only match
/// against the *configured* tenant — and stays separate.) `action` names the
/// flow in the error ("consent", "re-authentication").
fn ensure_same_identity(claims: &IdClaims, tenant: &TenantContext, action: &str) -> Result<()> {
    if claims.tid.as_deref() != Some(tenant.tenant_id.as_str()) {
        return Err(AuthError::Authorization(format!(
            "{action} completed for a different tenant — use Sign Out to switch"
        )));
    }
    if claims.oid.as_deref() != Some(tenant.account_oid.as_str()) {
        return Err(AuthError::Authorization(format!(
            "{action} completed with a different account — use Sign Out to switch"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_cache::init_mock_keyring;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Builds an auth service whose token endpoint points at `auth_root` (a mock
    /// server), already "signed in" to `tenant` with a stored refresh token.
    fn signed_in_service(auth_root: String, tenant: &str, oid: &str) -> EntraAuthService {
        init_mock_keyring();
        save_refresh_token(tenant, oid, "stored-refresh-token").unwrap();
        let svc = EntraAuthService {
            client_id: "client".into(),
            tenant_id: tenant.into(),
            auth_root,
            cloud: CloudEnvironment::Commercial,
            cache: TokenCache::new(),
            refresh_locks: Mutex::new(HashMap::new()),
            known_tenants: Mutex::new(HashMap::new()),
            http: reqwest::Client::new(),
        };
        svc.known_tenants.lock().insert(
            tenant.into(),
            TenantContext {
                tenant_id: tenant.into(),
                account_oid: oid.into(),
                username: None,
                display_name: None,
            },
        );
        svc
    }

    #[test]
    fn refresh_locks_are_keyed_per_tenant_and_scope_set() {
        let svc = signed_in_service("http://localhost".into(), "t1", "oid-1");
        let a1 = svc.refresh_lock_for("t1", &["b".into(), "a".into()]);
        // Same scope set, different order → canonical key → the same lock.
        let a2 = svc.refresh_lock_for("t1", &["a".into(), "b".into()]);
        // A different scope set or tenant gets its own lock, so those refreshes
        // proceed concurrently rather than serializing behind this one.
        let other_scope = svc.refresh_lock_for("t1", &["c".into()]);
        let other_tenant = svc.refresh_lock_for("t2", &["a".into(), "b".into()]);
        assert!(Arc::ptr_eq(&a1, &a2));
        assert!(!Arc::ptr_eq(&a1, &other_scope));
        assert!(!Arc::ptr_eq(&a1, &other_tenant));
    }

    async fn mount_token_error(server: &MockServer, tenant: &str, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(ResponseTemplate::new(400).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn mount_token_success(server: &MockServer, tenant: &str, access_token: &str) {
        let access_token = access_token.to_string();
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": access_token,
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn invalid_grant_purges_the_refresh_token_and_signs_out() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("purge-tenant", "purge-oid");
        mount_token_error(
            &server,
            tenant,
            serde_json::json!({
                "error": "invalid_grant",
                "error_description": "AADSTS70000: refresh token expired"
            }),
        )
        .await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        let result = svc
            .access_token_for_scopes(tenant, &["https://graph.microsoft.com/.default".into()])
            .await;
        // A dead grant purges the stored token and forgets the tenant.
        assert!(matches!(result, Err(AuthError::RefreshTokenMissing(_))));
        assert_eq!(load_refresh_token(tenant, oid).unwrap(), None);
        assert!(svc.known_tenants.lock().get(tenant).is_none());
    }

    #[tokio::test]
    async fn consent_required_keeps_the_refresh_token_and_session() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("consent-tenant", "consent-oid");
        // AADSTS65001 = not consented → ConsentRequired, which must NOT purge the
        // still-valid refresh token (the documented bug class).
        mount_token_error(
            &server,
            tenant,
            serde_json::json!({
                "error": "invalid_grant",
                "error_description": "AADSTS65001: The user or administrator has not consented"
            }),
        )
        .await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        let result = svc
            .access_token_for_scopes(
                tenant,
                &["https://graph.microsoft.com/Policy.Read.All".into()],
            )
            .await;
        // The refresh token and session survive a missing-consent rejection.
        assert!(matches!(result, Err(AuthError::ConsentRequired(_))));
        assert_eq!(
            load_refresh_token(tenant, oid).unwrap().as_deref(),
            Some("stored-refresh-token")
        );
        assert!(svc.known_tenants.lock().get(tenant).is_some());
    }

    #[tokio::test]
    async fn refresh_session_drops_cached_tokens_and_re_mints() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("refresh-tenant", "refresh-oid");
        mount_token_success(&server, tenant, "freshly-minted").await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        // Seed a still-valid cached access token for the read scopes — without a
        // refresh this is exactly what `access_token_for_scopes` would return.
        let read = svc.default_graph_read_scopes();
        svc.cache.put(
            tenant.to_string(),
            &read,
            AccessToken {
                token: "stale-from-before-pim-activation".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
                scopes: read.clone(),
            },
        );

        svc.refresh_session(tenant).await.unwrap();

        // The cache now holds the freshly minted token, not the stale one —
        // proving the session re-mints from the token endpoint (picking up the
        // user's current directory roles, e.g. a PIM role activated after
        // sign-in) instead of serving the cached pre-activation token.
        let cached = svc.cache.get(tenant, &read).expect("read token re-cached");
        assert_eq!(cached.token, "freshly-minted");
        // The session is intact: the keyring refresh token and tenant survive.
        assert_eq!(
            load_refresh_token(tenant, oid).unwrap().as_deref(),
            Some("stored-refresh-token")
        );
        assert!(svc.known_tenants.lock().get(tenant).is_some());
    }

    #[test]
    fn authorize_url_contains_pkce_and_scopes() {
        let svc = EntraAuthService::new("client-id-xyz", "tenant-id-abc");
        let (challenge, _verifier) = PkceCodeChallenge::new_random_sha256();
        let scope = svc.default_graph_read_scopes().join(" ");
        let url = svc
            .authorize_url(
                "https://login.microsoftonline.com/organizations",
                "http://127.0.0.1:1234",
                "state-xyz",
                "nonce-xyz",
                &challenge,
                &scope,
                "select_account",
                None,
            )
            .unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some("client-id-xyz")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("state-xyz"));
        assert_eq!(query.get("nonce").map(String::as_str), Some("nonce-xyz"));
        assert_eq!(
            query.get("prompt").map(String::as_str),
            Some("select_account")
        );
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(
            query
                .get("scope")
                .unwrap()
                .contains("https://graph.microsoft.com/Directory.Read.All")
        );
        assert!(!query.get("scope").unwrap().contains("ReadWrite"));
        assert!(query.get("scope").unwrap().contains("offline_access"));
        // No login_hint when none is passed (the sign-in case).
        assert!(!query.contains_key("login_hint"));
    }

    #[test]
    fn authorize_url_carries_consent_prompt_and_login_hint() {
        let svc = EntraAuthService::new("client-id-xyz", "tenant-id-abc");
        let (challenge, _verifier) = PkceCodeChallenge::new_random_sha256();
        let scope =
            EntraAuthService::resource_default_scopes("https://management.azure.com").join(" ");
        let url = svc
            .authorize_url(
                "https://login.microsoftonline.com/tenant-id-abc",
                "http://127.0.0.1:1234",
                "state-xyz",
                "nonce-xyz",
                &challenge,
                &scope,
                "consent",
                Some("admin@contoso.com"),
            )
            .unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("prompt").map(String::as_str), Some("consent"));
        assert_eq!(
            query.get("login_hint").map(String::as_str),
            Some("admin@contoso.com")
        );
        assert!(
            query
                .get("scope")
                .unwrap()
                .contains("https://management.azure.com/.default")
        );
    }

    #[test]
    fn identity_mismatch_is_rejected_on_both_axes() {
        let tenant = TenantContext {
            tenant_id: "t1".into(),
            account_oid: "o1".into(),
            username: None,
            display_name: None,
        };
        let ok = IdClaims {
            tid: Some("t1".into()),
            oid: Some("o1".into()),
            ..Default::default()
        };
        assert!(ensure_same_identity(&ok, &tenant, "consent").is_ok());

        // Wrong tenant, wrong account, and absent claims must all fail closed.
        let wrong_tenant = IdClaims {
            tid: Some("t2".into()),
            oid: Some("o1".into()),
            ..Default::default()
        };
        assert!(matches!(
            ensure_same_identity(&wrong_tenant, &tenant, "consent"),
            Err(AuthError::Authorization(_))
        ));
        let wrong_account = IdClaims {
            tid: Some("t1".into()),
            oid: Some("o2".into()),
            ..Default::default()
        };
        assert!(matches!(
            ensure_same_identity(&wrong_account, &tenant, "consent"),
            Err(AuthError::Authorization(_))
        ));
        assert!(ensure_same_identity(&IdClaims::default(), &tenant, "consent").is_err());
    }
}
