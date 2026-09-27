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
use azapptoolkit_core::http_retry::{
    Attempt, RetryClass, RetryReason, parse_retry_after_seconds, with_retries,
};
use azapptoolkit_core::identity::{SignInOutcome, TenantContext, canonical_tenant_id};

use crate::error::{AuthError, Result};
use crate::token_cache::{
    AccessToken, PurgeOutcome, TokenCache, delete_refresh_token, delete_refresh_token_if_current,
    load_refresh_token, save_refresh_token, scope_key,
};
use loopback::{listen_for_code, open_system_browser};
use wire::{
    IdClaims, TokenErrorBody, TokenResponse, build_cae_claims, classify_token_error,
    parse_id_token, parse_scopes, redacted_aad_error,
};

const REFRESH_LEEWAY_SECS: i64 = 60;

/// How long an interactive flow waits for the browser's redirect before it
/// treats the sign-in as abandoned ([`AuthError::Cancelled`]). Bounds a
/// sleeping machine or a closed tab, which otherwise hold the loopback socket
/// and block the caller forever.
const REDIRECT_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

/// Per-`(tenant, scope_key)` refresh locks, created lazily. See the
/// `EntraAuthService::refresh_locks` field.
type RefreshLocks = Mutex<HashMap<(String, String), Arc<AsyncMutex<()>>>>;

/// Launches the `/authorize` URL for an interactive flow. See the
/// `EntraAuthService::open_browser` field.
type BrowserOpener = Box<dyn Fn(&str) -> Result<()> + Send + Sync>;

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
    /// Per-`(tenant, scope_key)` refresh locks, created lazily. The token cache
    /// also keys on CAE-ness; the lock deliberately does not — a CAE and a
    /// non-CAE refresh of the same scope set serialising is harmless and rare. A
    /// refresh holds its lock across the token round trip (up to the 30s HTTP
    /// timeout) and across `post_token`'s retry backoff — intended, because the
    /// same-key waiters then get the retried result instead of each re-POSTing
    /// into the same throttle. A single global lock would let a slow Graph
    /// refresh stall an unrelated Key Vault or cross-tenant refresh. Same-key
    /// concurrency still collapses to one network call via the double-checked
    /// cache read taken under the lock.
    refresh_locks: RefreshLocks,
    known_tenants: Mutex<HashMap<String, TenantContext>>,
    http: reqwest::Client,
    /// Opens the `/authorize` URL of an interactive flow. Always
    /// [`open_system_browser`] in the app; a field (not a direct call) so tests
    /// can stand in for the browser and drive `sign_in`, `consent_for_scopes`
    /// and `reauthenticate` end to end — the loopback `redirect_uri`, `state`
    /// and `nonce` all travel in the URL it is handed.
    open_browser: BrowserOpener,
}

impl EntraAuthService {
    /// `tenant_id` is stored in its canonical (lowercase) spelling, the form
    /// the id token's `tid` claim takes, so `sign_in`'s tid check and every
    /// tenant-keyed map agree however the operator typed the GUID.
    pub fn new(client_id: impl Into<String>, tenant_id: impl AsRef<str>) -> Arc<Self> {
        let cloud = CloudEnvironment::from_env();
        Arc::new(Self {
            client_id: client_id.into(),
            tenant_id: canonical_tenant_id(tenant_id.as_ref()),
            auth_root: cloud.login_authority_root().to_string(),
            cloud,
            cache: TokenCache::new(),
            refresh_locks: Mutex::new(HashMap::new()),
            known_tenants: Mutex::new(HashMap::new()),
            http: reqwest::Client::builder()
                .user_agent(concat!("azapptoolkit/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(azapptoolkit_core::http_retry::CONNECT_TIMEOUT)
                .build()
                .expect("reqwest client builds"),
            open_browser: Box::new(open_system_browser),
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
        claims: Option<&str>,
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
            // CAE: advertise the `cp1` client capability for a Graph scope set,
            // so the code redeemed below mints a CAE token.
            if let Some(claims) = claims {
                pairs.append_pair("claims", claims);
            }
        }
        Ok(url)
    }

    /// POSTs one `/token` request under the shared retry budget
    /// (`core::http_retry`): a 429 (honouring `Retry-After`) or a 5xx / network
    /// failure is retried when [`retry_class_for`] allows it for this grant; any
    /// other rejection is terminal and classified exactly as before. A timeout
    /// is terminal too — a 30s-silent endpoint retried would hold the caller's
    /// per-scope refresh lock for minutes — and so is a `Retry-After` above
    /// [`TOKEN_RETRY_AFTER_MAX_SECS`], for the same reason. `params` carry the refresh token /
    /// code verifier, so only the grant type ever reaches the log label.
    async fn post_token(&self, authority: &str, params: &[(&str, &str)]) -> Result<TokenResponse> {
        let url = format!("{authority}/oauth2/v2.0/token");
        let label = format!("aad token {}", grant_type(params).unwrap_or("unknown"));
        with_retries(&label, retry_class_for(params), |_| {
            self.token_attempt(&url, params)
        })
        .await
    }

    /// One `/token` attempt, classified for [`with_retries`].
    async fn token_attempt(
        &self,
        url: &str,
        params: &[(&str, &str)],
    ) -> Attempt<TokenResponse, AuthError> {
        let resp = match self.http.post(url).form(params).send().await {
            Ok(resp) => resp,
            Err(e) if e.is_timeout() => return Attempt::Done(Err(e.into())),
            Err(e) => {
                return Attempt::Retry {
                    reason: RetryReason::Transient,
                    status: None,
                    retry_after_secs: None,
                    err: AuthError::Http(e),
                };
            }
        };
        let status = resp.status();
        let retry_after_secs = parse_retry_after_seconds(
            resp.headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
        );
        // Captured before the body consumes `resp`: on the non-Entra branch
        // below it is the one genuinely diagnostic, non-content signal — an
        // `text/html` here says "a proxy answered", which is the actual
        // question an operator is asking.
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = match resp.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return Attempt::Done(Err(e.into())),
        };
        if status.is_success() {
            return Attempt::Done(serde_json::from_slice(&bytes).map_err(Into::into));
        }
        let err = if let Ok(err_body) = serde_json::from_slice::<TokenErrorBody>(&bytes) {
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
            classify_token_error(&err_body)
        } else {
            // Body wasn't a TokenErrorBody. Tracing is wired to a daily rolling
            // FILE appender at info, so this lands on disk — and every other AAD
            // error path here is meticulously redacted (`redacted_aad_error`
            // drops `error_description` because it embeds tenant/user GUIDs and
            // client IPs). This branch fires precisely when the responder is
            // NOT Entra: a TLS-intercepting proxy, WAF or captive portal, which
            // commonly echo the offending request back in the block page. So
            // only non-content metadata is logged.
            tracing::warn!(
                target: "auth",
                %status,
                bytes = bytes.len(),
                content_type = content_type.as_deref().unwrap_or("<none>"),
                "AAD token endpoint returned non-success without TokenErrorBody"
            );
            AuthError::TokenExchange(format!("HTTP {status}"))
        };
        if retry_after_secs.is_some_and(|s| s > TOKEN_RETRY_AFTER_MAX_SECS) {
            // Waiting it out would hold the caller's per-scope refresh lock
            // (and, on the interactive paths, the operator) for minutes; fail
            // now with the throttle error instead.
            return Attempt::Done(Err(err));
        }
        match status.as_u16() {
            429 => Attempt::Retry {
                reason: RetryReason::Throttled,
                status: Some(429),
                retry_after_secs,
                err,
            },
            code if code >= 500 => Attempt::Retry {
                reason: RetryReason::Transient,
                status: Some(code),
                retry_after_secs,
                err,
            },
            _ => Attempt::Done(Err(err)),
        }
    }
}

/// The longest `Retry-After` a `/token` retry waits out. A throttle or 5xx that
/// asks for longer is terminal: the shared policy honours up to
/// `core::http_retry::RETRY_AFTER_MAX_SECS` (minutes) for Graph / ARM writes,
/// but a token call runs under the per-(tenant, scope) refresh lock, so every
/// same-key caller would queue behind the wait.
const TOKEN_RETRY_AFTER_MAX_SECS: u64 = 30;

/// The `grant_type` of a `/token` request — the one parameter safe to log.
fn grant_type<'a>(params: &[(&str, &'a str)]) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| *k == "grant_type")
        .map(|(_, v)| *v)
}

/// Whether a `/token` request may be replayed after an unknown outcome. A
/// `refresh_token` grant is idempotent (Entra does not revoke the refresh token
/// on use), so any transient failure may be replayed. An `authorization_code`
/// is single-use: once Entra has redeemed it, a replay can only fail, so it is
/// [`RetryClass::NonIdempotent`] — only a 429 (refused before any work) is
/// retried. That is narrower than "retry a transport error before any
/// response", which the shared seam cannot express without inventing a reason;
/// a failed code exchange is recovered by the operator selecting Sign in again.
fn retry_class_for(params: &[(&str, &str)]) -> RetryClass {
    match grant_type(params) {
        Some("refresh_token") => RetryClass::Idempotent,
        _ => RetryClass::NonIdempotent,
    }
}

impl EntraAuthService {
    /// Runs one loopback authorization-code + PKCE round trip for `scopes`:
    /// binds an ephemeral loopback listener, opens the system browser at the
    /// `/authorize` endpoint (with the given `prompt` and optional
    /// `login_hint`), waits for the redirect, and redeems the code at `/token`.
    /// Returns the redeemed token response plus the parsed ID-token claims.
    /// Shared by [`Self::sign_in`] (read scopes, `prompt=select_account`),
    /// [`Self::reauthenticate`] (read scopes, `prompt=login`),
    /// [`Self::consent_for_scopes`] (incremental scopes, `prompt=consent`) and
    /// [`Self::step_up_for_scopes`] (a resource's scopes, `prompt=login`).
    ///
    /// `cae` requests a Continuous Access Evaluation token: the `cp1` claims
    /// ride both the `/authorize` URL and the code redemption, so the token the
    /// caller seeds into the CAE cache slot is one the Graph adapters
    /// (`ScopedTokenAdapter::new_cae`) may serve. Pass it for a Graph scope set.
    async fn run_auth_code_flow(
        &self,
        scopes: &[String],
        prompt: &str,
        login_hint: Option<&str>,
        cae: bool,
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
        let cae_claims = cae.then(|| build_cae_claims(None));
        let auth_url = self.authorize_url(
            &authority,
            &redirect,
            csrf_state.secret(),
            nonce.secret(),
            &pkce_challenge,
            &scope,
            prompt,
            login_hint,
            cae_claims.as_deref(),
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
        if let Err(err) = (self.open_browser)(auth_url.as_str()) {
            tracing::warn!(
                ?err,
                "failed to auto-open browser; user must open URL manually"
            );
        }

        // Bound the wait on the browser redirect (`REDIRECT_WAIT`) so a sleeping
        // machine or a browser that never completes the flow can't hang sign-in
        // forever (the future holds the loopback socket and blocks the caller).
        // A redirect that never arrives is an abandoned sign-in — the operator
        // closed the tab — not a network fault, so it surfaces as `Cancelled`.
        let code = tokio::time::timeout(
            REDIRECT_WAIT,
            listen_for_code(listener, csrf_state.secret()),
        )
        .await
        .map_err(|_| AuthError::Cancelled)??;

        let verifier_secret =
            zeroize::Zeroizing::new(PkceCodeVerifier::secret(&pkce_verifier).to_string());
        let mut params = vec![
            ("client_id", self.client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("code_verifier", verifier_secret.as_str()),
            ("scope", scope.as_str()),
        ];
        if let Some(claims) = cae_claims.as_deref() {
            params.push(("claims", claims));
        }
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
        // The id token's `tid` is always the tenant GUID, so a tenant configured
        // by domain (env, settings.json or the `.env` bake — the config screen
        // only accepts a GUID) fails the tid check below every time. Say so
        // before sending the operator through the browser for nothing. A GUID
        // never contains a dot, so this needs no second copy of the GUID rule.
        if self.tenant_id.contains('.') {
            return Err(AuthError::TokenExchange(format!(
                "configured tenant {} is a domain; azapptoolkit needs the Directory (tenant) ID GUID from the app registration's Overview page",
                self.tenant_id
            )));
        }
        // The Graph read scopes: minted CAE, the slot `graph_for` reads.
        let initial_scopes = self.default_graph_read_scopes();
        let (token, claims) = self
            .run_auth_code_flow(&initial_scopes, "select_account", None, true)
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
        self.store_token_outcome(&tenant_id, &account_oid, &initial_scopes, &[], true, token)
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
        self.interactive_for_scopes(tenant_id, scopes, "consent", "consent")
            .await
    }

    /// Completes a **Conditional Access step-up** for `scopes`' resource: one
    /// browser round trip with `prompt=login`, pinned to the signed-in account,
    /// that forces the credential plus whatever interactive challenge (MFA,
    /// registration, an external factor) a policy demands for that audience.
    /// The new refresh token carries the satisfied claims, so later silent
    /// refreshes for the resource succeed.
    ///
    /// This is the recovery path for [`AuthError::InteractionRequired`]. It is
    /// scope-targeted on purpose: re-authenticating on the Graph read scopes
    /// never meets a policy scoped to ARM (or Exchange, or Log Analytics), so
    /// the next refresh for that audience failed again — a loop.
    pub async fn step_up_for_scopes(&self, tenant_id: &str, scopes: &[String]) -> Result<()> {
        self.interactive_for_scopes(tenant_id, scopes, "login", "verification")
            .await
    }

    /// The step-up the UI's "Verify identity" lever runs for a failed
    /// command's feature scope set — [`Self::step_up_for_scopes`] aimed at the
    /// set that can actually take it:
    ///
    /// - **A Graph set** steps up on the Graph **read** scopes, whatever
    ///   feature failed. Conditional Access targets the resource, not
    ///   individual scopes, so a verified Graph read token satisfies any Graph
    ///   policy; the read set is consented at sign-in, while stepping up on
    ///   the write (or another on-demand) set would show an operator who never
    ///   consented it a consent or admin-approval screen instead of the MFA
    ///   prompt. The token cache would mask the need (a cached read token is
    ///   still valid while the refresh behind a write needs MFA), so this runs
    ///   unconditionally.
    /// - **Any other set** (ARM, Exchange, Key Vault, Log Analytics) is first
    ///   acquired silently and stepped up only when that fails with
    ///   [`AuthError::InteractionRequired`]. Nothing in the error names the
    ///   audience that raised it, so a surface whose command touches two
    ///   audiences (Log Analytics then ARM for the usage query) asks for both
    ///   in order; the audience that needs no step-up costs no browser round
    ///   trip. Any other silent failure (e.g. `ConsentRequired`) is returned
    ///   as-is: `prompt=login` cannot fix it.
    pub async fn step_up_where_required(&self, tenant_id: &str, scopes: &[String]) -> Result<()> {
        if self.is_graph_scope_set(scopes) {
            let read = self.default_graph_read_scopes();
            return self.step_up_for_scopes(tenant_id, &read).await;
        }
        match self.access_token_for_scopes(tenant_id, scopes).await {
            Err(AuthError::InteractionRequired(_)) => {
                self.step_up_for_scopes(tenant_id, scopes).await
            }
            other => other.map(|_| ()),
        }
    }

    /// Shared core of [`Self::consent_for_scopes`] and
    /// [`Self::step_up_for_scopes`]: one interactive round trip for `scopes`
    /// with `prompt`, identity-checked against the session (`action` names the
    /// flow in a mismatch error), cached under the requested `scopes` — in the
    /// CAE slot for a Graph scope set, matching the adapter that consumes it.
    async fn interactive_for_scopes(
        &self,
        tenant_id: &str,
        scopes: &[String],
        prompt: &str,
        action: &str,
    ) -> Result<()> {
        let tenant = self
            .known_tenants
            .lock()
            .get(tenant_id)
            .cloned()
            .ok_or(AuthError::NotSignedIn)?;

        // The round trip needs an ID token (to confirm the same account
        // completed it) and a refresh token, so ensure the OIDC/offline scopes
        // are present even for bare resource `.default` scopes (e.g. ARM), which
        // omit them. The access token's audience is still set by the resource
        // scope; these reserved scopes only affect the id/refresh tokens.
        let mut auth_scopes = scopes.to_vec();
        for reserved in ["offline_access", "openid", "profile"] {
            if !auth_scopes.iter().any(|s| s == reserved) {
                auth_scopes.push(reserved.to_string());
            }
        }

        let cae = self.is_graph_scope_set(scopes);
        let (token, claims) = self
            .run_auth_code_flow(&auth_scopes, prompt, tenant.username.as_deref(), cae)
            .await?;

        // Defense-in-depth: a consent/login screen can switch tenant/account
        // even with a login_hint. Refuse to cache a token for a different
        // identity.
        ensure_same_identity(&claims, &tenant, action)?;

        // Cache under the *requested* `scopes` (not `auth_scopes`) so the next
        // silent acquisition for the same set hits this entry. `scope_key`
        // canonicalizes, so order doesn't matter.
        self.store_token_outcome(
            &tenant.tenant_id,
            &tenant.account_oid,
            scopes,
            scopes,
            cae,
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
    /// `interactive_for_scopes`, `reauthenticate`, `access_token_inner`):
    /// computes expiry, parses the issued scopes (`scope_fallback` covers
    /// responses that omit the `scope` echo), persists a rotated refresh token,
    /// and seeds the access-token cache under `cache_scopes` in the slot `cae`
    /// names — which must be how the token was minted. The keyring write is
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
        cae: bool,
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
            .put(tenant_id.to_string(), cache_scopes, cae, access.clone());
        Ok(access)
    }

    async fn access_token_inner(
        &self,
        tenant_id: &str,
        scopes: &[String],
        claims: Option<&str>,
        bypass_cache: bool,
    ) -> Result<AccessToken> {
        // A CAE request (`claims` always carries cp1) reads and fills the CAE
        // slot; a plain one the non-CAE slot — never the other's token.
        let cae = claims.is_some();
        if !bypass_cache
            && let Some(existing) = self.cache.get(tenant_id, scopes, cae)
            && !existing.needs_refresh(REFRESH_LEEWAY_SECS)
        {
            return Ok(existing);
        }

        let lock = self.refresh_lock_for(tenant_id, scopes);
        let _guard = lock.lock().await;
        if !bypass_cache
            && let Some(fresh) = self.cache.get(tenant_id, scopes, cae)
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
                // The refresh token we sent is no longer usable. Purge it and
                // drop any cached access tokens for the tenant so the next call
                // surfaces a clean "not signed in" rather than looping on a
                // stale token — but only if the keyring still holds THAT token.
                // Refresh locks are per scope set, so this POST can have been in
                // flight while a `reauthenticate`/consent stored a new one; an
                // unconditional purge would erase the session the operator just
                // re-established. The compare and the delete run under the
                // keyring's chunk-set lock (on the blocking pool), so no save
                // can land between them.
                tracing::warn!(tenant_id = %tenant.tenant_id, %reason, "refresh token rejected, purging");
                let (t, oid) = (tenant.tenant_id.clone(), tenant.account_oid.clone());
                let rejected = refresh_secret.clone();
                let purge = tokio::task::spawn_blocking(move || {
                    delete_refresh_token_if_current(&t, &oid, &rejected)
                })
                .await;
                if let Ok(Ok(PurgeOutcome::Superseded)) = purge {
                    // The newer session stays; the caller's silent retry
                    // (`refresh_session`) picks it up without a browser.
                    tracing::info!(
                        tenant_id = %tenant.tenant_id,
                        "refresh token was replaced while this refresh was in flight; keeping the newer session"
                    );
                    return Err(AuthError::RefreshTokenMissing(tenant.tenant_id.clone()));
                }
                // Deleted, already gone, or the keyring failed (ignored, as the
                // purge always was): the session is dead either way. One narrow
                // window remains: a `reauthenticate` that stores a new token and
                // re-registers the tenant after the delete above but before the
                // two lines below would lose its cached tokens and registration
                // (its keyring token survives, so launch restore still finds it).
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
            Err(AuthError::InteractionRequired(reason)) => {
                // A Conditional Access step-up for THIS resource (MFA,
                // registration, an external challenge). The refresh token is
                // still valid for every other audience — MSAL keeps the account
                // on `InteractionRequiredAuthError` — so do NOT purge, drop the
                // cached tokens or forget the tenant: that signed the operator
                // out of Graph browsing over an ARM-only MFA policy. Surface so
                // the caller can run `step_up_for_scopes`.
                tracing::info!(tenant_id = %tenant.tenant_id, %scope, %reason, "resource needs an interactive step-up");
                return Err(AuthError::InteractionRequired(reason));
            }
            Err(e) => return Err(e),
        };

        self.store_token_outcome(
            &tenant.tenant_id,
            &tenant.account_oid,
            scopes,
            scopes,
            cae,
            token,
        )
        .await
    }

    /// Ends `tenant`'s session: deletes the keyring refresh token, then drops
    /// the cached access tokens and the known-tenant entry.
    ///
    /// The keyring delete is the one fallible step, so it goes first: a failure
    /// leaves the known-tenant entry and cached tokens intact (the UI
    /// truthfully says "still signed in" and Sign out can be retried), never a
    /// cleared session whose refresh token survives for the next launch to
    /// restore. For a refresh token split across several keyring chunks
    /// (Windows) a failure after the first chunk is gone still leaves the
    /// in-memory session, but the stored token can no longer be loaded, so the
    /// next launch does not restore it.
    pub async fn sign_out(&self, tenant: &TenantContext) -> Result<()> {
        delete_refresh_token_off_worker(&tenant.tenant_id, &tenant.account_oid).await?;
        self.cache.invalidate_tenant(&tenant.tenant_id);
        self.known_tenants.lock().remove(&tenant.tenant_id);
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
    /// The read token is minted CAE, seeding the slot the Graph adapter
    /// (`ScopedTokenAdapter::new_cae`) reads.
    pub async fn refresh_session(&self, tenant_id: &str) -> Result<()> {
        self.cache.invalidate_tenant(tenant_id);
        self.access_token_for_scopes_cae(tenant_id, &self.default_graph_read_scopes(), None)
            .await?;
        Ok(())
    }

    /// Revives a *previous process's* session for `tenant` from the refresh
    /// token already in the OS keyring — no browser, no account picker.
    ///
    /// The keyring entry outlives the process, but it is keyed `{tenant}:{oid}`
    /// and nothing in memory knows the oid at launch, so the caller supplies the
    /// [`TenantContext`] it persisted at sign-in (`settings.json`'s
    /// `last_account` — the pointer, never the token). From there this is an
    /// ordinary silent acquisition of the sign-in read scopes: the same lazy
    /// shared refresh every Graph call takes, which is also what makes it a real
    /// proof of the session rather than a claim — a revoked or expired token
    /// fails here, at launch, instead of on the operator's first click.
    ///
    /// Errors exactly as [`Self::refresh_session`] does, `RefreshTokenMissing`
    /// included; a dead session is the *expected* outcome, so the caller shows
    /// the normal sign-in card rather than an error. Like
    /// [`Self::refresh_session`] it mints the read token CAE, seeding the slot
    /// the Graph adapter reads.
    pub async fn restore_session(&self, tenant: &TenantContext) -> Result<SignInOutcome> {
        // `access_token_inner` resolves the account — and therefore the keyring
        // key — through `known_tenants`, so the context has to be registered
        // before the grant. This is the one flow where that entry comes off disk
        // instead of a completed round trip, which is precisely why it must not
        // outlive a failed attempt: an unproven context left behind would let
        // any later command mint tokens for a session the operator was never
        // shown as signed into. `InvalidGrant` already removes it; the removal
        // is idempotent and also covers the failures that don't (a network
        // outage, a locked keyring), leaving the service exactly as found.
        self.known_tenants
            .lock()
            .insert(tenant.tenant_id.clone(), tenant.clone());
        match self
            .access_token_for_scopes_cae(&tenant.tenant_id, &self.default_graph_read_scopes(), None)
            .await
        {
            Ok(_) => Ok(SignInOutcome {
                tenant: tenant.clone(),
            }),
            Err(err) => {
                self.known_tenants.lock().remove(&tenant.tenant_id);
                Err(err)
            }
        }
    }

    /// Interactively re-authenticates the already-signed-in account, minting a
    /// fresh refresh + access token *without* ending the session or dropping the
    /// tenant's data caches. This is the recovery path for a **dead** session —
    /// an expired/revoked refresh token (surfaced as [`AuthError::InvalidGrant`],
    /// re-mapped to [`AuthError::RefreshTokenMissing`] after the stale token is
    /// purged) or a missing one — which the silent [`Self::refresh_session`]
    /// can't fix, sparing the user a full sign-out/sign-in (the latter would also
    /// wipe the cached lists + audit run). It is also the step-up for the Graph
    /// read scopes: a tenant-wide MFA or sign-in-frequency policy fails
    /// `refresh_session` with [`AuthError::InteractionRequired`], and this very
    /// round trip is what satisfies it.
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
            .run_auth_code_flow(&initial_scopes, "login", tenant.username.as_deref(), true)
            .await?;

        // Defense-in-depth (mirrors `consent_for_scopes`): a login screen can
        // switch tenant/account even with a login_hint.
        ensure_same_identity(&claims, tenant, "re-authentication")?;

        self.store_token_outcome(
            &tenant.tenant_id,
            &tenant.account_oid,
            &initial_scopes,
            &initial_scopes,
            true,
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

/// Keyring delete on the blocking pool — the same per-chunk OS round trips as
/// save/load, and it takes the std `CHUNK_SET_LOCK`, so never inline on a
/// tokio worker.
async fn delete_refresh_token_off_worker(tenant_id: &str, account_oid: &str) -> Result<()> {
    let (t, oid) = (tenant_id.to_string(), account_oid.to_string());
    tokio::task::spawn_blocking(move || delete_refresh_token(&t, &oid))
        .await
        .map_err(|e| AuthError::Keyring(format!("keyring delete task failed: {e}")))?
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
    use crate::token_cache::{fail_next_keyring_op, init_mock_keyring};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An auth service for `tenant` whose token endpoint points at `auth_root`
    /// (a mock server), with no session yet.
    fn fresh_service(
        auth_root: String,
        tenant: &str,
        open_browser: BrowserOpener,
    ) -> EntraAuthService {
        init_mock_keyring();
        EntraAuthService {
            client_id: "client".into(),
            // The same canonicalisation `new` applies.
            tenant_id: canonical_tenant_id(tenant),
            auth_root,
            cloud: CloudEnvironment::Commercial,
            cache: TokenCache::new(),
            refresh_locks: Mutex::new(HashMap::new()),
            known_tenants: Mutex::new(HashMap::new()),
            http: reqwest::Client::new(),
            open_browser,
        }
    }

    /// The silent paths never reach for a browser; one that does is a bug.
    fn no_browser() -> BrowserOpener {
        Box::new(|_| panic!("a silent path must not open a browser"))
    }

    /// Builds an auth service whose token endpoint points at `auth_root` (a mock
    /// server), already "signed in" to `tenant` with a stored refresh token.
    fn signed_in_service(auth_root: String, tenant: &str, oid: &str) -> EntraAuthService {
        let svc = fresh_service(auth_root, tenant, no_browser());
        save_refresh_token(tenant, oid, "stored-refresh-token").unwrap();
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

    /// An unsigned id token carrying the given claims — the shape
    /// `wire::parse_id_token` reads (it never checks the signature segment).
    fn id_token(tid: &str, oid: Option<&str>, nonce: &str) -> String {
        let mut claims = serde_json::json!({
            "tid": tid,
            "nonce": nonce,
            "preferred_username": "ada@contoso.com",
            "name": "Ada",
        });
        if let Some(oid) = oid {
            claims["oid"] = oid.into();
        }
        format!("h.{}.s", URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    /// Stands in for the system browser: reads the loopback `redirect_uri`,
    /// `state` and `nonce` from the authorize URL, records the nonce for the
    /// mock `/token`, and delivers the redirect the way Entra would. Counts its
    /// calls in `opened`.
    fn redirecting_opener(
        nonce_slot: Arc<Mutex<Option<String>>>,
        opened: Arc<AtomicUsize>,
    ) -> BrowserOpener {
        Box::new(move |url: &str| {
            opened.fetch_add(1, Ordering::SeqCst);
            let query: HashMap<String, String> = url::Url::parse(url)
                .unwrap()
                .query_pairs()
                .into_owned()
                .collect();
            *nonce_slot.lock() = query.get("nonce").cloned();
            let redirect = query["redirect_uri"].clone();
            // A CSRF token is base64url, so it needs no URL encoding.
            let state = query["state"].clone();
            tokio::spawn(async move {
                let mut socket =
                    tokio::net::TcpStream::connect(redirect.trim_start_matches("http://"))
                        .await
                        .unwrap();
                let request =
                    format!("GET /?code=test-code&state={state} HTTP/1.1\r\nHost: x\r\n\r\n");
                socket.write_all(request.as_bytes()).await.unwrap();
                let mut response = Vec::new();
                let _ = socket.read_to_end(&mut response).await;
            });
            Ok(())
        })
    }

    /// Mounts the interactive code redemption at the CONFIGURED tenant's
    /// authority, answering with an id token for `tid`/`oid`. The nonce is the
    /// one the opener saw in the authorize URL unless `forged_nonce` is set.
    async fn mount_interactive_token(
        server: &MockServer,
        configured_tenant: &str,
        tid: &str,
        oid: Option<&str>,
        forged_nonce: Option<&str>,
        nonce_slot: Arc<Mutex<Option<String>>>,
    ) {
        Mock::given(method("POST"))
            .and(path(format!("/{configured_tenant}/oauth2/v2.0/token")))
            .respond_with(interactive_token_response(
                tid,
                oid,
                forged_nonce,
                nonce_slot,
            ))
            .mount(server)
            .await;
    }

    /// The code-redemption response `mount_interactive_token` serves, for a
    /// test that needs its own matchers on the same mock.
    fn interactive_token_response(
        tid: &str,
        oid: Option<&str>,
        forged_nonce: Option<&str>,
        nonce_slot: Arc<Mutex<Option<String>>>,
    ) -> impl wiremock::Respond + use<> {
        let (tid, oid) = (tid.to_string(), oid.map(str::to_string));
        let forged_nonce = forged_nonce.map(str::to_string);
        move |_: &wiremock::Request| {
            let nonce = forged_nonce
                .clone()
                .or_else(|| nonce_slot.lock().clone())
                .expect("the browser was opened before the code was redeemed");
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "interactive-at",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "rt-interactive",
                "id_token": id_token(&tid, oid.as_deref(), &nonce),
            }))
        }
    }

    /// Wraps an opener so the authorize URL it was handed can be inspected.
    fn recording_opener(
        inner: BrowserOpener,
        url_slot: Arc<Mutex<Option<String>>>,
    ) -> BrowserOpener {
        Box::new(move |url: &str| {
            *url_slot.lock() = Some(url.to_string());
            inner(url)
        })
    }

    /// The query of the authorize URL a recording opener saw.
    fn recorded_query(url_slot: &Mutex<Option<String>>) -> HashMap<String, String> {
        let url = url_slot.lock().clone().expect("the browser was opened");
        url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect()
    }

    /// A service for `tenant` wired to the redirecting opener, plus the shared
    /// nonce slot and call counter.
    fn interactive_service(
        auth_root: String,
        tenant: &str,
    ) -> (
        EntraAuthService,
        Arc<Mutex<Option<String>>>,
        Arc<AtomicUsize>,
    ) {
        let nonce_slot = Arc::new(Mutex::new(None));
        let opened = Arc::new(AtomicUsize::new(0));
        let svc = fresh_service(
            auth_root,
            tenant,
            redirecting_opener(nonce_slot.clone(), opened.clone()),
        );
        (svc, nonce_slot, opened)
    }

    fn stored_token(tenant: &str, oid: &str) -> Option<String> {
        load_refresh_token(tenant, oid)
            .unwrap()
            .map(|t| t.as_str().to_string())
    }

    #[tokio::test]
    async fn sign_in_caches_the_read_token_and_registers_the_tenant() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("signin-ok-tenant", "signin-ok-oid");
        let (svc, nonce, _) = interactive_service(server.uri(), tenant);
        mount_interactive_token(&server, tenant, tenant, Some(oid), None, nonce).await;

        let outcome = svc.sign_in().await.unwrap();

        assert_eq!(outcome.tenant.account_oid, oid);
        let context = svc.tenant_context(tenant).expect("tenant registered");
        assert_eq!(context.account_oid, oid);
        assert_eq!(context.username.as_deref(), Some("ada@contoso.com"));
        assert_eq!(
            svc.cache
                .get(tenant, &svc.default_graph_read_scopes(), true)
                .expect("read token cached")
                .token,
            "interactive-at"
        );
        assert_eq!(stored_token(tenant, oid).as_deref(), Some("rt-interactive"));
    }

    /// An operator-typed uppercase GUID signs in against Entra's lowercase
    /// `tid`, and the session registers under the tid spelling.
    #[tokio::test]
    async fn sign_in_accepts_an_uppercase_configured_tenant() {
        let server = MockServer::start().await;
        let (tid, oid) = ("5a0e3c1d-9b7f-4e2a-8c6d-1f2e3d4c5b6a", "signin-upper-oid");
        let (svc, nonce, _) = interactive_service(server.uri(), &tid.to_ascii_uppercase());
        // The authority is built from the canonical (lowercase) tenant.
        mount_interactive_token(&server, tid, tid, Some(oid), None, nonce).await;

        let outcome = svc.sign_in().await.unwrap();

        assert_eq!(outcome.tenant.tenant_id, tid);
        assert!(svc.tenant_context(tid).is_some());
        assert_eq!(stored_token(tid, oid).as_deref(), Some("rt-interactive"));
    }

    #[test]
    fn new_stores_the_canonical_tenant() {
        let svc = EntraAuthService::new("c", " 5A0E3C1D-9B7F-4E2A-8C6D-1F2E3D4C5B6A ");
        assert_eq!(svc.tenant_id, "5a0e3c1d-9b7f-4e2a-8c6d-1f2e3d4c5b6a");
    }

    #[tokio::test]
    async fn sign_in_rejects_a_token_for_another_tenant() {
        let server = MockServer::start().await;
        let (tenant, other, oid) = ("signin-tid-tenant", "signin-tid-other", "signin-tid-oid");
        let (svc, nonce, _) = interactive_service(server.uri(), tenant);
        mount_interactive_token(&server, tenant, other, Some(oid), None, nonce).await;

        let result = svc.sign_in().await;

        assert!(
            matches!(&result, Err(AuthError::TokenExchange(m)) if m.contains("does not match")),
            "{:?}",
            result.err()
        );
        // Nothing of the foreign token was kept anywhere.
        assert!(svc.known_tenants.lock().is_empty());
        let read = svc.default_graph_read_scopes();
        assert!(svc.cache.get(tenant, &read, true).is_none());
        assert!(svc.cache.get(other, &read, true).is_none());
        assert_eq!(stored_token(other, oid), None);
        assert_eq!(stored_token(tenant, oid), None);
    }

    #[tokio::test]
    async fn sign_in_rejects_an_id_token_with_the_wrong_nonce() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("signin-nonce-tenant", "signin-nonce-oid");
        let (svc, nonce, _) = interactive_service(server.uri(), tenant);
        mount_interactive_token(&server, tenant, tenant, Some(oid), Some("forged"), nonce).await;

        let result = svc.sign_in().await;

        assert!(
            matches!(&result, Err(AuthError::TokenExchange(m)) if m == "id_token nonce mismatch"),
            "{:?}",
            result.err()
        );
        assert!(svc.known_tenants.lock().is_empty());
        assert!(
            svc.cache
                .get(tenant, &svc.default_graph_read_scopes(), true)
                .is_none()
        );
        assert_eq!(stored_token(tenant, oid), None);
    }

    #[tokio::test]
    async fn sign_in_rejects_an_id_token_without_oid() {
        let server = MockServer::start().await;
        let tenant = "signin-no-oid-tenant";
        let (svc, nonce, _) = interactive_service(server.uri(), tenant);
        mount_interactive_token(&server, tenant, tenant, None, None, nonce).await;

        let result = svc.sign_in().await;

        assert!(
            matches!(&result, Err(AuthError::TokenExchange(m)) if m == "id token missing oid"),
            "{:?}",
            result.err()
        );
        assert!(svc.known_tenants.lock().is_empty());
        assert!(
            svc.cache
                .get(tenant, &svc.default_graph_read_scopes(), true)
                .is_none()
        );
    }

    #[tokio::test]
    async fn sign_in_refuses_a_domain_tenant_before_opening_the_browser() {
        let server = MockServer::start().await;
        let (svc, _, opened) = interactive_service(server.uri(), "contoso.onmicrosoft.com");

        let result = svc.sign_in().await;

        assert!(
            matches!(&result, Err(AuthError::TokenExchange(m)) if m.contains("GUID")),
            "{:?}",
            result.err()
        );
        assert_eq!(
            opened.load(Ordering::SeqCst),
            0,
            "no wasted browser round trip"
        );
        assert!(svc.known_tenants.lock().is_empty());
    }

    #[tokio::test]
    async fn consent_as_a_different_account_is_rejected_and_the_cache_untouched() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("consent-id-tenant", "consent-id-oid");
        let mut svc = signed_in_service(server.uri(), tenant, oid);
        let nonce_slot = Arc::new(Mutex::new(None));
        svc.open_browser = redirecting_opener(nonce_slot.clone(), Arc::new(AtomicUsize::new(0)));
        mount_interactive_token(
            &server,
            tenant,
            tenant,
            Some("someone-else"),
            None,
            nonce_slot,
        )
        .await;
        let scopes = vec!["https://management.azure.com/.default".to_string()];

        let result = svc.consent_for_scopes(tenant, &scopes).await;

        assert!(
            matches!(result, Err(AuthError::Authorization(_))),
            "{:?}",
            result.err()
        );
        assert!(svc.cache.get(tenant, &scopes, false).is_none());
        assert_eq!(
            stored_token(tenant, oid).as_deref(),
            Some("stored-refresh-token")
        );
        assert!(svc.tenant_context(tenant).is_some());
    }

    #[tokio::test]
    async fn reauthenticate_restores_the_tenant_only_after_validation() {
        let context = |tenant: &str, oid: &str| TenantContext {
            tenant_id: tenant.into(),
            account_oid: oid.into(),
            username: Some("ada@contoso.com".into()),
            display_name: None,
        };

        // Same account: the session comes back (a dead grant had removed it).
        let server = MockServer::start().await;
        let (tenant, oid) = ("reauth-ok-tenant", "reauth-ok-oid");
        let mut svc = relaunched_service(server.uri(), tenant, oid);
        let nonce_slot = Arc::new(Mutex::new(None));
        svc.open_browser = redirecting_opener(nonce_slot.clone(), Arc::new(AtomicUsize::new(0)));
        mount_interactive_token(&server, tenant, tenant, Some(oid), None, nonce_slot).await;

        svc.reauthenticate(&context(tenant, oid)).await.unwrap();

        assert!(svc.tenant_context(tenant).is_some());
        assert_eq!(stored_token(tenant, oid).as_deref(), Some("rt-interactive"));

        // Another account at the login screen: refused, and not re-registered.
        let server = MockServer::start().await;
        let (tenant, oid) = ("reauth-other-tenant", "reauth-other-oid");
        let mut svc = relaunched_service(server.uri(), tenant, oid);
        let nonce_slot = Arc::new(Mutex::new(None));
        svc.open_browser = redirecting_opener(nonce_slot.clone(), Arc::new(AtomicUsize::new(0)));
        mount_interactive_token(
            &server,
            tenant,
            tenant,
            Some("someone-else"),
            None,
            nonce_slot,
        )
        .await;

        let result = svc.reauthenticate(&context(tenant, oid)).await;

        assert!(
            matches!(result, Err(AuthError::Authorization(_))),
            "{:?}",
            result.err()
        );
        assert!(svc.tenant_context(tenant).is_none());
        assert_eq!(
            stored_token(tenant, oid).as_deref(),
            Some("stored-refresh-token")
        );
    }

    #[tokio::test]
    async fn sign_out_keeps_the_whole_session_when_the_keyring_delete_fails() {
        let (tenant, oid) = ("signout-tenant", "signout-oid");
        let svc = signed_in_service("http://localhost".into(), tenant, oid);
        let read = svc.default_graph_read_scopes();
        svc.cache.put(
            tenant.to_string(),
            &read,
            true,
            AccessToken {
                token: "cached".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
                scopes: read.clone(),
            },
        );
        let context = svc.tenant_context(tenant).unwrap();
        fail_next_keyring_op(tenant, oid, 0);

        // A locked credential store: nothing is cleared, so "you are still
        // signed in" is true and the next launch has nothing stale to restore.
        let result = svc.sign_out(&context).await;
        assert!(matches!(result, Err(AuthError::Keyring(_))), "{result:?}");
        assert!(svc.tenant_context(tenant).is_some());
        assert!(svc.cache.get(tenant, &read, true).is_some());
        assert_eq!(
            stored_token(tenant, oid).as_deref(),
            Some("stored-refresh-token")
        );

        // The retry succeeds and clears all three.
        svc.sign_out(&context).await.unwrap();
        assert!(svc.tenant_context(tenant).is_none());
        assert!(svc.cache.get(tenant, &read, true).is_none());
        assert_eq!(stored_token(tenant, oid), None);
    }

    #[tokio::test]
    async fn invalid_grant_does_not_purge_a_token_stored_during_the_refresh() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("superseded-tenant", "superseded-oid");
        let (t, o) = (tenant.to_string(), oid.to_string());
        // The re-authentication lands while the old token's refresh is still
        // in flight: the responder stores the new token, then rejects the old.
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(move |_: &wiremock::Request| {
                save_refresh_token(&t, &o, "rt-reauthed").unwrap();
                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "AADSTS70000: refresh token expired"
                }))
            })
            .mount(&server)
            .await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        let result = svc
            .access_token_for_scopes(tenant, &["https://management.azure.com/.default".into()])
            .await;

        assert!(matches!(result, Err(AuthError::RefreshTokenMissing(_))));
        assert_eq!(stored_token(tenant, oid).as_deref(), Some("rt-reauthed"));
        assert!(svc.tenant_context(tenant).is_some());
    }

    /// Every keyring call in the service runs on the blocking pool: they are
    /// OS round trips per chunk and take a std mutex, so an inline one parks a
    /// tokio worker (often while holding a refresh lock). The call must sit on
    /// the `spawn_blocking` line or, where rustfmt wraps the closure, the line
    /// right below it.
    #[test]
    fn keyring_calls_stay_on_the_blocking_pool() {
        let source = include_str!("mod.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let lines: Vec<&str> = production.lines().collect();
        let mut calls = 0;
        for (idx, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let calls_keyring = [
                "save_refresh_token(",
                "load_refresh_token(",
                "delete_refresh_token(",
                "delete_refresh_token_if_current(",
            ]
            .iter()
            .any(|call| line.contains(call));
            if !calls_keyring {
                continue;
            }
            calls += 1;
            let previous = idx.checked_sub(1).map_or("", |i| lines[i]);
            assert!(
                line.contains("spawn_blocking") || previous.contains("spawn_blocking"),
                "keyring call outside spawn_blocking: {}",
                line.trim()
            );
        }
        // save, load, the conditional purge and the sign-out delete.
        assert!(calls >= 4, "the scan found only {calls} keyring calls");
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
            load_refresh_token(tenant, oid)
                .unwrap()
                .as_deref()
                .map(String::as_str),
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
            true,
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
        let cached = svc
            .cache
            .get(tenant, &read, true)
            .expect("read token re-cached");
        assert_eq!(cached.token, "freshly-minted");
        // The session is intact: the keyring refresh token and tenant survive.
        assert_eq!(
            load_refresh_token(tenant, oid)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("stored-refresh-token")
        );
        assert!(svc.known_tenants.lock().get(tenant).is_some());
    }

    /// A fresh process at launch: the keyring still holds the refresh token but
    /// nothing is in `known_tenants`, which is the state `restore_session` has
    /// to work from.
    fn relaunched_service(auth_root: String, tenant: &str, oid: &str) -> EntraAuthService {
        let svc = signed_in_service(auth_root, tenant, oid);
        svc.known_tenants.lock().clear();
        svc
    }

    #[tokio::test]
    async fn restore_session_revives_the_session_from_the_keyring() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("restore-tenant", "restore-oid");
        mount_token_success(&server, tenant, "restored-token").await;
        let svc = relaunched_service(server.uri(), tenant, oid);
        let context = TenantContext {
            tenant_id: tenant.into(),
            account_oid: oid.into(),
            username: Some("ada@contoso.com".into()),
            display_name: None,
        };

        let outcome = svc.restore_session(&context).await.unwrap();

        // The restored session is a real one: the read token is minted and
        // cached, and the tenant is registered for every later command.
        assert_eq!(outcome.tenant.account_oid, oid);
        assert_eq!(
            svc.cache
                .get(tenant, &svc.default_graph_read_scopes(), true)
                .expect("read token cached")
                .token,
            "restored-token"
        );
        assert!(svc.tenant_context(tenant).is_some());
    }

    #[tokio::test]
    async fn restore_session_leaves_no_session_behind_when_the_token_is_dead() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("restore-dead-tenant", "restore-dead-oid");
        mount_token_error(
            &server,
            tenant,
            serde_json::json!({
                "error": "invalid_grant",
                "error_description": "AADSTS70000: refresh token expired"
            }),
        )
        .await;
        let svc = relaunched_service(server.uri(), tenant, oid);
        let context = TenantContext {
            tenant_id: tenant.into(),
            account_oid: oid.into(),
            username: None,
            display_name: None,
        };

        let result = svc.restore_session(&context).await;

        // Revoked overnight: the operator lands on the normal sign-in card, and
        // the context we speculatively registered is gone — a half-live session
        // would let a later command mint tokens nobody signed in for.
        assert!(matches!(result, Err(AuthError::RefreshTokenMissing(_))));
        assert!(svc.tenant_context(tenant).is_none());
        assert_eq!(load_refresh_token(tenant, oid).unwrap(), None);
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
        assert!(!query.contains_key("claims"));
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
                None,
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
        assert!(!query.contains_key("claims"));
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

    fn token_ok(access_token: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": access_token,
            "expires_in": 3600,
            "token_type": "Bearer"
        }))
    }

    fn arm_scopes() -> Vec<String> {
        EntraAuthService::resource_default_scopes("https://management.azure.com")
    }

    fn fresh_token(token: &str, scopes: &[String]) -> AccessToken {
        AccessToken {
            token: token.into(),
            expires_at: Utc::now() + Duration::seconds(3600),
            scopes: scopes.to_vec(),
        }
    }

    // ---- F113: an abandoned browser round trip is `Cancelled` ----

    /// The operator closed the tab: no redirect ever arrives. Paused time
    /// auto-advances past `REDIRECT_WAIT` while the listener waits.
    #[tokio::test(start_paused = true)]
    async fn an_abandoned_browser_sign_in_is_cancelled() {
        let svc = fresh_service(
            "http://localhost".into(),
            "abandoned-tenant",
            Box::new(|_| Ok(())),
        );

        let result = svc.sign_in().await;

        assert!(matches!(result, Err(AuthError::Cancelled)), "{result:?}");
        assert!(svc.known_tenants.lock().is_empty());
    }

    // ---- F111: the /token POST rides the shared retry budget ----

    #[tokio::test]
    async fn a_throttled_refresh_is_retried_and_cached() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("retry-429-tenant", "retry-429-oid");
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(token_ok("after-throttle"))
            .expect(1)
            .mount(&server)
            .await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        let token = svc
            .access_token_for_scopes(tenant, &arm_scopes())
            .await
            .unwrap();

        assert_eq!(token.token, "after-throttle");
        assert_eq!(
            svc.cache.get(tenant, &arm_scopes(), false).unwrap().token,
            "after-throttle"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn a_server_error_on_refresh_is_retried() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("retry-503-tenant", "retry-503-oid");
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(token_ok("after-outage"))
            .expect(1)
            .mount(&server)
            .await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        let token = svc
            .access_token_for_scopes(tenant, &arm_scopes())
            .await
            .unwrap();

        assert_eq!(token.token, "after-outage");
        server.verify().await;
    }

    #[tokio::test]
    async fn a_rejection_is_not_retried() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("retry-400-tenant", "retry-400-oid");
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "AADSTS7000215: Invalid client secret"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        let result = svc.access_token_for_scopes(tenant, &arm_scopes()).await;

        assert!(
            matches!(&result, Err(AuthError::TokenExchange(m)) if m == "invalid_client (AADSTS7000215)"),
            "{result:?}"
        );
        server.verify().await;
    }

    /// An authorization code is single-use: a 5xx after Entra may already have
    /// redeemed it is never replayed.
    #[tokio::test]
    async fn the_code_exchange_is_not_replayed_after_a_server_error() {
        let server = MockServer::start().await;
        let tenant = "retry-code-tenant";
        let (svc, _, _) = interactive_service(server.uri(), tenant);
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(ResponseTemplate::new(500).insert_header("Retry-After", "0"))
            .expect(1)
            .mount(&server)
            .await;

        let result = svc.sign_in().await;

        assert!(
            matches!(&result, Err(AuthError::TokenExchange(m)) if m.contains("500")),
            "{result:?}"
        );
        server.verify().await;
    }

    #[test]
    fn only_a_refresh_grant_is_idempotent() {
        assert_eq!(
            retry_class_for(&[("grant_type", "refresh_token")]),
            RetryClass::Idempotent
        );
        assert_eq!(
            retry_class_for(&[("grant_type", "authorization_code")]),
            RetryClass::NonIdempotent
        );
        assert_eq!(retry_class_for(&[]), RetryClass::NonIdempotent);
    }

    // ---- F107: Graph flows mint CAE, and the cache keys on it ----

    #[test]
    fn authorize_url_carries_cae_claims_when_given() {
        let svc = EntraAuthService::new("client-id-xyz", "tenant-id-abc");
        let (challenge, _verifier) = PkceCodeChallenge::new_random_sha256();
        let claims = build_cae_claims(None);
        let url = svc
            .authorize_url(
                "https://login.microsoftonline.com/tenant-id-abc",
                "http://127.0.0.1:1234",
                "state-xyz",
                "nonce-xyz",
                &challenge,
                "openid",
                "login",
                None,
                Some(&claims),
            )
            .unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let v: serde_json::Value = serde_json::from_str(&query["claims"]).unwrap();
        assert_eq!(v["access_token"]["xms_cc"]["values"][0], "cp1");
    }

    #[tokio::test]
    async fn restore_and_refresh_mint_cae_graph_tokens() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("cae-restore-tenant", "cae-restore-oid");
        // A request without the cp1 claims falls through to a 404 and fails.
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(wiremock::matchers::body_string_contains("xms_cc"))
            .respond_with(token_ok("cae-read"))
            .expect(2)
            .mount(&server)
            .await;
        let svc = relaunched_service(server.uri(), tenant, oid);
        let context = TenantContext {
            tenant_id: tenant.into(),
            account_oid: oid.into(),
            username: None,
            display_name: None,
        };

        svc.restore_session(&context).await.unwrap();
        svc.refresh_session(tenant).await.unwrap();

        let read = svc.default_graph_read_scopes();
        assert_eq!(
            svc.cache.get(tenant, &read, true).unwrap().token,
            "cae-read"
        );
        assert!(svc.cache.get(tenant, &read, false).is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn sign_in_requests_a_cae_token() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("cae-signin-tenant", "cae-signin-oid");
        let (mut svc, nonce, opened) = interactive_service(server.uri(), tenant);
        let url_slot = Arc::new(Mutex::new(None));
        svc.open_browser =
            recording_opener(redirecting_opener(nonce.clone(), opened), url_slot.clone());
        // The code redemption must carry the cp1 claims too.
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(wiremock::matchers::body_string_contains("xms_cc"))
            .respond_with(interactive_token_response(tenant, Some(oid), None, nonce))
            .expect(1)
            .mount(&server)
            .await;

        svc.sign_in().await.unwrap();

        let query = recorded_query(&url_slot);
        let v: serde_json::Value = serde_json::from_str(&query["claims"]).unwrap();
        assert_eq!(v["access_token"]["xms_cc"]["values"][0], "cp1");
        let read = svc.default_graph_read_scopes();
        assert!(svc.cache.get(tenant, &read, true).is_some());
        assert!(svc.cache.get(tenant, &read, false).is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn consent_mints_cae_only_for_a_graph_scope_set() {
        // A non-Graph audience (ARM) stays non-CAE.
        let server = MockServer::start().await;
        let (tenant, oid) = ("cae-consent-arm-tenant", "cae-consent-arm-oid");
        let mut svc = signed_in_service(server.uri(), tenant, oid);
        let (nonce, url_slot) = (Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
        svc.open_browser = recording_opener(
            redirecting_opener(nonce.clone(), Arc::new(AtomicUsize::new(0))),
            url_slot.clone(),
        );
        mount_interactive_token(&server, tenant, tenant, Some(oid), None, nonce).await;

        svc.consent_for_scopes(tenant, &arm_scopes()).await.unwrap();

        assert!(!recorded_query(&url_slot).contains_key("claims"));
        assert_eq!(
            svc.cache.get(tenant, &arm_scopes(), false).unwrap().token,
            "interactive-at"
        );
        assert!(svc.cache.get(tenant, &arm_scopes(), true).is_none());

        // A Graph scope set is minted CAE — the slot `new_cae` reads.
        let server = MockServer::start().await;
        let (tenant, oid) = ("cae-consent-graph-tenant", "cae-consent-graph-oid");
        let mut svc = signed_in_service(server.uri(), tenant, oid);
        let (nonce, url_slot) = (Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
        svc.open_browser = recording_opener(
            redirecting_opener(nonce.clone(), Arc::new(AtomicUsize::new(0))),
            url_slot.clone(),
        );
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(wiremock::matchers::body_string_contains("xms_cc"))
            .respond_with(interactive_token_response(tenant, Some(oid), None, nonce))
            .expect(1)
            .mount(&server)
            .await;
        let write = svc.default_graph_write_scopes();

        svc.consent_for_scopes(tenant, &write).await.unwrap();

        let query = recorded_query(&url_slot);
        assert_eq!(query.get("prompt").map(String::as_str), Some("consent"));
        assert!(query.contains_key("claims"));
        assert!(svc.cache.get(tenant, &write, true).is_some());
        assert!(svc.cache.get(tenant, &write, false).is_none());
        server.verify().await;
    }

    // ---- F108: a Conditional Access step-up is not a dead session ----

    #[tokio::test]
    async fn interaction_required_keeps_the_refresh_token_and_session() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("step-up-tenant", "step-up-oid");
        mount_token_error(
            &server,
            tenant,
            serde_json::json!({
                "error": "interaction_required",
                "error_description": "AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication"
            }),
        )
        .await;
        let svc = signed_in_service(server.uri(), tenant, oid);
        let read = svc.default_graph_read_scopes();
        svc.cache.put(
            tenant.to_string(),
            &read,
            true,
            fresh_token("graph-read", &read),
        );

        let result = svc.access_token_for_scopes(tenant, &arm_scopes()).await;

        assert!(
            matches!(result, Err(AuthError::InteractionRequired(_))),
            "{result:?}"
        );
        // Nothing was purged: the keyring token, the tenant and every other
        // audience's cached token all survive.
        assert_eq!(
            stored_token(tenant, oid).as_deref(),
            Some("stored-refresh-token")
        );
        assert!(svc.known_tenants.lock().get(tenant).is_some());
        assert_eq!(
            svc.cache.get(tenant, &read, true).unwrap().token,
            "graph-read"
        );
    }

    #[tokio::test]
    async fn step_up_for_scopes_seeds_the_resource_token() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("step-up-ok-tenant", "step-up-ok-oid");
        let mut svc = signed_in_service(server.uri(), tenant, oid);
        let (nonce, url_slot) = (Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
        svc.open_browser = recording_opener(
            redirecting_opener(nonce.clone(), Arc::new(AtomicUsize::new(0))),
            url_slot.clone(),
        );
        mount_interactive_token(&server, tenant, tenant, Some(oid), None, nonce).await;

        svc.step_up_for_scopes(tenant, &arm_scopes()).await.unwrap();

        // `prompt=login` forces the credential plus the resource's CA challenge.
        let query = recorded_query(&url_slot);
        assert_eq!(query.get("prompt").map(String::as_str), Some("login"));
        assert_eq!(
            svc.cache.get(tenant, &arm_scopes(), false).unwrap().token,
            "interactive-at"
        );
        assert_eq!(stored_token(tenant, oid).as_deref(), Some("rt-interactive"));
        assert!(svc.tenant_context(tenant).is_some());
    }

    #[tokio::test]
    async fn step_up_as_a_different_account_is_rejected() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("step-up-id-tenant", "step-up-id-oid");
        let mut svc = signed_in_service(server.uri(), tenant, oid);
        let nonce = Arc::new(Mutex::new(None));
        svc.open_browser = redirecting_opener(nonce.clone(), Arc::new(AtomicUsize::new(0)));
        mount_interactive_token(&server, tenant, tenant, Some("someone-else"), None, nonce).await;

        let result = svc.step_up_for_scopes(tenant, &arm_scopes()).await;

        assert!(
            matches!(&result, Err(AuthError::Authorization(m)) if m.starts_with("verification")),
            "{result:?}"
        );
        assert!(svc.cache.get(tenant, &arm_scopes(), false).is_none());
        assert_eq!(
            stored_token(tenant, oid).as_deref(),
            Some("stored-refresh-token")
        );
    }

    // ---- F108 follow-up: the step-up aims at the set that can take it ----

    #[tokio::test]
    async fn a_graph_step_up_runs_on_the_read_scopes_not_the_failed_set() {
        // A Graph write failing `interaction_required` must not step up on the
        // write bundle: an operator who never consented it would get a consent
        // screen instead of the MFA prompt. The read set is always consented.
        let server = MockServer::start().await;
        let (tenant, oid) = ("graph-step-up-tenant", "graph-step-up-oid");
        let mut svc = signed_in_service(server.uri(), tenant, oid);
        let (nonce, url_slot) = (Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
        svc.open_browser = recording_opener(
            redirecting_opener(nonce.clone(), Arc::new(AtomicUsize::new(0))),
            url_slot.clone(),
        );
        mount_interactive_token(&server, tenant, tenant, Some(oid), None, nonce).await;
        let (read, write) = (
            svc.default_graph_read_scopes(),
            svc.default_graph_write_scopes(),
        );

        svc.step_up_where_required(tenant, &write).await.unwrap();

        let query = recorded_query(&url_slot);
        assert_eq!(query.get("prompt").map(String::as_str), Some("login"));
        let scope = &query["scope"];
        assert!(scope.contains("Directory.Read.All"), "{scope}");
        assert!(!scope.contains("Application.ReadWrite.All"), "{scope}");
        // Seeded in the CAE read slot the Graph read adapter consumes.
        assert!(svc.cache.get(tenant, &read, true).is_some());
        assert!(svc.cache.get(tenant, &write, true).is_none());
    }

    #[tokio::test]
    async fn a_resource_that_needs_no_step_up_opens_no_browser() {
        // A surface names every audience its command touches (the usage query
        // needs Log Analytics AND ARM); the one whose silent acquisition works
        // must cost no browser round trip (`signed_in_service` panics on one).
        let server = MockServer::start().await;
        let (tenant, oid) = ("no-step-up-tenant", "no-step-up-oid");
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(token_ok("arm-silent"))
            .expect(1)
            .mount(&server)
            .await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        svc.step_up_where_required(tenant, &arm_scopes())
            .await
            .unwrap();

        assert_eq!(
            svc.cache.get(tenant, &arm_scopes(), false).unwrap().token,
            "arm-silent"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn a_resource_that_needs_a_step_up_gets_one() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("needs-step-up-tenant", "needs-step-up-oid");
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(wiremock::matchers::body_string_contains(
                "grant_type=refresh_token",
            ))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "interaction_required",
                "error_description": "AADSTS50076: you must use multi-factor authentication"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut svc = signed_in_service(server.uri(), tenant, oid);
        let (nonce, opened) = (Arc::new(Mutex::new(None)), Arc::new(AtomicUsize::new(0)));
        svc.open_browser = redirecting_opener(nonce.clone(), opened.clone());
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(wiremock::matchers::body_string_contains(
                "grant_type=authorization_code",
            ))
            .respond_with(interactive_token_response(tenant, Some(oid), None, nonce))
            .expect(1)
            .mount(&server)
            .await;

        svc.step_up_where_required(tenant, &arm_scopes())
            .await
            .unwrap();

        assert_eq!(opened.load(Ordering::SeqCst), 1);
        assert_eq!(
            svc.cache.get(tenant, &arm_scopes(), false).unwrap().token,
            "interactive-at"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn a_missing_consent_is_not_answered_with_a_step_up() {
        // `prompt=login` can't grant consent: the typed error comes back and
        // no browser opens (`signed_in_service` panics on one).
        let server = MockServer::start().await;
        let (tenant, oid) = ("step-up-consent-tenant", "step-up-consent-oid");
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

        let result = svc.step_up_where_required(tenant, &arm_scopes()).await;

        assert!(
            matches!(result, Err(AuthError::ConsentRequired(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_long_retry_after_on_the_token_endpoint_is_terminal() {
        // Honouring minutes of Retry-After would hold the per-scope refresh
        // lock (and every same-key caller) for the whole wait.
        let server = MockServer::start().await;
        let (tenant, oid) = ("long-retry-after-tenant", "long-retry-after-oid");
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", (TOKEN_RETRY_AFTER_MAX_SECS + 1).to_string()),
            )
            .expect(1)
            .mount(&server)
            .await;
        let svc = signed_in_service(server.uri(), tenant, oid);

        let started = std::time::Instant::now();
        let result = svc.access_token_for_scopes(tenant, &arm_scopes()).await;

        assert!(result.is_err(), "{result:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(TOKEN_RETRY_AFTER_MAX_SECS));
        server.verify().await;
    }

    // ---- F115: the single-flight refresh, proven by behaviour ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_same_scope_requests_collapse_to_one_token_call() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("single-flight-tenant", "single-flight-oid");
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(token_ok("one-and-only").set_delay(std::time::Duration::from_millis(200)))
            .expect(1)
            .mount(&server)
            .await;
        let svc = Arc::new(signed_in_service(server.uri(), tenant, oid));

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let svc = svc.clone();
            set.spawn(async move {
                svc.access_token_for_scopes("single-flight-tenant", &arm_scopes())
                    .await
                    .map(|t| t.token.clone())
            });
        }
        let mut tokens = Vec::new();
        while let Some(joined) = set.join_next().await {
            tokens.push(joined.unwrap().unwrap());
        }

        assert_eq!(tokens.len(), 8);
        assert!(tokens.iter().all(|t| t == "one-and-only"), "{tokens:?}");
        server.verify().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn different_scope_sets_refresh_independently() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("per-key-tenant", "per-key-oid");
        // Each answer is held for `delay`; the responder records when each
        // request ARRIVED. Serialised behind one lock, the second cannot even
        // be sent until the first is answered, so the gap between arrivals is
        // at least `delay` by construction — no wall-clock budget to flake on.
        let delay = std::time::Duration::from_secs(2);
        let arrivals = Arc::new(Mutex::new(Vec::<std::time::Instant>::new()));
        let seen = arrivals.clone();
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .respond_with(move |_: &wiremock::Request| {
                seen.lock().push(std::time::Instant::now());
                token_ok("per-key").set_delay(delay)
            })
            .expect(2)
            .mount(&server)
            .await;
        let svc = Arc::new(signed_in_service(server.uri(), tenant, oid));
        let vault = EntraAuthService::resource_default_scopes("https://vault.azure.net");

        let arm = arm_scopes();
        let (a, b) = tokio::join!(
            svc.access_token_for_scopes(tenant, &arm),
            svc.access_token_for_scopes(tenant, &vault),
        );

        a.unwrap();
        b.unwrap();
        server.verify().await;
        // The per-key locks let the second audience's request reach the
        // endpoint while the first was still being held.
        let arrivals = arrivals.lock();
        assert_eq!(arrivals.len(), 2);
        let gap = arrivals[1].duration_since(arrivals[0]);
        assert!(
            gap < delay,
            "second request arrived {gap:?} after the first"
        );
    }

    #[tokio::test]
    async fn a_cae_challenge_bypasses_the_cache_and_sends_claims() {
        let server = MockServer::start().await;
        let (tenant, oid) = ("cae-challenge-tenant", "cae-challenge-oid");
        // The challenge's claims are forwarded (merged with cp1).
        Mock::given(method("POST"))
            .and(path(format!("/{tenant}/oauth2/v2.0/token")))
            .and(wiremock::matchers::body_string_contains("claims="))
            .and(wiremock::matchers::body_string_contains("1700000000"))
            .respond_with(token_ok("re-minted"))
            .expect(1)
            .mount(&server)
            .await;
        let svc = signed_in_service(server.uri(), tenant, oid);
        let read = svc.default_graph_read_scopes();
        svc.cache.put(
            tenant.to_string(),
            &read,
            true,
            fresh_token("seeded", &read),
        );
        let challenge = URL_SAFE_NO_PAD
            .encode(r#"{"access_token":{"nbf":{"essential":true,"value":"1700000000"}}}"#);

        let token = svc
            .access_token_for_scopes_cae(tenant, &read, Some(&challenge))
            .await
            .unwrap();

        assert_eq!(token.token, "re-minted");
        assert_eq!(
            svc.cache.get(tenant, &read, true).unwrap().token,
            "re-minted"
        );
        server.verify().await;
    }
}
