//! Entra ID sign-in via OAuth2 authorization code + PKCE.
//!
//! High-level flow:
//!   1. Bind a loopback listener on an ephemeral port.
//!   2. Build the authorize URL (read-only scopes from
//!      `azapptoolkit_core::constants::GRAPH_READ_SCOPES` plus `offline_access`),
//!      open it in the system browser. Write scopes are consented incrementally
//!      the first time a mutating Graph call needs them.
//!   3. Accept one HTTP request on the listener, pull `code` + `state`, reply
//!      with a success page, shut down.
//!   4. Exchange the code at `/token` with our own reqwest call so we can read
//!      `id_token` from the response.
//!   5. Resolve tenant id + account oid from the ID token claims.
//!
//! Access tokens are kept in memory only. Callers invoke
//! [`EntraAuthService::access_token_for_scopes`] on every Graph request; it
//! refreshes lazily 60s ahead of expiry under a single shared mutex, and caches
//! per scope set so the read and write tokens coexist.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{Duration, Utc};
use oauth2::{CsrfToken, PkceCodeChallenge, PkceCodeVerifier};
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_core::constants::{GRAPH_READ_SCOPES, GRAPH_WRITE_SCOPES};
use azapptoolkit_core::identity::{SignInOutcome, TenantContext};

use crate::error::{AuthError, Result};
use crate::token_cache::{
    delete_refresh_token, load_refresh_token, save_refresh_token, scope_key, AccessToken,
    TokenCache,
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

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    expires_in: u64,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
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

    /// Read-only Graph scopes requested at sign-in and used for every GET.
    /// `GRAPH_READ_SCOPES` plus `offline_access`, `openid`, `profile`.
    pub fn default_graph_read_scopes(&self) -> Vec<String> {
        self.graph_scopes(GRAPH_READ_SCOPES)
    }

    /// Read-write Graph scopes, requested on demand for mutating requests.
    /// `GRAPH_WRITE_SCOPES` plus `offline_access`, `openid`, `profile`. The
    /// refresh token minted at sign-in is redeemed for these the first time a
    /// write runs; admin consent on the tenant keeps the redemption silent.
    pub fn default_graph_write_scopes(&self) -> Vec<String> {
        self.graph_scopes(GRAPH_WRITE_SCOPES)
    }

    /// `Synchronization.Read.All` Graph scope for reading SCIM provisioning job
    /// status. Acquired on demand (incremental consent), not at sign-in, with
    /// the same graceful-degradation contract as the reports scope.
    pub fn default_graph_sync_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["Synchronization.Read.All"])
    }

    /// `AuditLog.Read.All` Graph scope for the directory activity / change log.
    /// Acquired on demand (incremental consent), never at sign-in, with the same
    /// graceful-degradation contract as the reports scope — a tenant that hasn't
    /// admin-consented (or lacks Entra ID P1/P2) can still sign in and browse;
    /// the Activity tab simply reports the feature as unavailable.
    pub fn default_graph_audit_log_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["AuditLog.Read.All"])
    }

    /// `Policy.Read.All` Graph scope for reading Conditional Access policies.
    /// Acquired on demand (incremental consent), never at sign-in, with the same
    /// graceful-degradation contract — a tenant without admin consent (or Entra
    /// ID P1/P2) can still sign in and browse; the Conditional Access tab simply
    /// reports the feature as unavailable.
    pub fn default_graph_policy_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["Policy.Read.All"])
    }

    /// `Policy.ReadWrite.ApplicationConfiguration` Graph scope for creating and
    /// assigning claims-mapping policies (SAML attribute & claim customization
    /// in the SSO setup flow). Admin-consent-only; acquired on demand, never at
    /// sign-in, so SSO setups that don't customize claims never request it and a
    /// tenant that hasn't consented can still sign in and browse.
    pub fn default_graph_policy_write_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["Policy.ReadWrite.ApplicationConfiguration"])
    }

    /// `Sites.FullControl.All` Graph scope for the SharePoint `Sites.Selected`
    /// model — listing, granting, and revoking a site's per-app permissions
    /// (the Permissions tab's SharePoint site access section). The
    /// site-permission endpoints require this
    /// scope even for reads. Acquired on demand (incremental consent), never at
    /// sign-in: it needs admin consent and a SharePoint-admin / site-owner
    /// signed-in user, so baking it into the write bundle would over-request it
    /// on every ordinary app edit and could block sign-in for un-consented
    /// tenants. The UI degrades to a "Grant consent" prompt instead.
    pub fn default_graph_sharepoint_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["Sites.FullControl.All"])
    }

    /// `GroupMember.ReadWrite.All` Graph scope for adding/removing a service
    /// principal as a member of a security group (group-gated APIs like
    /// Power BI / Fabric admit service principals via group membership).
    /// Deliberately the membership-only scope, not `Group.ReadWrite.All` — the
    /// app never creates or deletes groups. Admin-consent-only; acquired on
    /// demand, never at sign-in, with the same graceful-degradation contract
    /// as the SharePoint scope (membership *reads* ride `Directory.Read.All`).
    pub fn default_graph_group_member_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["GroupMember.ReadWrite.All"])
    }

    /// Prefixes each Graph permission with the Graph resource URL and appends
    /// the OIDC scopes (`offline_access` for the refresh token, `openid` +
    /// `profile` for the ID token). Callers that need tokens for other
    /// resources (Key Vault, ARM, SharePoint) use [`Self::resource_default_scopes`].
    fn graph_scopes(&self, permissions: &[&str]) -> Vec<String> {
        let resource = self.cloud.graph_resource();
        let mut scopes: Vec<String> = permissions
            .iter()
            .map(|s| format!("{resource}/{s}"))
            .collect();
        scopes.push("offline_access".to_string());
        scopes.push("openid".to_string());
        scopes.push("profile".to_string());
        scopes
    }

    /// Exchange Online Admin API scopes (`EXCHANGE_SCOPES` plus
    /// `offline_access`), for managing RBAC for Applications. The audience is
    /// `outlook.office365.com`, so this is a distinct token from the Graph
    /// read/write tokens; it is redeemed on demand from the sign-in refresh
    /// token the first time an Exchange operation runs.
    pub fn default_exchange_scopes(&self) -> Vec<String> {
        vec![
            // Classic scope — the InvokeCommand gateway rejects `ManageV2`
            // (preview per-cmdlet API only) with a bodyless 403. See
            // `azapptoolkit_core::constants::EXCHANGE_SCOPES`.
            format!("{}/Exchange.Manage", self.cloud.exchange_resource()),
            "offline_access".to_string(),
        ]
    }

    /// Scopes to request for a non-Graph audience. Every Entra-secured
    /// resource advertises a `<resource>/.default` scope that asks for "every
    /// permission the user consented to for this audience"; we always add
    /// `offline_access` so the refresh token keeps working across audiences.
    pub fn resource_default_scopes(resource_url: &str) -> Vec<String> {
        vec![
            format!("{}/.default", resource_url.trim_end_matches('/')),
            "offline_access".to_string(),
        ]
    }

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

    async fn listen_for_code(listener: TcpListener, expected_state: &str) -> Result<String> {
        let (mut socket, _peer) = listener
            .accept()
            .await
            .map_err(|e| AuthError::Loopback(e.to_string()))?;

        let mut buf = vec![0u8; 8192];
        let n = socket
            .read(&mut buf)
            .await
            .map_err(|e| AuthError::Loopback(e.to_string()))?;
        let request = String::from_utf8_lossy(&buf[..n]);

        let first_line = request.lines().next().unwrap_or_default();
        let mut parts = first_line.split_whitespace();
        let _method = parts.next();
        let path = parts.next().unwrap_or("");

        let query = path.split('?').nth(1).unwrap_or("");
        let mut code: Option<String> = None;
        let mut state: Option<String> = None;
        let mut error: Option<String> = None;
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                _ => {}
            }
        }

        let body = if error.is_some() {
            "<html><body><h2>Sign-in failed.</h2><p>You can close this window.</p></body></html>"
        } else {
            "<html><body><h2>azapptoolkit sign-in complete.</h2><p>You can close this window.</p></body></html>"
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;

        if let Some(err) = error {
            return Err(AuthError::Authorization(err));
        }

        let got_state = state.ok_or(AuthError::StateMismatch)?;
        if got_state != expected_state {
            return Err(AuthError::StateMismatch);
        }
        code.ok_or_else(|| AuthError::Authorization("no code returned".into()))
    }

    async fn post_token(&self, authority: &str, params: &[(&str, &str)]) -> Result<TokenResponse> {
        let url = format!("{authority}/oauth2/v2.0/token");
        let resp = self.http.post(&url).form(params).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            if let Ok(err_body) = serde_json::from_slice::<TokenErrorBody>(&bytes) {
                // Log the full AAD payload (description + correlation id +
                // anything else) for operators, but never surface it: AAD
                // error_description routinely embeds tenant/user GUIDs,
                // correlation IDs, and client IPs that should not flow into
                // the UI or audit log.
                tracing::warn!(
                    target: "auth",
                    aad_error = %err_body.error,
                    aad_description = err_body.error_description.as_deref().unwrap_or(""),
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

/// Maps an AAD `/token` error body to the right [`AuthError`]. A missing-consent
/// rejection (AADSTS65001 "not consented", 65004 "user declined", or the
/// `consent_required` OAuth code) is recoverable via interactive consent and
/// must be distinguished *first* — unlike [`AuthError::InvalidGrant`], it must
/// NOT purge the refresh token. Everything else `invalid_grant`-like means the
/// refresh token is dead; the remainder is a generic exchange failure. The
/// carried string is always the UI-safe redacted summary.
fn classify_token_error(body: &TokenErrorBody) -> AuthError {
    let safe = redacted_aad_error(body);
    let aadsts = body
        .error_description
        .as_deref()
        .and_then(extract_aadsts_code);
    if body.error == "consent_required"
        || matches!(aadsts.as_deref(), Some("AADSTS65001") | Some("AADSTS65004"))
    {
        return AuthError::ConsentRequired(safe);
    }
    if matches!(
        body.error.as_str(),
        "invalid_grant" | "interaction_required" | "login_required"
    ) {
        return AuthError::InvalidGrant(safe);
    }
    AuthError::TokenExchange(safe)
}

/// Builds a UI-safe summary of an AAD error response. Keeps the canonical
/// OAuth error code (e.g. `invalid_client`) and the AADSTS numeric code if
/// present, and drops the rest of `error_description` (which routinely
/// embeds tenant/user GUIDs, correlation IDs, and client IPs).
fn redacted_aad_error(body: &TokenErrorBody) -> String {
    let aadsts = body
        .error_description
        .as_deref()
        .and_then(extract_aadsts_code);
    match aadsts {
        Some(code) => format!("{} ({})", body.error, code),
        None => body.error.clone(),
    }
}

/// Pulls the first `AADSTSnnnnn` token out of an AAD error_description.
fn extract_aadsts_code(description: &str) -> Option<String> {
    let idx = description.find("AADSTS")?;
    let tail = &description[idx + "AADSTS".len()..];
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("AADSTS{digits}"))
    }
}

#[cfg(test)]
mod aad_redaction_tests {
    use super::*;

    #[test]
    fn extracts_aadsts_code() {
        let s = "AADSTS50034: The user account does not exist in <tenant guid> directory.";
        assert_eq!(extract_aadsts_code(s).as_deref(), Some("AADSTS50034"));
    }

    #[test]
    fn returns_none_when_no_code() {
        assert!(extract_aadsts_code("invalid_grant").is_none());
    }

    #[test]
    fn redacted_combines_oauth_and_aadsts() {
        let body = TokenErrorBody {
            error: "invalid_grant".into(),
            error_description: Some("AADSTS70008: The refresh token has expired...".into()),
        };
        assert_eq!(redacted_aad_error(&body), "invalid_grant (AADSTS70008)");
    }

    #[test]
    fn redacted_falls_back_to_oauth_code() {
        let body = TokenErrorBody {
            error: "invalid_client".into(),
            error_description: None,
        };
        assert_eq!(redacted_aad_error(&body), "invalid_client");
    }

    #[test]
    fn consent_codes_classify_as_consent_required_not_invalid_grant() {
        // AADSTS65001 ("not consented") arrives wrapped as `invalid_grant`; it
        // must surface as ConsentRequired so the refresh token is NOT purged.
        let body = TokenErrorBody {
            error: "invalid_grant".into(),
            error_description: Some(
                "AADSTS65001: The user or administrator has not consented to use the application."
                    .into(),
            ),
        };
        assert!(matches!(
            classify_token_error(&body),
            AuthError::ConsentRequired(_)
        ));

        // 65004 (user declined) and the explicit `consent_required` OAuth code
        // are the same recoverable class.
        let declined = TokenErrorBody {
            error: "invalid_grant".into(),
            error_description: Some("AADSTS65004: User declined to consent...".into()),
        };
        assert!(matches!(
            classify_token_error(&declined),
            AuthError::ConsentRequired(_)
        ));
        let explicit = TokenErrorBody {
            error: "consent_required".into(),
            error_description: None,
        };
        assert!(matches!(
            classify_token_error(&explicit),
            AuthError::ConsentRequired(_)
        ));
    }

    #[test]
    fn expired_refresh_token_stays_invalid_grant() {
        // A genuinely dead refresh token (70008) must still purge — it is NOT
        // a consent problem.
        let body = TokenErrorBody {
            error: "invalid_grant".into(),
            error_description: Some("AADSTS70008: The refresh token has expired...".into()),
        };
        assert!(matches!(
            classify_token_error(&body),
            AuthError::InvalidGrant(_)
        ));
    }

    #[test]
    fn other_errors_are_generic_token_exchange() {
        let body = TokenErrorBody {
            error: "invalid_client".into(),
            error_description: Some("AADSTS7000215: Invalid client secret...".into()),
        };
        assert!(matches!(
            classify_token_error(&body),
            AuthError::TokenExchange(_)
        ));
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
            Self::listen_for_code(listener, csrf_state.secret()),
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

        let expires_at = Utc::now() + Duration::seconds(token.expires_in as i64);
        let scopes = token
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default();

        let tenant = TenantContext {
            tenant_id: tenant_id.clone(),
            account_oid: account_oid.clone(),
            username: claims.preferred_username,
            display_name: claims.name,
        };

        self.cache.put(
            tenant_id.clone(),
            &initial_scopes,
            AccessToken {
                token: token.access_token,
                expires_at,
                scopes,
            },
        );
        self.known_tenants
            .lock()
            .insert(tenant_id.clone(), tenant.clone());
        if let Some(refresh) = token.refresh_token {
            save_refresh_token(&tenant_id, &account_oid, &refresh)?;
        }
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
        if claims.tid.as_deref() != Some(tenant.tenant_id.as_str()) {
            return Err(AuthError::Authorization(
                "consent completed for a different tenant".into(),
            ));
        }
        if claims.oid.as_deref() != Some(tenant.account_oid.as_str()) {
            return Err(AuthError::Authorization(
                "consent completed for a different account".into(),
            ));
        }

        let expires_at = Utc::now() + Duration::seconds(token.expires_in as i64);
        let issued_scopes = token
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_else(|| scopes.to_vec());

        if let Some(refresh) = token.refresh_token {
            save_refresh_token(&tenant.tenant_id, &tenant.account_oid, &refresh)?;
        }
        // Cache under the *requested* `scopes` (not `auth_scopes`) so the next
        // silent acquisition for the same set hits this entry. `scope_key`
        // canonicalizes, so order doesn't matter.
        self.cache.put(
            tenant_id.to_string(),
            scopes,
            AccessToken {
                token: token.access_token,
                expires_at,
                scopes: issued_scopes,
            },
        );
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

    async fn access_token_inner(
        &self,
        tenant_id: &str,
        scopes: &[String],
        claims: Option<&str>,
        bypass_cache: bool,
    ) -> Result<AccessToken> {
        if !bypass_cache {
            if let Some(existing) = self.cache.get(tenant_id, scopes) {
                if !existing.needs_refresh(REFRESH_LEEWAY_SECS) {
                    return Ok(existing);
                }
            }
        }

        let lock = self.refresh_lock_for(tenant_id, scopes);
        let _guard = lock.lock().await;
        if !bypass_cache {
            if let Some(fresh) = self.cache.get(tenant_id, scopes) {
                if !fresh.needs_refresh(REFRESH_LEEWAY_SECS) {
                    return Ok(fresh);
                }
            }
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

        let expires_at = Utc::now() + Duration::seconds(token.expires_in as i64);
        let issued_scopes = token
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_else(|| scopes.to_vec());

        if let Some(refresh) = token.refresh_token {
            // Blocking keyring write — off the async worker (see the read above).
            let (t, oid) = (tenant.tenant_id.clone(), tenant.account_oid.clone());
            tokio::task::spawn_blocking(move || save_refresh_token(&t, &oid, &refresh))
                .await
                .map_err(|e| AuthError::Keyring(format!("keyring write task failed: {e}")))??;
        }
        let access = AccessToken {
            token: token.access_token,
            expires_at,
            scopes: issued_scopes,
        };
        self.cache
            .put(tenant_id.to_string(), scopes, access.clone());
        Ok(access)
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

fn open_system_browser(url: &str) -> Result<()> {
    webbrowser::open(url)?;
    Ok(())
}

/// Base64-decodes a CAE `claims=` challenge value, tolerating both the
/// URL-safe (no-pad) and standard alphabets that different services emit.
fn decode_claims_challenge(b64: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(b64)
        .ok()
        .or_else(|| STANDARD.decode(b64).ok())
}

/// Builds the `claims` request parameter for a CAE-capable token. It always
/// advertises the `cp1` client capability (`xms_cc`) so Microsoft Graph issues a
/// CAE token; when a base64 `challenge` from a `401 insufficient_claims` is
/// supplied, its decoded claims are merged under `access_token` so the re-minted
/// token also satisfies the resource's new requirement.
fn build_cae_claims(challenge_b64: Option<&str>) -> String {
    use serde_json::{json, Value};
    let mut claims: Value = challenge_b64
        .and_then(decode_claims_challenge)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));

    let root = claims
        .as_object_mut()
        .expect("claims initialized as an object");
    let access_token = root.entry("access_token").or_insert_with(|| json!({}));
    if !access_token.is_object() {
        *access_token = json!({});
    }
    access_token
        .as_object_mut()
        .expect("access_token is an object")
        .insert("xms_cc".into(), json!({ "values": ["cp1"] }));
    claims.to_string()
}

#[derive(Debug, Default)]
struct IdClaims {
    tid: Option<String>,
    oid: Option<String>,
    preferred_username: Option<String>,
    name: Option<String>,
    nonce: Option<String>,
}

/// Decodes the **claims** segment of an ID token *without verifying its
/// signature* — it base64-decodes the middle JWT segment and reads fields.
///
/// Safe **only** because every call site feeds a token that arrived over TLS
/// directly from Entra's `/token` endpoint, and the security-relevant claims
/// (`nonce`, `tid`, `oid`) are re-bound to the request afterwards. Do NOT reuse
/// this on a token from an untrusted source: it performs no signature, issuer,
/// audience, or expiry validation.
fn parse_id_token(id_token: Option<&str>) -> Result<IdClaims> {
    let id_token =
        id_token.ok_or_else(|| AuthError::TokenExchange("no id_token in response".into()))?;
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() < 2 {
        return Err(AuthError::TokenExchange("malformed id_token".into()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AuthError::TokenExchange(format!("id_token b64 decode: {e}")))?;
    let value: serde_json::Value = serde_json::from_slice(&decoded)?;
    let claim = |key: &str| value.get(key).and_then(|v| v.as_str()).map(str::to_string);
    Ok(IdClaims {
        tid: claim("tid"),
        oid: claim("oid"),
        preferred_username: claim("preferred_username"),
        name: claim("name"),
        nonce: claim("nonce"),
    })
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
    fn read_scopes_are_read_only_with_offline_access() {
        let scopes = EntraAuthService::new("c", "t").default_graph_read_scopes();
        assert!(scopes.iter().any(|s| s == "offline_access"));
        assert!(scopes
            .iter()
            .any(|s| s == "https://graph.microsoft.com/Directory.Read.All"));
        assert!(
            !scopes.iter().any(|s| s.contains("ReadWrite")),
            "sign-in must not request any write scope"
        );
    }

    #[test]
    fn write_scopes_cover_mutations() {
        let scopes = EntraAuthService::new("c", "t").default_graph_write_scopes();
        assert!(scopes.iter().any(|s| s == "offline_access"));
        for perm in [
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "DelegatedPermissionGrant.ReadWrite.All",
        ] {
            assert!(scopes
                .iter()
                .any(|s| s == &format!("https://graph.microsoft.com/{perm}")));
        }
    }

    #[test]
    fn exchange_scopes_target_outlook_audience_with_offline_access() {
        let scopes = EntraAuthService::new("c", "t").default_exchange_scopes();
        assert!(scopes
            .iter()
            .any(|s| s == "https://outlook.office365.com/Exchange.Manage"));
        assert!(scopes.iter().any(|s| s == "offline_access"));
        // Must not leak any Graph scope into the Exchange token request.
        assert!(!scopes.iter().any(|s| s.contains("graph.microsoft.com")));
    }

    #[test]
    fn resource_default_scopes_appends_default_suffix() {
        let scopes = EntraAuthService::resource_default_scopes("https://vault.azure.net");
        assert!(scopes
            .iter()
            .any(|s| s == "https://vault.azure.net/.default"));
        assert!(scopes.iter().any(|s| s == "offline_access"));
    }

    #[test]
    fn parse_id_token_reads_tid_oid() {
        let payload =
            URL_SAFE_NO_PAD.encode(r#"{"tid":"t1","oid":"o1","name":"Alice","nonce":"n1"}"#);
        let id_token = format!("header.{payload}.sig");
        let claims = parse_id_token(Some(&id_token)).unwrap();
        assert_eq!(claims.tid.as_deref(), Some("t1"));
        assert_eq!(claims.oid.as_deref(), Some("o1"));
        assert_eq!(claims.name.as_deref(), Some("Alice"));
        assert_eq!(claims.nonce.as_deref(), Some("n1"));
    }

    #[test]
    fn cae_claims_advertise_cp1_and_merge_challenge() {
        // No challenge → just the cp1 client capability under access_token.
        let v: serde_json::Value = serde_json::from_str(&build_cae_claims(None)).unwrap();
        assert_eq!(v["access_token"]["xms_cc"]["values"][0], "cp1");

        // A challenge's claims are preserved AND cp1 is added alongside.
        let challenge = URL_SAFE_NO_PAD
            .encode(r#"{"access_token":{"nbf":{"essential":true,"value":"1700000000"}}}"#);
        let v: serde_json::Value =
            serde_json::from_str(&build_cae_claims(Some(&challenge))).unwrap();
        assert_eq!(v["access_token"]["nbf"]["value"], "1700000000");
        assert_eq!(v["access_token"]["xms_cc"]["values"][0], "cp1");
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
        assert!(query
            .get("scope")
            .unwrap()
            .contains("https://graph.microsoft.com/Directory.Read.All"));
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
        assert!(query
            .get("scope")
            .unwrap()
            .contains("https://management.azure.com/.default"));
    }
}
