//! Bridges `EntraAuthService` into the shared `azapptoolkit_core::BearerProvider`
//! used by both the Graph and Key Vault clients. One adapter serves every
//! audience — `scopes` selects which (Graph vs Key Vault vs …).

use std::sync::Arc;

use async_trait::async_trait;

use azapptoolkit_auth::{AuthError, EntraAuthService};
use azapptoolkit_core::token::{BearerProvider, TokenError};

use crate::dto::UiError;

/// Carries the auth classification across the `BearerProvider` boundary — the
/// sole mapping from `AuthError` to `TokenError`.
///
/// This is the ONLY place that knows both `AuthError` and `TokenError`, and it
/// is what lets a client call report a dead session (and a missing consent, and
/// a refresh-time network outage): without it every token failure reached the
/// command layer as the undifferentiated `token_error`, so
/// `UiError::is_reauth_fatal` never fired for a Graph/Exchange/Key Vault/ARM
/// call and long-running fan-outs warned their way through a session that was
/// already gone.
///
/// It no longer keeps its own code table: `From<AuthError> for UiError` is the
/// one classification, and this only translates its auth-plane code into the
/// client plane ([`client_plane_code`]). The message is unchanged — that
/// conversion builds it from `err.to_string()`.
fn token_error(err: AuthError) -> TokenError {
    let ui = UiError::from(err);
    TokenError::new(client_plane_code(&ui.code), ui.message)
}

/// Auth-plane `UiError` code → the code a client's `Token` arm understands
/// (`core::reauth::passthrough_code`); anything unclassified is `token_error`.
///
/// `TokenExchange` (auth-plane `token_exchange`) deliberately stays
/// `token_error`: `post_token` reports every unrecognised non-2xx — 4xx
/// included — that way, so calling it transient would retry permanent failures.
fn client_plane_code(auth_code: &str) -> &'static str {
    match auth_code {
        // The auth plane spells a transport failure `network` (From<AuthError>:
        // Http); the client plane and `http_retry` spell it `network_error`.
        "network" => "network_error",
        c => azapptoolkit_core::reauth::passthrough_code(c).unwrap_or("token_error"),
    }
}

pub struct ScopedTokenAdapter {
    auth: Arc<EntraAuthService>,
    tenant_id: String,
    scopes: Vec<String>,
    /// The session epoch this adapter was built under. A sign-out or a
    /// same-tenant account switch moves it, and `AppState::forget_tenant`
    /// drops the client maps — but a write run that already holds an
    /// `Arc<GraphClient>` keeps calling; tokens resolve by tenant, so without
    /// this check it would mint the NEW account's tokens for the OLD
    /// operator's run. Re-auth in place does not move the epoch, so a run
    /// survives it.
    epoch: u64,
    /// When `true`, tokens are acquired CAE-aware (advertise `cp1`; honor a
    /// claims challenge). Set only for the Microsoft Graph clients, which handle
    /// the `401 insufficient_claims` retry; other resources stay non-CAE so they
    /// never receive a challenge they don't handle.
    cae: bool,
}

impl ScopedTokenAdapter {
    pub fn new(auth: Arc<EntraAuthService>, tenant_id: String, scopes: Vec<String>) -> Arc<Self> {
        let epoch = auth.session_epoch();
        Arc::new(Self {
            auth,
            tenant_id,
            scopes,
            epoch,
            cae: false,
        })
    }

    /// Like [`Self::new`] but CAE-capable — for the Graph clients (see the `cae`
    /// field).
    pub fn new_cae(
        auth: Arc<EntraAuthService>,
        tenant_id: String,
        scopes: Vec<String>,
    ) -> Arc<Self> {
        let epoch = auth.session_epoch();
        Arc::new(Self {
            auth,
            tenant_id,
            scopes,
            epoch,
            cae: true,
        })
    }

    /// Refuses to mint once the session this adapter was built under has
    /// ended: `not_signed_in`, which every long-running loop stops on.
    fn require_live_session(&self) -> Result<(), TokenError> {
        if self.auth.session_epoch() == self.epoch {
            Ok(())
        } else {
            Err(token_error(AuthError::NotSignedIn))
        }
    }
}

#[async_trait]
impl BearerProvider for ScopedTokenAdapter {
    async fn bearer(&self) -> Result<String, TokenError> {
        self.require_live_session()?;
        let mut token = if self.cae {
            self.auth
                .access_token_for_scopes_cae(&self.tenant_id, &self.scopes, None)
                .await
        } else {
            self.auth
                .access_token_for_scopes(&self.tenant_id, &self.scopes)
                .await
        }
        .map_err(token_error)?;
        // Again after the wait: a caller parked on the refresh lock across a
        // sign-out and sign-in would otherwise be handed the new account's
        // token by the re-check under that lock.
        self.require_live_session()?;
        // `AccessToken: Drop` (zeroizes on drop), so we can't move the inner
        // String out — extract it via `mem::take`, leaving the husk to be
        // dropped harmlessly.
        Ok(std::mem::take(&mut token.token))
    }

    async fn bearer_with_claims(&self, claims: &str) -> Result<String, TokenError> {
        // A non-CAE adapter never advertised cp1, so it shouldn't see a challenge;
        // fall back to a normal token if one somehow arrives.
        if !self.cae {
            return self.bearer().await;
        }
        self.require_live_session()?;
        let mut token = self
            .auth
            .access_token_for_scopes_cae(&self.tenant_id, &self.scopes, Some(claims))
            .await
            .map_err(token_error)?;
        self.require_live_session()?;
        Ok(std::mem::take(&mut token.token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_graph::GraphError;

    /// A constructor for one `AuthError` case and its boundary code.
    type Case = (fn() -> AuthError, &'static str);

    /// Every constructible `AuthError` (the same cases as dto's
    /// `auth_error_maps_to_stable_code_and_retryable`) and the code it must
    /// carry across the `BearerProvider` boundary. `AuthError` isn't `Clone`,
    /// so each case is a constructor.
    fn cases() -> Vec<Case> {
        vec![
            (|| AuthError::NotSignedIn, "not_signed_in"),
            (
                || AuthError::RefreshTokenMissing("tenant".into()),
                "refresh_missing",
            ),
            (
                || AuthError::InvalidGrant("invalid_grant".into()),
                "refresh_missing",
            ),
            (
                || AuthError::ConsentRequired("AADSTS65001".into()),
                "consent_required",
            ),
            (
                || AuthError::InteractionRequired("AADSTS50076".into()),
                "interaction_required",
            ),
            (
                || AuthError::TokenExchange("HTTP 400".into()),
                "token_error",
            ),
            (|| AuthError::Authorization("boom".into()), "token_error"),
            (|| AuthError::Loopback("boom".into()), "token_error"),
            (|| AuthError::StateMismatch, "token_error"),
            (|| AuthError::Cancelled, "token_error"),
            (|| AuthError::Keyring("locked".into()), "token_error"),
            (
                || AuthError::Url(reqwest::Url::parse("http://[bad").unwrap_err()),
                "token_error",
            ),
            (
                || AuthError::Serde(serde_json::from_str::<i32>("nope").unwrap_err()),
                "token_error",
            ),
            (
                || AuthError::Io(std::io::Error::other("disk")),
                "token_error",
            ),
        ]
    }

    #[test]
    fn every_classified_auth_error_crosses_the_boundary_with_its_code() {
        for (make, code) in cases() {
            let tok = token_error(make());
            assert_eq!(tok.code, code, "boundary code for {:?}", make());
            // Derived from the one classification table, not a copy of it.
            assert_eq!(tok.code, client_plane_code(&UiError::from(make()).code));
            assert_eq!(tok.message, make().to_string(), "message unchanged");
        }
    }

    #[test]
    fn a_network_failure_during_refresh_stays_retryable() {
        assert_eq!(client_plane_code("network"), "network_error");

        // reqwest defers an unparseable URL to `build()`, which is the one
        // public way to get a `reqwest::Error` without a live socket.
        let http = reqwest::Client::new()
            .get("not a url")
            .build()
            .expect_err("an unparseable URL fails to build");
        let tok = token_error(AuthError::Http(http));
        assert_eq!(tok.code, "network_error");
        assert!(GraphError::Token(tok.clone()).is_retryable());
        let ui = UiError::from(GraphError::Token(tok));
        assert_eq!(ui.code, "network_error");
        assert!(ui.retryable);
    }

    #[test]
    fn the_client_facing_codes_survive_into_a_graph_error() {
        let makers: [fn() -> AuthError; 4] = [
            || AuthError::NotSignedIn,
            || AuthError::InvalidGrant("invalid_grant".into()),
            || AuthError::ConsentRequired("AADSTS65001".into()),
            || AuthError::InteractionRequired("AADSTS50076".into()),
        ];
        for make in makers {
            let through_graph = UiError::from(GraphError::Token(token_error(make())));
            assert_eq!(through_graph.code, UiError::from(make()).code);
        }
    }
}
