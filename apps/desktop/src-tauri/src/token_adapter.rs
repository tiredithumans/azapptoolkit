//! Bridges `EntraAuthService` into the shared `azapptoolkit_core::BearerProvider`
//! used by both the Graph and Key Vault clients. One adapter serves every
//! audience — `scopes` selects which (Graph vs Key Vault vs …).

use std::sync::Arc;

use async_trait::async_trait;

use azapptoolkit_auth::{AuthError, EntraAuthService};
use azapptoolkit_core::token::{BearerProvider, TokenError};

/// Carries the auth classification across the `BearerProvider` boundary.
///
/// This is the ONLY place that knows both `AuthError` and `TokenError`, and it
/// is what lets a client call report a dead session: without it every token
/// failure reached the command layer as the undifferentiated `token_error`, so
/// `UiError::is_reauth_fatal` never fired for a Graph/Exchange/Key Vault/ARM
/// call and long-running fan-outs warned their way through a session that was
/// already gone. The codes must match `UiError`'s — `From<AuthError> for
/// UiError` is the source of truth for the mapping.
fn token_error(err: AuthError) -> TokenError {
    let code = match &err {
        AuthError::NotSignedIn => "not_signed_in",
        AuthError::RefreshTokenMissing(_) | AuthError::InvalidGrant(_) => "refresh_missing",
        AuthError::ConsentRequired(_) => "consent_required",
        _ => "token_error",
    };
    TokenError::new(code, err.to_string())
}

pub struct ScopedTokenAdapter {
    auth: Arc<EntraAuthService>,
    tenant_id: String,
    scopes: Vec<String>,
    /// When `true`, tokens are acquired CAE-aware (advertise `cp1`; honor a
    /// claims challenge). Set only for the Microsoft Graph clients, which handle
    /// the `401 insufficient_claims` retry; other resources stay non-CAE so they
    /// never receive a challenge they don't handle.
    cae: bool,
}

impl ScopedTokenAdapter {
    pub fn new(auth: Arc<EntraAuthService>, tenant_id: String, scopes: Vec<String>) -> Arc<Self> {
        Arc::new(Self {
            auth,
            tenant_id,
            scopes,
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
        Arc::new(Self {
            auth,
            tenant_id,
            scopes,
            cae: true,
        })
    }
}

#[async_trait]
impl BearerProvider for ScopedTokenAdapter {
    async fn bearer(&self) -> Result<String, TokenError> {
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
        let mut token = self
            .auth
            .access_token_for_scopes_cae(&self.tenant_id, &self.scopes, Some(claims))
            .await
            .map_err(token_error)?;
        Ok(std::mem::take(&mut token.token))
    }
}
