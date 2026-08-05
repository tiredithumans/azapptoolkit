//! Shared bearer-token abstraction for the Azure REST clients.
//!
//! Both the Graph and Key Vault clients pull a bearer token per request but
//! for different audiences. They share this one trait so the desktop layer
//! wires a single adapter regardless of audience; the error is [`TokenError`]
//! — a code plus a message, carrying no client's error type — which callers map
//! into `GraphError::Token` / `KeyVaultError::Token`.

use async_trait::async_trait;
use std::sync::Arc;

/// Why a bearer token could not be obtained.
///
/// `code` is the stable classification (the same vocabulary
/// `azapptoolkit_dto::UiError` uses), and it exists because this boundary used
/// to be a bare `String`. Every client mapped that to its own
/// `Token(String)` variant with the fixed code `token_error`, so a **dead
/// session became indistinguishable from a transient token failure** — and
/// `UiError::is_reauth_fatal` could never fire for a client call. Long-running
/// fan-outs then warned their way through a session that was never coming back
/// and returned a partial result the UI presented as complete.
///
/// Keep this free of `AuthError`: the trait is used by clients that don't
/// depend on `azapptoolkit-auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenError {
    pub code: String,
    pub message: String,
}

impl TokenError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// A failure with no better classification available.
    pub fn opaque(message: impl Into<String>) -> Self {
        Self::new("token_error", message)
    }

    /// The session is gone and no amount of retrying will bring it back — the
    /// single definition is `UiError::is_reauth_fatal`, mirrored here because
    /// this crate sits below the DTO layer.
    pub fn is_reauth_fatal(&self) -> bool {
        matches!(self.code.as_str(), "refresh_missing" | "not_signed_in")
    }
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for TokenError {
    fn from(message: String) -> Self {
        Self::opaque(message)
    }
}

impl From<&str> for TokenError {
    fn from(message: &str) -> Self {
        Self::opaque(message)
    }
}

#[async_trait]
pub trait BearerProvider: Send + Sync {
    async fn bearer(&self) -> Result<String, TokenError>;

    /// Re-acquires a bearer token in response to a Continuous Access Evaluation
    /// (CAE) claims challenge — a `401` whose `WWW-Authenticate` carries
    /// `error="insufficient_claims"` and a `claims=` directive. `claims` is that
    /// (base64) challenge value, forwarded to the token endpoint so the new token
    /// satisfies the resource's freshly-required claims. The default ignores the
    /// challenge and returns a normal token (correct for providers that don't
    /// advertise CAE capability and so never receive a challenge).
    async fn bearer_with_claims(&self, _claims: &str) -> Result<String, TokenError> {
        self.bearer().await
    }
}

/// Test/harness provider returning a fixed string.
pub struct StaticTokenProvider {
    token: String,
}

impl StaticTokenProvider {
    pub fn new(token: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            token: token.into(),
        })
    }
}

#[async_trait]
impl BearerProvider for StaticTokenProvider {
    async fn bearer(&self) -> Result<String, TokenError> {
        Ok(self.token.clone())
    }
}
