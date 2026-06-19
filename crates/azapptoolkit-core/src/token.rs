//! Shared bearer-token abstraction for the Azure REST clients.
//!
//! Both the Graph and Key Vault clients pull a bearer token per request but
//! for different audiences. They share this one trait so the desktop layer
//! wires a single adapter regardless of audience; the error is a plain
//! `String` so the trait stays free of any one client's error type (callers
//! map it into `GraphError::Token` / `KeyVaultError::Token`).

use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait BearerProvider: Send + Sync {
    async fn bearer(&self) -> Result<String, String>;

    /// Re-acquires a bearer token in response to a Continuous Access Evaluation
    /// (CAE) claims challenge — a `401` whose `WWW-Authenticate` carries
    /// `error="insufficient_claims"` and a `claims=` directive. `claims` is that
    /// (base64) challenge value, forwarded to the token endpoint so the new token
    /// satisfies the resource's freshly-required claims. The default ignores the
    /// challenge and returns a normal token (correct for providers that don't
    /// advertise CAE capability and so never receive a challenge).
    async fn bearer_with_claims(&self, _claims: &str) -> Result<String, String> {
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
    async fn bearer(&self) -> Result<String, String> {
        Ok(self.token.clone())
    }
}
