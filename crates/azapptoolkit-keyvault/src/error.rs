use thiserror::Error;

pub type Result<T> = std::result::Result<T, KeyVaultError>;

#[derive(Debug, Error)]
pub enum KeyVaultError {
    #[error("unauthorized (401)")]
    Unauthorized,

    #[error("forbidden (403): {0}")]
    Forbidden(String),

    #[error("not found (404): {0}")]
    NotFound(String),

    #[error("throttled (429); retry after {retry_after_secs:?}s")]
    Throttled { retry_after_secs: Option<u64> },

    #[error("vault error ({status}): {body}")]
    Api { status: u16, body: String },

    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },

    #[error("network: {0}")]
    Network(String),

    #[error("deserialize: {0}")]
    Deserialize(String),

    #[error("token: {0}")]
    Token(String),

    #[error("invalid name: {0}")]
    InvalidName(String),

    #[error("protocol: {0}")]
    Protocol(String),
}

impl KeyVaultError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            KeyVaultError::Throttled { .. }
                | KeyVaultError::Server { .. }
                | KeyVaultError::Network(_)
        )
    }

    pub fn ui_code(&self) -> &'static str {
        match self {
            KeyVaultError::Unauthorized => "unauthorized",
            KeyVaultError::Forbidden(_) => "forbidden",
            KeyVaultError::NotFound(_) => "not_found",
            KeyVaultError::Throttled { .. } => "throttled",
            KeyVaultError::Api { .. } => "vault_error",
            KeyVaultError::Server { .. } => "server_error",
            KeyVaultError::Network(_) => "network_error",
            KeyVaultError::Deserialize(_) => "deserialize_error",
            KeyVaultError::Token(_) => "token_error",
            KeyVaultError::InvalidName(_) => "invalid_name",
            KeyVaultError::Protocol(_) => "protocol_error",
        }
    }

    /// Actionable role guidance appended to the raw message when surfacing the
    /// error (mirrors `ExchangeError::ui_hint`). A 403 means the signed-in user
    /// lacks an Azure RBAC data-plane role on the vault — sourced from the
    /// `keyvault_secrets` capability so the text matches the readiness checklist
    /// and the proactive label (it also flags the RBAC-permission-mode caveat).
    pub fn ui_hint(&self) -> Option<&'static str> {
        match self {
            KeyVaultError::Forbidden(_) => {
                azapptoolkit_core::capabilities::capability("keyvault_secrets")
                    .map(|c| c.remediation)
            }
            KeyVaultError::Unauthorized => Some(
                "Your Key Vault token was rejected. Sign out and back in; if it persists, confirm \
                 the app has consented the vault.azure.net scope.",
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_and_unauthorized_carry_role_hints() {
        // A 403 names the Key Vault data-plane role from the catalog.
        let f = KeyVaultError::Forbidden("denied".into())
            .ui_hint()
            .expect("forbidden has a hint");
        assert!(f.contains("Key Vault Secrets Officer"));
        assert!(KeyVaultError::Unauthorized.ui_hint().is_some());
        // Non-authz variants carry no role hint.
        assert!(KeyVaultError::NotFound(String::new()).ui_hint().is_none());
        assert!(KeyVaultError::InvalidName("x".into()).ui_hint().is_none());
    }
}
