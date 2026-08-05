use thiserror::Error;

pub type Result<T> = std::result::Result<T, ArmError>;

#[derive(Debug, Error)]
pub enum ArmError {
    #[error("unauthorized (401)")]
    Unauthorized,

    #[error("forbidden (403): {0}")]
    Forbidden(String),

    #[error("not found (404): {0}")]
    NotFound(String),

    #[error("throttled (429); retry after {retry_after_secs:?}s")]
    Throttled { retry_after_secs: Option<u64> },

    #[error("arm error ({status}): {body}")]
    Api { status: u16, body: String },

    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },

    #[error("network: {0}")]
    Network(String),

    #[error("deserialize: {0}")]
    Deserialize(String),

    #[error("token: {0}")]
    Token(azapptoolkit_core::token::TokenError),

    /// Client-side contract violation — e.g. a paging `nextLink` pointing off
    /// the ARM origin, which is refused before the bearer is attached.
    #[error("protocol: {0}")]
    Protocol(String),
}

impl ArmError {
    /// Delegates to the shared policy — see
    /// [`azapptoolkit_core::http_retry::is_retryable_code`]. `ui_code` below is
    /// this crate's only variant-to-class table.
    pub fn is_retryable(&self) -> bool {
        azapptoolkit_core::http_retry::is_retryable_code(self.ui_code())
    }

    pub fn ui_code(&self) -> &'static str {
        match self {
            ArmError::Unauthorized => "unauthorized",
            ArmError::Forbidden(_) => "forbidden",
            ArmError::NotFound(_) => "not_found",
            ArmError::Throttled { .. } => "throttled",
            ArmError::Api { .. } => "arm_error",
            ArmError::Server { .. } => "server_error",
            ArmError::Network(_) => "network_error",
            ArmError::Deserialize(_) => "deserialize_error",
            // Pass an auth classification through instead of flattening it:
            // `is_reauth_fatal` is what stops a long-running fan-out.
            ArmError::Token(t) => match t.code.as_str() {
                "refresh_missing" => "refresh_missing",
                "not_signed_in" => "not_signed_in",
                _ => "token_error",
            },
            ArmError::Protocol(_) => "protocol_error",
        }
    }

    /// Actionable role guidance appended to the raw message when surfacing the
    /// error (mirrors `ExchangeError::ui_hint`). A 403 on an ARM call means the
    /// signed-in user's Azure RBAC role is insufficient — sourced from the
    /// `azure_role_reads` capability so the text matches the readiness checklist
    /// and the proactive label. The one ARM *write* path (assigning a role to a
    /// managed identity) overrides this with more specific guidance at the
    /// command layer (`azure_role_assign`), so this gives the read-path role.
    pub fn ui_hint(&self) -> Option<&'static str> {
        match self {
            ArmError::Forbidden(_) => {
                azapptoolkit_core::capabilities::capability("azure_role_reads")
                    .map(|c| c.remediation)
            }
            ArmError::Unauthorized => Some(
                "Your Azure Resource Manager token was rejected. Sign out and back in; if it \
                 persists, confirm the app has consented the management.azure.com scope.",
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_throttle_server_network_are_retryable() {
        assert!(
            ArmError::Throttled {
                retry_after_secs: Some(5)
            }
            .is_retryable()
        );
        assert!(
            ArmError::Server {
                status: 503,
                body: String::new()
            }
            .is_retryable()
        );
        assert!(ArmError::Network("reset".into()).is_retryable());

        assert!(!ArmError::Unauthorized.is_retryable());
        assert!(!ArmError::Forbidden(String::new()).is_retryable());
        assert!(!ArmError::NotFound(String::new()).is_retryable());
        assert!(
            !ArmError::Api {
                status: 400,
                body: String::new()
            }
            .is_retryable()
        );
        assert!(!ArmError::Deserialize("bad".into()).is_retryable());
        assert!(!ArmError::Token("expired".into()).is_retryable());
        assert!(!ArmError::Protocol("off-origin nextLink".into()).is_retryable());
    }

    #[test]
    fn ui_code_is_stable_per_variant() {
        assert_eq!(ArmError::Unauthorized.ui_code(), "unauthorized");
        assert_eq!(ArmError::Forbidden(String::new()).ui_code(), "forbidden");
        assert_eq!(ArmError::NotFound(String::new()).ui_code(), "not_found");
        assert_eq!(
            ArmError::Throttled {
                retry_after_secs: None
            }
            .ui_code(),
            "throttled"
        );
        assert_eq!(
            ArmError::Api {
                status: 400,
                body: String::new()
            }
            .ui_code(),
            "arm_error"
        );
        assert_eq!(
            ArmError::Server {
                status: 500,
                body: String::new()
            }
            .ui_code(),
            "server_error"
        );
        assert_eq!(ArmError::Network(String::new()).ui_code(), "network_error");
        assert_eq!(
            ArmError::Deserialize(String::new()).ui_code(),
            "deserialize_error"
        );
        assert_eq!(
            ArmError::Token(azapptoolkit_core::token::TokenError::opaque("")).ui_code(),
            "token_error"
        );
        assert_eq!(
            ArmError::Protocol(String::new()).ui_code(),
            "protocol_error"
        );
    }

    #[test]
    fn forbidden_and_unauthorized_carry_role_hints() {
        // A 403 names the Azure RBAC read role (Reader) from the catalog.
        let f = ArmError::Forbidden("denied".into())
            .ui_hint()
            .expect("forbidden has a hint");
        assert!(f.contains("Reader"));
        assert!(ArmError::Unauthorized.ui_hint().is_some());
        // Non-authz variants carry no role hint.
        assert!(ArmError::NotFound(String::new()).ui_hint().is_none());
        assert!(ArmError::Token("x".into()).ui_hint().is_none());
    }
}
