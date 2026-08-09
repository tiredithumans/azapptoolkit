//! ARM client errors.
//!
//! The taxonomy is generated from [`azapptoolkit_core::http_error_enum`] — one
//! definition shared with `GraphError` and `KeyVaultError`. `ui_hint` stays
//! hand-written: it is the one method that genuinely differs per crate, naming
//! this API's Azure RBAC role from the capabilities catalog.

pub type Result<T> = std::result::Result<T, ArmError>;

azapptoolkit_core::http_error_enum! {
    /// Every failure mode of an Azure Resource Manager call.
    pub enum ArmError {
        api_display = "arm error ({status}): {body}",
        api_code = "arm_error",
    }
}

impl ArmError {
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
