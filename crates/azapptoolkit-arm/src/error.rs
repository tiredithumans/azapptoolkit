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
                "Your Azure Resource Manager token was rejected. Use \"Refresh token\" (next to \
                 Sign out), then retry; if it persists, confirm the app has consented the \
                 management.azure.com scope.",
            ),
            _ => None,
        }
    }

    /// The ARM error envelope's `error.code` (e.g. `RoleAssignmentExists`) of a
    /// terminal 4xx [`ArmError::Api`], so a caller can branch on the code rather
    /// than substring-match the JSON. `None` for any other variant or a body
    /// that is not the envelope. The body is sanitized and capped, which leaves
    /// ARM's short envelopes intact.
    pub fn arm_error_code(&self) -> Option<String> {
        let ArmError::Api { body, .. } = self else {
            return None;
        };
        serde_json::from_str::<serde_json::Value>(body)
            .ok()?
            .pointer("/error/code")?
            .as_str()
            .map(str::to_owned)
    }

    /// ARM's answer to a role assignment the principal already holds at that
    /// scope: 409 `RoleAssignmentExists`. Nothing was created.
    pub fn is_role_assignment_exists(&self) -> bool {
        matches!(self, ArmError::Api { status: 409, .. })
            && self.arm_error_code().as_deref() == Some("RoleAssignmentExists")
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
        // A 401 points at the in-place lever, never at signing out (which
        // would drop every data cache).
        let u = ArmError::Unauthorized
            .ui_hint()
            .expect("unauthorized has a hint");
        assert!(u.contains("Refresh token"), "{u}");
        assert!(!u.contains("Sign out and back in"), "{u}");
        // Non-authz variants carry no role hint.
        assert!(ArmError::NotFound(String::new()).ui_hint().is_none());
        assert!(ArmError::Token("x".into()).ui_hint().is_none());
    }

    #[test]
    fn a_duplicate_role_assignment_is_recognised_by_status_and_code() {
        let api = |status, body: &str| ArmError::Api {
            status,
            body: body.to_string(),
        };
        let exists = r#"{"error":{"code":"RoleAssignmentExists","message":"The role assignment already exists."}}"#;
        let err = api(409, exists);
        assert_eq!(
            err.arm_error_code().as_deref(),
            Some("RoleAssignmentExists")
        );
        assert!(err.is_role_assignment_exists());

        // A different 409 conflict is not a duplicate.
        let other = api(
            409,
            r#"{"error":{"code":"RoleAssignmentUpdateNotPermitted","message":"no"}}"#,
        );
        assert_eq!(
            other.arm_error_code().as_deref(),
            Some("RoleAssignmentUpdateNotPermitted")
        );
        assert!(!other.is_role_assignment_exists());
        // The code on a non-409 status is not trusted as the duplicate case.
        assert!(!api(400, exists).is_role_assignment_exists());
        // A body that is not the envelope (a proxy page) yields no code.
        let html = api(409, "<html>conflict</html>");
        assert_eq!(html.arm_error_code(), None);
        assert!(!html.is_role_assignment_exists());
        // Only the Api variant carries an ARM envelope.
        assert_eq!(ArmError::Forbidden(exists.into()).arm_error_code(), None);
    }
}
