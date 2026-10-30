//! Key Vault client errors.
//!
//! The taxonomy is generated from [`azapptoolkit_core::http_error_enum`] — one
//! definition shared with `GraphError` and `ArmError`. `InvalidName` is
//! genuinely this crate's own (client-side vault/secret name validation);
//! `ui_hint` stays hand-written, as in ARM.

pub type Result<T> = std::result::Result<T, KeyVaultError>;

azapptoolkit_core::http_error_enum! {
    /// Every failure mode of an Azure Key Vault data-plane call.
    pub enum KeyVaultError {
        api_display = "vault error ({status}): {body}",
        api_code = "vault_error",
        extra {
            /// Rejected before any request: vault and secret names have a fixed
            /// charset, so a bad one is a caller bug, not a 400 to round-trip.
            InvalidName(String) => "invalid_name", display = "invalid name: {0}",
        }
    }
}

impl KeyVaultError {
    /// Actionable role guidance appended to the raw message (mirrors
    /// `ExchangeError::ui_hint`). A 403 = the signed-in user lacks an Azure
    /// RBAC data-plane role on the vault; sourced from the `keyvault_secrets`
    /// capability so the text matches the readiness checklist and proactive
    /// label (which also flags the RBAC-permission-mode caveat).
    pub fn ui_hint(&self) -> Option<&'static str> {
        match self {
            KeyVaultError::Forbidden(_) => {
                azapptoolkit_core::capabilities::capability("keyvault_secrets")
                    .map(|c| c.remediation)
            }
            KeyVaultError::Unauthorized => Some(
                "Your Key Vault token was rejected. Use \"Refresh token\" (next to Sign out), \
                 then retry; if it persists, confirm the app has consented the vault.azure.net \
                 scope.",
            ),
            _ => None,
        }
    }

    /// True when the call failed before any request left the process, so a
    /// write cannot have landed: a name the validator refused, or a bearer
    /// that couldn't be minted (the transport mints it once, before its first
    /// attempt). Every other failure of a write leaves its outcome open: a
    /// replayed `PUT` can fail after an earlier attempt committed, and a 2xx
    /// whose body can't be read or parsed is a committed write reported as an
    /// error.
    pub fn sent_nothing(&self) -> bool {
        matches!(
            self,
            KeyVaultError::Token(_) | KeyVaultError::InvalidName(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_and_unauthorized_carry_role_hints() {
        // A 403 names the Key Vault data-plane role from the catalog, and the
        // permission each operation needs — the rotation's ownership check
        // reads only a secret's metadata.
        let f = KeyVaultError::Forbidden("denied".into())
            .ui_hint()
            .expect("forbidden has a hint");
        assert!(f.contains("Key Vault Secrets Officer"));
        for permission in ["readMetadata", "getSecret", "setSecret"] {
            assert!(f.contains(permission), "{permission} missing from: {f}");
        }
        // A 401 points at the in-place lever, never at signing out (which
        // would drop every data cache).
        let u = KeyVaultError::Unauthorized
            .ui_hint()
            .expect("unauthorized has a hint");
        assert!(u.contains("Refresh token"), "{u}");
        assert!(!u.contains("Sign out and back in"), "{u}");
        // Non-authz variants carry no role hint.
        assert!(KeyVaultError::NotFound(String::new()).ui_hint().is_none());
        assert!(KeyVaultError::InvalidName("x".into()).ui_hint().is_none());
    }

    /// Only a failure raised before the request is proof that a write did not
    /// land; an HTTP status, a lost connection or an unreadable reply is not.
    #[test]
    fn only_a_pre_request_failure_proves_nothing_was_sent() {
        use azapptoolkit_core::token::TokenError;
        assert!(KeyVaultError::Token(TokenError::new("refresh_missing", "gone")).sent_nothing());
        assert!(KeyVaultError::InvalidName("a/b".into()).sent_nothing());
        for err in [
            KeyVaultError::Unauthorized,
            KeyVaultError::Forbidden("denied".into()),
            KeyVaultError::NotFound("gone".into()),
            KeyVaultError::Throttled {
                retry_after_secs: None,
            },
            KeyVaultError::Api {
                status: 409,
                body: String::new(),
            },
            KeyVaultError::Server {
                status: 503,
                body: String::new(),
            },
            KeyVaultError::Network("reset".into()),
            KeyVaultError::Deserialize("truncated".into()),
            KeyVaultError::Protocol("body too large".into()),
        ] {
            assert!(!err.sent_nothing(), "{err:?} may follow a committed write");
        }
    }
}
