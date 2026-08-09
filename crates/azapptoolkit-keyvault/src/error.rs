//! Key Vault client errors.
//!
//! The taxonomy is generated from [`azapptoolkit_core::http_error_enum`] — one
//! definition shared with `GraphError` and `ArmError`. `InvalidName` is
//! genuinely this crate's own (client-side vault/secret name validation), and
//! `ui_hint` stays hand-written for the same reason it does in ARM.

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
