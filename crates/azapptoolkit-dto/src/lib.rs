//! Serializable DTOs that cross the Tauri IPC boundary.
//!
//! Single source of truth for types the WASM front-end and Tauri backend
//! exchange over `invoke()` / event payloads — with one sanctioned exception:
//! a few `azapptoolkit-core` domain types (`Application`, `Organization`,
//! `AuditItem` + its remediation/scope subtree) also cross IPC by direct
//! re-use, embedded in or alongside the DTOs here, because both sides share
//! the same Rust definitions. Kept dependency-light (just `serde`) so it
//! compiles cleanly to `wasm32-unknown-unknown`. Backend-only
//! `From<…Error>` conversions are gated behind the `backend` feature.

pub mod activity;
pub mod applications;
pub mod audit;
pub mod backup;
pub mod bulk;
pub mod conditional_access;
pub mod config;
pub mod consent;
pub mod credentials;
pub mod diagnostics;
pub mod enterprise_application;
pub mod exchange;
pub mod expose_api;
pub mod keyvault;
pub mod managed_identity;
pub mod permission_tester;
pub mod permissions;
pub mod readiness;
pub mod remediation;
pub mod search;
pub mod sharepoint;
pub mod sso;
pub mod updater;
pub mod usage;

use serde::{Deserialize, Serialize};

/// Stable error shape returned to the front-end from every fallible
/// `#[tauri::command]`. The `code` is a machine-readable discriminator the UI
/// uses to branch (e.g. `"not_signed_in"` triggers a re-auth flow); `message`
/// is human-readable for display; `retryable` advises whether a retry button
/// should be shown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl UiError {
    /// Full-control constructor. The fields stay `pub`, so literal construction
    /// still works; these factories just drop the repetitive `retryable: false`
    /// boilerplate at the ~50 command call sites.
    pub fn new(code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        UiError {
            code: code.into(),
            message: message.into(),
            retryable,
        }
    }

    /// Not-found error: `code = "{resource}_not_found"`, never retryable.
    pub fn not_found(resource: impl Into<String>, message: impl Into<String>) -> Self {
        UiError::new(format!("{}_not_found", resource.into()), message, false)
    }

    /// Validation / constraint failure: caller-supplied `code`, never retryable.
    pub fn validation(code: impl Into<String>, message: impl Into<String>) -> Self {
        UiError::new(code, message, false)
    }

    /// Filesystem error: fixed `io` code, retryable (a transient disk issue may clear).
    pub fn io(message: impl Into<String>) -> Self {
        UiError::new("io", message, true)
    }

    /// (De)serialization error: fixed `serde` code, never retryable.
    pub fn serde(message: impl Into<String>) -> Self {
        UiError::new("serde", message, false)
    }
}

#[cfg(feature = "backend")]
mod backend_conv {
    use super::UiError;
    use azapptoolkit_arm::ArmError;
    use azapptoolkit_auth::AuthError;
    use azapptoolkit_exchange::ExchangeError;
    use azapptoolkit_graph::GraphError;
    use azapptoolkit_keyvault::KeyVaultError;

    /// Generates `From<E> for UiError` for an error type exposing `ui_code()`,
    /// `is_retryable()`, and `Display`. The `hint` form appends `ui_hint()` —
    /// the role/RBAC guidance behind a 403 (Exchange, Key Vault, ARM) — to the
    /// message so the UI shows *what to do*, not just an opaque status; the
    /// `no_hint` form is for error types without that guidance (Graph).
    macro_rules! ui_error_from {
        ($err:ty, hint) => {
            impl From<$err> for UiError {
                fn from(err: $err) -> Self {
                    let message = match err.ui_hint() {
                        Some(hint) => format!("{err}\n\n{hint}"),
                        None => err.to_string(),
                    };
                    UiError {
                        code: err.ui_code().to_string(),
                        retryable: err.is_retryable(),
                        message,
                    }
                }
            }
        };
        ($err:ty, no_hint) => {
            impl From<$err> for UiError {
                fn from(err: $err) -> Self {
                    UiError {
                        code: err.ui_code().to_string(),
                        retryable: err.is_retryable(),
                        message: err.to_string(),
                    }
                }
            }
        };
    }

    ui_error_from!(ExchangeError, hint);
    ui_error_from!(KeyVaultError, hint);
    ui_error_from!(ArmError, hint);
    ui_error_from!(GraphError, no_hint);

    impl From<AuthError> for UiError {
        fn from(err: AuthError) -> Self {
            let (code, retryable) = match &err {
                AuthError::NotSignedIn => ("not_signed_in", false),
                AuthError::RefreshTokenMissing(_) => ("refresh_missing", false),
                AuthError::InvalidGrant(_) => ("refresh_missing", false),
                AuthError::ConsentRequired(_) => ("consent_required", false),
                AuthError::TokenExchange(_) => ("token_exchange", true),
                AuthError::Authorization(_) => ("authorization", true),
                AuthError::Loopback(_) => ("loopback", true),
                AuthError::StateMismatch => ("state_mismatch", false),
                AuthError::Cancelled => ("cancelled", false),
                AuthError::Keyring(_) => ("keyring", false),
                AuthError::Http(_) => ("network", true),
                AuthError::Url(_) => ("url", false),
                AuthError::Serde(_) => ("serde", false),
                AuthError::Io(_) => ("io", true),
                _ => ("unknown_auth", false),
            };
            UiError {
                code: code.to_string(),
                retryable,
                message: err.to_string(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use azapptoolkit_auth::AuthError;

        /// Pins the machine-readable `code` + `retryable` the front-end branches
        /// on for every constructible `AuthError` variant. These strings are a
        /// wire contract — `not_signed_in` drives the re-auth flow, and the
        /// `consent_required` vs `refresh_missing` split is load-bearing
        /// (AGENTS.md): `InvalidGrant` must purge the refresh token while
        /// `ConsentRequired` must not. A silent change here breaks a UI branch
        /// with no compile error, so lock it down.
        #[test]
        fn auth_error_maps_to_stable_code_and_retryable() {
            let cases: Vec<(AuthError, &str, bool)> = vec![
                (AuthError::NotSignedIn, "not_signed_in", false),
                (
                    AuthError::RefreshTokenMissing("tenant".into()),
                    "refresh_missing",
                    false,
                ),
                (
                    AuthError::InvalidGrant("invalid_grant".into()),
                    "refresh_missing",
                    false,
                ),
                (
                    AuthError::ConsentRequired("AADSTS65001".into()),
                    "consent_required",
                    false,
                ),
                (
                    AuthError::TokenExchange("boom".into()),
                    "token_exchange",
                    true,
                ),
                (
                    AuthError::Authorization("boom".into()),
                    "authorization",
                    true,
                ),
                (AuthError::Loopback("boom".into()), "loopback", true),
                (AuthError::StateMismatch, "state_mismatch", false),
                (AuthError::Cancelled, "cancelled", false),
                (AuthError::Keyring("locked".into()), "keyring", false),
                (
                    AuthError::Url(url::Url::parse("http://[bad").unwrap_err()),
                    "url",
                    false,
                ),
                (
                    AuthError::Serde(serde_json::from_str::<i32>("nope").unwrap_err()),
                    "serde",
                    false,
                ),
                (AuthError::Io(std::io::Error::other("disk")), "io", true),
            ];

            for (err, code, retryable) in cases {
                let ui: UiError = err.into();
                assert_eq!(ui.code, code, "code mismatch");
                assert_eq!(ui.retryable, retryable, "retryable mismatch for `{code}`");
                assert!(!ui.message.is_empty(), "empty message for `{code}`");
            }
            // `AuthError::Http(reqwest::Error)` is the only variant omitted —
            // `reqwest::Error` has no public constructor — but its arm maps to
            // ("network", true).
        }
    }
}
