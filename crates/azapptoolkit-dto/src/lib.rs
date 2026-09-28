//! Serializable DTOs that cross the Tauri IPC boundary.
//!
//! Single source of truth for types the WASM front-end and Tauri backend
//! exchange over `invoke()` / event payloads — with one sanctioned exception:
//! a few `azapptoolkit-core` domain types (`Application`, `Organization`,
//! `AuditItem` + its remediation/scope subtree) also cross IPC by direct
//! re-use, embedded in or alongside the DTOs here, because both sides share
//! the same Rust definitions. Kept dependency-light (`serde` + `chrono`) so it
//! compiles cleanly to `wasm32-unknown-unknown`. Backend-only
//! `From<…Error>` conversions are gated behind the `backend` feature.
//!
//! # Timestamps
//!
//! A timestamp crosses IPC in one of two Rust types, which put identical
//! RFC3339 UTC text on the wire (chrono's `DateTime<Utc>` serializes to
//! exactly that):
//!
//! - **`DateTime<Utc>`** — the default for a **new** field whenever the
//!   backend holds a parsed value: a typed Graph model (`credentials.rs`) or a
//!   stamp the backend mints itself (`backup.rs` `created_at`).
//! - **`String`, documented as RFC3339 UTC** — kept where one bad value must
//!   degrade just that field instead of failing deserialization of the whole
//!   payload: values lifted verbatim from untyped upstream JSON (the SAML
//!   `keyCredentials` read as `serde_json::Value`, Key Vault attributes), and
//!   payloads that outlive a build (the cached audit `completed_at`). The
//!   frontend parses these only through `util::time_ago` (a stamp it can't
//!   read renders nothing), or takes the date part for display.
//!
//! Existing `String` stamps are grandfathered. Converting one is a per-module
//! change that must keep the wire text and every frontend consumer in step.

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

    /// True for the wire codes that mean **the session is dead**, not that this
    /// one operation failed: a refresh token that can no longer be re-minted
    /// silently (`refresh_missing`, from `InvalidGrant`/`RefreshTokenMissing`) or
    /// no session at all (`not_signed_in`). Both need ONE interactive round trip
    /// (`reauthenticate`) — not a sign-out, which would drop every data cache.
    ///
    /// **The single definition**, now genuinely single: the code set itself
    /// lives in [`azapptoolkit_core::reauth::REAUTH_FATAL_CODES`] and this is a
    /// thin reading of it.
    ///
    /// It was previously three hand-maintained `matches!` arms across the
    /// frontend, which AGENTS.md called out as a footgun ("a new re-auth-fatal
    /// code must extend BOTH `matches!` sets"). Collapsing those into this
    /// method fixed the frontend but left `core::token::TokenError` — which sits
    /// *below* this crate and so cannot call it — hardcoding the same two
    /// literals behind a comment admitting it was a mirror. Both now read one
    /// slice, so adding a code is one edit and cannot half-land.
    ///
    /// Retryability is orthogonal: these are never `retryable`, because
    /// retrying without re-auth just fails again.
    pub fn is_reauth_fatal(&self) -> bool {
        azapptoolkit_core::reauth::is_reauth_fatal(&self.code)
    }

    /// True when the failure is a missing admin/user consent for one resource
    /// (`consent_required`, from `AuthError::ConsentRequired` — AADSTS65001/65004),
    /// read from the one literal in [`azapptoolkit_core::reauth::CONSENT_REQUIRED`].
    ///
    /// Not re-auth-fatal (the session is fine, a fan-out carries on) and not
    /// retryable (a silent grant cannot obtain consent): the recovery is the
    /// interactive `request_scope_consent`, which is what every "Grant consent"
    /// affordance branches on this to offer.
    pub fn is_consent_required(&self) -> bool {
        self.code == azapptoolkit_core::reauth::CONSENT_REQUIRED
    }

    /// True when a Conditional Access policy demands an interactive step
    /// (MFA, registration, an external challenge) for one resource
    /// (`interaction_required`, from `AuthError::InteractionRequired`), read
    /// from the one literal in [`azapptoolkit_core::reauth::INTERACTION_REQUIRED`].
    ///
    /// Not re-auth-fatal (the refresh token is fine for every other audience)
    /// and not retryable (a silent grant cannot satisfy the challenge): the
    /// recovery is the interactive `request_scope_step_up` behind the "Verify
    /// identity" toast, or — for the Graph read scopes — `reauthenticate`.
    pub fn is_interaction_required(&self) -> bool {
        self.code == azapptoolkit_core::reauth::INTERACTION_REQUIRED
    }

    /// True for a rejected access token (`unauthorized`, a client 401), read
    /// from the one literal in [`azapptoolkit_core::reauth::UNAUTHORIZED`].
    ///
    /// Not re-auth-fatal (one 401 does not prove the session is dead) and not
    /// retryable as-is: the recovery is the in-place token refresh the top bar
    /// and the 401 toast offer.
    pub fn is_unauthorized(&self) -> bool {
        self.code == azapptoolkit_core::reauth::UNAUTHORIZED
    }

    /// For a rejected token, the curated guidance its message carries beyond
    /// the bare status line ([`azapptoolkit_core::reauth::UNAUTHORIZED_STATUS`])
    /// — Exchange, Key Vault and ARM append what to check if a refresh doesn't
    /// help; a Graph surface may replace the line entirely. `None` when the
    /// message is only the status line (nothing to show but a generic lead), or
    /// when this is not a rejected token at all.
    pub fn unauthorized_guidance(&self) -> Option<&str> {
        if !self.is_unauthorized() {
            return None;
        }
        let msg = self.message.trim();
        let rest = msg
            .strip_prefix(azapptoolkit_core::reauth::UNAUTHORIZED_STATUS)
            .unwrap_or(msg)
            .trim();
        (!rest.is_empty()).then_some(rest)
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
            // Exhaustive on purpose (no wildcard): a new `AuthError` variant
            // must be given a code here before the workspace compiles.
            let (code, retryable) = match &err {
                AuthError::NotSignedIn => ("not_signed_in", false),
                AuthError::RefreshTokenMissing(_) => ("refresh_missing", false),
                AuthError::InvalidGrant(_) => ("refresh_missing", false),
                AuthError::ConsentRequired(_) => ("consent_required", false),
                AuthError::InteractionRequired(_) => ("interaction_required", false),
                AuthError::TokenExchange(_) => ("token_exchange", true),
                AuthError::Authorization(_) => ("authorization", true),
                AuthError::Loopback(_) => ("loopback", true),
                AuthError::StateMismatch => ("state_mismatch", false),
                AuthError::Cancelled => ("cancelled", false),
                AuthError::Keyring(_) => ("keyring", false),
                AuthError::KeyringUnavailable(_) => ("keyring_unavailable", false),
                AuthError::Http(_) => ("network", true),
                AuthError::Url(_) => ("url", false),
                AuthError::Serde(_) => ("serde", false),
                AuthError::Io(_) => ("io", true),
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
        /// `consent_required` / `interaction_required` vs `refresh_missing`
        /// split is load-bearing (AGENTS.md): `InvalidGrant` must purge the
        /// refresh token while `ConsentRequired` and `InteractionRequired` (a
        /// per-resource Conditional Access step-up) must not. A silent change here breaks a UI branch
        /// with no compile error, so lock it down. Completeness is enforced by
        /// the compiler (the `From` match is exhaustive, `AuthError` is not
        /// `#[non_exhaustive]`); this test pins the values.
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
                    AuthError::InteractionRequired("AADSTS50076".into()),
                    "interaction_required",
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
                    AuthError::KeyringUnavailable("no session bus".into()),
                    "keyring_unavailable",
                    false,
                ),
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
            // `reqwest::Error` has no public constructor and this crate has no
            // reqwest dependency — but its arm maps to ("network", true).
            // `token_adapter`'s tests in the desktop crate construct one and pin
            // it end to end (auth-plane `network` → client-plane `network_error`).
        }

        /// A classified `TokenError` crossing a client's `Token` arm keeps its
        /// code — and its retryability — in every client's `UiError`. Before,
        /// only the re-auth-fatal codes survived: `consent_required` became a
        /// generic `token_error` (so no "Grant consent" action could appear) and
        /// a refresh-time network outage became a non-retryable `token_error`.
        #[test]
        fn classified_token_codes_survive_every_client_error() {
            use azapptoolkit_core::token::TokenError;

            let cases: [(TokenError, &str, bool); 6] = [
                (
                    TokenError::new("refresh_missing", "m"),
                    "refresh_missing",
                    false,
                ),
                (
                    TokenError::new("not_signed_in", "m"),
                    "not_signed_in",
                    false,
                ),
                (
                    TokenError::new("consent_required", "m"),
                    "consent_required",
                    false,
                ),
                (
                    TokenError::new("interaction_required", "m"),
                    "interaction_required",
                    false,
                ),
                (TokenError::new("network_error", "m"), "network_error", true),
                (TokenError::opaque("m"), "token_error", false),
            ];
            for (tok, code, retryable) in cases {
                let uis = [
                    UiError::from(GraphError::Token(tok.clone())),
                    UiError::from(ExchangeError::Token(tok.clone())),
                    UiError::from(ArmError::Token(tok.clone())),
                    UiError::from(KeyVaultError::Token(tok.clone())),
                ];
                for ui in uis {
                    assert_eq!(ui.code, code, "code for token `{code}`");
                    assert_eq!(ui.retryable, retryable, "retryable for token `{code}`");
                }
            }
        }

        /// The front end's 401 toast shows a client's curated guidance (what to
        /// check if a refresh doesn't help) and falls back to a generic lead
        /// only for a bare status line. That split reads the shared
        /// `UNAUTHORIZED_STATUS` prefix, so pin it for every client.
        #[test]
        fn a_401_keeps_its_curated_guidance_past_the_status_line() {
            use azapptoolkit_core::reauth::{UNAUTHORIZED, UNAUTHORIZED_STATUS};

            let graph = UiError::from(GraphError::Unauthorized);
            assert_eq!(graph.code, UNAUTHORIZED);
            assert_eq!(graph.message, UNAUTHORIZED_STATUS);
            assert!(graph.is_unauthorized());
            assert_eq!(graph.unauthorized_guidance(), None, "a bare 401");

            for ui in [
                UiError::from(ExchangeError::Unauthorized),
                UiError::from(KeyVaultError::Unauthorized),
                UiError::from(ArmError::Unauthorized),
            ] {
                assert_eq!(ui.code, UNAUTHORIZED);
                assert!(
                    ui.message.starts_with(UNAUTHORIZED_STATUS),
                    "{}",
                    ui.message
                );
                let guidance = ui.unauthorized_guidance().expect("a guided 401");
                assert!(!guidance.starts_with(UNAUTHORIZED_STATUS), "{guidance}");
                assert!(guidance.contains("if it persists"), "{guidance}");
            }

            // A Graph surface that replaced the status line entirely.
            let curated = UiError::new(
                UNAUTHORIZED,
                "Your access token was rejected. Retry.",
                false,
            );
            assert_eq!(
                curated.unauthorized_guidance(),
                Some("Your access token was rejected. Retry.")
            );
            // Not a 401 at all.
            assert_eq!(
                UiError::new("forbidden", "x", false).unauthorized_guidance(),
                None
            );
        }
    }
}

#[cfg(test)]
mod reauth_agreement_tests {
    use super::UiError;
    use azapptoolkit_core::reauth::REAUTH_FATAL_CODES;
    use azapptoolkit_core::token::TokenError;

    /// The two predicates sit on opposite sides of a dependency edge — `UiError`
    /// here, `TokenError` in the crate below — and used to hardcode the same two
    /// literals independently, behind a comment that admitted the mirror. A code
    /// added to one and not the other desyncs silently, and the consequence is
    /// the one the classification exists to prevent: a long-running fan-out that
    /// never learns the session is dead, warns its way to the end, and returns a
    /// partial result the UI presents as complete.
    ///
    /// This is the test that makes "the single definition" true rather than
    /// aspirational: it walks the shared set, so a new code that reaches only
    /// one side cannot pass.
    #[test]
    fn ui_error_and_token_error_agree_on_every_fatal_code() {
        assert!(
            !REAUTH_FATAL_CODES.is_empty(),
            "an empty set would make every assertion below vacuous"
        );
        for code in REAUTH_FATAL_CODES {
            let ui = UiError::new(*code, "session is gone", false);
            let token = TokenError::new(*code, "session is gone");
            assert!(ui.is_reauth_fatal(), "UiError missed `{code}`");
            assert!(token.is_reauth_fatal(), "TokenError missed `{code}`");
        }
    }

    #[test]
    fn ui_error_and_token_error_agree_that_an_operation_failure_is_survivable() {
        for code in [
            "token_error",
            "forbidden",
            "throttled",
            "network_error",
            "consent_required",
        ] {
            assert!(!UiError::new(code, "m", true).is_reauth_fatal());
            assert!(!TokenError::new(code, "m").is_reauth_fatal());
        }
    }

    #[test]
    fn consent_required_is_its_own_non_fatal_class() {
        let consent = UiError::new("consent_required", "needs consent", false);
        assert!(consent.is_consent_required());
        assert!(!consent.is_reauth_fatal());
        for code in ["refresh_missing", "token_error", "forbidden"] {
            assert!(
                !UiError::new(code, "m", false).is_consent_required(),
                "{code} is not a missing consent"
            );
        }
    }
}
