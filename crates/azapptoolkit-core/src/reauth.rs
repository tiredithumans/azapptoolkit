//! The wire codes that mean **the session is dead** — one definition, shared by
//! every layer that has to recognise them.
//!
//! Deliberately its own tiny module, ungated for `wasm32`, because the two
//! predicates that answer this question live on opposite sides of a dependency
//! edge: [`crate::token::TokenError`] sits below the DTO layer (and is itself
//! gated off `wasm32`), while `azapptoolkit_dto::UiError` must compile for the
//! WASM front-end. Neither can host the set for the other, so it lives here,
//! under both.
//!
//! Why it is worth this much ceremony: these codes are what stops a
//! long-running fan-out. When the classification was flattened at the
//! `BearerProvider` boundary, `is_reauth_fatal` could never fire for a client
//! call, and audits and bulk runs warned their way through a session that was
//! never coming back — then returned a partial result the UI presented as
//! complete. The predicate is only as good as its agreement across layers, and
//! that agreement used to be four independent `matches!` arms plus four
//! per-client pass-through arms, each maintained by hand.
//!
//! **Adding a code is one edit: this slice.** Everything else derives from it.

/// Codes meaning the session cannot be revived without one interactive round
/// trip (`reauthenticate`) — never a sign-out, which would drop every data
/// cache along with it.
///
/// * `refresh_missing` — the refresh token is absent, expired or revoked and
///   cannot be re-minted silently (`AuthError::RefreshTokenMissing` /
///   `AuthError::InvalidGrant`).
/// * `not_signed_in` — there is no session at all (`AuthError::NotSignedIn`).
///
/// These are never `retryable`: retrying without re-auth just fails again.
pub const REAUTH_FATAL_CODES: &[&str] = &["refresh_missing", "not_signed_in"];

/// Whether `code` means the session is dead. The single predicate behind
/// `UiError::is_reauth_fatal` and `TokenError::is_reauth_fatal`.
pub fn is_reauth_fatal(code: &str) -> bool {
    REAUTH_FATAL_CODES.contains(&code)
}

/// The `&'static str` for `code` when it is re-auth-fatal, for the client
/// `ui_code()` implementations that pass an auth classification through their
/// own error enum instead of flattening it to `token_error`.
///
/// Flattening is what previously made `is_reauth_fatal` unfirable for every
/// client call, so each client kept its own copy of these arms. This returns
/// the borrowed slice entry, so a new code reaches all of them at once.
pub fn passthrough_code(code: &str) -> Option<&'static str> {
    REAUTH_FATAL_CODES.iter().copied().find(|c| *c == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documented_codes_are_the_fatal_ones() {
        for code in ["refresh_missing", "not_signed_in"] {
            assert!(is_reauth_fatal(code), "{code} must be re-auth-fatal");
            assert_eq!(passthrough_code(code), Some(code));
        }
    }

    #[test]
    fn an_operation_level_failure_is_not_a_dead_session() {
        // The distinction the whole module exists to preserve: these fail one
        // call, and a fan-out should carry on. Only the codes above mean stop.
        for code in [
            "token_error",
            "unauthorized",
            "forbidden",
            "throttled",
            "server_error",
            "network_error",
            "consent_required",
            "cancelled",
            "",
        ] {
            assert!(!is_reauth_fatal(code), "{code} must NOT be re-auth-fatal");
            assert_eq!(passthrough_code(code), None);
        }
    }

    #[test]
    fn passthrough_agrees_with_the_predicate_by_construction() {
        for code in REAUTH_FATAL_CODES {
            assert!(is_reauth_fatal(code));
            assert_eq!(passthrough_code(code), Some(*code));
        }
    }
}
