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
//!
//! A second, disjoint slice — [`PASSTHROUGH_NON_FATAL_CODES`] — lists the
//! classifications that must ALSO survive a client's `Token` arm (so the UI can
//! offer its recovery action, or `is_retryable` can see a transient failure)
//! but must never halt a run. A non-fatal classification is a one-slice edit
//! there; [`passthrough_code`] consults both.

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

/// The wire code for a missing admin/user consent (`AuthError::ConsentRequired`,
/// AADSTS65001/65004). One literal, read by the pass-through set below and by
/// `UiError::is_consent_required`.
pub const CONSENT_REQUIRED: &str = "consent_required";

/// The wire code for a rejected access token — a client 401 (a revoked token,
/// or a Continuous Access Evaluation claims challenge the silent re-mint
/// couldn't satisfy). Deliberately NOT in [`REAUTH_FATAL_CODES`]: one 401 does
/// not prove the session is dead. One literal, read by every client's
/// `ui_code()` (`http_error_enum!`) and by `UiError::is_unauthorized`.
pub const UNAUTHORIZED: &str = "unauthorized";

/// The `Display` of every client's `Unauthorized` variant — the bare status
/// line, which names nothing to do. A client whose 401 carries curated
/// guidance (Exchange, Key Vault, ARM) appends it after this line, so the UI
/// can tell a bare 401 from a guided one without matching on prose.
pub const UNAUTHORIZED_STATUS: &str = "unauthorized (401)";

/// Token classifications a client's `Token` arm passes through WITHOUT them
/// meaning the session is dead — disjoint from [`REAUTH_FATAL_CODES`], so
/// [`is_reauth_fatal`] never fires for them and a fan-out keeps going.
///
/// * `consent_required` — per-resource: one scope is missing consent, the
///   session is fine. A fan-out treats it as per-item (`bulk.rs`
///   `only_session_death_is_fatal`); it is not retryable (consent needs an
///   interactive grant). Passing it through is what lets the UI's shared
///   "Grant consent" fallback fire for a scoped client call.
/// * `network_error` — the lazy token refresh could not reach the token
///   endpoint. Spelt in the client plane (not the auth plane's `network`) so
///   `http_retry::is_retryable_code` sees it as the transient failure it is,
///   exactly like the same outage one line later during the API call.
pub const PASSTHROUGH_NON_FATAL_CODES: &[&str] = &[CONSENT_REQUIRED, "network_error"];

/// The `&'static str` for `code` when it is a classification a client's
/// `ui_code()` passes through its own error enum instead of flattening it to
/// `token_error`: every [`REAUTH_FATAL_CODES`] entry (which halt a fan-out) and
/// every [`PASSTHROUGH_NON_FATAL_CODES`] entry (which do not).
///
/// Flattening is what previously made `is_reauth_fatal` unfirable for every
/// client call, and hid a missing consent behind a generic `token_error`, so
/// each client kept its own copy of these arms. This returns the borrowed
/// slice entry, so a new code reaches all of them at once.
pub fn passthrough_code(code: &str) -> Option<&'static str> {
    REAUTH_FATAL_CODES
        .iter()
        .chain(PASSTHROUGH_NON_FATAL_CODES)
        .copied()
        .find(|c| *c == code)
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
        }
        // ...and of those, only the classified non-fatal codes cross a
        // client's `Token` arm; everything else is (rightly) `token_error`.
        for code in [
            "token_error",
            "unauthorized",
            "forbidden",
            "throttled",
            "server_error",
            "cancelled",
            "",
        ] {
            assert_eq!(passthrough_code(code), None, "{code} must not pass through");
        }
    }

    #[test]
    fn non_fatal_passthrough_codes_pass_through_but_never_halt_a_run() {
        for code in PASSTHROUGH_NON_FATAL_CODES {
            assert_eq!(passthrough_code(code), Some(*code));
            assert!(!is_reauth_fatal(code), "{code} must NOT be re-auth-fatal");
        }
        assert!(PASSTHROUGH_NON_FATAL_CODES.contains(&CONSENT_REQUIRED));
        assert!(PASSTHROUGH_NON_FATAL_CODES.contains(&"network_error"));
    }

    #[test]
    fn the_two_slices_are_disjoint() {
        for code in PASSTHROUGH_NON_FATAL_CODES {
            assert!(
                !REAUTH_FATAL_CODES.contains(code),
                "{code} is in both slices"
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_passed_through_refresh_outage_is_retryable_but_consent_is_not() {
        assert!(crate::http_retry::is_retryable_code("network_error"));
        assert!(!crate::http_retry::is_retryable_code(CONSENT_REQUIRED));
    }

    #[test]
    fn passthrough_agrees_with_the_predicate_by_construction() {
        for code in REAUTH_FATAL_CODES {
            assert!(is_reauth_fatal(code));
            assert_eq!(passthrough_code(code), Some(*code));
        }
    }
}
