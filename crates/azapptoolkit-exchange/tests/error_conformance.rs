//! Exchange conforms to the shared HTTP error + retry policy.
//!
//! AGENTS.md: "One definition per policy: HTTP errors from
//! `core::http_error_enum!` (Exchange: hand-rolled, conformance-tested)".
//!
//! Exchange is the one client whose taxonomy is hand-written.
//! `ExchangeError::Forbidden { detail, had_diagnostics }` is a struct variant —
//! `ui_hint` branches on whether the RBAC engine named a reason in
//! `x-ms-diagnostics` — and the macro's `extra` arm can only add single-field
//! tuple variants, not reshape a shared one. So this crate carries a fourth
//! `ui_code` table, which is exactly "the part a hand-rolled re-implementation
//! would get subtly wrong": which failures are retryable, and whether an auth
//! classification survives the `BearerProvider` boundary. This file pins that
//! table to the macro itself, so a drift in either fails here.

use azapptoolkit_core::http_retry::is_retryable_code;
use azapptoolkit_core::token::TokenError;
use azapptoolkit_exchange::ExchangeError;

// The shared taxonomy, instantiated here as the reference the hand-written
// enum must match variant for variant.
azapptoolkit_core::http_error_enum! {
    /// What `ExchangeError` would be if the macro could express its `Forbidden`.
    pub enum Reference {
        api_display = "exchange error ({status}): {body}",
        api_code = "exchange_error",
    }
}

fn token(code: &str) -> TokenError {
    TokenError {
        code: code.to_string(),
        message: "session is gone".into(),
    }
}

/// One representative of every variant — `Forbidden` in both of its forms.
fn every_variant() -> Vec<ExchangeError> {
    vec![
        ExchangeError::Unauthorized,
        ExchangeError::Forbidden {
            detail: "[Get-Group] role required".into(),
            had_diagnostics: true,
        },
        ExchangeError::Forbidden {
            detail: "[Get-Group] <no body>".into(),
            had_diagnostics: false,
        },
        ExchangeError::NotFound("missing".into()),
        ExchangeError::Throttled {
            retry_after_secs: Some(5),
        },
        ExchangeError::Server {
            status: 503,
            body: String::new(),
        },
        ExchangeError::Api {
            status: 400,
            body: "bad".into(),
        },
        ExchangeError::Network("reset".into()),
        ExchangeError::Deserialize("bad json".into()),
        ExchangeError::Token(token("refresh_missing")),
        ExchangeError::Protocol("off-origin nextLink".into()),
    ]
}

/// The macro's counterpart of `e`. Exhaustive with no `_` arm on purpose: a
/// variant added to `ExchangeError` fails to compile here until someone decides
/// what the shared taxonomy says about it.
fn reference_for(e: &ExchangeError) -> Reference {
    match e {
        ExchangeError::Unauthorized => Reference::Unauthorized,
        ExchangeError::Forbidden { detail, .. } => Reference::Forbidden(detail.clone()),
        ExchangeError::NotFound(m) => Reference::NotFound(m.clone()),
        ExchangeError::Throttled { retry_after_secs } => Reference::Throttled {
            retry_after_secs: *retry_after_secs,
        },
        ExchangeError::Server { status, body } => Reference::Server {
            status: *status,
            body: body.clone(),
        },
        ExchangeError::Api { status, body } => Reference::Api {
            status: *status,
            body: body.clone(),
        },
        ExchangeError::Network(m) => Reference::Network(m.clone()),
        ExchangeError::Deserialize(m) => Reference::Deserialize(m.clone()),
        ExchangeError::Token(t) => Reference::Token(t.clone()),
        ExchangeError::Protocol(m) => Reference::Protocol(m.clone()),
    }
}

/// The hand-written `ui_code`, `is_retryable` and Display agree with the macro
/// for every variant — the drift pin the macro gives Graph, ARM and Key Vault
/// for free.
#[test]
fn the_ui_code_table_matches_the_shared_macro() {
    for err in every_variant() {
        let reference = reference_for(&err);
        assert_eq!(
            err.ui_code(),
            reference.ui_code(),
            "{err:?}: the hand-written ui_code drifted from http_error_enum!"
        );
        assert_eq!(
            err.is_retryable(),
            reference.is_retryable(),
            "{err:?}: retryability drifted from http_error_enum!"
        );
        assert_eq!(
            err.to_string(),
            reference.to_string(),
            "{err:?}: the Display string drifted from http_error_enum!"
        );
    }
    // The macro's serde_json conversion lands on the same class as ours.
    let bad = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    assert_eq!(Reference::from(bad).ui_code(), "deserialize_error");
    let bad = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    assert_eq!(ExchangeError::from(bad).ui_code(), "deserialize_error");
}

/// `is_retryable()` is the shared policy, not a local opinion — and the
/// transport classifies every attempt through it.
#[test]
fn retryability_comes_from_the_shared_policy_for_every_variant() {
    for err in every_variant() {
        assert_eq!(
            err.is_retryable(),
            is_retryable_code(err.ui_code()),
            "{err:?} disagrees with the shared retry policy for code {:?}",
            err.ui_code()
        );
    }
}

/// Only throttling, server errors and network failures are worth retrying.
///
/// Retrying a 401/403/404 burns the budget on a call that cannot succeed, and
/// on a fan-out that is multiplied by every item.
#[test]
fn the_retryable_set_is_exactly_throttle_server_network() {
    let retryable: Vec<&str> = every_variant()
        .iter()
        .filter(|e| e.is_retryable())
        .map(|e| e.ui_code())
        .collect();
    assert_eq!(
        retryable,
        vec!["throttled", "server_error", "network_error"],
        "the retryable set changed — a client-side or auth failure must not be retried"
    );
}

/// A dead session survives INTO `ExchangeError` rather than flattening to a
/// string.
///
/// Flattening this to `token_error` once made `is_reauth_fatal` unfirable for
/// every client call: every long-running loop stops on a re-auth-fatal code, so
/// losing the classification here means an Exchange sweep keeps going against
/// a session that cannot work.
#[test]
fn a_dead_session_keeps_its_code_through_the_exchange_error() {
    for code in azapptoolkit_core::reauth::REAUTH_FATAL_CODES {
        let err = ExchangeError::Token(token(code));
        assert_eq!(
            err.ui_code(),
            *code,
            "the auth classification was flattened — `is_reauth_fatal` can never fire"
        );
        assert!(
            azapptoolkit_core::reauth::is_reauth_fatal(err.ui_code()),
            "{code} must still read as re-auth-fatal after crossing into ExchangeError"
        );
        assert!(
            !err.is_retryable(),
            "a dead session is not a transient failure — retrying it burns the budget"
        );
    }
}

/// A 403 in which Exchange named an RBAC reason carries the catalog's role
/// guidance; a reasonless one must not claim a definite role gap; a 404 invents
/// no guidance at all.
#[test]
fn forbidden_hint_comes_from_the_catalog_only_when_exchange_named_a_reason() {
    let catalog =
        azapptoolkit_core::capabilities::capability("exchange_rbac").map(|c| c.remediation);
    let named = ExchangeError::Forbidden {
        detail: "denied".into(),
        had_diagnostics: true,
    }
    .ui_hint();
    assert_eq!(
        named, catalog,
        "the hint must come from the catalog so it matches the readiness checklist"
    );
    assert!(
        named.is_some_and(|h| !h.trim().is_empty()),
        "the capability's remediation resolved to empty text"
    );

    let reasonless = ExchangeError::Forbidden {
        detail: "<no body>".into(),
        had_diagnostics: false,
    }
    .ui_hint()
    .expect("a reasonless 403 still needs guidance (stale token / propagation)");
    assert_ne!(
        Some(reasonless),
        catalog,
        "a reasonless 403 must not be reported as a definite Exchange RBAC gap"
    );

    assert!(ExchangeError::NotFound("gone".into()).ui_hint().is_none());
}

/// The Exchange twin of the ARM / Key Vault pin: the throttled message reads
/// as a wait in words, never the old "retry after Some(30)s".
#[test]
fn throttled_message_is_readable() {
    assert_eq!(
        ExchangeError::Throttled {
            retry_after_secs: Some(30),
        }
        .to_string(),
        "throttled (429): the service is limiting requests. Wait 30 seconds, then try again."
    );
    assert_eq!(
        ExchangeError::Throttled {
            retry_after_secs: None,
        }
        .to_string(),
        "throttled (429): the service is limiting requests. Wait a moment, then try again."
    );
}
