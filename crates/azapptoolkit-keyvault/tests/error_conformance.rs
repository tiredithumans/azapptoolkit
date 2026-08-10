//! Key Vault conforms to the shared HTTP error + retry policy.
//!
//! The twin of `azapptoolkit-arm/tests/error_conformance.rs`, and the same
//! reasoning: AGENTS.md requires the taxonomy to come from
//! `core::http_error_enum!` and the retry budget from `core::http_retry`, with
//! each client supplying "only what is genuinely its own" — and nothing pinned
//! it here either. This crate had 12 inline tests across 775 lines, no
//! out-of-line tree, and it writes secrets.
//!
//! Deliberately a near-copy rather than a shared helper crate: a dev-dependency
//! between two leaf clients to share four assertions would couple them for less
//! than it costs, and each crate's `extra` variants differ (`InvalidName` is
//! Key Vault's alone).

use azapptoolkit_core::http_retry::is_retryable_code;
use azapptoolkit_core::token::TokenError;
use azapptoolkit_keyvault::KeyVaultError;

/// One representative of every variant, including this crate's own `extra`.
fn every_variant() -> Vec<KeyVaultError> {
    vec![
        KeyVaultError::Unauthorized,
        KeyVaultError::Forbidden("no data-plane role".into()),
        KeyVaultError::NotFound("missing".into()),
        KeyVaultError::Throttled {
            retry_after_secs: Some(5),
        },
        KeyVaultError::Api {
            status: 400,
            body: "bad".into(),
        },
        KeyVaultError::Server {
            status: 503,
            body: String::new(),
        },
        KeyVaultError::Network("reset".into()),
        KeyVaultError::Deserialize("bad json".into()),
        KeyVaultError::Protocol("off-origin nextLink".into()),
        KeyVaultError::Token(TokenError {
            code: "refresh_missing".into(),
            message: "dead".into(),
        }),
        KeyVaultError::InvalidName("no spaces allowed".into()),
    ]
}

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

/// The crate's own variant must not accidentally become retryable.
///
/// `InvalidName` is rejected before any request is sent — it is a caller bug,
/// so retrying it loops on a call that can never be made.
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
    assert!(
        !KeyVaultError::InvalidName("bad".into()).is_retryable(),
        "a name rejected before the request cannot be fixed by sending it again"
    );
}

#[test]
fn a_dead_session_keeps_its_code_through_the_vault_error() {
    for code in azapptoolkit_core::reauth::REAUTH_FATAL_CODES {
        let err = KeyVaultError::Token(TokenError {
            code: (*code).to_string(),
            message: "session is gone".into(),
        });
        assert_eq!(
            err.ui_code(),
            *code,
            "the auth classification was flattened — `is_reauth_fatal` can never fire"
        );
        assert!(azapptoolkit_core::reauth::is_reauth_fatal(err.ui_code()));
        assert!(
            !err.is_retryable(),
            "a dead session is not a transient failure"
        );
    }
}

#[test]
fn forbidden_carries_role_guidance_from_the_capabilities_catalog() {
    let hint = KeyVaultError::Forbidden("denied".into())
        .ui_hint()
        .expect("a 403 must name the Azure RBAC role that would fix it");
    assert_eq!(
        Some(hint),
        azapptoolkit_core::capabilities::capability("keyvault_secrets").map(|c| c.remediation),
        "the hint must come from the catalog so it matches the readiness checklist"
    );
    assert!(KeyVaultError::NotFound("gone".into()).ui_hint().is_none());
}
