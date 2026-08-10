//! ARM conforms to the shared HTTP error + retry policy.
//!
//! AGENTS.md: "One definition per policy. The Graph/ARM/Key Vault error
//! taxonomy comes from `core::http_error_enum!`; retry budget + backoff from
//! `core::http_retry`. A client supplies only what is genuinely its own."
//!
//! Nothing pinned that for this crate. `azapptoolkit-graph` has 105 tests plus
//! a dedicated `tests/` tree; `azapptoolkit-arm` had 19 inline tests across 1121
//! lines and no out-of-line tree at all — while sitting on a privileged path
//! (enumerating Azure role assignments, which feeds Access Readiness). The
//! conformance most worth pinning is the part a hand-rolled re-implementation
//! would get subtly wrong: which failures are retryable, and whether an auth
//! classification survives the `BearerProvider` boundary.

use azapptoolkit_arm::ArmError;
use azapptoolkit_core::http_retry::is_retryable_code;
use azapptoolkit_core::token::TokenError;

/// One representative of every macro-generated variant.
fn every_variant() -> Vec<ArmError> {
    vec![
        ArmError::Unauthorized,
        ArmError::Forbidden("no role".into()),
        ArmError::NotFound("missing".into()),
        ArmError::Throttled {
            retry_after_secs: Some(5),
        },
        ArmError::Api {
            status: 400,
            body: "bad".into(),
        },
        ArmError::Server {
            status: 503,
            body: String::new(),
        },
        ArmError::Network("reset".into()),
        ArmError::Deserialize("bad json".into()),
        ArmError::Protocol("off-origin nextLink".into()),
        ArmError::Token(TokenError {
            code: "refresh_missing".into(),
            message: "dead".into(),
        }),
    ]
}

/// `is_retryable()` is the shared policy, not a local opinion.
///
/// The macro defines it as `is_retryable_code(self.ui_code())`, so the only way
/// this can drift is a hand-written override — which is exactly what "a client
/// supplies only what is genuinely its own" forbids.
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

/// A dead session survives INTO `ArmError` rather than flattening to a string.
///
/// AGENTS.md records that flattening this to `token_error` "made
/// `is_reauth_fatal` unfirable for every client call": every long-running loop
/// stops on a re-auth-fatal code, so losing the classification here means a
/// sweep keeps going against a session that cannot work.
#[test]
fn a_dead_session_keeps_its_code_through_the_arm_error() {
    for code in azapptoolkit_core::reauth::REAUTH_FATAL_CODES {
        let err = ArmError::Token(TokenError {
            code: (*code).to_string(),
            message: "session is gone".into(),
        });
        assert_eq!(
            err.ui_code(),
            *code,
            "the auth classification was flattened — `is_reauth_fatal` can never fire"
        );
        assert!(
            azapptoolkit_core::reauth::is_reauth_fatal(err.ui_code()),
            "{code} must still read as re-auth-fatal after crossing into ArmError"
        );
        assert!(
            !err.is_retryable(),
            "a dead session is not a transient failure — retrying it burns the budget"
        );
    }
}

/// A 403 carries the Azure RBAC role guidance; a 404 does not invent any.
///
/// `ui_hint` is the one method that legitimately differs per crate, so it is
/// the one worth asserting is wired to the capabilities catalog rather than to
/// a hardcoded role string.
#[test]
fn forbidden_carries_role_guidance_from_the_capabilities_catalog() {
    let hint = ArmError::Forbidden("denied".into())
        .ui_hint()
        .expect("a 403 must name the Azure RBAC role that would fix it");
    assert!(
        !hint.trim().is_empty(),
        "the capability's remediation resolved to empty text"
    );
    assert_eq!(
        Some(hint),
        azapptoolkit_core::capabilities::capability("azure_role_reads").map(|c| c.remediation),
        "the hint must come from the catalog so it matches the readiness checklist"
    );
    assert!(ArmError::NotFound("gone".into()).ui_hint().is_none());
}
