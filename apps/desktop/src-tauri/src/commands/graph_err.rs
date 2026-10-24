//! Shared error mapping for premium / role-gated Graph reads.
//!
//! Several detail-pane tabs (Activity log, Conditional Access, …) read Graph
//! surfaces that need an Entra ID P1/P2 license, a consented on-demand scope
//! *and* a role that can read them. They all want the same behaviour on
//! failure: degrade to a graceful, body-safe message (never leak a raw Graph
//! body), distinguish a missing license from a missing role, keep a classified
//! token failure's own code so the UI can offer its lever, and keep only
//! transient classes `retryable`. Keeping that logic in one place stops the
//! per-tab copies from drifting apart — they previously had two definitions of
//! the license heuristic that had already diverged.

use azapptoolkit_core::capabilities::capability;
use azapptoolkit_core::reauth::passthrough_code;
use azapptoolkit_graph::GraphError;

use crate::dto::UiError;

/// The capabilities catalog's remediation for `capability_key`, but **only**
/// when `err` is a 403.
///
/// Five command modules re-derived this same pair of conditions — "is this
/// forbidden" plus the catalog lookup — before splicing the remediation into
/// their message, each with its own spelling of the test. Composing the final
/// message stays with the caller, because the shapes genuinely differ (replace
/// the body, append to it, or append a concrete scope); only the decision is
/// shared. Adding a privileged feature means adding a catalog entry, never a
/// hardcoded role string.
pub(crate) fn forbidden_remediation(err: &UiError, capability_key: &str) -> Option<&'static str> {
    if err.code != "forbidden" {
        return None;
    }
    capability(capability_key).map(|c| c.remediation)
}

/// True when a 403 body looks like a missing-license rejection rather than a
/// missing-role one. Graph encodes the body as JSON, so `error.code` and
/// `error.message` are both present in the raw string — a lowercased substring
/// scan covers both. `requestfromnonpremium` is Graph's actual license-denial
/// code; the broader words back it up. Bare `" p1"`/`" p2"` are deliberately
/// NOT matched — they false-match unrelated words (e.g. "map1ng").
pub(crate) fn looks_like_missing_license(body: &str) -> bool {
    let lower = body.to_lowercase();
    ["license", "premium", "requestfromnonpremium"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Maps a Graph error from a premium / role-gated read into a graceful,
/// body-safe [`UiError`] so the tab degrades instead of failing the surrounding
/// detail pane. `code` is the feature's `*_unavailable` code; `title` is the
/// sentence-start noun phrase ("The activity log" / "Conditional Access") and
/// `feature` its mid-sentence form ("the activity log" / "Conditional Access");
/// `capability_key` is its capabilities-catalog entry (`"audit_reports"` /
/// `"conditional_access"`), whose scope and remediation the messages name —
/// this file hardcodes no role or scope.
///
/// A **classified token failure keeps its own code** (anything
/// `core::reauth::passthrough_code` knows: a dead session, a Conditional
/// Access step-up, a missing consent, an unreachable token endpoint). Each has
/// a lever the UI offers — Re-authenticate, Verify identity, Grant consent, a
/// transient Retry — and folding it into `*_unavailable` told the operator to
/// go and get admin consent for a failure no consent fixes, while a dead
/// session no longer read as one. Only an opaque token error degrades.
///
/// A **non-license 403 is not a missing consent**: an un-consented scope
/// fails at `/token` (AADSTS65001 → `consent_required`, above) before Graph
/// is ever called, so a Graph 403 means the signed-in account lacks a role
/// that can read the surface. Its message is the catalog's remediation.
pub(crate) fn premium_feature_err(
    code: &str,
    title: &str,
    feature: &str,
    capability_key: &str,
    err: GraphError,
) -> UiError {
    if let GraphError::Token(t) = &err
        && passthrough_code(&t.code).is_some()
    {
        return UiError::from(err);
    }
    let catalog = capability(capability_key);
    let msg = |retryable: bool, message: String| UiError {
        code: code.to_string(),
        message,
        retryable,
    };
    match &err {
        GraphError::Forbidden(body) => {
            if looks_like_missing_license(body) {
                msg(
                    false,
                    format!(
                        "{title} requires an Entra ID P1 or P2 license, which this tenant doesn't appear to have."
                    ),
                )
            } else {
                let remediation = catalog.map_or(
                    "Ask an administrator which role can read it, then reopen this tab.",
                    |c| c.remediation,
                );
                msg(
                    false,
                    format!("Microsoft Graph refused {feature} for your account. {remediation}"),
                )
            }
        }
        GraphError::Token(_) => {
            let scope =
                catalog.map_or_else(|| "the extra scope".to_string(), |c| c.scopes.join(" + "));
            msg(
                false,
                format!(
                    "Couldn't acquire {scope} for {feature}. It needs admin consent (and Entra ID P1/P2); the rest of the app is unaffected."
                ),
            )
        }
        GraphError::Unauthorized => msg(
            false,
            format!(
                "Your access token was rejected. Use \"Refresh token\" (next to Sign out), then reopen {feature}."
            ),
        ),
        GraphError::Throttled { .. } | GraphError::Server { .. } | GraphError::Network(_) => msg(
            true,
            format!("Couldn't reach {feature} just now. Try Refresh in a moment."),
        ),
        // NotFound / Api / Deserialize / Protocol / Url: don't leak the raw Graph
        // body; surface a generic, non-retryable unavailable message.
        _ => msg(
            false,
            format!("{title} is unavailable for this app right now."),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p1_p2_substrings_are_not_treated_as_license_denials() {
        // Guards the heuristic that drifted between the two former copies: a body
        // containing "p1"/"p2" inside unrelated words must NOT read as a license
        // denial, while a genuine premium/license signal must.
        assert!(!looks_like_missing_license(
            "the map1ng failed at step p2x for this app"
        ));
        assert!(looks_like_missing_license(
            "Tenant doesn't have a premium license"
        ));
        assert!(looks_like_missing_license(
            "{\"error\":{\"code\":\"Authentication_RequestFromNonPremiumTenantOrB2CTenant\"}}"
        ));
    }

    #[test]
    fn license_vs_role_split_and_retryable_classification() {
        let license = premium_feature_err(
            "activity_unavailable",
            "The activity log",
            "the activity log",
            "audit_reports",
            GraphError::Forbidden("doesn't have premium license".into()),
        );
        assert_eq!(license.code, "activity_unavailable");
        assert!(license.message.contains("license"));
        assert!(!license.retryable);

        // A non-license 403 is a role gap, not a missing consent (that fails
        // at /token as `consent_required`, before Graph is called): the
        // message is the feature's own catalog remediation, and never sends
        // the operator to an admin-consent granter.
        let admin_consent =
            azapptoolkit_core::capabilities::capability("admin_consent").expect("catalog entry");
        for (code, title, feature, key) in [
            (
                "ca_unavailable",
                "Conditional Access",
                "Conditional Access",
                "conditional_access",
            ),
            (
                "activity_unavailable",
                "The activity log",
                "the activity log",
                "audit_reports",
            ),
        ] {
            let role = premium_feature_err(
                code,
                title,
                feature,
                key,
                GraphError::Forbidden("Insufficient privileges".into()),
            );
            assert_eq!(role.code, code);
            assert!(!role.retryable);
            let remediation = azapptoolkit_core::capabilities::capability(key)
                .expect("catalog entry")
                .remediation;
            assert!(
                role.message.contains(remediation),
                "{key}: {}",
                role.message
            );
            assert!(
                !role.message.contains("requires admin consent"),
                "{key}: {}",
                role.message
            );
            for granter in admin_consent.role_names() {
                // Global Administrator also reads every surface, so it may
                // appear in a remediation; the consent-only granters may not.
                if granter == "Global Administrator" {
                    continue;
                }
                assert!(
                    !role.message.contains(granter),
                    "{key} names the consent granter {granter}: {}",
                    role.message
                );
            }
        }

        // Transient classes stay retryable and never leak the raw body.
        let transient = premium_feature_err(
            "ca_unavailable",
            "Conditional Access",
            "Conditional Access",
            "conditional_access",
            GraphError::Server {
                status: 503,
                body: "secret-internal".into(),
            },
        );
        assert!(transient.retryable);
        assert!(!transient.message.contains("secret-internal"));
    }

    /// A classified token failure keeps its code so the UI offers its lever
    /// (Re-authenticate, Verify identity, Grant consent, a transient Retry);
    /// only an opaque one degrades to the feature's `*_unavailable` notice.
    #[test]
    fn a_classified_token_failure_keeps_its_code() {
        use azapptoolkit_core::reauth::{PASSTHROUGH_NON_FATAL_CODES, REAUTH_FATAL_CODES};
        use azapptoolkit_core::token::TokenError;
        for &code in REAUTH_FATAL_CODES.iter().chain(PASSTHROUGH_NON_FATAL_CODES) {
            let e = premium_feature_err(
                "ca_unavailable",
                "Conditional Access",
                "Conditional Access",
                "conditional_access",
                GraphError::Token(TokenError::new(code, "boom")),
            );
            assert_eq!(e.code, code);
            assert_eq!(
                e.is_reauth_fatal(),
                azapptoolkit_core::reauth::is_reauth_fatal(code),
                "{code}"
            );
            // Only the unreachable token endpoint is worth retrying as-is.
            assert_eq!(e.retryable, code == "network_error", "{code}");
        }
        let opaque = premium_feature_err(
            "activity_unavailable",
            "The activity log",
            "the activity log",
            "audit_reports",
            GraphError::Token(TokenError::opaque("user declined")),
        );
        assert_eq!(opaque.code, "activity_unavailable");
        assert!(
            opaque.message.contains("AuditLog.Read.All"),
            "{}",
            opaque.message
        );
    }

    #[test]
    fn a_rejected_token_points_at_refresh_token_not_sign_in() {
        let e = premium_feature_err(
            "ca_unavailable",
            "Conditional Access",
            "Conditional Access",
            "conditional_access",
            GraphError::Unauthorized,
        );
        assert!(e.message.contains("Refresh token"), "{}", e.message);
        assert!(!e.message.contains("Sign in again"), "{}", e.message);
    }
}
