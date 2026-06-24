//! Shared error mapping for premium / admin-consent-gated Graph reads.
//!
//! Several detail-pane tabs (Activity log, Conditional Access, …) read Graph
//! surfaces that need an Entra ID P1/P2 license *and* admin consent. They all
//! want the same behaviour on failure: degrade to a graceful, body-safe message
//! (never leak a raw Graph body), distinguish a missing license from missing
//! consent, and keep only transient classes `retryable`. Keeping that logic in
//! one place stops the per-tab copies from drifting apart — they previously had
//! two definitions of the license heuristic that had already diverged.

use azapptoolkit_graph::GraphError;

use crate::dto::UiError;

/// True when a 403 body looks like a missing-license rejection rather than a
/// missing-consent one. Graph encodes the body as JSON, so `error.code` and
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

/// Maps a Graph error from a premium/admin-consent-gated read into a graceful,
/// body-safe [`UiError`] so the tab degrades instead of failing the surrounding
/// detail pane. `code` is the feature's `*_unavailable` code; `title` is the
/// sentence-start noun phrase ("The activity log" / "Conditional Access") and
/// `feature` its mid-sentence form ("the activity log" / "Conditional Access");
/// `scope` is the Graph permission it needs (e.g. "AuditLog.Read.All").
pub(crate) fn premium_feature_err(
    code: &str,
    title: &str,
    feature: &str,
    scope: &str,
    err: GraphError,
) -> UiError {
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
                msg(
                    false,
                    format!(
                        "{title} requires admin consent for {scope}. Ask a Global Administrator to grant it, then reopen this tab."
                    ),
                )
            }
        }
        GraphError::Token(_) => msg(
            false,
            format!(
                "Couldn't acquire {scope} consent for {feature}. It needs admin consent (and Entra ID P1/P2); the rest of the app is unaffected."
            ),
        ),
        GraphError::Unauthorized => msg(
            false,
            format!("Your session expired. Sign in again to view {feature}."),
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
    fn license_vs_consent_split_and_retryable_classification() {
        let license = premium_feature_err(
            "activity_unavailable",
            "The activity log",
            "the activity log",
            "AuditLog.Read.All",
            GraphError::Forbidden("doesn't have premium license".into()),
        );
        assert_eq!(license.code, "activity_unavailable");
        assert!(license.message.contains("license"));
        assert!(!license.retryable);

        let consent = premium_feature_err(
            "ca_unavailable",
            "Conditional Access",
            "Conditional Access",
            "Policy.Read.All",
            GraphError::Forbidden("Insufficient privileges".into()),
        );
        assert!(consent.message.contains("consent"));
        assert!(!consent.retryable);

        // Transient classes stay retryable and never leak the raw body.
        let transient = premium_feature_err(
            "ca_unavailable",
            "Conditional Access",
            "Conditional Access",
            "Policy.Read.All",
            GraphError::Server {
                status: 503,
                body: "secret-internal".into(),
            },
        );
        assert!(transient.retryable);
        assert!(!transient.message.contains("secret-internal"));
    }
}
