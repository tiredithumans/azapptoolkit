//! Conditional Access visibility commands.
//!
//! Reads tenant Conditional Access policies via the on-demand `Policy.Read.All`
//! token and reports which ones apply to a given app (by its appId / client id).
//! Degrades gracefully: a tenant without consent or an Entra ID P1/P2 license
//! surfaces a friendly "unavailable" message rather than a hard error.

use tauri::State;

use azapptoolkit_core::models::{CaApplications, ConditionalAccessPolicy};
use azapptoolkit_graph::GraphError;

use crate::commands::graph_err;
use crate::dto::UiError;
use crate::dto::conditional_access::ConditionalAccessPolicyDto;
use crate::state::AppState;

/// Conditional Access policies that apply to `app_id` (the application's appId /
/// client id), most-relevant first. Empty when none apply.
#[tauri::command]
pub async fn list_conditional_access_for_app(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<Vec<ConditionalAccessPolicyDto>, UiError> {
    let client = state.graph_for(&tenant_id);
    let policies = client
        .list_conditional_access_policies()
        .await
        .map_err(map_ca_err)?;

    let mut rows: Vec<ConditionalAccessPolicyDto> = policies
        .into_iter()
        .filter_map(|p| to_dto(p, &app_id))
        .collect();

    // Directly-targeted ("appId" / "all") first, then "may apply" groupings;
    // within each, enabled policies before report-only/disabled, then by name.
    rows.sort_by(|a, b| {
        reason_rank(&a.applies_reason)
            .cmp(&reason_rank(&b.applies_reason))
            .then_with(|| state_rank(&a.state).cmp(&state_rank(&b.state)))
            .then_with(|| {
                a.display_name
                    .to_lowercase()
                    .cmp(&b.display_name.to_lowercase())
            })
    });
    Ok(rows)
}

/// Maps a policy to a DTO **iff** it applies to `app_id`, else `None`.
fn to_dto(policy: ConditionalAccessPolicy, app_id: &str) -> Option<ConditionalAccessPolicyDto> {
    let apps = policy
        .conditions
        .as_ref()
        .and_then(|c| c.applications.as_ref())?;
    let reason = applies_reason(apps, app_id)?;
    let (grant_controls, grant_operator) = match policy.grant_controls {
        Some(g) => (g.built_in_controls, g.operator),
        None => (Vec::new(), None),
    };
    Some(ConditionalAccessPolicyDto {
        id: policy.id.unwrap_or_default(),
        display_name: policy
            .display_name
            .unwrap_or_else(|| "(unnamed policy)".to_string()),
        state: policy.state.unwrap_or_else(|| "unknown".to_string()),
        applies_reason: reason.to_string(),
        grant_controls,
        grant_operator,
    })
}

/// Decides whether (and why) a CA policy's application condition targets
/// `app_id`. The security-critical contract: **exclude always wins**, the
/// well-known `All` token is matched before any GUID compare, and a policy that
/// targets only user actions (empty include + non-empty `includeUserActions`)
/// never matches an app. Returns a stable reason code or `None`.
fn applies_reason(apps: &CaApplications, app_id: &str) -> Option<&'static str> {
    // Excluded apps are never subject to the policy, even under an `All` include.
    if apps
        .exclude_applications
        .iter()
        .any(|a| a.eq_ignore_ascii_case(app_id))
    {
        return None;
    }
    let inc = &apps.include_applications;
    if inc.iter().any(|a| a == "All") {
        return Some("all");
    }
    if inc.iter().any(|a| a.eq_ignore_ascii_case(app_id)) {
        return Some("appId");
    }
    // Well-known groupings *may* include this app (Graph doesn't expand them).
    if inc.iter().any(|a| a == "Office365") {
        return Some("office365");
    }
    if inc.iter().any(|a| a == "MicrosoftAdminPortals") {
        return Some("adminPortals");
    }
    // An application filter (attribute-based, on the app's custom security
    // attributes) may target this app; only consider it when no explicit app
    // include is present. We can't evaluate the rule, so the result is always
    // "may apply" — but the *mode* flips the bias, so report it: an `include`
    // filter applies only to the matching subset, while an `exclude` filter
    // applies to everything *except* a matching subset (so it likely applies).
    if inc.is_empty()
        && let Some(f) = &apps.application_filter
    {
        return Some(if f.mode.as_deref() == Some("exclude") {
            "filterExclude"
        } else {
            "filter"
        });
    }
    // Empty include with user actions (or nothing) → not app-targeting.
    None
}

fn reason_rank(reason: &str) -> u8 {
    match reason {
        "appId" => 0,
        "all" => 1,
        _ => 2, // groupings / filter ("may apply")
    }
}

fn state_rank(state: &str) -> u8 {
    match state {
        "enabled" => 0,
        "enabledForReportingButNotEnforced" => 1,
        _ => 2, // disabled / unknown
    }
}

/// Graceful, body-safe error mapping for the Conditional Access tab. Shares the
/// premium/consent mapping with the Activity tab (see
/// [`graph_err::premium_feature_err`]): a missing license vs. consent gets a
/// distinct message, every variant degrades to `ca_unavailable`, and a raw Graph
/// body is never leaked.
fn map_ca_err(err: GraphError) -> UiError {
    graph_err::premium_feature_err(
        "ca_unavailable",
        "Conditional Access",
        "Conditional Access",
        "Policy.Read.All",
        err,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::CaApplicationFilter;

    fn apps(include: &[&str], exclude: &[&str], user_actions: &[&str]) -> CaApplications {
        CaApplications {
            include_applications: include.iter().map(|s| s.to_string()).collect(),
            exclude_applications: exclude.iter().map(|s| s.to_string()).collect(),
            include_user_actions: user_actions.iter().map(|s| s.to_string()).collect(),
            application_filter: None,
        }
    }

    const APP: &str = "11111111-1111-1111-1111-111111111111";
    const OTHER: &str = "22222222-2222-2222-2222-222222222222";

    #[test]
    fn explicit_include_matches() {
        assert_eq!(applies_reason(&apps(&[APP], &[], &[]), APP), Some("appId"));
    }

    #[test]
    fn all_matches_unless_excluded() {
        assert_eq!(applies_reason(&apps(&["All"], &[], &[]), APP), Some("all"));
        // Exclude wins even under an All include.
        assert_eq!(applies_reason(&apps(&["All"], &[APP], &[]), APP), None);
    }

    #[test]
    fn exclude_only_does_not_apply() {
        assert_eq!(applies_reason(&apps(&[OTHER], &[APP], &[]), APP), None);
    }

    #[test]
    fn other_app_does_not_match() {
        assert_eq!(applies_reason(&apps(&[OTHER], &[], &[]), APP), None);
    }

    #[test]
    fn well_known_groupings_may_apply() {
        assert_eq!(
            applies_reason(&apps(&["Office365"], &[], &[]), APP),
            Some("office365")
        );
        assert_eq!(
            applies_reason(&apps(&["MicrosoftAdminPortals"], &[], &[]), APP),
            Some("adminPortals")
        );
    }

    #[test]
    fn user_action_only_policy_does_not_match_apps() {
        // Empty include + user actions present → targets user actions, not apps.
        assert_eq!(
            applies_reason(&apps(&[], &[], &["urn:user:registersecurityinfo"]), APP),
            None
        );
    }

    #[test]
    fn application_filter_may_apply_when_no_explicit_include() {
        let mut a = apps(&[], &[], &[]);
        a.application_filter = Some(CaApplicationFilter {
            mode: Some("include".into()),
            rule: Some("app.tags -contains \"hr\"".into()),
        });
        assert_eq!(applies_reason(&a, APP), Some("filter"));
    }

    #[test]
    fn exclude_mode_filter_is_distinct_from_include() {
        // An exclude-mode filter targets every app except the matching subset,
        // so it must not be reported with the (narrower) "filter" code.
        let mut a = apps(&[], &[], &[]);
        a.application_filter = Some(CaApplicationFilter {
            mode: Some("exclude".into()),
            rule: Some("app.tags -contains \"hr\"".into()),
        });
        assert_eq!(applies_reason(&a, APP), Some("filterExclude"));
    }

    #[test]
    fn include_is_case_insensitive() {
        assert_eq!(
            applies_reason(&apps(&[&APP.to_uppercase()], &[], &[]), APP),
            Some("appId")
        );
    }

    #[test]
    fn ca_err_is_body_safe_and_classified() {
        let license = map_ca_err(GraphError::Forbidden(
            "{\"error\":{\"code\":\"Authentication_RequestFromNonPremiumTenantOrB2CTenant\"}}"
                .into(),
        ));
        assert_eq!(license.code, "ca_unavailable");
        assert!(license.message.contains("license"));

        // A consent-style denial (no license keywords) must classify as consent,
        // not license — guards the dropped " p1"/" p2" substring false-match.
        let consent = map_ca_err(GraphError::Forbidden(
            "{\"error\":{\"code\":\"Authorization_RequestDenied\",\"message\":\"Insufficient privileges\"}}"
                .into(),
        ));
        assert_eq!(consent.code, "ca_unavailable");
        assert!(consent.message.contains("consent"));

        let server = map_ca_err(GraphError::Server {
            status: 503,
            body: "internal".into(),
        });
        assert!(server.retryable);
        assert!(!server.message.contains("internal"));
    }
}
