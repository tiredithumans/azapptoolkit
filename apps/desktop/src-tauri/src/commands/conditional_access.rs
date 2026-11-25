//! Conditional Access visibility commands.
//!
//! Reads tenant Conditional Access policies via the on-demand `Policy.Read.All`
//! token and reports which ones apply to a given app (by its appId / client id).
//! Degrades gracefully: a tenant without an Entra ID P1/P2 license (or an
//! account without a policy-reading role) surfaces a friendly "unavailable"
//! message rather than a hard error, while a missing consent, a dead session or
//! a step-up keeps its own code so the tab can offer that failure's lever.

use tauri::State;

use azapptoolkit_core::conditional_access::applies;
use azapptoolkit_core::models::ConditionalAccessPolicy;
use azapptoolkit_graph::GraphError;

use crate::commands::graph_err;
use crate::commands::guid::require_app_id;
use crate::dto::UiError;
use crate::dto::conditional_access::ConditionalAccessPolicyDto;
use crate::state::{AppState, ConsentFeature};

/// Conditional Access policies that apply to `app_id` (the application's appId /
/// client id), most-relevant first. Empty when none apply.
///
/// Applicability reads **both** condition axes: the resource axis
/// (`conditions.applications`, keyed by appId) and the client axis
/// (`conditions.clientApplications`, keyed by service-principal object id).
/// The app's own SP is resolved via the lean, self-invalidating SP cache
/// first; without one the client axis cannot name this app and is skipped
/// (a brand-new single-tenant app behaves exactly as before this axis
/// existed). A failed SP read is logged and also degrades to "skip the
/// client axis" — the tab then over-shows (resource-axis rows keep their
/// "may apply" codes) rather than hide a policy that gates the app.
///
/// The `Policy.Read.All` token is pre-acquired (the
/// `get_enterprise_app_provisioning` pattern), so a missing consent arrives
/// typed as `consent_required` and the tab offers "Grant consent & retry" for
/// the `policy` feature — the one consent that also enables the
/// app-management-policy reads; a dead session or a step-up arrives typed too.
#[tauri::command]
pub async fn list_conditional_access_for_app(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<Vec<ConditionalAccessPolicyDto>, UiError> {
    require_app_id(&app_id)?;
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    state
        .ensure_feature_token(&tenant_id, ConsentFeature::Policy)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);
    let policies = client
        .list_conditional_access_policies()
        .await
        .map_err(map_ca_err)?;

    // Only reached when the policy read succeeded, so an unlicensed /
    // un-consented tenant never pays for the SP lookup.
    let sp = client
        .get_service_principal_by_app_id_lean(&app_id)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(
                app = %app_id,
                ?err,
                "CA: SP lookup failed; client axis skipped"
            );
            None
        });
    let sp_id = sp.as_ref().map(|s| s.id.as_str());

    let mut rows: Vec<ConditionalAccessPolicyDto> = policies
        .into_iter()
        .filter_map(|p| to_dto(p, &app_id, sp_id))
        .collect();

    // Directly-targeted ("appId" / "sp" / "all") first, then "may apply"
    // groupings; within each, enabled policies before report-only/disabled,
    // then by name.
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

/// Maps a policy to a DTO **iff** it applies to `app_id` (as resource and/or
/// as client), else `None`.
fn to_dto(
    policy: ConditionalAccessPolicy,
    app_id: &str,
    sp_id: Option<&str>,
) -> Option<ConditionalAccessPolicyDto> {
    let conditions = policy.conditions.as_ref()?;
    // No application condition at all → the policy does not target apps
    // (neither as resource nor through our SP as client).
    conditions.applications.as_ref()?;
    let (reason, workload_clients) = applies(conditions, app_id, sp_id)?;
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
        workload_clients,
        grant_controls,
        grant_operator,
    })
}

fn reason_rank(reason: &str) -> u8 {
    match reason {
        // Confirmed to gate this app (as resource or as client).
        "appId" | "sp" => 0,
        // Confirmed to gate a group this app is certainly in.
        "all" | "allWorkload" => 1,
        _ => 2, // groupings / filters ("may apply")
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
/// premium/role mapping with the Activity tab (see
/// [`graph_err::premium_feature_err`]): a missing license vs. role gets a
/// distinct message, every Graph failure degrades to `ca_unavailable` (a
/// classified token failure keeps its own code), and a raw Graph body is never
/// leaked.
pub(crate) fn map_ca_err(err: GraphError) -> UiError {
    graph_err::premium_feature_err(
        "ca_unavailable",
        "Conditional Access",
        "Conditional Access",
        "conditional_access",
        err,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_ranks_confirmed_client_matches_first() {
        assert_eq!(reason_rank("sp"), reason_rank("appId"));
        assert_eq!(reason_rank("allWorkload"), reason_rank("all"));
        assert!(reason_rank("all") < reason_rank("clientFilter"));
        assert!(reason_rank("sp") < reason_rank("allWorkload"));
    }

    // ---- error mapping ---------------------------------------------------

    #[test]
    fn ca_err_is_body_safe_and_classified() {
        const LICENSE_BODY: &str =
            "{\"error\":{\"code\":\"Authentication_RequestFromNonPremiumTenantOrB2CTenant\"}}";
        const CONSENT_BODY: &str = "{\"error\":{\"code\":\"Authorization_RequestDenied\",\"message\":\"Insufficient privileges\"}}";
        // The typed discriminator: the body classifies as license vs consent
        // before any prose is involved. Both still share the one
        // `ca_unavailable` code (the documented `premium_feature_err` design).
        assert!(graph_err::looks_like_missing_license(LICENSE_BODY));
        // A privilege denial (no license keywords) must classify as a role
        // gap, not license — guards the dropped " p1"/" p2" substring
        // false-match.
        assert!(!graph_err::looks_like_missing_license(CONSENT_BODY));

        let license = map_ca_err(GraphError::Forbidden(LICENSE_BODY.into()));
        assert_eq!(license.code, "ca_unavailable");
        assert!(license.message.contains("license"));

        // The role gap names the roles that can read policies (the catalog
        // remediation), not admin consent — that fails at /token, typed.
        let role = map_ca_err(GraphError::Forbidden(CONSENT_BODY.into()));
        assert_eq!(role.code, "ca_unavailable");
        assert!(role.message.contains("Security Reader"), "{}", role.message);
        assert!(!role.message.contains("requires admin consent"));
        // Neither a missing license nor a missing role fixes itself on retry.
        assert!(!license.retryable && !role.retryable);

        let server = map_ca_err(GraphError::Server {
            status: 503,
            body: "internal".into(),
        });
        assert!(server.retryable);
        assert!(!server.message.contains("internal"));
    }
}
