//! Readiness checklist — what the signed-in user currently holds vs. what each
//! feature needs.
//!
//! `check_readiness` checks the signed-in user's **active directory roles** and
//! **consented scopes** against the capability catalog
//! ([`azapptoolkit_core::capabilities`]) and returns a per-capability verdict on
//! both axes. There is no single role that unlocks the app — three independent
//! authorization planes, see `docs/operator-rbac/OPERATOR-ROLES.md` — so this
//! tells the user exactly what to activate. Read-only and best-effort: every
//! probe that can't run yields [`Verdict::Unknown`] ("?"), never a hard error,
//! so the page loads even for a user who lacks every optional scope.

use std::collections::{HashMap, HashSet};

use tauri::State;

use azapptoolkit_auth::AuthError;
use azapptoolkit_core::capabilities::{CAPABILITIES, Capability, RoleDetect};

use crate::dto::UiError;
use crate::dto::readiness::{ReadinessItem, ReadinessReport, Verdict};
use crate::state::AppState;

/// Builds the readiness report for `tenant_id`. Never cached — the whole point is
/// freshness after a PIM activation; the underlying token probes reuse the
/// per-scope token cache, so a probe that already has a fresh token costs no
/// round trip.
#[tauri::command]
pub async fn check_readiness(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<ReadinessReport, UiError> {
    // Active directory-role display names. PIM-eligible-but-inactive roles are
    // absent (only activated assignments are memberships) — exactly the signal
    // we want. A read failure isn't fatal: every DirectoryRole row degrades to
    // "?" and the UI shows one banner.
    let active_roles = state
        .graph_for(&tenant_id)
        .me_active_directory_roles()
        .await
        .inspect_err(|err| {
            tracing::warn!(?err, "readiness: couldn't read active directory roles");
        });
    let directory_roles_indeterminate = active_roles.is_err();
    let active_roles = active_roles.unwrap_or_default();

    // Probe each DISTINCT scope audience once, concurrently — `write` and `arm`
    // are each shared by two capabilities. Serial probing paid a token-endpoint
    // round trip per feature back-to-back; fanning them out cuts the readiness
    // page's cold latency to roughly one probe's worth.
    let distinct_features: Vec<&'static str> = {
        let mut seen = HashSet::new();
        CAPABILITIES
            .iter()
            .filter_map(|c| c.scope_feature)
            .filter(|f| seen.insert(*f))
            .collect()
    };
    let scope_verdicts: HashMap<&'static str, Verdict> =
        futures::future::join_all(distinct_features.into_iter().map(|f| {
            let st = &state;
            let tid = tenant_id.as_str();
            async move { (f, probe_scope(st, tid, f).await) }
        }))
        .await
        .into_iter()
        .collect();

    let mut items = Vec::with_capacity(CAPABILITIES.len());
    for cap in CAPABILITIES {
        let (role_verdict, role_detail) =
            role_for(cap, &active_roles, directory_roles_indeterminate);

        let (scope_verdict, scope_detail) = match cap.scope_feature {
            Some(feature) => {
                let verdict = scope_verdicts
                    .get(feature)
                    .copied()
                    .unwrap_or(Verdict::Unknown);
                (verdict, scope_detail_text(cap, verdict))
            }
            None => (Verdict::Have, "Included in the sign-in scopes.".to_string()),
        };

        items.push(ReadinessItem {
            key: cap.key.to_string(),
            plane: cap.plane.as_str().to_string(),
            plane_label: cap.plane.label().to_string(),
            label: cap.label.to_string(),
            description: cap.description.to_string(),
            role_verdict,
            role_detail,
            scope_verdict,
            scope_detail,
            remediation: cap.remediation.to_string(),
        });
    }

    Ok(ReadinessReport {
        items,
        directory_roles_indeterminate,
    })
}

/// The role half of a capability — pure, so it's unit-tested without a client.
/// `directory_unreadable` is true when `/me` directory roles couldn't be read,
/// turning every directory-role capability into "?".
fn role_for(
    cap: &Capability,
    active_roles: &[String],
    directory_unreadable: bool,
) -> (Verdict, String) {
    match cap.role_detect {
        RoleDetect::DirectoryRole => {
            if directory_unreadable {
                return (
                    Verdict::Unknown,
                    "Couldn't read your active directory roles.".to_string(),
                );
            }
            match cap.directory_roles_any.iter().find(|needed| {
                active_roles
                    .iter()
                    .any(|have| have.eq_ignore_ascii_case(needed))
            }) {
                Some(matched) => (Verdict::Have, format!("Active role: {matched}.")),
                None => (
                    Verdict::Missing,
                    format!("Activate one of: {}.", cap.directory_roles_any.join(", ")),
                ),
            }
        }
        // Exchange RBAC isn't cheaply enumerable per-user at the tenant level
        // (a probe needs a real cmdlet + an app target and can false-negative on
        // a missing object). The per-app scoping actions surface the authoritative
        // 403 with `ExchangeError::ui_hint` when used, so report "?" with the
        // activate-the-role nudge here.
        RoleDetect::ExchangeProbe => (
            Verdict::Unknown,
            "Activate the Exchange Administrator role (active, not just PIM-eligible); a mailbox \
             scoping action will confirm Role Management access."
                .to_string(),
        ),
        RoleDetect::Indeterminate => (
            Verdict::Unknown,
            format!(
                "Not enumerable from the directory — verify the {} role in PIM for Azure \
                 resources.",
                cap.directory_roles_any.join(" / ")
            ),
        ),
    }
}

fn scope_detail_text(cap: &Capability, verdict: Verdict) -> String {
    match verdict {
        Verdict::Have => "Scope consented.".to_string(),
        Verdict::Missing => format!("Not consented: {}.", cap.scopes.join(", ")),
        Verdict::Unknown => "Couldn't determine scope consent.".to_string(),
    }
}

/// Silently acquires the feature's scopes and classifies the result: a token ⇒
/// consented ([`Verdict::Have`]); a typed `consent_required` ⇒ not consented
/// ([`Verdict::Missing`]); anything else ⇒ indeterminate ([`Verdict::Unknown`]).
/// This is a *silent* refresh-token acquisition — it never prompts and never
/// purges the refresh token on a `consent_required` (the AGENTS.md invariant), so
/// probing an un-consented optional scope is side-effect-free. Graph scopes use
/// the CAE path (matching the Graph adapter) so the cached token is reused;
/// resource audiences (ARM / Key Vault / Exchange) don't.
async fn probe_scope(state: &AppState, tenant_id: &str, feature: &str) -> Verdict {
    let Some(scopes) = state.consent_scopes_for(feature) else {
        return Verdict::Unknown;
    };
    let is_graph = matches!(
        feature,
        "write" | "sync" | "audit_log" | "policy" | "policy_write" | "sharepoint"
    );
    let result = if is_graph {
        state
            .auth
            .access_token_for_scopes_cae(tenant_id, &scopes, None)
            .await
    } else {
        state.auth.access_token_for_scopes(tenant_id, &scopes).await
    };
    match result {
        Ok(_) => Verdict::Have,
        Err(AuthError::ConsentRequired(_)) => Verdict::Missing,
        Err(_) => Verdict::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::capabilities::capability;

    #[test]
    fn directory_role_present_is_have() {
        let cap = capability("app_registrations").unwrap();
        let (v, detail) = role_for(cap, &["Global Administrator".to_string()], false);
        assert_eq!(v, Verdict::Have);
        assert!(detail.contains("Global Administrator"));
    }

    #[test]
    fn directory_role_absent_is_missing_and_lists_alternatives() {
        let cap = capability("app_registrations").unwrap();
        let (v, detail) = role_for(cap, &["User Administrator".to_string()], false);
        assert_eq!(v, Verdict::Missing);
        assert!(detail.contains("Cloud Application Administrator"));
    }

    #[test]
    fn directory_unreadable_is_unknown() {
        let cap = capability("app_registrations").unwrap();
        let (v, _) = role_for(cap, &[], true);
        assert_eq!(v, Verdict::Unknown);
    }

    #[test]
    fn azure_and_exchange_roles_are_unknown() {
        // Indeterminate (Azure) and ExchangeProbe both report "?" — they aren't
        // directory-enumerable.
        let (v, _) = role_for(capability("keyvault_secrets").unwrap(), &[], false);
        assert_eq!(v, Verdict::Unknown);
        let (v, _) = role_for(capability("exchange_rbac").unwrap(), &[], false);
        assert_eq!(v, Verdict::Unknown);
    }

    #[test]
    fn scope_detail_names_missing_scopes() {
        let cap = capability("audit_reports").unwrap();
        let text = scope_detail_text(cap, Verdict::Missing);
        assert!(text.contains("AuditLog.Read.All"));
    }
}
