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

use futures::stream::{self, StreamExt};
use tauri::State;

use azapptoolkit_auth::AuthError;
use azapptoolkit_core::capabilities::{
    CAPABILITIES, Capability, RoleDetect, matched_directory_role,
};
use azapptoolkit_core::models::ActiveDirectoryRole;

use crate::dto::UiError;
use crate::dto::readiness::{ReadinessItem, ReadinessReport, Verdict};
use crate::state::AppState;

/// Max concurrent ARM calls for the per-subscription role-assignment sweep.
/// Matches the Key Vault / managed-identity sweeps so a large estate stays
/// inside ARM's rate limits (429s are retried in the client).
const ARM_CONCURRENCY: usize = 8;

/// Builds the readiness report for `tenant_id`. Never cached — the whole point is
/// freshness after a PIM activation; the underlying token probes reuse the
/// per-scope token cache, so a probe that already has a fresh token costs no
/// round trip.
#[tauri::command]
pub async fn check_readiness(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<ReadinessReport, UiError> {
    // Active directory roles (display name + roleTemplateId — matching uses
    // the template id; tenants carry legacy display names). PIM-eligible-but-
    // inactive roles are absent (only activated assignments are memberships) —
    // exactly the signal we want. A read failure isn't fatal: every
    // DirectoryRole row degrades to "?" and the UI shows one banner.
    let graph = state.graph_for(&tenant_id);
    let roles_fut = graph.me_active_directory_roles();

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
    let scopes_fut = futures::future::join_all(distinct_features.into_iter().map(|f| {
        let st = &state;
        let tid = tenant_id.as_str();
        async move { (f, probe_scope(st, tid, f).await) }
    }));

    // Azure-RBAC plane: enumerate the user's direct role assignments once
    // (best-effort). `None` => the Azure capabilities fall back to "?".
    let azure_fut = enumerate_azure_role_ids(&state, &tenant_id);

    // The three planes share no inputs — Graph directory roles, token-endpoint
    // scope probes and the ARM sweep are independent — so they run concurrently
    // and the page's cold latency is the slowest single plane rather than their
    // sum. Each still degrades on its own: a failure here is never fatal.
    let (active_roles, scope_verdicts, azure_held) = tokio::join!(roles_fut, scopes_fut, azure_fut);

    let active_roles = active_roles.inspect_err(|err| {
        tracing::warn!(?err, "readiness: couldn't read active directory roles");
    });
    let directory_roles_indeterminate = active_roles.is_err();
    let active_roles = active_roles.unwrap_or_default();
    let scope_verdicts: HashMap<&'static str, Verdict> = scope_verdicts.into_iter().collect();

    let mut items = Vec::with_capacity(CAPABILITIES.len());
    for cap in CAPABILITIES {
        let (role_verdict, role_detail) = role_for(
            cap,
            &active_roles,
            directory_roles_indeterminate,
            azure_held.as_ref(),
        );

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
/// turning every directory-role capability into "?". `azure_held` is the set of
/// Azure role-definition GUIDs directly assigned to the signed-in user (`None`
/// when they couldn't be enumerated), used for the Azure-RBAC plane.
fn role_for(
    cap: &Capability,
    active_roles: &[ActiveDirectoryRole],
    directory_unreadable: bool,
    azure_held: Option<&HashSet<String>>,
) -> (Verdict, String) {
    match cap.role_detect {
        RoleDetect::DirectoryRole => {
            if directory_unreadable {
                return (
                    Verdict::Unknown,
                    "Couldn't read your active directory roles.".to_string(),
                );
            }
            // Matched by roleTemplateId (with a name fallback) — a name-only
            // match reported active roles as missing in tenants whose
            // directoryRole objects carry legacy display names.
            match matched_directory_role(cap, active_roles) {
                Some(matched) => (Verdict::Have, format!("Active role: {matched}.")),
                None => (
                    Verdict::Missing,
                    format!(
                        "Activate one of: {}.",
                        cap.role_names().collect::<Vec<_>>().join(", ")
                    ),
                ),
            }
        }
        RoleDetect::Indeterminate => azure_role_verdict(cap, azure_held),
    }
}

/// Azure-RBAC verdict from the user's enumerated **direct** role assignments.
/// Only direct assignments are visible (the `principalId` filter doesn't return
/// group-inherited roles), so this only ever upgrades to `Have` on a confirmed
/// assignment — it never reports `Missing` (which could be a false alarm for a
/// role held via a group). It stays `Unknown` otherwise.
fn azure_role_verdict(cap: &Capability, azure_held: Option<&HashSet<String>>) -> (Verdict, String) {
    let roles: Vec<&str> = cap.role_names().collect();
    match azure_held {
        // Couldn't enumerate (no ARM consent / no signed-in oid / ARM error).
        None => (
            Verdict::Unknown,
            format!(
                "Azure RBAC is granted per subscription/resource — grant this app Azure access (or \
                 activate the {} role in PIM) so readiness can check it.",
                roles.join(" / ")
            ),
        ),
        Some(held) => {
            if roles
                .iter()
                .any(|name| azapptoolkit_core::azure_roles::azure_role_satisfied(name, held))
            {
                (
                    Verdict::Have,
                    "Active Azure role assignment (direct).".to_string(),
                )
            } else {
                (
                    Verdict::Unknown,
                    format!(
                        "No direct Azure role assignment found — you may still hold {} via a group \
                         (not visible here) or on a specific resource; check Resource Access.",
                        roles.join(" / ")
                    ),
                )
            }
        }
    }
}

/// Best-effort: the set of Azure role-definition GUIDs **directly** assigned to
/// the signed-in user across all their subscriptions. `None` when it can't be
/// determined (no signed-in oid, missing ARM consent, or an ARM error) — the
/// caller then reports Azure capabilities as "?" rather than guessing.
async fn enumerate_azure_role_ids(state: &AppState, tenant_id: &str) -> Option<HashSet<String>> {
    let oid = state.auth.tenant_context(tenant_id)?.account_oid;
    if oid.is_empty() {
        return None;
    }
    // Enumeration needs ARM control-plane access; absent consent => "?".
    state.ensure_arm_token(tenant_id).await.ok()?;
    let arm = state.arm_for(tenant_id);
    let subs = arm.list_subscriptions().await.ok()?;
    // Bounded fan-out. A serial loop paid one ARM round trip per subscription
    // back-to-back, which dominated this page's load time in tenants with a
    // large estate (the cost scaled with the operator's subscription count).
    // Partial enumeration beats none — a subscription we can't read is skipped,
    // not fatal; a 403 is terminal in the ARM transport, so it fails fast.
    let ids: HashSet<String> = stream::iter(subs)
        .map(|sub| {
            let arm = arm.clone();
            let oid = oid.clone();
            async move {
                match arm
                    .list_role_assignments_for_principal(&sub.subscription_id, &oid)
                    .await
                {
                    Ok(assignments) => assignments,
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            subscription = %sub.subscription_id,
                            "readiness: role-assignment enumeration failed; skipping subscription",
                        );
                        Vec::new()
                    }
                }
            }
        })
        .buffer_unordered(ARM_CONCURRENCY)
        .collect::<Vec<Vec<_>>>()
        .await
        .into_iter()
        .flatten()
        .filter_map(|a| {
            a.properties
                .role_definition_id
                .as_deref()
                .and_then(azapptoolkit_core::azure_roles::role_id_tail)
        })
        .collect();
    Some(ids)
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

    fn role(name: &str, template_id: &str) -> ActiveDirectoryRole {
        ActiveDirectoryRole {
            id: "role-obj".into(),
            display_name: Some(name.into()),
            role_template_id: Some(template_id.into()),
        }
    }

    #[test]
    fn directory_role_present_is_have() {
        let cap = capability("app_registrations").unwrap();
        let (v, detail) = role_for(
            cap,
            &[role(
                "Global Administrator",
                "62e90394-69f5-4237-9190-012177145e10",
            )],
            false,
            None,
        );
        assert_eq!(v, Verdict::Have);
        assert!(detail.contains("Global Administrator"));
    }

    #[test]
    fn legacy_named_role_matches_by_template_id() {
        // The user-reported bug: an ACTIVE SharePoint Administrator read as
        // "Role missing" because the tenant's directoryRole object is named
        // "SharePoint Service Administrator" (the documented Graph legacy
        // name). The template id must satisfy the check regardless.
        let cap = capability("sharepoint_sites_selected").unwrap();
        let (v, detail) = role_for(
            cap,
            &[role(
                "SharePoint Service Administrator",
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
            )],
            false,
            None,
        );
        assert_eq!(v, Verdict::Have);
        assert!(detail.contains("SharePoint Administrator"));
    }

    #[test]
    fn directory_role_absent_is_missing_and_lists_alternatives() {
        let cap = capability("app_registrations").unwrap();
        let (v, detail) = role_for(
            cap,
            &[role(
                "User Administrator",
                "fe930be7-5e62-47db-91af-98c3a49a38b1",
            )],
            false,
            None,
        );
        assert_eq!(v, Verdict::Missing);
        assert!(detail.contains("Cloud Application Administrator"));
    }

    #[test]
    fn directory_unreadable_is_unknown() {
        let cap = capability("app_registrations").unwrap();
        let (v, _) = role_for(cap, &[], true, None);
        assert_eq!(v, Verdict::Unknown);
    }

    #[test]
    fn azure_rbac_unknown_when_not_enumerable() {
        // No ARM enumeration available (None) => "?" with a grant-access nudge.
        let cap = capability("keyvault_secrets").unwrap();
        let (v, detail) = role_for(cap, &[], false, None);
        assert_eq!(v, Verdict::Unknown);
        assert!(detail.contains("Azure"));
    }

    #[test]
    fn azure_rbac_have_when_a_direct_assignment_satisfies() {
        // azure_role_reads needs "Reader"; a held Reader assignment => Have.
        let reader = "acdd72a7-3385-48ef-bd42-f606fba81ae7".to_string();
        let held: HashSet<String> = HashSet::from([reader]);
        let (v, _) = role_for(
            capability("azure_role_reads").unwrap(),
            &[],
            false,
            Some(&held),
        );
        assert_eq!(v, Verdict::Have);
    }

    #[test]
    fn azure_rbac_unknown_not_missing_when_no_direct_assignment() {
        // Enumeration succeeded but the required role isn't directly held: stay
        // Unknown (it may be group-inherited), never falsely Missing.
        let held: HashSet<String> = HashSet::new();
        let (v, _) = role_for(
            capability("keyvault_secrets").unwrap(),
            &[],
            false,
            Some(&held),
        );
        assert_eq!(v, Verdict::Unknown);
    }

    #[test]
    fn active_exchange_admin_is_have() {
        // Regression: Exchange Online RBAC is activated via the Entra "Exchange
        // Administrator" role, which `/me` reports — so an ACTIVE Exchange Admin
        // must read as Have, not "?" (the user-reported bug).
        let cap = capability("exchange_rbac").unwrap();
        let (v, detail) = role_for(
            cap,
            &[role(
                "Exchange Administrator",
                "29232cdf-9323-42fd-ade2-1d097af3e4de",
            )],
            false,
            None,
        );
        assert_eq!(v, Verdict::Have);
        assert!(detail.contains("Exchange Administrator"));

        // Global Administrator supersets it and also satisfies the check.
        let (v, _) = role_for(
            cap,
            &[role(
                "Global Administrator",
                "62e90394-69f5-4237-9190-012177145e10",
            )],
            false,
            None,
        );
        assert_eq!(v, Verdict::Have);
    }

    #[test]
    fn exchange_rbac_without_the_role_is_missing() {
        let cap = capability("exchange_rbac").unwrap();
        let (v, detail) = role_for(
            cap,
            &[role(
                "User Administrator",
                "fe930be7-5e62-47db-91af-98c3a49a38b1",
            )],
            false,
            None,
        );
        assert_eq!(v, Verdict::Missing);
        assert!(detail.contains("Exchange Administrator"));
    }

    #[test]
    fn scope_detail_names_missing_scopes() {
        let cap = capability("audit_reports").unwrap();
        let text = scope_detail_text(cap, Verdict::Missing);
        assert!(text.contains("AuditLog.Read.All"));
    }
}
