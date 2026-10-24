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
use std::time::Duration;

use futures::stream::{self, StreamExt};
use parking_lot::Mutex;
use tauri::State;

use azapptoolkit_auth::AuthError;
use azapptoolkit_core::capabilities::{
    CAPABILITIES, Capability, RoleDetect, matched_directory_role,
};
use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_core::models::ActiveDirectoryRole;

use crate::commands::dispatch::ARM_CONCURRENCY;
use crate::dto::UiError;
use crate::dto::readiness::{ReadinessItem, ReadinessReport, Verdict};
use crate::state::{AppState, ConsentFeature};

/// How long the Azure-RBAC plane may take before the page gives up on it.
/// The other two planes answer in about a second; an ARM host that drops
/// traffic (an egress allow-list that admits Graph only) held the whole page
/// for the ARM retry budget instead — ~47 s per blocked call, far longer over a
/// subscription fan-out. Past this the Azure rows keep what the sweep had
/// confirmed and read "?" with a re-check note for the rest, never Missing.
const AZURE_PLANE_BUDGET: Duration = Duration::from_secs(15);

/// What the Azure-RBAC sweep produced for the role half of the Azure plane.
#[derive(Debug)]
enum AzureRoles {
    /// The role-definition GUIDs directly assigned to the signed-in user.
    Held(HashSet<String>),
    /// Couldn't be enumerated (no signed-in oid, no ARM consent, an ARM error).
    Unavailable,
    /// The sweep ran past [`AZURE_PLANE_BUDGET`] and was abandoned, holding
    /// what the subscriptions it did reach confirmed. Still a superset check:
    /// a confirmed assignment is `Have`, anything else `Unknown` (this plane
    /// never emits Missing), so a partial set loses nothing true.
    TimedOut(HashSet<String>),
}

/// Runs the Azure-RBAC sweep under `budget`, so a blocked ARM egress costs the
/// page at most that long. The sweep records each subscription's assignments
/// into `found` as they land, so a timeout keeps what was already confirmed.
/// Split out so the bound is testable on a paused clock.
async fn azure_plane_within(
    budget: Duration,
    found: &Mutex<HashSet<String>>,
    sweep: impl std::future::Future<Output = Option<()>>,
) -> AzureRoles {
    let collected = || std::mem::take(&mut *found.lock());
    match tokio::time::timeout(budget, sweep).await {
        Ok(Some(())) => AzureRoles::Held(collected()),
        Ok(None) => AzureRoles::Unavailable,
        Err(_) => {
            let partial = collected();
            tracing::warn!(
                budget_secs = budget.as_secs(),
                confirmed = partial.len(),
                "readiness: Azure role-assignment sweep timed out; unconfirmed Azure rows read unknown"
            );
            AzureRoles::TimedOut(partial)
        }
    }
}

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
    // (best-effort, bounded by `AZURE_PLANE_BUDGET`). What isn't confirmed
    // falls back to "?".
    let azure_found = Mutex::new(HashSet::new());
    let azure_fut = azure_plane_within(
        AZURE_PLANE_BUDGET,
        &azure_found,
        enumerate_azure_role_ids(&state, &tenant_id, &azure_found),
    );

    // The three planes share no inputs — Graph directory roles, token-endpoint
    // scope probes and the ARM sweep are independent — so they run concurrently
    // and the page's cold latency is the slowest single plane rather than their
    // sum. Each still degrades on its own: a failure here is never fatal.
    let (active_roles, scope_verdicts, azure_roles) =
        tokio::join!(roles_fut, scopes_fut, azure_fut);

    // Kept as the client's own error, so the page names the real cause (a
    // dead session, a 403, an unreachable Graph) instead of guessing one.
    let (active_roles, directory_roles_error) = match active_roles {
        Ok(roles) => (roles, None),
        Err(err) => {
            tracing::warn!(?err, "readiness: couldn't read active directory roles");
            (Vec::new(), Some(UiError::from(err)))
        }
    };
    let directory_roles_indeterminate = directory_roles_error.is_some();
    let scope_verdicts: HashMap<&'static str, Verdict> = scope_verdicts.into_iter().collect();

    let cloud = state.auth.cloud();
    let mut items = Vec::with_capacity(CAPABILITIES.len());
    for cap in CAPABILITIES {
        let (role_verdict, role_detail) = role_for(
            cap,
            &active_roles,
            directory_roles_indeterminate,
            &azure_roles,
        );

        let (scope_verdict, scope_detail) = match cap.scope_feature {
            Some(feature) => {
                let verdict = scope_verdicts
                    .get(feature)
                    .copied()
                    .unwrap_or(Verdict::Unknown);
                (verdict, scope_detail_text(cap, verdict, cloud))
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
        directory_roles_error,
        pim_activation_url: Some(state.auth.cloud().pim_my_roles_url()),
    })
}

/// The role half of a capability — pure, so it's unit-tested without a client.
/// `directory_unreadable` is true when `/me` directory roles couldn't be read,
/// turning every directory-role capability into "?". `azure` is what the
/// Azure-RBAC sweep found for the Azure plane.
fn role_for(
    cap: &Capability,
    active_roles: &[ActiveDirectoryRole],
    directory_unreadable: bool,
    azure: &AzureRoles,
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
            // Missing covers two states `/me` can't tell apart: PIM-eligible
            // (activate it) and not assigned (ask for an assignment). Telling
            // them apart needs `RoleEligibilitySchedule.Read.Directory`, a scope
            // the app deliberately doesn't request, so the text names both.
            match matched_directory_role(cap, active_roles) {
                Some(matched) => (Verdict::Have, format!("Active role: {matched}.")),
                None => (
                    Verdict::Missing,
                    format!(
                        "Not active. If you're eligible in PIM, activate one of: {}. Otherwise \
                         ask your role administrator for an assignment.",
                        cap.role_names().collect::<Vec<_>>().join(", ")
                    ),
                ),
            }
        }
        RoleDetect::Indeterminate => azure_role_verdict(cap, azure),
    }
}

/// Azure-RBAC verdict from the user's enumerated **direct** role assignments.
/// Only direct assignments are visible (the `principalId` filter doesn't return
/// group-inherited roles), so this only ever upgrades to `Have` on a confirmed
/// assignment — it never reports `Missing` (which could be a false alarm for a
/// role held via a group). It stays `Unknown` otherwise, a timed-out sweep
/// included — which still upgrades whatever it confirmed before the budget.
fn azure_role_verdict(cap: &Capability, azure: &AzureRoles) -> (Verdict, String) {
    let roles: Vec<&str> = cap.role_names().collect();
    let (held, timed_out) = match azure {
        // Couldn't enumerate (no ARM consent / no signed-in oid / ARM error).
        AzureRoles::Unavailable => {
            return (
                Verdict::Unknown,
                format!(
                    "Azure RBAC is granted per subscription/resource — grant this app Azure access \
                     (or activate the {} role in PIM) so readiness can check it.",
                    roles.join(" / ")
                ),
            );
        }
        AzureRoles::Held(held) => (held, false),
        AzureRoles::TimedOut(partial) => (partial, true),
    };
    if roles
        .iter()
        .any(|name| azapptoolkit_core::azure_roles::azure_role_satisfied(name, held))
    {
        (
            Verdict::Have,
            "Active Azure role assignment (direct).".to_string(),
        )
    } else if timed_out {
        (
            Verdict::Unknown,
            format!(
                "Timed out: the Azure role-assignment check didn't finish within {} seconds, and \
                 the subscriptions it reached showed no direct {} assignment — re-check later \
                 with Refresh token (top right).",
                AZURE_PLANE_BUDGET.as_secs(),
                roles.join(" / ")
            ),
        )
    } else {
        (
            Verdict::Unknown,
            format!(
                "No direct Azure role assignment found — you may still hold {} via a group (not \
                 visible here) or on a specific resource; check Resource Access.",
                roles.join(" / ")
            ),
        )
    }
}

/// Best-effort: records into `found` the Azure role-definition GUIDs
/// **directly** assigned to the signed-in user, subscription by subscription
/// as each answers (so [`azure_plane_within`]'s timeout keeps what landed).
/// `None` when it can't be determined at all (no signed-in oid, missing ARM
/// consent, or an ARM error listing subscriptions) — the caller then reports
/// Azure capabilities as "?" rather than guessing.
async fn enumerate_azure_role_ids(
    state: &AppState,
    tenant_id: &str,
    found: &Mutex<HashSet<String>>,
) -> Option<()> {
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
    stream::iter(subs)
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
        .for_each(|assignments| {
            let ids = assignments.into_iter().filter_map(|a| {
                a.properties
                    .role_definition_id
                    .as_deref()
                    .and_then(azapptoolkit_core::azure_roles::role_id_tail)
            });
            found.lock().extend(ids);
            std::future::ready(())
        })
        .await;
    Some(())
}

/// The scope half's detail line. A missing scope is named in `cloud`'s form
/// ([`Capability::display_scopes`]) — the audience the probe actually asked for.
fn scope_detail_text(cap: &Capability, verdict: Verdict, cloud: CloudEnvironment) -> String {
    match verdict {
        Verdict::Have => "Scope consented.".to_string(),
        Verdict::Missing => format!("Not consented: {}.", cap.display_scopes(cloud).join(", ")),
        Verdict::Unknown => "Couldn't determine scope consent.".to_string(),
    }
}

/// Silently acquires the feature's scopes and classifies the result: a token ⇒
/// consented ([`Verdict::Have`]); a typed `consent_required` ⇒ not consented
/// ([`Verdict::Missing`]); anything else ⇒ indeterminate ([`Verdict::Unknown`]).
/// This is a *silent* refresh-token acquisition — it never prompts and never
/// purges the refresh token on a `consent_required` (the AGENTS.md invariant), so
/// probing an un-consented optional scope is side-effect-free. It goes through
/// [`AppState::ensure_feature_token`] — the same [`ConsentFeature`] scope set and
/// CAE derivation the `ensure_*` wrappers use — so a readiness pre-warm can
/// never seed a token in a different CAE slot from the adapter that later reuses
/// it (a hand-kept feature list here once probed `group_membership` non-CAE).
async fn probe_scope(state: &AppState, tenant_id: &str, feature: &str) -> Verdict {
    let Some(feature) = ConsentFeature::parse(feature) else {
        return Verdict::Unknown;
    };
    match state.ensure_feature_token(tenant_id, feature).await {
        Ok(()) => Verdict::Have,
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
            &AzureRoles::Unavailable,
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
            &AzureRoles::Unavailable,
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
            &AzureRoles::Unavailable,
        );
        assert_eq!(v, Verdict::Missing);
        assert!(detail.contains("Cloud Application Administrator"));
    }

    #[test]
    fn missing_role_detail_covers_eligible_and_unassigned() {
        let (v, detail) = role_for(
            capability("provisioning_read").unwrap(),
            &[],
            false,
            &AzureRoles::Unavailable,
        );
        assert_eq!(v, Verdict::Missing);
        assert!(detail.contains("PIM"), "{detail}");
        assert!(detail.contains("assignment"), "{detail}");
        assert!(detail.contains("Hybrid Identity Administrator"), "{detail}");
    }

    #[test]
    fn directory_unreadable_is_unknown() {
        let cap = capability("app_registrations").unwrap();
        let (v, _) = role_for(cap, &[], true, &AzureRoles::Unavailable);
        assert_eq!(v, Verdict::Unknown);
    }

    #[test]
    fn azure_rbac_unknown_when_not_enumerable() {
        // No ARM enumeration available (None) => "?" with a grant-access nudge.
        let cap = capability("keyvault_secrets").unwrap();
        let (v, detail) = role_for(cap, &[], false, &AzureRoles::Unavailable);
        assert_eq!(v, Verdict::Unknown);
        assert!(detail.contains("Azure"));
    }

    #[test]
    fn azure_rbac_have_when_a_direct_assignment_satisfies() {
        // azure_role_reads needs "Reader"; a held Reader assignment => Have.
        let reader = "acdd72a7-3385-48ef-bd42-f606fba81ae7".to_string();
        let held = AzureRoles::Held(HashSet::from([reader]));
        let (v, _) = role_for(capability("azure_role_reads").unwrap(), &[], false, &held);
        assert_eq!(v, Verdict::Have);
    }

    #[test]
    fn azure_rbac_unknown_not_missing_when_no_direct_assignment() {
        // Enumeration succeeded but the required role isn't directly held: stay
        // Unknown (it may be group-inherited), never falsely Missing.
        let held = AzureRoles::Held(HashSet::new());
        let (v, _) = role_for(capability("keyvault_secrets").unwrap(), &[], false, &held);
        assert_eq!(v, Verdict::Unknown);
    }

    /// A blocked ARM egress no longer holds the page: past the budget the
    /// sweep is abandoned, what it had confirmed still counts, and the other
    /// Azure rows read "?" with a re-check note — never Missing, which would be
    /// a false alarm.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_azure_sweep_times_out_keeping_what_it_confirmed() {
        // Reader (azure_role_reads) landed from one subscription before the
        // next one stalled.
        let reader = "acdd72a7-3385-48ef-bd42-f606fba81ae7".to_string();
        let found = Mutex::new(HashSet::new());
        let started = tokio::time::Instant::now();
        let azure = azure_plane_within(AZURE_PLANE_BUDGET, &found, async {
            found.lock().insert(reader.clone());
            std::future::pending::<Option<()>>().await
        })
        .await;
        assert_eq!(started.elapsed(), AZURE_PLANE_BUDGET);
        let AzureRoles::TimedOut(partial) = &azure else {
            panic!("{azure:?}");
        };
        assert!(partial.contains(&reader));

        let (v, _) = role_for(capability("azure_role_reads").unwrap(), &[], false, &azure);
        assert_eq!(
            v,
            Verdict::Have,
            "a confirmed assignment survives the timeout"
        );
        let (v, detail) = role_for(capability("keyvault_secrets").unwrap(), &[], false, &azure);
        assert_eq!(v, Verdict::Unknown);
        assert!(detail.starts_with("Timed out"), "{detail}");
        assert!(
            detail.contains("didn't finish within 15 seconds"),
            "{detail}"
        );
        assert!(detail.contains("re-check"), "{detail}");

        // A sweep that finishes inside the budget is used as-is.
        let found = Mutex::new(HashSet::new());
        let azure = azure_plane_within(AZURE_PLANE_BUDGET, &found, async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            found.lock().insert(reader.clone());
            Some(())
        })
        .await;
        assert!(
            matches!(&azure, AzureRoles::Held(h) if h.contains(&reader)),
            "{azure:?}"
        );
        let unavailable =
            azure_plane_within(AZURE_PLANE_BUDGET, &Mutex::new(HashSet::new()), async {
                None
            })
            .await;
        assert!(matches!(unavailable, AzureRoles::Unavailable));
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
            &AzureRoles::Unavailable,
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
            &AzureRoles::Unavailable,
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
            &AzureRoles::Unavailable,
        );
        assert_eq!(v, Verdict::Missing);
        assert!(detail.contains("Exchange Administrator"));
    }

    #[test]
    fn scope_detail_names_missing_scopes() {
        let cap = capability("audit_reports").unwrap();
        let text = scope_detail_text(cap, Verdict::Missing, CloudEnvironment::Commercial);
        assert!(text.contains("AuditLog.Read.All"));
    }

    #[test]
    fn scope_detail_names_the_configured_clouds_audience() {
        let cap = capability("keyvault_secrets").unwrap();
        let text = scope_detail_text(cap, Verdict::Missing, CloudEnvironment::UsGov);
        assert!(text.contains("vault.usgovcloudapi.net"), "{text}");
        assert!(!text.contains("vault.azure.net"), "{text}");
    }

    /// The checklist's "Not consented: …" text names exactly the resource
    /// audience the probe requests, so the two can't drift apart again.
    #[test]
    fn displayed_resource_scopes_are_the_probed_ones() {
        let state = AppState::for_test("t", "http://127.0.0.1:1");
        let cloud = state.auth.cloud();
        let mut checked = 0;
        for cap in CAPABILITIES {
            let Some(feature) = cap.scope_feature else {
                continue;
            };
            if !matches!(feature, "keyvault" | "arm" | "log_analytics" | "exchange") {
                continue;
            }
            let probed = state.consent_scopes_for(feature).unwrap();
            for shown in cap.display_scopes(cloud) {
                assert!(
                    probed.contains(&shown),
                    "{}: shows {shown} but probes {probed:?}",
                    cap.key
                );
                checked += 1;
            }
        }
        assert!(checked >= 4, "only {checked} resource scopes checked");
    }
}
