//! Pass 5: re-binding Graph app roles to managed identities already recreated
//! in the destination.

use std::collections::{HashMap, HashSet};

use azapptoolkit_graph::GraphClient;

use crate::commands::dispatch::SessionDead;
use crate::commands::managed_identity::{grant_managed_identity_roles_core, mi_subtype_label};
use crate::commands::progress::ProgressSink;
use crate::dto::backup::{
    ManagedIdentityBackup, ManualItem, PrivilegedKind, RestoreApproval, RestoreReport,
    RestoredManagedIdentity,
};
use crate::dto::managed_identity::MiSubtype;
use crate::state::CancelToken;

use super::RestoreProgress;

/// Pass-5 work: re-bind managed-identity permissions. MIs can't be created via
/// Graph (they're Azure resources), so this matches each backed-up MI to one
/// **already recreated** in the destination (by display name and, where both
/// sides know it, sub-type) and re-binds its
/// held Graph app-roles to the new principal. Azure RBAC re-creation, and MIs
/// not yet recreated, are emitted as runbook items (source RBAC scopes don't
/// exist in the destination, so they can't be replayed automatically).
///
/// A failed destination listing is ONE runbook item saying so — never a "not
/// found" item per MI, which would send the infra team to recreate identities
/// that already exist — and is noted through `session`. A name that matches
/// several destination identities re-binds none of them: the backup cannot say
/// which one is this identity.
///
/// Every app role is app-only access, so an MI's roles are re-bound only when
/// `approved` names it (the plan's opt-in); otherwise they are withheld as one
/// runbook item.
///
/// Ticks `progress` once per identity it settles ([`rebind_one`]).
pub(super) async fn restore_managed_identities(
    client: &GraphClient,
    mis: &[ManagedIdentityBackup],
    approved: &HashSet<RestoreApproval>,
    report: &mut RestoreReport,
    session: &SessionDead,
    cancel: &CancelToken,
    progress: &mut RestoreProgress<'_, impl ProgressSink>,
) {
    let dest = match client.list_managed_identities().await {
        Ok(list) => list,
        Err(e) => {
            session.note_code(e.ui_code());
            report.manual_items.push(ManualItem {
                display_name: format!("Managed identities ({})", mis.len()),
                reason: format!(
                    "Couldn't list the destination's managed identities ({e}), so none were \
                     re-bound and none are reported missing. Run the restore again once the read \
                     succeeds."
                ),
            });
            return;
        }
    };
    // Every destination MI under each name — never a map that keeps only the
    // last, which would re-bind the roles to whichever identity came last.
    let mut by_name: HashMap<String, Vec<(String, MiSubtype)>> = HashMap::new();
    for sp in dest {
        let subtype = MiSubtype::from_alternative_names(&sp.alternative_names);
        by_name
            .entry(sp.display_name.to_ascii_lowercase())
            .or_default()
            .push((sp.id, subtype));
    }

    for mi in mis {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        rebind_one(client, mi, &by_name, approved, report, session).await;
        progress.tick(&mi.display_name);
    }
}

/// Pass-5 work for one backed-up identity, against the destination's
/// identities by lower-cased name (`by_name`): re-bind its approved Graph app
/// roles to the one match, or record why not, plus its Azure RBAC runbook item.
async fn rebind_one(
    client: &GraphClient,
    mi: &ManagedIdentityBackup,
    by_name: &HashMap<String, Vec<(String, MiSubtype)>>,
    approved: &HashSet<RestoreApproval>,
    report: &mut RestoreReport,
    session: &SessionDead,
) {
    // By name AND sub-type where both are known: a user-assigned identity
    // created under a system-assigned one's name (or the reverse) is not
    // the identity the backup described, however it is called.
    let matches: Vec<&str> = by_name
        .get(&mi.display_name.to_ascii_lowercase())
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|(_, subtype)| subtype_compatible(*subtype, mi.subtype))
        .map(|(id, _)| id.as_str())
        .collect();
    if matches.len() > 1 {
        report.manual_items.push(ManualItem {
            display_name: mi.display_name.clone(),
            reason: format!(
                "{} managed identities in the destination are named '{}' ({}), so none was \
                 re-bound — the backup cannot say which one is this identity. Rename or \
                 remove the duplicates, then run the restore again with this backup.",
                matches.len(),
                mi.display_name,
                matches.join(", ")
            ),
        });
        return;
    }
    let Some(principal_id) = matches.first().map(|id| id.to_string()) else {
        let arm = mi
            .arm_resource_id
            .as_deref()
            .map(|a| format!(" — {a}"))
            .unwrap_or_default();
        report.manual_items.push(ManualItem {
            display_name: mi.display_name.clone(),
            reason: format!(
                "Managed identity ({}{}) not found in the destination. Recreate it via your \
                 infrastructure-as-code, then run the restore again with this backup — apps \
                 it already created are recognised by their restore tag, not duplicated — \
                 to re-bind its Graph app-roles.",
                mi_subtype_label(mi.subtype),
                arm
            ),
        });
        return;
    };

    let mut out = RestoredManagedIdentity {
        display_name: mi.display_name.clone(),
        new_principal_id: principal_id.clone(),
        ..Default::default()
    };

    // Group the held Graph app-roles by resource appId → role values, so one
    // grant call covers all roles on a given resource. Unresolved entries
    // (no value, or the resource couldn't be resolved at backup) can't be
    // re-bound by value.
    let mut by_resource: HashMap<String, Vec<String>> = HashMap::new();
    let mi_approved = approved.contains(&RestoreApproval {
        kind: PrivilegedKind::ManagedIdentity,
        source_app_id: mi.source_app_id.clone(),
    });
    let mut withheld: Vec<String> = Vec::new();
    for r in &mi.held_app_roles {
        match r.app_role_value.as_deref() {
            Some(v) if !v.is_empty() && !r.resource_app_id.is_empty() && !mi_approved => {
                withheld.push(v.to_string());
            }
            Some(v) if !v.is_empty() && !r.resource_app_id.is_empty() => {
                by_resource
                    .entry(r.resource_app_id.clone())
                    .or_default()
                    .push(v.to_string());
            }
            _ => out
                .warnings
                .push("a held app-role couldn't be re-bound (resource or value unresolved)".into()),
        }
    }
    if !withheld.is_empty() {
        report.manual_items.push(ManualItem {
            display_name: mi.display_name.clone(),
            reason: format!(
                "App roles not re-bound: not approved in the plan ({}). Grant them from the \
                 managed identity's detail view if they are intended.",
                withheld.join(", ")
            ),
        });
    }
    for (resource_app_id, roles) in by_resource {
        match grant_managed_identity_roles_core(client, &principal_id, &resource_app_id, &roles)
            .await
        {
            Ok((granted, _skipped, failures)) => {
                out.app_roles_rebound += granted.len();
                out.warnings.extend(failures);
            }
            Err(e) => {
                session.note_code(&e.code);
                out.warnings
                    .push(format!("re-bind on {resource_app_id}: {}", e.message));
            }
        }
    }

    // Azure RBAC always needs manual re-creation — source scopes are
    // subscription/resource-specific and don't exist in the destination.
    report.manual_items.push(ManualItem {
        display_name: mi.display_name.clone(),
        reason: "Re-create this managed identity's Azure RBAC role assignments manually at the \
                 destination's equivalent scopes (source scopes don't transfer)."
            .into(),
    });

    report.managed_identities.push(out);
}

/// Whether two managed-identity sub-types can describe one identity: equal,
/// or either unknown (a system-assigned identity may carry no
/// `alternativeNames`, which reads as `Unknown` on either side).
fn subtype_compatible(a: MiSubtype, b: MiSubtype) -> bool {
    a == MiSubtype::Unknown || b == MiSubtype::Unknown || a == b
}
