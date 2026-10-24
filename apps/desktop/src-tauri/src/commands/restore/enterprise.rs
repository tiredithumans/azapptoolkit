//! Pass 4: re-applying an enterprise application's settings, app-role
//! assignments and group memberships to its recreated service principal.

use std::collections::HashSet;

use crate::commands::progress::ProgressSink;
use crate::dto::backup::{
    EnterpriseAppBackup, ManualItem, PrincipalRef, RestoreApproval, RestoreReport,
    RestoredEnterpriseApp,
};
use crate::state::CancelToken;

use super::plan::app_approval;
use super::principals::{PrincipalMemo, owner_label, resolve_principal};
use super::{PassCtx, RestoreProgress};

/// Default-access app role (the all-zero GUID) — present on every SP, so an
/// assignment to it never needs role remapping.
pub(super) const DEFAULT_ACCESS_ROLE: &str = "00000000-0000-0000-0000-000000000000";

/// Pass-4 work for one enterprise app. If its service principal was recreated by
/// the app-reg restore, re-applies settings + role assignments + group
/// memberships; otherwise records a runbook entry (foreign/gallery apps and
/// paired apps that weren't restored can't be replayed automatically).
///
/// Every failure is noted through `ctx.session`, as in Pass 2, so a session
/// that dies here stops the restore instead of producing one wrong runbook item
/// per remaining app. `withhold` (its app was not approved in the plan) skips
/// the group memberships into one runbook item; role assignments still apply.
pub(super) async fn restore_enterprise_app(
    ctx: &PassCtx<'_>,
    ent: &EnterpriseAppBackup,
    withhold: bool,
    report: &mut RestoreReport,
    principals: &mut PrincipalMemo,
    cancel: &CancelToken,
) {
    let PassCtx {
        client,
        session,
        app_id_remap,
        ..
    } = *ctx;
    // Restorable only when its app registration was recreated here.
    let new_app_id = match app_id_remap.get(&ent.source_app_id) {
        Some(id) if !ent.is_foreign_tenant => id.clone(),
        _ => {
            let reason = if ent.is_foreign_tenant {
                "Foreign/gallery enterprise app — re-consent or re-instantiate it from the \
                 gallery in the destination tenant."
            } else {
                "No paired app registration was restored for this enterprise app."
            };
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: reason.into(),
            });
            return;
        }
    };

    // The SP is created alongside its app registration in Pass 1.
    let sp = match client.get_service_principal_by_app_id(&new_app_id).await {
        Ok(Some(sp)) => sp,
        Ok(None) => {
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: "Service principal was not created (the app had none in the backup)."
                    .into(),
            });
            return;
        }
        // A failed read is not an absent SP: saying "the app had none" would
        // send the operator after a problem that does not exist.
        Err(e) => {
            session.note_code(e.ui_code());
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: format!(
                    "Couldn't read the restored service principal ({e}); its access was not \
                     re-applied."
                ),
            });
            return;
        }
    };

    let mut out = RestoredEnterpriseApp {
        display_name: ent.display_name.clone(),
        new_sp_object_id: sp.id.clone(),
        ..Default::default()
    };

    // Settings (best-effort).
    if !ent.tags.is_empty()
        && let Err(e) = client.set_service_principal_tags(&sp.id, &ent.tags).await
    {
        session.note_code(e.ui_code());
        out.warnings.push(format!("tags: {e}"));
    }
    if let Some(required) = ent.app_role_assignment_required {
        let body = serde_json::json!({ "appRoleAssignmentRequired": required });
        if let Err(e) = client.patch_service_principal(&sp.id, &body).await {
            session.note_code(e.ui_code());
            out.warnings.push(format!("assignment-required: {e}"));
        }
    }

    // App-role assignments — principal remapped by name, role by value.
    for assignee in &ent.app_role_assignees {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        let principal_id =
            match resolve_principal(client, principals, &assignee.principal, session).await {
                Ok(id) => id,
                Err(why) => {
                    out.unresolved_principals
                        .push(why.label(&assignee.principal));
                    continue;
                }
            };
        let Some(role_id) = map_assignee_role_id(assignee, &sp.app_roles) else {
            out.warnings.push(format!(
                "role '{}' not found on the restored app; assignment for '{}' skipped",
                assignee.app_role_value.as_deref().unwrap_or("(custom)"),
                owner_label(&assignee.principal),
            ));
            continue;
        };
        match client
            .assign_app_role_to(&sp.id, &principal_id, &role_id)
            .await
        {
            Ok(_) => out.assignments_applied += 1,
            Err(e) => {
                session.note_code(e.ui_code());
                out.warnings.push(format!("assignment: {e}"));
            }
        }
    }

    // Group memberships — resolve each group by display name. The file chooses
    // the group, and a role-assignable group carries a directory role, so an
    // app not approved in the plan joins none of them.
    let groups: &[PrincipalRef] = if withhold {
        if !ent.group_memberships.is_empty() {
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: format!(
                    "Group memberships not added: not approved in the plan ({}). Add the \
                     service principal to them manually if they are intended.",
                    ent.group_memberships
                        .iter()
                        .map(owner_label)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        &[]
    } else {
        &ent.group_memberships
    };
    for group in groups {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        match resolve_principal(client, principals, group, session).await {
            Ok(group_id) => match client.add_group_member(&group_id, &sp.id).await {
                Ok(()) => out.group_memberships_applied += 1,
                Err(e) => {
                    session.note_code(e.ui_code());
                    out.warnings.push(format!("group membership: {e}"));
                }
            },
            Err(why) => out.unresolved_principals.push(why.label(group)),
        }
    }

    report.enterprise_apps.push(out);
}

/// Maps a backed-up assignee's role to a role id on the restored SP: the
/// default-access role passes through (always present); a custom role is matched
/// by its `value` against the new SP's `appRoles`. Custom role *definitions*
/// aren't restored, so an unmatched custom role yields `None` (reported, not
/// assigned).
pub(super) fn map_assignee_role_id(
    assignee: &crate::dto::backup::AppRoleAssigneeRef,
    new_sp_roles: &[azapptoolkit_core::models::AppRole],
) -> Option<String> {
    if assignee.app_role_id == DEFAULT_ACCESS_ROLE {
        return Some(DEFAULT_ACCESS_ROLE.to_string());
    }
    let value = assignee
        .app_role_value
        .as_deref()
        .filter(|v| !v.is_empty())?;
    new_sp_roles
        .iter()
        .find(|r| r.value == value)
        .map(|r| r.id.clone())
}

/// Pass 4 of [`run_restore`](super::run_restore): re-apply each enterprise
/// app's access ([`restore_enterprise_app`]) to the service principal Pass 1
/// recreated; group memberships only for an app `approved` names.
///
/// Stops at the next enterprise app on `cancel` (flagging the report) and on a
/// dead session. Ticks `progress` once per enterprise app it settles.
pub(super) async fn pass4_enterprise(
    ctx: &PassCtx<'_>,
    enterprise_apps: &[EnterpriseAppBackup],
    approved: &HashSet<RestoreApproval>,
    principals: &mut PrincipalMemo,
    cancel: &CancelToken,
    report: &mut RestoreReport,
    progress: &mut RestoreProgress<'_, impl ProgressSink>,
) {
    let session = ctx.session;
    for ent in enterprise_apps {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        // Group memberships always need approval, so they apply only to an app
        // the operator approved — decided from the approvals themselves, never
        // from a classification that could miss an enterprise app.
        restore_enterprise_app(
            ctx,
            ent,
            !approved.contains(&app_approval(&ent.source_app_id)),
            report,
            principals,
            cancel,
        )
        .await;
        progress.tick(&ent.display_name);
    }
}
