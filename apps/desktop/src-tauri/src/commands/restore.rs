//! Disaster-recovery restore — replays a [`TenantBackup`] into the **current**
//! tenant (which, in a real DR, is a *different* tenant than the one backed up).
//!
//! This slice restores **app registrations**. It runs in passes so inter-app
//! dependencies resolve (see `docs/architecture/backup-and-restore.md`):
//!
//! 1. **Create shells** — create every app (+ paired SP) and build the
//!    `source_app_id → new_app_id` remap. Reuses `create_application_core`.
//! 2. **Wire references** — declared permissions (remapped), identifier URIs
//!    (`api://{old}` → `api://{new}`), Expose-an-API scopes + pre-authorized
//!    apps, authentication/redirect URIs, federated credentials (verbatim),
//!    owners (remapped by UPN / display name), and bulk-regenerate secrets.
//! 3. **Re-consent** — re-grant admin consent for apps that had it, *after* all
//!    apps are wired so a custom resource's SP + scopes already exist.
//!
//! Secret/cert values can't be restored: secrets are regenerated (the show-once
//! values land in the [`RestoreReport`] for redistribution); certificates are
//! reported as needing manual re-upload from the operator's own PKI.
//!
//! Long-running, so it polls the dedicated `AppState.dr_cancel` flag and emits
//! `restore-progress`. A cancel stops creating *new* apps but still finishes
//! wiring the ones already created (never leaves bare shells), and reports it.

use std::collections::HashMap;

use tauri::{AppHandle, Emitter, State};

use azapptoolkit_core::models::{PreAuthorizedApplication, RequiredResourceAccess};
use azapptoolkit_graph::client::{
    ApiApplicationPatch, AppPatch, ApplicationAuthenticationPatch, ApplicationExposeApiPatch,
    ApplicationPublicClientPatch, ApplicationSpaPatch, ApplicationWebPatch,
    FederatedCredentialRequest, ImplicitGrantSettingsPatch,
};
use azapptoolkit_graph::GraphClient;

use crate::commands::applications::{create_application_core, invalidate_app_lists};
use crate::commands::managed_identity::grant_managed_identity_roles_core;
use crate::commands::permissions::grant_admin_consent_core;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::backup::{
    AppRegistrationBackup, CloudMismatch, EnterpriseAppBackup, ManagedIdentityBackup, ManualItem,
    PrincipalRef, RegeneratedSecret, RestoreFailure, RestorePlan, RestoreReport, RestoredApp,
    RestoredEnterpriseApp, RestoredManagedIdentity, TenantBackup,
};
use crate::dto::bulk::BulkProgress;
use crate::dto::UiError;
use crate::state::AppState;

/// Lifetime for regenerated secrets — matches the app-creation default (180d).
/// The original expiry can't be honored (it may be in the past), so a fresh
/// standard window is minted and surfaced in the report.
const REGEN_SECRET_DAYS: u32 = 180;

/// Dry-run analysis of restoring `backup` into the current tenant — counts and
/// warnings only, no writes. The frontend shows this before the operator
/// confirms the (irreversible) restore.
#[tauri::command]
pub async fn plan_restore(
    state: State<'_, AppState>,
    tenant_id: String,
    backup: TenantBackup,
) -> Result<RestorePlan, UiError> {
    let dest_cloud = state.auth.cloud().as_str();
    let cloud_mismatch = (backup.cloud != dest_cloud).then(|| CloudMismatch {
        backup_cloud: backup.cloud.clone(),
        destination_cloud: dest_cloud.to_string(),
    });
    let sum = |f: fn(&AppRegistrationBackup) -> usize| -> usize {
        backup.app_registrations.iter().map(f).sum()
    };
    Ok(RestorePlan {
        cloud_mismatch,
        tenant_changed: backup.source_tenant_id != tenant_id,
        source_tenant_id: backup.source_tenant_id.clone(),
        destination_tenant_id: tenant_id,
        app_registrations_to_create: backup.app_registrations.len(),
        secrets_to_regenerate: sum(|a| a.secrets.len()),
        certificates_needing_manual_upload: sum(|a| a.certificates.len()),
        federated_credentials_to_restore: sum(|a| a.federated_credentials.len()),
        owners_to_remap: sum(|a| a.owners.len()),
    })
}

/// Replays the backup's app registrations into the current tenant. See the
/// module docs for the pass structure. Busts the destination list caches on a
/// run that created anything.
#[tauri::command]
pub async fn restore_tenant(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    backup: TenantBackup,
) -> Result<RestoreReport, UiError> {
    state.dr_cancel.reset();

    // A cross-cloud restore is never valid: endpoints and well-known appIds
    // differ, so the remapped permissions would point at the wrong resources.
    let dest_cloud = state.auth.cloud().as_str();
    if backup.cloud != dest_cloud {
        return Err(UiError::validation(
            "cloud_mismatch",
            format!(
                "backup is from cloud '{}', but this build targets '{}'",
                backup.cloud, dest_cloud
            ),
        ));
    }

    let client = state.graph_for(&tenant_id);
    let total = backup.app_registrations.len();
    emit(&app_handle, 0, total, None);

    let mut report = RestoreReport::default();
    // source_app_id → new app id, for remapping cross-app references.
    let mut app_id_remap: HashMap<String, String> = HashMap::new();
    // The apps we actually created, paired with their backup + new ids, so
    // passes 2–3 finish wiring exactly those (even after a cancel).
    let mut created: Vec<CreatedApp> = Vec::new();

    // ---- Pass 1: create shells ----
    let mut done = 0;
    for app in &backup.app_registrations {
        if state.dr_cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        let input = CreateApplicationInput {
            display_name: app.display_name.clone(),
            sign_in_audience: app.sign_in_audience.clone(),
            description: app.description.clone(),
            create_service_principal: app.has_service_principal,
            initial_owner_ids: Vec::new(),
            initial_secret_display_name: None,
            initial_secret_lifetime_days: None,
        };
        match create_application_core(&client, input).await {
            Ok(res) => {
                app_id_remap.insert(app.source_app_id.clone(), res.application.app_id.clone());
                created.push(CreatedApp {
                    backup: app.clone(),
                    new_object_id: res.application.id,
                    new_app_id: res.application.app_id,
                });
            }
            Err(e) => report.failures.push(RestoreFailure {
                display_name: app.display_name.clone(),
                source_app_id: app.source_app_id.clone(),
                message: e.message,
            }),
        }
        done += 1;
        emit(&app_handle, done, total, Some(app.display_name.clone()));
    }

    // ---- Pass 2: wire references + regenerate secrets (per created app) ----
    for c in &created {
        report
            .apps
            .push(wire_application(&client, c, &app_id_remap).await);
    }

    // ---- Pass 3: re-consent (after all apps wired, so resources exist) ----
    for (idx, c) in created.iter().enumerate() {
        if !c.backup.admin_consent_granted {
            continue;
        }
        match grant_admin_consent_core(&client, &c.new_object_id).await {
            Ok(grant) => {
                report.apps[idx].consent_granted = true;
                for f in grant.failures {
                    report.apps[idx]
                        .warnings
                        .push(format!("consent: {} ({})", f.message, f.resource_app_id));
                }
            }
            Err(e) => report.apps[idx]
                .warnings
                .push(format!("admin consent failed: {}", e.message)),
        }
    }

    // ---- Pass 5: enterprise applications ----
    // Re-apply access (assignments + group memberships + settings) for SPs that
    // were recreated by the app-reg restore above. Foreign/gallery apps — and
    // paired apps that weren't restored — become runbook entries.
    for ent in &backup.enterprise_apps {
        restore_enterprise_app(&client, ent, &app_id_remap, &mut report).await;
    }

    // ---- Pass 6: managed identities ----
    // MIs are Azure resources — they can't be created here. Re-bind Graph
    // app-roles to any MI already recreated (matched by name); Azure RBAC and
    // not-yet-recreated MIs become runbook entries.
    if !backup.managed_identities.is_empty() {
        restore_managed_identities(&client, &backup.managed_identities, &mut report).await;
    }

    // Anything created means the destination's lists/details/audit are stale.
    // Only on the success path (we're returning Ok).
    if !created.is_empty() {
        invalidate_app_lists(&state.cache, &tenant_id);
    }
    emit(&app_handle, total, total, None);
    Ok(report)
}

/// Writes the restore report to a JSON file via the OS save dialog. **The
/// report contains the regenerated client-secret values** (show-once) — it is a
/// secret-bearing artifact; the UI warns the operator to store it securely,
/// redistribute the secrets, then delete it. Returns the path, or `None` if
/// cancelled. JSON only.
#[tauri::command]
pub async fn save_restore_report_to_file(
    app_handle: AppHandle,
    report: RestoreReport,
    format: String,
) -> Result<Option<String>, UiError> {
    if format != "json" {
        return Err(UiError::validation(
            "unsupported_format",
            "restore report is JSON only",
        ));
    }
    super::audit::save_export_via_dialog(
        &app_handle,
        "restore-report",
        "json",
        String::new, // unreachable: format validated to "json" above
        || serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string()),
    )
    .await
}

// Cancellation shares `cancel_dr` (and `AppState.dr_cancel`) with the backup
// command in `commands::backup`.

// ---------------- internals ----------------

struct CreatedApp {
    backup: AppRegistrationBackup,
    new_object_id: String,
    new_app_id: String,
}

/// Pass-2 work for one created app: declared permissions, identifier URIs +
/// Expose-an-API, authentication, federated credentials, owners, and secret
/// regeneration. Every step is best-effort — a failure becomes a warning and
/// the app keeps its other config (it already exists).
async fn wire_application(
    client: &GraphClient,
    c: &CreatedApp,
    app_id_remap: &HashMap<String, String>,
) -> RestoredApp {
    let app = &c.backup;
    let mut out = RestoredApp {
        display_name: app.display_name.clone(),
        source_app_id: app.source_app_id.clone(),
        new_app_id: c.new_app_id.clone(),
        new_object_id: c.new_object_id.clone(),
        ..Default::default()
    };

    // Declared API permissions (full-replace), with custom resource appIds
    // remapped to their new ids (first-party appIds survive verbatim).
    let rra = remap_required_resource_access(&app.required_resource_access, app_id_remap);
    if !rra.is_empty() {
        let patch = AppPatch {
            required_resource_access: Some(rra),
            ..Default::default()
        };
        if let Err(e) = client.update_application(&c.new_object_id, &patch).await {
            out.warnings.push(format!("permissions: {e}"));
        }
    }

    // Identifier URIs + Expose-an-API (scope ids preserved so consumers' grants
    // still resolve; `api://{old}` rewritten to the new appId).
    let identifier_uris =
        rewrite_identifier_uris(&app.identifier_uris, &app.source_app_id, &c.new_app_id);
    let pre_auth = remap_pre_authorized(&app.pre_authorized_applications, app_id_remap);
    if !identifier_uris.is_empty() || !app.api_scopes.is_empty() || !pre_auth.is_empty() {
        let patch = ApplicationExposeApiPatch {
            identifier_uris: (!identifier_uris.is_empty()).then_some(identifier_uris),
            api: Some(ApiApplicationPatch {
                oauth2_permission_scopes: (!app.api_scopes.is_empty())
                    .then(|| app.api_scopes.clone()),
                pre_authorized_applications: (!pre_auth.is_empty()).then_some(pre_auth),
            }),
        };
        if let Err(e) = client
            .patch_application_expose_api(&c.new_object_id, &patch)
            .await
        {
            out.warnings
                .push(format!("identifier URIs / Expose-an-API: {e}"));
        }
    }

    // Authentication (redirect URIs + implicit-grant flags + public-client).
    let has_auth = !app.web_redirect_uris.is_empty()
        || !app.spa_redirect_uris.is_empty()
        || !app.public_client_redirect_uris.is_empty()
        || app.logout_url.is_some()
        || app.enable_access_token_issuance
        || app.enable_id_token_issuance
        || app.is_fallback_public_client;
    if has_auth {
        let patch = ApplicationAuthenticationPatch {
            web: Some(ApplicationWebPatch {
                redirect_uris: Some(app.web_redirect_uris.clone()),
                logout_url: Some(app.logout_url.clone().unwrap_or_default()),
                implicit_grant_settings: Some(ImplicitGrantSettingsPatch {
                    enable_access_token_issuance: Some(app.enable_access_token_issuance),
                    enable_id_token_issuance: Some(app.enable_id_token_issuance),
                }),
            }),
            spa: Some(ApplicationSpaPatch {
                redirect_uris: Some(app.spa_redirect_uris.clone()),
            }),
            public_client: Some(ApplicationPublicClientPatch {
                redirect_uris: Some(app.public_client_redirect_uris.clone()),
            }),
            is_fallback_public_client: Some(app.is_fallback_public_client),
        };
        if let Err(e) = client.patch_application_web(&c.new_object_id, &patch).await {
            out.warnings.push(format!("authentication: {e}"));
        }
    }

    // Federated identity credentials — restored verbatim (no secret material).
    for fic in &app.federated_credentials {
        let audiences = if fic.audiences.is_empty() {
            vec!["api://AzureADTokenExchange".to_string()]
        } else {
            fic.audiences.clone()
        };
        let body = FederatedCredentialRequest {
            name: fic.name.clone(),
            issuer: fic.issuer.clone(),
            subject: fic.subject.clone(),
            audiences,
            description: fic.description.clone(),
        };
        if let Err(e) = client
            .add_federated_credential(&c.new_object_id, &body)
            .await
        {
            out.warnings
                .push(format!("federated credential '{}': {e}", fic.name));
        }
    }

    // Owners — remap each principal by UPN / display name in the destination.
    for owner in &app.owners {
        match resolve_principal(client, owner).await {
            Some(new_id) => {
                if let Err(e) = client.add_owner(&c.new_object_id, &new_id).await {
                    out.warnings.push(format!("owner: {e}"));
                }
            }
            None => out.unresolved_owners.push(owner_label(owner)),
        }
    }

    // Secrets — values are unrecoverable, so mint fresh ones (show-once).
    for meta in &app.secrets {
        let name = meta
            .display_name
            .clone()
            .unwrap_or_else(|| "restored".into());
        let lifetime = std::time::Duration::from_secs(REGEN_SECRET_DAYS as u64 * 86_400);
        match client.add_password(&c.new_object_id, &name, lifetime).await {
            Ok(cred) => out.regenerated_secrets.push(RegeneratedSecret {
                display_name: name,
                key_id: cred.key_id,
                secret_value: cred.secret_text.unwrap_or_default(),
                expires: cred.end_date_time,
            }),
            Err(e) => out.warnings.push(format!("secret '{name}': {e}")),
        }
    }

    // Certificates can't be restored (private key never left the source);
    // surface them for manual re-upload from the operator's PKI.
    out.certificates_needing_manual_upload = app
        .certificates
        .iter()
        .map(|c| c.display_name.clone().unwrap_or_else(|| "(unnamed)".into()))
        .collect();

    out
}

/// Default-access app role (the all-zero GUID) — present on every SP, so an
/// assignment to it never needs role remapping.
const DEFAULT_ACCESS_ROLE: &str = "00000000-0000-0000-0000-000000000000";

/// Pass-5 work for one enterprise app. If its service principal was recreated by
/// the app-reg restore, re-applies settings + role assignments + group
/// memberships; otherwise records a runbook entry (foreign/gallery apps and
/// paired apps that weren't restored can't be replayed automatically).
async fn restore_enterprise_app(
    client: &GraphClient,
    ent: &EnterpriseAppBackup,
    app_id_remap: &HashMap<String, String>,
    report: &mut RestoreReport,
) {
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
        _ => {
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: "Service principal was not created (the app had none in the backup)."
                    .into(),
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
    if !ent.tags.is_empty() {
        if let Err(e) = client.set_service_principal_tags(&sp.id, &ent.tags).await {
            out.warnings.push(format!("tags: {e}"));
        }
    }
    if let Some(required) = ent.app_role_assignment_required {
        let body = serde_json::json!({ "appRoleAssignmentRequired": required });
        if let Err(e) = client.patch_service_principal(&sp.id, &body).await {
            out.warnings.push(format!("assignment-required: {e}"));
        }
    }

    // App-role assignments — principal remapped by name, role by value.
    for assignee in &ent.app_role_assignees {
        let Some(principal_id) = resolve_principal(client, &assignee.principal).await else {
            out.unresolved_principals
                .push(owner_label(&assignee.principal));
            continue;
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
            Err(e) => out.warnings.push(format!("assignment: {e}")),
        }
    }

    // Group memberships — resolve each group by display name.
    for group in &ent.group_memberships {
        match resolve_principal(client, group).await {
            Some(group_id) => match client.add_group_member(&group_id, &sp.id).await {
                Ok(()) => out.group_memberships_applied += 1,
                Err(e) => out.warnings.push(format!("group membership: {e}")),
            },
            None => out.unresolved_principals.push(owner_label(group)),
        }
    }

    report.enterprise_apps.push(out);
}

/// Pass-6 work: re-bind managed-identity permissions. MIs can't be created via
/// Graph (they're Azure resources), so this matches each backed-up MI to one
/// **already recreated** in the destination (by display name) and re-binds its
/// held Graph app-roles to the new principal. Azure RBAC re-creation, and MIs
/// not yet recreated, are emitted as runbook items (source RBAC scopes don't
/// exist in the destination, so they can't be replayed automatically).
async fn restore_managed_identities(
    client: &GraphClient,
    mis: &[ManagedIdentityBackup],
    report: &mut RestoreReport,
) {
    let dest = client.list_managed_identities().await.unwrap_or_default();
    let by_name: HashMap<String, String> = dest
        .into_iter()
        .map(|sp| (sp.display_name.to_ascii_lowercase(), sp.id))
        .collect();

    for mi in mis {
        let Some(principal_id) = by_name.get(&mi.display_name.to_ascii_lowercase()).cloned() else {
            let arm = mi
                .arm_resource_id
                .as_deref()
                .map(|a| format!(" — {a}"))
                .unwrap_or_default();
            report.manual_items.push(ManualItem {
                display_name: mi.display_name.clone(),
                reason: format!(
                    "Managed identity ({}{}) not found in the destination. Recreate it via your \
                     infrastructure-as-code, then re-run the restore to re-bind its Graph \
                     app-roles.",
                    mi.subtype, arm
                ),
            });
            continue;
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
        for r in &mi.held_app_roles {
            match r.app_role_value.as_deref() {
                Some(v) if !v.is_empty() && !r.resource_app_id.is_empty() => {
                    by_resource
                        .entry(r.resource_app_id.clone())
                        .or_default()
                        .push(v.to_string());
                }
                _ => out.warnings.push(
                    "a held app-role couldn't be re-bound (resource or value unresolved)".into(),
                ),
            }
        }
        for (resource_app_id, roles) in by_resource {
            match grant_managed_identity_roles_core(client, &principal_id, &resource_app_id, &roles)
                .await
            {
                Ok((granted, _skipped, failures)) => {
                    out.app_roles_rebound += granted.len();
                    out.warnings.extend(failures);
                }
                Err(e) => out
                    .warnings
                    .push(format!("re-bind on {resource_app_id}: {}", e.message)),
            }
        }

        // Azure RBAC always needs manual re-creation — source scopes are
        // subscription/resource-specific and don't exist in the destination.
        report.manual_items.push(ManualItem {
            display_name: mi.display_name.clone(),
            reason:
                "Re-create this managed identity's Azure RBAC role assignments manually at the \
                     destination's equivalent scopes (source scopes don't transfer)."
                    .into(),
        });

        report.managed_identities.push(out);
    }
}

/// Maps a backed-up assignee's role to a role id on the restored SP: the
/// default-access role passes through (always present); a custom role is matched
/// by its `value` against the new SP's `appRoles`. Custom role *definitions*
/// aren't restored, so an unmatched custom role yields `None` (reported, not
/// assigned).
fn map_assignee_role_id(
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

/// Remaps an app's declared permissions: a `resource_app_id` that names another
/// app in this backup is rewritten to that app's new appId; first-party (and
/// any pre-existing external) resource appIds are left untouched. Permission
/// (role/scope) ids are preserved — first-party ids are stable, and a custom
/// resource's exposed-scope ids are re-applied verbatim by its own restore.
fn remap_required_resource_access(
    rra: &[RequiredResourceAccess],
    app_id_remap: &HashMap<String, String>,
) -> Vec<RequiredResourceAccess> {
    rra.iter()
        .map(|r| RequiredResourceAccess {
            resource_app_id: app_id_remap
                .get(&r.resource_app_id)
                .cloned()
                .unwrap_or_else(|| r.resource_app_id.clone()),
            resource_access: r.resource_access.clone(),
        })
        .collect()
}

/// Rewrites the `api://{source_app_id}` identifier URI to the new appId. Other
/// URIs (custom domains, other forms) are passed through unchanged.
fn rewrite_identifier_uris(uris: &[String], source_app_id: &str, new_app_id: &str) -> Vec<String> {
    let old = format!("api://{source_app_id}");
    let new = format!("api://{new_app_id}");
    uris.iter()
        .map(|u| if u == &old { new.clone() } else { u.clone() })
        .collect()
}

/// Remaps pre-authorized client appIds against the backup; a client app that
/// isn't in the backup is left as-is (it may pre-exist in the destination).
fn remap_pre_authorized(
    pre_auth: &[PreAuthorizedApplication],
    app_id_remap: &HashMap<String, String>,
) -> Vec<PreAuthorizedApplication> {
    pre_auth
        .iter()
        .map(|p| PreAuthorizedApplication {
            app_id: app_id_remap
                .get(&p.app_id)
                .cloned()
                .unwrap_or_else(|| p.app_id.clone()),
            delegated_permission_ids: p.delegated_permission_ids.clone(),
        })
        .collect()
}

/// Resolves a backed-up principal to its object id in the destination tenant by
/// UPN (users) or display name (groups), returning `None` when no exact match
/// exists yet. Best-effort: a lookup error resolves to `None` (the owner is then
/// reported as unresolved rather than failing the whole restore).
async fn resolve_principal(client: &GraphClient, principal: &PrincipalRef) -> Option<String> {
    if let Some(upn) = principal
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        if let Ok(hits) = client.search_users(upn).await {
            return hits.into_iter().find_map(|u| {
                let matches = u
                    .user_principal_name
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(upn));
                matches.then_some(u.id)
            });
        }
        return None;
    }
    if let Some(name) = principal.display_name.as_deref().filter(|s| !s.is_empty()) {
        if let Ok(hits) = client.search_groups(name).await {
            if let Some(id) = hits.into_iter().find_map(|g| {
                let matches = g.display_name.as_deref().is_some_and(|v| v == name);
                matches.then_some(g.id)
            }) {
                return Some(id);
            }
        }
        if let Ok(hits) = client.search_users(name).await {
            return hits.into_iter().find_map(|u| {
                let matches = u.display_name.as_deref().is_some_and(|v| v == name);
                matches.then_some(u.id)
            });
        }
    }
    None
}

fn owner_label(p: &PrincipalRef) -> String {
    p.user_principal_name
        .clone()
        .or_else(|| p.display_name.clone())
        .unwrap_or_else(|| p.source_id.clone())
}

fn emit(app_handle: &AppHandle, done: usize, total: usize, current_app: Option<String>) {
    let progress = BulkProgress {
        done,
        total,
        current_app,
        cancelled: false,
    };
    if let Err(err) = app_handle.emit("restore-progress", progress) {
        tracing::warn!(?err, "failed to emit restore-progress event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::ResourceAccess;

    fn remap() -> HashMap<String, String> {
        // Only the custom app is in the backup; Graph's appId is not.
        HashMap::from([("custom-src-app".to_string(), "custom-new-app".to_string())])
    }

    #[test]
    fn first_party_resource_survives_custom_is_remapped() {
        let graph = "00000003-0000-0000-c000-000000000000";
        let rra = vec![
            RequiredResourceAccess {
                resource_app_id: graph.to_string(),
                resource_access: vec![ResourceAccess {
                    id: "role-1".into(),
                    r#type: "Role".into(),
                }],
            },
            RequiredResourceAccess {
                resource_app_id: "custom-src-app".into(),
                resource_access: vec![ResourceAccess {
                    id: "scope-1".into(),
                    r#type: "Scope".into(),
                }],
            },
        ];
        let out = remap_required_resource_access(&rra, &remap());
        // First-party Graph appId untouched; its permission id preserved.
        assert_eq!(out[0].resource_app_id, graph);
        assert_eq!(out[0].resource_access[0].id, "role-1");
        // Custom resource appId remapped; scope id preserved (re-applied by the
        // custom app's own restore).
        assert_eq!(out[1].resource_app_id, "custom-new-app");
        assert_eq!(out[1].resource_access[0].id, "scope-1");
    }

    #[test]
    fn identifier_uri_appid_form_is_rewritten_others_passthrough() {
        let uris = vec![
            "api://src-app".to_string(),
            "https://contoso.com/app".to_string(),
        ];
        let out = rewrite_identifier_uris(&uris, "src-app", "new-app");
        assert_eq!(out[0], "api://new-app");
        assert_eq!(out[1], "https://contoso.com/app");
    }

    #[test]
    fn pre_authorized_client_appid_remapped_when_in_backup() {
        let pre = vec![
            PreAuthorizedApplication {
                app_id: "custom-src-app".into(),
                delegated_permission_ids: vec!["p1".into()],
            },
            PreAuthorizedApplication {
                app_id: "external-app".into(),
                delegated_permission_ids: vec!["p2".into()],
            },
        ];
        let out = remap_pre_authorized(&pre, &remap());
        assert_eq!(out[0].app_id, "custom-new-app");
        assert_eq!(out[0].delegated_permission_ids, vec!["p1".to_string()]);
        // Not in the backup → left as-is (may pre-exist in the destination).
        assert_eq!(out[1].app_id, "external-app");
    }

    #[test]
    fn assignee_role_maps_default_passthrough_value_match_or_none() {
        use crate::dto::backup::{AppRoleAssigneeRef, PrincipalRef};
        use azapptoolkit_core::models::AppRole;

        let roles = vec![AppRole {
            id: "new-role-id".into(),
            value: "Writer".into(),
            ..Default::default()
        }];

        // Default-access role passes through unchanged (always present).
        let default = AppRoleAssigneeRef {
            principal: PrincipalRef::default(),
            app_role_id: DEFAULT_ACCESS_ROLE.into(),
            app_role_value: None,
        };
        assert_eq!(
            map_assignee_role_id(&default, &roles).as_deref(),
            Some(DEFAULT_ACCESS_ROLE)
        );

        // Custom role matched by value → the new SP's role id.
        let writer = AppRoleAssigneeRef {
            principal: PrincipalRef::default(),
            app_role_id: "old-role-id".into(),
            app_role_value: Some("Writer".into()),
        };
        assert_eq!(
            map_assignee_role_id(&writer, &roles).as_deref(),
            Some("new-role-id")
        );

        // Custom role whose value isn't on the restored app → unmapped.
        let admin = AppRoleAssigneeRef {
            principal: PrincipalRef::default(),
            app_role_id: "old-admin-id".into(),
            app_role_value: Some("Admin".into()),
        };
        assert_eq!(map_assignee_role_id(&admin, &roles), None);
    }

    #[test]
    fn owner_label_prefers_upn_then_name_then_id() {
        let by_upn = PrincipalRef {
            source_id: "id".into(),
            user_principal_name: Some("a@b.com".into()),
            display_name: Some("Alice".into()),
            ..Default::default()
        };
        assert_eq!(owner_label(&by_upn), "a@b.com");
        let by_name = PrincipalRef {
            source_id: "id".into(),
            display_name: Some("Group X".into()),
            ..Default::default()
        };
        assert_eq!(owner_label(&by_name), "Group X");
    }
}
