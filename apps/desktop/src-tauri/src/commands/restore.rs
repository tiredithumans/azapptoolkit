//! Disaster-recovery restore — replays a [`TenantBackup`] into the **current**
//! tenant (which, in a real DR, is a *different* tenant than the one backed up).
//!
//! It restores app registrations, enterprise applications and managed-identity
//! permissions in five passes, so inter-app dependencies resolve (see
//! `docs/architecture/backup-and-restore.md`):
//!
//! 1. **Create shells** — create every app (+ paired SP) and build the
//!    `source_app_id → new_app_id` remap, or adopt the app an earlier run of
//!    this restore already created (see below). Reuses
//!    `create_application_core_tagged`.
//! 2. **Wire references** — declared permissions (remapped), identifier URIs
//!    (`api://{old}` → `api://{new}`), Expose-an-API scopes + pre-authorized
//!    apps, authentication/redirect URIs, federated credentials (validated +
//!    reported), owners (remapped by UPN / display name), and bulk-regenerate
//!    secrets.
//! 3. **Re-consent** — re-grant admin consent for apps that had it, *after* all
//!    apps are wired so a custom resource's SP + scopes already exist.
//! 4. **Enterprise applications** — re-apply settings, app-role assignments and
//!    group memberships to the SPs recreated in pass 1.
//! 5. **Managed identities** — re-bind Graph app-roles to MIs already recreated
//!    in the destination; everything else becomes a runbook item.
//!
//! **Re-running is safe for the apps a run created.** Every app is created with
//! the tag `azapptoolkit:restoredFrom:<source appId>` in its create POST, so a
//! re-run finds it and finishes wiring it rather than creating it twice. The tag
//! and the display name are both writable by anyone who may register apps, so a
//! hit is adopted only once it is also provably this restore's: created after
//! the backup, and owned by nobody but the operator and the manifest's owners.
//! Anything else — an ambiguous or unprovable match, or a read that failed — is
//! a runbook item and never a blind create.
//!
//! Secret/cert values can't be restored: secrets are regenerated (the show-once
//! values land in the [`RestoreReport`] for redistribution) — except those that
//! had already expired when the backup was taken; certificates are reported as
//! needing manual re-upload from the operator's own PKI.
//!
//! Long-running, so it polls its own `AppState.restore_cancel` token (stopped
//! only by `cancel_restore`, never by a backup's Cancel) and emits
//! `restore-progress`. A cancel stops at the next item in whichever pass is
//! running, and the report flags the run cancelled (partial); a re-run adopts
//! the already-created, tagged apps and finishes wiring them.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use tauri::{AppHandle, State};

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_core::federation::validate_federated_credential;
use azapptoolkit_core::models::{Application, DirectoryObject};
use azapptoolkit_core::redirect::validate_redirect_uri;
use azapptoolkit_core::restore_plan::{
    remap_pre_authorized, remap_required_resource_access, rewrite_identifier_uris,
};
use azapptoolkit_graph::GraphClient;
use azapptoolkit_graph::client::{
    ApiApplicationPatch, AppPatch, ApplicationAuthenticationPatch, ApplicationExposeApiPatch,
    ApplicationPublicClientPatch, ApplicationSpaPatch, ApplicationWebPatch,
    FederatedCredentialRequest, ImplicitGrantSettingsPatch,
};

use crate::commands::applications::{create_application_core_tagged, invalidate_app_lists};
use crate::commands::dispatch::SessionDead;
use crate::commands::managed_identity::{grant_managed_identity_roles_core, mi_subtype_label};
use crate::commands::permissions::grant_admin_consent_core;
use crate::commands::progress::{ProgressSink, emit_progress};
use crate::dto::UiError;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::backup::{
    AppRegistrationBackup, BACKUP_SCHEMA_VERSION, CloudMismatch, CredentialMeta,
    EnterpriseAppBackup, ManagedIdentityBackup, ManualItem, PrincipalRef, RegeneratedSecret,
    RestoreFailure, RestorePlan, RestoreReport, RestoredApp, RestoredEnterpriseApp,
    RestoredManagedIdentity, TenantBackup,
};
use crate::dto::bulk::BulkProgress;
use crate::state::AppState;

/// Keeps only the redirect URIs that pass `core::redirect`, recording each
/// rejection in the restore report.
///
/// Per-URI rather than all-or-nothing on the list: a manifest with one bad
/// reply URL among four good ones should restore the four, and the operator
/// needs to know precisely which one was dropped. Mirrors the
/// federated-credential loop's "was NOT restored — {reason}" phrasing so the
/// report reads consistently.
fn checked_uris(uris: &[String], label: &str, warnings: &mut Vec<String>) -> Vec<String> {
    uris.iter()
        .filter(|u| match validate_redirect_uri(u) {
            Ok(()) => true,
            Err(reason) => {
                warnings.push(format!("{label}: '{u}' was NOT restored — {reason}"));
                false
            }
        })
        .cloned()
        .collect()
}

/// Lifetime for regenerated secrets — matches the app-creation default (180d).
///
/// The original expiry can't be honoured (the value is new, and the old end
/// date may already have passed), so a fresh standard window is minted and
/// surfaced in the report — but only for secrets that were still valid when the
/// backup was taken ([`expired_at_backup`]). A secret already expired then
/// cannot have been in use, and re-issuing it would only widen the restored
/// app's live credential surface.
const REGEN_SECRET_DAYS: u32 = 180;

/// Whether a backed-up secret had already expired when the backup was taken.
///
/// The cutoff is the backup's own timestamp, never "now": a secret that was
/// live at backup time and expired during the outage is exactly the one a
/// recovering client still holds, so it is re-issued. No end date = not expired.
fn expired_at_backup(meta: &CredentialMeta, taken_at: DateTime<Utc>) -> bool {
    meta.end_date_time.is_some_and(|end| end < taken_at)
}

/// Prefix of the tag every app created by a restore carries; the suffix is the
/// app's **source** appId, the one key that survives the tenant move.
const RESTORE_MARKER_PREFIX: &str = "azapptoolkit:restoredFrom:";

/// The restore tag for the app backed up as `source_app_id`.
fn restore_marker(source_app_id: &str) -> String {
    format!("{RESTORE_MARKER_PREFIX}{source_app_id}")
}

/// What Pass 1 does with one manifest app, given the destination apps that
/// already carry its restore tag.
#[derive(Debug, PartialEq)]
enum Adoption {
    /// Nothing carries the tag — create it.
    Create,
    /// An earlier run created it — finish wiring that one instead.
    Adopt {
        object_id: String,
        app_id: String,
        /// Display names of the secrets it already holds, so Pass 2 does not
        /// issue them a second time.
        live_secret_names: Vec<String>,
    },
    /// Something carries the tag but cannot safely be taken for this app;
    /// the reason becomes a runbook item and nothing is created.
    Refuse(String),
}

/// Pure Pass-1 decision on the tag lookup. Adoption needs the tag, the exact
/// display name **and** a creation time after the backup was taken: the tag
/// alone could be on an app someone has since repurposed, the name alone proves
/// nothing, and an app older than the backup cannot be one a restore of it
/// created. Anything else fails closed — never a second copy. An `Adopt` here is
/// still provisional: [`decide_adoption`] checks the hit's owners before Pass 1
/// takes it.
fn adoption_for(
    app: &AppRegistrationBackup,
    hits: &[Application],
    taken_at: DateTime<Utc>,
) -> Adoption {
    match hits {
        [] => Adoption::Create,
        [hit] if hit.display_name != app.display_name => Adoption::Refuse(format!(
            "An app carrying the restore tag for source appId {} already exists as '{}' \
             (appId {}), so this app was not created again. Reconcile it manually: rename it \
             back to '{}' and run the restore again to finish it, or delete it to have the \
             restore recreate it.",
            app.source_app_id, hit.display_name, hit.app_id, app.display_name
        )),
        [hit] if !hit.created_date_time.is_some_and(|t| t >= taken_at) => {
            let created = hit.created_date_time.map_or_else(
                || "an unknown time".to_string(),
                |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
            );
            Adoption::Refuse(format!(
                "An app carrying the restore tag for source appId {} already exists as '{}' \
                 (appId {}), but it was created at {created}, not after this backup was taken \
                 ({}), so no restore of this backup can have created it. It was not adopted \
                 (that would give it this app's permissions and admin consent) and not created \
                 again. Find out who created it; delete it to have the restore recreate the app.",
                app.source_app_id,
                hit.display_name,
                hit.app_id,
                taken_at.format("%Y-%m-%d %H:%M UTC")
            ))
        }
        [hit] => Adoption::Adopt {
            object_id: hit.id.clone(),
            app_id: hit.app_id.clone(),
            live_secret_names: hit
                .password_credentials
                .iter()
                .filter_map(|p| p.display_name.clone())
                .collect(),
        },
        many => Adoption::Refuse(format!(
            "{} apps carry the restore tag for source appId {} ({}), so none was created again. \
             Delete the duplicates, then run the restore again.",
            many.len(),
            app.source_app_id,
            many.iter()
                .map(|h| h.app_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The owners of an adoption candidate that neither the operator nor the
/// manifest accounts for, labelled for the runbook item (UPN, else display
/// name, else object id). `allowed` holds destination object ids.
fn unexpected_owners(owners: &[DirectoryObject], allowed: &HashSet<String>) -> Vec<String> {
    owners
        .iter()
        .filter(|o| !allowed.contains(&o.id))
        .map(|o| {
            o.user_principal_name
                .clone()
                .or_else(|| o.display_name.clone())
                .unwrap_or_else(|| o.id.clone())
        })
        .collect()
}

/// The whole Pass-1 decision for one manifest app: tag lookup, [`adoption_for`],
/// then the owner check that makes an adoption provable.
///
/// The tag and the display name are both writable by anyone allowed to register
/// apps, and source appIds are not secret — so a pre-seeded app with the right
/// tag and name would otherwise be adopted and then handed the manifest's
/// permissions, fresh secrets and tenant-wide admin consent while keeping its
/// planter as an owner. An app this restore created has no owners but the
/// operator (`operator_oid`, the signed-in account in the destination) and the
/// manifest's own owners (resolved through the run's `principals` memo, which
/// Pass 2 then reuses), so any other owner is refused by name. Every read that
/// fails refuses too: neither adopting nor creating blind is safe.
async fn decide_adoption(
    client: &GraphClient,
    app: &AppRegistrationBackup,
    taken_at: DateTime<Utc>,
    operator_oid: Option<&str>,
    principals: &mut HashMap<String, Option<String>>,
    session: &SessionDead,
) -> Adoption {
    // Looked up by the restore tag, the only key that survives the tenant move
    // — the appId changes, and `api://{new}` is not in the manifest.
    let hits = match client
        .find_applications_by_tag(&restore_marker(&app.source_app_id))
        .await
    {
        Ok(hits) => hits,
        Err(e) => {
            session.note_code(e.ui_code());
            return Adoption::Refuse(format!(
                "Couldn't check whether an earlier restore already created this app ({e}); it \
                 was NOT created, to avoid a duplicate. Run the restore again once the read \
                 succeeds."
            ));
        }
    };
    let adoption = adoption_for(app, &hits, taken_at);
    let Adoption::Adopt {
        object_id, app_id, ..
    } = &adoption
    else {
        return adoption;
    };
    let owners = match client.list_owners(object_id).await {
        Ok(owners) => owners,
        Err(e) => {
            session.note_code(e.ui_code());
            return Adoption::Refuse(format!(
                "Couldn't read the owners of '{}' (appId {app_id}), which carries this app's \
                 restore tag ({e}), so it was neither adopted nor created again. Run the restore \
                 again once the read succeeds.",
                app.display_name
            ));
        }
    };
    let mut allowed: HashSet<String> = operator_oid
        .filter(|oid| !oid.is_empty())
        .map(str::to_owned)
        .into_iter()
        .collect();
    // Resolve the manifest's owners only when someone besides the operator owns it.
    if owners.iter().any(|o| !allowed.contains(&o.id)) {
        for owner in &app.owners {
            if let Some(id) = resolve_principal(client, principals, owner).await {
                allowed.insert(id);
            }
        }
    }
    let extra = unexpected_owners(&owners, &allowed);
    if extra.is_empty() {
        return adoption;
    }
    Adoption::Refuse(format!(
        "'{}' (appId {app_id}) carries this app's restore tag, but it has owners this restore \
         did not set: {}. Anyone who can register apps can write that tag and name, so it was \
         not adopted (that would give it this app's permissions and admin consent) and not \
         created again. Find out who created it: if it is legitimate, remove those owners and \
         run the restore again; otherwise delete it to have the restore recreate the app.",
        app.display_name,
        extra.join(", ")
    ))
}

/// Dry-run analysis of restoring `backup` into the current tenant — counts and
/// warnings only, no writes. The frontend shows this before the operator
/// confirms the (irreversible) restore.
#[tauri::command]
pub async fn plan_restore(
    state: State<'_, AppState>,
    tenant_id: String,
    backup: TenantBackup,
) -> Result<RestorePlan, UiError> {
    Ok(build_restore_plan(&backup, tenant_id, state.auth.cloud()))
}

/// Refuses a manifest written by a *newer* build.
///
/// A restore is not a read — it mutates the tenant before anyone can inspect
/// the result — so a manifest carrying fields this build cannot interpret has
/// to be rejected rather than partially applied. `schema_version` exists for
/// exactly this refusal and was never checked.
///
/// Only the future direction is rejected: every field is `serde(default)` and
/// additive, so an older manifest restores correctly, and refusing one would
/// break the DR case the format was versioned to support.
fn check_manifest_schema(schema_version: u32) -> Result<(), UiError> {
    if schema_version > BACKUP_SCHEMA_VERSION {
        return Err(UiError::validation(
            "schema_too_new",
            format!(
                "backup uses manifest schema version {schema_version} but this build understands \
                 up to {BACKUP_SCHEMA_VERSION}. Restoring it could silently skip settings it does \
                 not recognise — update azapptoolkit first."
            ),
        ));
    }
    Ok(())
}

/// Pure dry-run analysis (no I/O): the counts plus the cloud/tenant checks
/// derived from the backup. Split out from [`plan_restore`] so it is unit-testable
/// without an `AppState`. `dest_cloud` is the destination build's cloud.
fn build_restore_plan(
    backup: &TenantBackup,
    tenant_id: String,
    dest_cloud: CloudEnvironment,
) -> RestorePlan {
    let cloud_mismatch = (backup.cloud != dest_cloud).then_some(CloudMismatch {
        backup_cloud: backup.cloud,
        destination_cloud: dest_cloud,
    });
    let sum = |f: fn(&AppRegistrationBackup) -> usize| -> usize {
        backup.app_registrations.iter().map(f).sum()
    };
    let taken_at = backup.created_at;
    let expired_secrets_skipped: usize = backup
        .app_registrations
        .iter()
        .flat_map(|a| &a.secrets)
        .filter(|m| expired_at_backup(m, taken_at))
        .count();
    RestorePlan {
        cloud_mismatch,
        tenant_changed: backup.source_tenant_id != tenant_id,
        source_tenant_id: backup.source_tenant_id.clone(),
        destination_tenant_id: tenant_id,
        app_registrations_to_create: backup.app_registrations.len(),
        secrets_to_regenerate: sum(|a| a.secrets.len()) - expired_secrets_skipped,
        expired_secrets_skipped,
        certificates_needing_manual_upload: sum(|a| a.certificates.len()),
        federated_credentials_to_restore: sum(|a| a.federated_credentials.len()),
        owners_to_remap: sum(|a| a.owners.len()),
    }
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
    check_manifest_schema(backup.schema_version)?;

    // A cross-cloud restore is never valid: endpoints and well-known appIds
    // differ, so the remapped permissions would point at the wrong resources.
    let cloud = state.auth.cloud();
    if backup.cloud != cloud {
        return Err(UiError::validation(
            "cloud_mismatch",
            format!(
                "backup is from cloud '{}', but this build targets '{}'",
                backup.cloud.as_str(),
                cloud.as_str()
            ),
        ));
    }

    let client = state.graph_for(&tenant_id);
    // The signed-in account's object id in the destination: the one owner an
    // app this restore created may have besides the manifest's own.
    let operator_oid = state.auth.tenant_context(&tenant_id).map(|t| t.account_oid);
    let total = backup.app_registrations.len();
    emit(&app_handle, 0, total, None);

    let mut report = RestoreReport::default();
    // source_app_id → new app id, for remapping cross-app references.
    let mut app_id_remap: HashMap<String, String> = HashMap::new();
    // Per-run principal-resolution memo (UPN/group display name → destination
    // object id), shared across passes so a principal reused across owners,
    // assignees, and group memberships is searched once, not per occurrence.
    let mut principals: HashMap<String, Option<String>> = HashMap::new();
    // The apps we actually created, paired with their backup + new ids, so
    // passes 2–3 wire exactly those.
    let mut created: Vec<CreatedApp> = Vec::new();
    // One latch across all five passes: the first re-auth-fatal error stops the
    // rest instead of letting each remaining item fail the same way.
    let session = SessionDead::new();
    // One cancel token for the whole restore, claimed before the first write.
    // Claiming per pass would take a new generation each time and lose a cancel
    // the operator issued during an earlier pass.
    let cancel = state.restore_cancel.claim();

    // ---- Pass 1: create shells ----
    let mut done = 0;
    for app in &backup.app_registrations {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        // A dead session makes every remaining create fail identically, so the
        // loop would otherwise manufacture one indistinguishable failure per
        // remaining app and report them as if the tenant had rejected them.
        if session.is_dead() {
            report.cancelled = true;
            break;
        }
        // Has an earlier run of this restore already created it? Every read
        // failure and every unprovable match is refused into a runbook item:
        // creating blind is how a re-run duplicates apps, and adopting blind
        // would hand someone else's app this one's permissions and consent.
        match decide_adoption(
            &client,
            app,
            backup.created_at,
            operator_oid.as_deref(),
            &mut principals,
            &session,
        )
        .await
        {
            Adoption::Refuse(reason) => {
                report.manual_items.push(ManualItem {
                    display_name: app.display_name.clone(),
                    reason,
                });
                done += 1;
                emit(&app_handle, done, total, Some(app.display_name.clone()));
                continue;
            }
            Adoption::Adopt {
                object_id,
                app_id,
                live_secret_names,
            } => {
                let mut warnings = Vec::new();
                // The earlier run may have died between the app POST and its
                // SP; `ensure_service_principal` is a no-op when it exists.
                if app.has_service_principal
                    && let Err(e) = client.ensure_service_principal(&app_id).await
                {
                    session.note_code(e.ui_code());
                    warnings.push(format!("service principal: {e}"));
                }
                app_id_remap.insert(app.source_app_id.clone(), app_id.clone());
                created.push(CreatedApp {
                    backup: app.clone(),
                    new_object_id: object_id,
                    new_app_id: app_id,
                    adopted: true,
                    live_secret_names,
                    warnings,
                });
                done += 1;
                emit(&app_handle, done, total, Some(app.display_name.clone()));
                continue;
            }
            Adoption::Create => {}
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
        // The tag rides the create POST itself, so no app this restore creates
        // can exist without it — not even one whose SP create then failed.
        let marker = restore_marker(&app.source_app_id);
        match create_application_core_tagged(&client, input, vec![marker]).await {
            // The registration landed even when its SP then failed (the only
            // later step this input runs): record it as created — so it is
            // wired, counted and cache-busted — with the SP failure as a
            // warning, exactly as the adopt branch above does. Recording it as
            // a failure hid an app that exists.
            Ok((res, error)) => {
                let mut warnings = Vec::new();
                if let Some(e) = error {
                    session.note_code(&e.code);
                    warnings.push(format!("service principal: {}", e.message));
                }
                app_id_remap.insert(app.source_app_id.clone(), res.application.app_id.clone());
                created.push(CreatedApp {
                    backup: app.clone(),
                    new_object_id: res.application.id,
                    new_app_id: res.application.app_id,
                    adopted: false,
                    live_secret_names: Vec::new(),
                    warnings,
                });
            }
            Err(e) => {
                session.note_code(&e.code);
                report.failures.push(RestoreFailure {
                    display_name: app.display_name.clone(),
                    source_app_id: app.source_app_id.clone(),
                    message: e.message,
                });
            }
        }
        done += 1;
        emit(&app_handle, done, total, Some(app.display_name.clone()));
    }

    // ---- Pass 2: wire references + regenerate secrets (per created app) ----
    for c in &created {
        // Both stop conditions, in every pass. Passes 2-5 once checked only
        // `is_dead()`, so Cancel stopped mattering the moment Pass 1 finished:
        // the operator pressed it and watched the restore keep wiring, granting
        // consent and re-binding roles for every remaining app.
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        let (restored, trusts) = wire_application(
            &client,
            c,
            &app_id_remap,
            &mut principals,
            &session,
            cloud,
            backup.created_at,
        )
        .await;
        report.apps.push(restored);
        report.manual_items.extend(trusts);
    }

    // ---- Pass 3: re-consent (after all apps wired, so resources exist) ----
    for (idx, c) in created.iter().enumerate() {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        if !c.backup.admin_consent_granted {
            continue;
        }
        // The freshly-restored app reg usually has its SP already (Pass 1),
        // and a run that created one still busts the list tier below, since
        // `created` is non-empty — so `sp_created` is moot here.
        match grant_admin_consent_core(&client, &c.new_object_id).await {
            Ok(run) => {
                report.apps[idx].consent_granted = run.error.is_none();
                for f in run.result.failures {
                    report.apps[idx]
                        .warnings
                        .push(format!("consent: {} ({})", f.message, f.resource_app_id));
                }
                if let Some(e) = run.error {
                    session.note_code(&e.code);
                    report.apps[idx]
                        .warnings
                        .push(format!("admin consent failed: {}", e.message));
                }
            }
            Err(e) => {
                session.note_code(&e.code);
                report.apps[idx]
                    .warnings
                    .push(format!("admin consent failed: {}", e.message));
            }
        }
    }

    // ---- Pass 4: enterprise applications ----
    // Re-apply access (assignments + group memberships + settings) for SPs that
    // were recreated by the app-reg restore above. Foreign/gallery apps — and
    // paired apps that weren't restored — become runbook entries.
    for ent in &backup.enterprise_apps {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        restore_enterprise_app(
            &client,
            ent,
            &app_id_remap,
            &mut report,
            &mut principals,
            &session,
        )
        .await;
    }

    // ---- Pass 5: managed identities ----
    // MIs are Azure resources — they can't be created here. Re-bind Graph
    // app-roles to any MI already recreated (matched by name); Azure RBAC and
    // not-yet-recreated MIs become runbook entries.
    if cancel.is_cancelled() {
        report.cancelled = true;
    } else if !backup.managed_identities.is_empty() && !session.is_dead() {
        restore_managed_identities(&client, &backup.managed_identities, &mut report, &session)
            .await;
    }

    // Anything created means the destination's lists/details/audit are stale.
    // Only on the success path (we're returning Ok).
    if !created.is_empty() {
        invalidate_app_lists(&state.cache, &tenant_id);
    }
    // Unlike the read-only fan-outs, which return `session.err(..)` rather than
    // a partial result, a restore has already created objects in the tenant —
    // discarding the report would leave the operator with no record of what
    // exists. So the report comes back, flagged, and the front end pairs the
    // flag with the re-auth prompt.
    report.session_expired = session.is_dead();
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
    // Serialized up front so a failure is an error, never an empty `{}` written
    // as success — this file is the only home of the show-once secret values.
    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| UiError::serde(format!("could not serialize the restore report: {e}")))?;
    super::export::save_export_via_dialog(
        &app_handle,
        "restore-report",
        "json",
        String::new, // unreachable: format validated to "json" above
        move || json,
    )
    .await
}

/// Signals an in-progress [`restore_tenant`] to stop at the next item of
/// whichever pass is running; the report flags the run cancelled.
#[tauri::command]
pub fn cancel_restore(state: State<'_, AppState>) {
    state.restore_cancel.cancel();
}

// ---------------- internals ----------------

/// An app Pass 1 created — or adopted from an earlier run of this restore —
/// paired with its backup and destination ids.
struct CreatedApp {
    backup: AppRegistrationBackup,
    new_object_id: String,
    new_app_id: String,
    /// Recognised by its restore tag rather than created by this run.
    adopted: bool,
    /// For an adopted app, the display names of the secrets it already holds.
    live_secret_names: Vec<String>,
    /// Pass-1 warnings to carry into the app's report entry.
    warnings: Vec<String>,
}

/// Pass-2 work for one created (or adopted) app: declared permissions,
/// identifier URIs + Expose-an-API, authentication, federated credentials,
/// owners, and secret regeneration.
///
/// Every step is best-effort — a failure becomes a warning and the app keeps
/// its other config (it already exists). So a dead session would otherwise be
/// indistinguishable from a tenant rejecting each individual write; `session`
/// is the latch that tells them apart: each failure is noted through it by
/// `ui_code`, keeping `UiError::is_reauth_fatal` the single definition of which
/// codes are fatal.
///
/// For an adopted app the PATCHes are full-replace and simply re-applied, while
/// the additive writes (federated credentials, owners, secrets) skip what the
/// earlier run already put there. `taken_at` is the backup's timestamp, the
/// cutoff for [`expired_at_backup`].
async fn wire_application(
    client: &GraphClient,
    c: &CreatedApp,
    app_id_remap: &HashMap<String, String>,
    principals: &mut HashMap<String, Option<String>>,
    session: &SessionDead,
    cloud: CloudEnvironment,
    taken_at: DateTime<Utc>,
) -> (RestoredApp, Vec<ManualItem>) {
    let app = &c.backup;
    // Sign-in trusts this app gained from the manifest. Reported separately
    // from `warnings`, because these are the steps that *succeeded* — and a
    // secretless trust the operator did not intend is not visible any other way.
    let mut trusts: Vec<ManualItem> = Vec::new();
    let mut out = RestoredApp {
        display_name: app.display_name.clone(),
        source_app_id: app.source_app_id.clone(),
        new_app_id: c.new_app_id.clone(),
        new_object_id: c.new_object_id.clone(),
        adopted: c.adopted,
        warnings: c.warnings.clone(),
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
            session.note_code(e.ui_code());
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
    //
    // Reply URLs are where auth codes get delivered, so a manifest carrying
    // `https://*.evil.example/cb` or a plaintext `http://attacker.example/cb`
    // hands an attacker the codes for the restored app. The interactive
    // authentication editor rejects both before its PATCH; a manifest is
    // untrusted input for exactly the reason the federated-credential loop
    // below already documents, so it gets the same validator and the same
    // shape: reject the offending list, name it in the report, keep going.
    let web_redirect_uris = checked_uris(
        &app.web_redirect_uris,
        "web redirect URIs",
        &mut out.warnings,
    );
    let spa_redirect_uris = checked_uris(
        &app.spa_redirect_uris,
        "SPA redirect URIs",
        &mut out.warnings,
    );
    let public_client_redirect_uris = checked_uris(
        &app.public_client_redirect_uris,
        "public-client redirect URIs",
        &mut out.warnings,
    );
    // A logout URL is a single value, not a list — same rule, one entry.
    let logout_url = match app.logout_url.as_deref() {
        Some(u) => match validate_redirect_uri(u) {
            Ok(()) => app.logout_url.clone(),
            Err(reason) => {
                out.warnings
                    .push(format!("logout URL was NOT restored — {reason}"));
                None
            }
        },
        None => None,
    };

    let has_auth = !web_redirect_uris.is_empty()
        || !spa_redirect_uris.is_empty()
        || !public_client_redirect_uris.is_empty()
        || logout_url.is_some()
        || app.enable_access_token_issuance
        || app.enable_id_token_issuance
        || app.is_fallback_public_client;
    if has_auth {
        let patch = ApplicationAuthenticationPatch {
            web: Some(ApplicationWebPatch {
                redirect_uris: Some(web_redirect_uris.clone()),
                logout_url: Some(logout_url.clone().unwrap_or_default()),
                implicit_grant_settings: Some(ImplicitGrantSettingsPatch {
                    enable_access_token_issuance: Some(app.enable_access_token_issuance),
                    enable_id_token_issuance: Some(app.enable_id_token_issuance),
                }),
            }),
            spa: Some(ApplicationSpaPatch {
                redirect_uris: Some(spa_redirect_uris.clone()),
            }),
            public_client: Some(ApplicationPublicClientPatch {
                redirect_uris: Some(public_client_redirect_uris.clone()),
            }),
            is_fallback_public_client: Some(app.is_fallback_public_client),
        };
        if let Err(e) = client.patch_application_web(&c.new_object_id, &patch).await {
            session.note_code(e.ui_code());
            out.warnings.push(format!("authentication: {e}"));
        } else {
            // Surface what was actually written, the way a restored federated
            // credential is surfaced: a reply URL is standing configuration an
            // operator should be able to review after the fact.
            for uri in web_redirect_uris
                .iter()
                .chain(&spa_redirect_uris)
                .chain(&public_client_redirect_uris)
            {
                out.warnings.push(format!("restored reply URL: {uri}"));
            }
        }
    }

    // Federated identity credentials.
    //
    // These are the only thing a manifest can carry that grants standing access
    // to the restored app **without any secret**: whoever controls the named
    // issuer can mint tokens as it, indefinitely. The manifest is a file, and a
    // file may not have been written by the operator restoring it — so each one
    // is validated like any other untrusted input (`core::federation`, the same
    // check the interactive editor uses), and each one that *is* created is
    // named in the report rather than applied silently.
    //
    // An adopted app may already hold the ones an earlier run created; a failed
    // read falls through to creating, where a duplicate is a 409 warning.
    let existing_fics: HashSet<String> = if c.adopted && !app.federated_credentials.is_empty() {
        match client.list_federated_credentials(&c.new_object_id).await {
            Ok(list) => list.into_iter().map(|f| f.name).collect(),
            Err(e) => {
                session.note_code(e.ui_code());
                HashSet::new()
            }
        }
    } else {
        HashSet::new()
    };
    for fic in &app.federated_credentials {
        let audiences = if fic.audiences.is_empty() {
            vec![cloud.token_exchange_audience().to_string()]
        } else {
            fic.audiences.clone()
        };
        if let Err(reason) = validate_federated_credential(
            Some(&fic.name),
            &fic.issuer,
            &fic.subject,
            &audiences,
            fic.description.as_deref(),
        ) {
            out.warnings.push(format!(
                "federated credential '{}' was NOT restored — {reason}",
                fic.name
            ));
            continue;
        }
        if existing_fics.contains(&fic.name) {
            out.warnings.push(format!(
                "federated credential '{}' already exists from an earlier restore run — not added \
                 again",
                fic.name
            ));
            continue;
        }
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
            session.note_code(e.ui_code());
            out.warnings
                .push(format!("federated credential '{}': {e}", fic.name));
        } else {
            trusts.push(ManualItem {
                display_name: format!("{} — federated credential '{}'", app.display_name, fic.name),
                reason: format!(
                    "Restored a secretless sign-in trust: anything presenting subject '{}' \
                     from issuer '{}' can now obtain tokens as this application, with no \
                     secret and no expiry. Confirm that external workload still exists and \
                     should have this access in this tenant.",
                    fic.subject, fic.issuer
                ),
            });
        }
    }

    // Owners — remap each principal by UPN / display name in the destination.
    // An adopted app skips the owners it already has (a failed read falls
    // through to adding, where a duplicate is only a warning).
    let existing_owners: HashSet<String> = if c.adopted && !app.owners.is_empty() {
        match client.list_owners(&c.new_object_id).await {
            Ok(list) => list.into_iter().map(|o| o.id).collect(),
            Err(e) => {
                session.note_code(e.ui_code());
                HashSet::new()
            }
        }
    } else {
        HashSet::new()
    };
    for owner in &app.owners {
        match resolve_principal(client, principals, owner).await {
            Some(new_id) if existing_owners.contains(&new_id) => {}
            Some(new_id) => {
                if let Err(e) = client.add_owner(&c.new_object_id, &new_id).await {
                    session.note_code(e.ui_code());
                    out.warnings.push(format!("owner: {e}"));
                }
            }
            None => out.unresolved_owners.push(owner_label(owner)),
        }
    }

    // Secrets — values are unrecoverable, so mint fresh ones (show-once). Not
    // for one already expired when the backup was taken, and not for one an
    // earlier run of this restore already issued on an adopted app (matched by
    // name, as a multiset, so two same-named secrets still count as two).
    let mut already_issued = c.live_secret_names.clone();
    for meta in &app.secrets {
        let name = meta
            .display_name
            .clone()
            .unwrap_or_else(|| "restored".into());
        if expired_at_backup(meta, taken_at) {
            let end = meta
                .end_date_time
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default();
            out.warnings.push(format!(
                "secret '{name}' had already expired at backup time ({end}) — not re-issued"
            ));
            continue;
        }
        if let Some(pos) = already_issued.iter().position(|n| *n == name) {
            already_issued.swap_remove(pos);
            out.warnings.push(format!(
                "secret '{name}' already exists from an earlier restore run — not issued again \
                 (its value was in that run's report; regenerate it if that report is lost)"
            ));
            continue;
        }
        let lifetime = std::time::Duration::from_secs(REGEN_SECRET_DAYS as u64 * 86_400);
        match client.add_password(&c.new_object_id, &name, lifetime).await {
            Ok(cred) => out.regenerated_secrets.push(RegeneratedSecret {
                display_name: name,
                key_id: cred.key_id,
                secret_value: cred.secret_text.unwrap_or_default(),
                expires: cred.end_date_time,
            }),
            Err(e) => {
                session.note_code(e.ui_code());
                out.warnings.push(format!("secret '{name}': {e}"));
            }
        }
    }

    // Certificates can't be restored (private key never left the source);
    // surface them for manual re-upload from the operator's PKI.
    out.certificates_needing_manual_upload = app
        .certificates
        .iter()
        .map(|c| c.display_name.clone().unwrap_or_else(|| "(unnamed)".into()))
        .collect();

    (out, trusts)
}

/// Default-access app role (the all-zero GUID) — present on every SP, so an
/// assignment to it never needs role remapping.
const DEFAULT_ACCESS_ROLE: &str = "00000000-0000-0000-0000-000000000000";

/// Pass-4 work for one enterprise app. If its service principal was recreated by
/// the app-reg restore, re-applies settings + role assignments + group
/// memberships; otherwise records a runbook entry (foreign/gallery apps and
/// paired apps that weren't restored can't be replayed automatically).
///
/// Every failure is noted through `session`, as in Pass 2, so a session that
/// dies here stops the restore instead of producing one wrong runbook item per
/// remaining app.
async fn restore_enterprise_app(
    client: &GraphClient,
    ent: &EnterpriseAppBackup,
    app_id_remap: &HashMap<String, String>,
    report: &mut RestoreReport,
    principals: &mut HashMap<String, Option<String>>,
    session: &SessionDead,
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
        let Some(principal_id) = resolve_principal(client, principals, &assignee.principal).await
        else {
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
            Err(e) => {
                session.note_code(e.ui_code());
                out.warnings.push(format!("assignment: {e}"));
            }
        }
    }

    // Group memberships — resolve each group by display name.
    for group in &ent.group_memberships {
        match resolve_principal(client, principals, group).await {
            Some(group_id) => match client.add_group_member(&group_id, &sp.id).await {
                Ok(()) => out.group_memberships_applied += 1,
                Err(e) => {
                    session.note_code(e.ui_code());
                    out.warnings.push(format!("group membership: {e}"));
                }
            },
            None => out.unresolved_principals.push(owner_label(group)),
        }
    }

    report.enterprise_apps.push(out);
}

/// Pass-5 work: re-bind managed-identity permissions. MIs can't be created via
/// Graph (they're Azure resources), so this matches each backed-up MI to one
/// **already recreated** in the destination (by display name) and re-binds its
/// held Graph app-roles to the new principal. Azure RBAC re-creation, and MIs
/// not yet recreated, are emitted as runbook items (source RBAC scopes don't
/// exist in the destination, so they can't be replayed automatically).
///
/// A failed destination listing is ONE runbook item saying so — never a "not
/// found" item per MI, which would send the infra team to recreate identities
/// that already exist — and is noted through `session`.
async fn restore_managed_identities(
    client: &GraphClient,
    mis: &[ManagedIdentityBackup],
    report: &mut RestoreReport,
    session: &SessionDead,
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
                     infrastructure-as-code, then run the restore again with this backup — apps \
                     it already created are recognised by their restore tag, not duplicated — \
                     to re-bind its Graph app-roles.",
                    mi_subtype_label(mi.subtype),
                    arm
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

/// Cache key for a principal: its UPN (lowercased) when present, else its display
/// name. `None` when neither is set (nothing to resolve). Mirrors the lookup
/// branch order in [`resolve_principal_uncached`].
fn principal_cache_key(principal: &PrincipalRef) -> Option<String> {
    if let Some(upn) = principal
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        return Some(format!("upn:{}", upn.to_ascii_lowercase()));
    }
    principal
        .display_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|name| format!("name:{name}"))
}

/// Resolves a backed-up principal to its destination object id, memoizing the
/// result for the whole restore run. The same UPN or group is reused across
/// owners, app-role assignees, and group memberships, so without the memo a
/// multi-app restore re-runs identical `search_users`/`search_groups` calls many
/// times. The cache is per-run and keyed by [`principal_cache_key`]; negative
/// results are cached too (a principal absent now stays absent for the run).
async fn resolve_principal(
    client: &GraphClient,
    cache: &mut HashMap<String, Option<String>>,
    principal: &PrincipalRef,
) -> Option<String> {
    let key = principal_cache_key(principal)?;
    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }
    let resolved = resolve_principal_uncached(client, principal).await;
    cache.insert(key, resolved.clone());
    resolved
}

/// Resolves a backed-up principal to its object id in the destination tenant by
/// UPN (users) or display name (groups), returning `None` when no exact match
/// exists yet. Best-effort: a lookup error resolves to `None` (the owner is then
/// reported as unresolved rather than failing the whole restore).
async fn resolve_principal_uncached(
    client: &GraphClient,
    principal: &PrincipalRef,
) -> Option<String> {
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
        if let Ok(hits) = client.search_groups(name).await
            && let Some(id) = hits.into_iter().find_map(|g| {
                let matches = g.display_name.as_deref().is_some_and(|v| v == name);
                matches.then_some(g.id)
            })
        {
            return Some(id);
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

fn emit(progress: &impl ProgressSink, done: usize, total: usize, current_app: Option<String>) {
    let payload = BulkProgress {
        done,
        total,
        current_app,
        cancelled: false,
        in_flight_cap: None,
    };
    emit_progress(progress, "restore-progress", payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_from_a_newer_build_is_refused_but_an_older_one_restores() {
        // Older and current: additive, `serde(default)` fields — restoring one
        // is the DR case the version field exists to support.
        assert!(check_manifest_schema(0).is_ok());
        assert!(check_manifest_schema(BACKUP_SCHEMA_VERSION).is_ok());
        // Newer: this build cannot know what it would be dropping, and a
        // restore mutates the tenant before anyone can look.
        let err = check_manifest_schema(BACKUP_SCHEMA_VERSION + 1).unwrap_err();
        assert_eq!(err.code, "schema_too_new");
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

    #[test]
    fn principal_cache_key_prefers_lowercased_upn_then_name_then_none() {
        // UPN wins and is lowercased, so case-variant UPNs share one memo entry.
        let by_upn = PrincipalRef {
            source_id: "id".into(),
            user_principal_name: Some("Alice@Contoso.com".into()),
            display_name: Some("Alice".into()),
            ..Default::default()
        };
        assert_eq!(
            principal_cache_key(&by_upn).as_deref(),
            Some("upn:alice@contoso.com")
        );

        // No UPN → keyed by display name (the group path).
        let by_name = PrincipalRef {
            source_id: "id".into(),
            display_name: Some("Group X".into()),
            ..Default::default()
        };
        assert_eq!(
            principal_cache_key(&by_name).as_deref(),
            Some("name:Group X")
        );

        // An empty UPN is ignored, falling through to the display name.
        let empty_upn = PrincipalRef {
            source_id: "id".into(),
            user_principal_name: Some(String::new()),
            display_name: Some("Group Y".into()),
            ..Default::default()
        };
        assert_eq!(
            principal_cache_key(&empty_upn).as_deref(),
            Some("name:Group Y")
        );

        // Neither set → no key (nothing to resolve or memoize).
        assert_eq!(principal_cache_key(&PrincipalRef::default()), None);
    }

    #[test]
    fn build_restore_plan_counts_actions_and_flags_cloud_and_tenant_changes() {
        use crate::dto::backup::{AppRegistrationBackup, CredentialMeta, TenantBackup};
        use azapptoolkit_core::models::FederatedIdentityCredential;

        let app =
            |secrets: usize, certs: usize, feds: usize, owners: usize| AppRegistrationBackup {
                secrets: vec![CredentialMeta::default(); secrets],
                certificates: vec![CredentialMeta::default(); certs],
                federated_credentials: vec![FederatedIdentityCredential::default(); feds],
                owners: vec![PrincipalRef::default(); owners],
                ..Default::default()
            };
        let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
        let ending = |secs: i64| CredentialMeta {
            end_date_time: chrono::DateTime::from_timestamp(secs, 0),
            ..Default::default()
        };
        // Two undated secrets, one still valid at backup time, one already
        // expired then: only the expired one is left out.
        let mut first = app(2, 1, 3, 1);
        first.secrets.push(ending(2_000_000));
        let mut second = app(0, 0, 0, 2);
        second.secrets.push(ending(500_000));
        let backup = TenantBackup {
            schema_version: 1,
            created_at: taken_at,
            source_tenant_id: "src-tenant".into(),
            cloud: CloudEnvironment::Commercial,
            app_registrations: vec![first, second],
            enterprise_apps: Vec::new(),
            managed_identities: Vec::new(),
            skipped: Vec::new(),
        };

        // Same cloud, different destination tenant — the expected DR case. Counts
        // are summed across every app registration.
        let plan = build_restore_plan(
            &backup,
            "dest-tenant".to_string(),
            CloudEnvironment::Commercial,
        );
        assert!(plan.cloud_mismatch.is_none());
        assert!(plan.tenant_changed);
        assert_eq!(plan.destination_tenant_id, "dest-tenant");
        assert_eq!(plan.app_registrations_to_create, 2);
        assert_eq!(plan.secrets_to_regenerate, 3);
        assert_eq!(plan.expired_secrets_skipped, 1);
        assert_eq!(plan.certificates_needing_manual_upload, 1);
        assert_eq!(plan.federated_credentials_to_restore, 3);
        assert_eq!(plan.owners_to_remap, 3);

        // A cross-cloud manifest is flagged; restoring into the source tenant is
        // not a "tenant change".
        let blocked =
            build_restore_plan(&backup, "src-tenant".to_string(), CloudEnvironment::UsGov);
        assert!(blocked.cloud_mismatch.is_some());
        assert!(!blocked.tenant_changed);
    }

    #[test]
    fn expired_at_backup_uses_the_backup_time_not_now() {
        let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
        let ending = |end: Option<DateTime<Utc>>| CredentialMeta {
            end_date_time: end,
            ..Default::default()
        };
        // Expired before the backup was taken: nothing could have used it.
        assert!(expired_at_backup(
            &ending(chrono::DateTime::from_timestamp(999_999, 0)),
            taken_at
        ));
        // Live at backup time, long expired by now: a recovering client still
        // holds it, so it is re-issued.
        assert!(!expired_at_backup(
            &ending(chrono::DateTime::from_timestamp(1_000_001, 0)),
            taken_at
        ));
        // No end date is not "expired".
        assert!(!expired_at_backup(&ending(None), taken_at));
    }

    #[test]
    fn restore_marker_is_prefix_plus_source_app_id() {
        assert_eq!(
            restore_marker("11111111-2222-3333-4444-555555555555"),
            "azapptoolkit:restoredFrom:11111111-2222-3333-4444-555555555555"
        );
        assert!(restore_marker("x").starts_with(RESTORE_MARKER_PREFIX));
    }

    #[test]
    fn adoption_for_creates_adopts_or_refuses() {
        use azapptoolkit_core::models::PasswordCredential;

        let app = AppRegistrationBackup {
            display_name: "App A".into(),
            source_app_id: "src-a".into(),
            ..Default::default()
        };
        let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
        // Created after the backup was taken, as anything a restore of it made.
        let hit = |id: &str, name: &str| Application {
            id: format!("obj-{id}"),
            app_id: format!("app-{id}"),
            display_name: name.into(),
            created_date_time: chrono::DateTime::from_timestamp(1_000_600, 0),
            ..Default::default()
        };

        // Nothing carries the tag: create.
        assert_eq!(adoption_for(&app, &[], taken_at), Adoption::Create);

        // One tagged app with the same name: an earlier run made it — adopt it,
        // carrying the names of the secrets it already holds.
        let mut same = hit("1", "App A");
        same.password_credentials = vec![
            PasswordCredential {
                display_name: Some("ci".into()),
                ..Default::default()
            },
            PasswordCredential::default(),
        ];
        assert_eq!(
            adoption_for(&app, &[same], taken_at),
            Adoption::Adopt {
                object_id: "obj-1".into(),
                app_id: "app-1".into(),
                live_secret_names: vec!["ci".into()],
            }
        );

        // Tagged but renamed: never adopted on the tag alone, never duplicated.
        let Adoption::Refuse(reason) = adoption_for(&app, &[hit("2", "Renamed")], taken_at) else {
            panic!("a renamed tagged app must be refused");
        };
        assert!(reason.contains("Renamed") && reason.contains("app-2"));

        // Two tagged apps: ambiguous, so neither is taken and nothing is created.
        let Adoption::Refuse(reason) =
            adoption_for(&app, &[hit("1", "App A"), hit("2", "App A")], taken_at)
        else {
            panic!("two tagged apps must be refused");
        };
        assert!(reason.starts_with("2 apps carry the restore tag"));

        // Tag and name match, but the app predates the backup — or its creation
        // time is unknown: no restore of this backup can be proven to have made
        // it, so it is refused rather than handed this app's consent.
        let mut older = hit("3", "App A");
        older.created_date_time = chrono::DateTime::from_timestamp(999_000, 0);
        let Adoption::Refuse(reason) = adoption_for(&app, &[older], taken_at) else {
            panic!("an app older than the backup must be refused");
        };
        assert!(
            reason.contains("not after this backup was taken"),
            "{reason}"
        );
        let mut undated = hit("4", "App A");
        undated.created_date_time = None;
        let Adoption::Refuse(reason) = adoption_for(&app, &[undated], taken_at) else {
            panic!("an app of unknown age must be refused");
        };
        assert!(reason.contains("an unknown time"), "{reason}");
    }

    #[test]
    fn unexpected_owners_names_everyone_not_allowed() {
        let owner = |id: &str, upn: Option<&str>, name: Option<&str>| DirectoryObject {
            id: id.into(),
            user_principal_name: upn.map(Into::into),
            display_name: name.map(Into::into),
            ..Default::default()
        };
        let owners = [
            owner("op", Some("admin@contoso.com"), None),
            owner("x1", Some("mallory@contoso.com"), Some("Mallory")),
            owner("x2", None, Some("Some Group")),
            owner("x3", None, None),
        ];
        let allowed = HashSet::from(["op".to_string()]);
        assert_eq!(
            unexpected_owners(&owners, &allowed),
            ["mallory@contoso.com", "Some Group", "x3"]
        );
        let everyone = HashSet::from(["op", "x1", "x2", "x3"].map(String::from));
        assert!(unexpected_owners(&owners, &everyone).is_empty());
    }

    /// A token provider whose refresh token is gone: every read fails with the
    /// re-auth-fatal code before any request is sent.
    struct DeadSession;
    #[async_trait::async_trait]
    impl azapptoolkit_core::token::BearerProvider for DeadSession {
        async fn bearer(&self) -> Result<String, azapptoolkit_core::token::TokenError> {
            Err(azapptoolkit_core::token::TokenError::new(
                "refresh_missing",
                "gone",
            ))
        }
    }

    fn graph_over(server: &wiremock::MockServer, dead: bool) -> GraphClient {
        use azapptoolkit_core::cache::Cache;
        use azapptoolkit_core::token::{BearerProvider, StaticTokenProvider};
        use std::sync::Arc;
        let token: Arc<dyn BearerProvider> = if dead {
            Arc::new(DeadSession)
        } else {
            StaticTokenProvider::new("tok")
        };
        GraphClient::with_base_url(
            "tenant-test",
            token.clone(),
            token,
            Cache::new(),
            server.uri(),
        )
    }

    fn two_mis() -> Vec<ManagedIdentityBackup> {
        ["mi-one", "mi-two"]
            .into_iter()
            .map(|name| ManagedIdentityBackup {
                display_name: name.into(),
                ..Default::default()
            })
            .collect()
    }

    // `unwrap_or_default()` once turned a failed listing into an empty
    // destination, and every MI was reported "not found — recreate it via IaC".
    #[tokio::test]
    async fn a_failed_mi_listing_is_reported_once_not_as_missing_identities() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let client = graph_over(&server, false);
        let session = SessionDead::new();
        let mut report = RestoreReport::default();

        restore_managed_identities(&client, &two_mis(), &mut report, &session).await;

        assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
        assert!(report.manual_items[0].reason.contains("Couldn't list"));
        assert!(
            !report
                .manual_items
                .iter()
                .any(|m| m.reason.contains("not found in the destination")),
            "a failed read must not be reported as missing identities"
        );
        assert!(report.managed_identities.is_empty());
        assert!(!session.is_dead(), "a 403 is not a dead session");
    }

    #[tokio::test]
    async fn a_dead_session_during_the_mi_listing_latches() {
        // Never answered: the token fails before any request is sent.
        let server = wiremock::MockServer::start().await;
        let client = graph_over(&server, true);
        let session = SessionDead::new();
        let mut report = RestoreReport::default();

        restore_managed_identities(&client, &two_mis(), &mut report, &session).await;

        assert!(session.is_dead(), "a dead refresh token must latch");
        assert_eq!(report.manual_items.len(), 1);
    }

    // The `_` arm once reported any read failure as "the app had none in the
    // backup", which is false whenever the backup said it had one.
    #[tokio::test]
    async fn a_failed_sp_read_is_not_reported_as_having_no_sp() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let client = graph_over(&server, false);
        let session = SessionDead::new();
        let mut report = RestoreReport::default();
        let ent = EnterpriseAppBackup {
            display_name: "Ent A".into(),
            source_app_id: "src-a".into(),
            ..Default::default()
        };
        let remap = HashMap::from([("src-a".to_string(), "new-a".to_string())]);

        restore_enterprise_app(
            &client,
            &ent,
            &remap,
            &mut report,
            &mut HashMap::new(),
            &session,
        )
        .await;

        assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
        let reason = &report.manual_items[0].reason;
        assert!(!reason.contains("had none in the backup"), "{reason}");
        assert!(reason.contains("Couldn't read the restored service principal"));
        assert!(report.enterprise_apps.is_empty());
    }

    fn tagged_app_a() -> AppRegistrationBackup {
        AppRegistrationBackup {
            display_name: "App A".into(),
            source_app_id: "src-a".into(),
            ..Default::default()
        }
    }

    /// Mounts the tag lookup answering one hit named "App A", created after
    /// `taken_at` in [`decide`], and its owners.
    async fn mount_tagged_hit(server: &wiremock::MockServer, owners: serde_json::Value) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "obj-1",
                    "appId": "app-1",
                    "displayName": "App A",
                    "createdDateTime": "2026-01-02T00:00:00Z"
                }]
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-1/owners"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": owners })),
            )
            .mount(server)
            .await;
    }

    async fn decide(client: &GraphClient, session: &SessionDead) -> Adoption {
        let taken_at = "2026-01-01T00:00:00Z".parse().unwrap();
        decide_adoption(
            client,
            &tagged_app_a(),
            taken_at,
            Some("operator-oid"),
            &mut HashMap::new(),
            session,
        )
        .await
    }

    // The fail-closed branch is the package's key safety property: a failed tag
    // lookup must never fall through to a create.
    #[tokio::test]
    async fn a_failed_tag_lookup_refuses_instead_of_creating() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/applications"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let client = graph_over(&server, false);
        let session = SessionDead::new();

        let Adoption::Refuse(reason) = decide(&client, &session).await else {
            panic!("a failed lookup must be refused");
        };
        assert!(reason.contains("it was NOT created"), "{reason}");
        assert!(!session.is_dead(), "a 403 is not a dead session");
    }

    #[tokio::test]
    async fn a_dead_session_during_the_tag_lookup_refuses_and_latches() {
        let server = wiremock::MockServer::start().await;
        let client = graph_over(&server, true);
        let session = SessionDead::new();

        assert!(matches!(
            decide(&client, &session).await,
            Adoption::Refuse(_)
        ));
        assert!(session.is_dead(), "a dead refresh token must latch");
    }

    // Anyone who may register apps can write the tag and the name, so a hit
    // with an owner the restore did not set is someone else's app: adopting it
    // would give them this app's permissions and admin consent.
    #[tokio::test]
    async fn a_tagged_app_with_a_foreign_owner_is_not_adopted() {
        let server = wiremock::MockServer::start().await;
        mount_tagged_hit(
            &server,
            serde_json::json!([
                { "id": "operator-oid", "userPrincipalName": "admin@contoso.com" },
                { "id": "mallory-oid", "userPrincipalName": "mallory@contoso.com" }
            ]),
        )
        .await;
        let client = graph_over(&server, false);

        let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
            panic!("a foreign owner must block adoption");
        };
        assert!(reason.contains("mallory@contoso.com"), "{reason}");
        assert!(!reason.contains("admin@contoso.com"), "{reason}");
    }

    #[tokio::test]
    async fn a_tagged_app_owned_only_by_the_operator_is_adopted() {
        let server = wiremock::MockServer::start().await;
        mount_tagged_hit(
            &server,
            serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
        )
        .await;
        let client = graph_over(&server, false);

        assert_eq!(
            decide(&client, &SessionDead::new()).await,
            Adoption::Adopt {
                object_id: "obj-1".into(),
                app_id: "app-1".into(),
                live_secret_names: Vec::new(),
            }
        );
    }

    #[tokio::test]
    async fn a_failed_owner_read_refuses_the_adoption() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-1/owners"))
            .respond_with(ResponseTemplate::new(403))
            .with_priority(1)
            .mount(&server)
            .await;
        mount_tagged_hit(&server, serde_json::json!([])).await;
        let client = graph_over(&server, false);

        let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
            panic!("an unreadable owner list must block adoption");
        };
        assert!(reason.contains("Couldn't read the owners"), "{reason}");
    }

    /// A manifest is untrusted input — the same premise the federated-credential
    /// loop states. Reply URLs are where auth codes are delivered, so a wildcard
    /// or plaintext one must not reach the tenant just because it arrived in a
    /// file rather than through the editor.
    #[test]
    fn restored_reply_urls_are_validated_like_editor_input() {
        let uris = [
            "https://good.contoso.com/cb",
            "https://*.evil.example/cb",
            "http://attacker.example/cb",
            "http://localhost:5173/cb",
        ]
        .map(String::from);
        let mut warnings = Vec::new();
        let kept = checked_uris(&uris, "web redirect URIs", &mut warnings);

        // Per-URI, not all-or-nothing: one bad entry must not discard the good
        // ones, and loopback http stays legal exactly as it is in the editor.
        assert_eq!(
            kept,
            vec![
                "https://good.contoso.com/cb".to_string(),
                "http://localhost:5173/cb".to_string()
            ]
        );
        assert_eq!(
            warnings.len(),
            2,
            "each rejection is reported: {warnings:?}"
        );
        assert!(warnings.iter().any(|w| w.contains("*.evil.example")));
        assert!(warnings.iter().any(|w| w.contains("attacker.example")));
        // The operator can tell which list it was.
        assert!(
            warnings
                .iter()
                .all(|w| w.starts_with("web redirect URIs: "))
        );
    }

    /// An empty list restores nothing and warns about nothing — the common case
    /// must stay silent.
    #[test]
    fn checked_uris_is_silent_when_everything_is_valid() {
        let uris = ["https://a.contoso.com/cb"].map(String::from);
        let mut warnings = Vec::new();
        assert_eq!(
            checked_uris(&uris, "web redirect URIs", &mut warnings).len(),
            1
        );
        assert!(warnings.is_empty());
    }
}
