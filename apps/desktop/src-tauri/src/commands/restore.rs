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
//!    `create_application_core_with`.
//! 2. **Wire references** — declared permissions (remapped), identifier URIs
//!    (every `api://` segment naming the source appId / source tenant →
//!    the new appId / destination tenant), Expose-an-API scopes + pre-authorized
//!    apps, authentication/redirect URIs, federated credentials (validated +
//!    reported), owners (remapped by UPN / display name), and bulk-regenerate
//!    secrets.
//! 3. **Re-consent** — re-grant admin consent for apps that had it, *after* all
//!    apps are wired so a custom resource's SP + scopes already exist. Consent
//!    covering a high-risk or unidentifiable application permission is granted
//!    only to apps the operator approved in the plan.
//! 4. **Enterprise applications** — re-apply settings, app-role assignments and
//!    group memberships to the SPs recreated in pass 1.
//! 5. **Managed identities** — re-bind Graph app-roles to MIs already recreated
//!    in the destination (high-risk ones only when approved); everything else
//!    becomes a runbook item.
//!
//! **Re-running is safe for the apps a run created.** Every app is created with
//! the tag `azapptoolkit:restoredFrom:<source appId>` in its create POST, so a
//! re-run finds it and finishes wiring it rather than creating it twice. The tag
//! and the display name are both writable by anyone who may register apps, so a
//! hit is adopted only once it is also provably this restore's: created after
//! the backup, owned by nobody but the operator and the manifest's owners,
//! holding no credential (secret, certificate, federated credential) the
//! manifest does not account for, and with a service principal (if it has one)
//! holding no credential at all and no other owner. Anything else — an ambiguous or unprovable
//! match, or a read that failed — is a runbook item and never a blind create.
//!
//! Secret/cert values can't be restored: secrets are regenerated (the show-once
//! values land in the [`RestoreReport`] for redistribution) — except those that
//! had already expired when the backup was taken; certificates are reported as
//! needing manual re-upload from the operator's own PKI.
//!
//! Long-running, so it polls its own `AppState.restore_cancel` token (stopped
//! only by `cancel_restore`, never by a backup's Cancel) and emits
//! `restore-progress`. A cancel stops at the next item in whichever pass is
//! running, and the report flags the run cancelled (partial) — still listing
//! every app Pass 1 created, each it stopped before wiring fully flagged
//! `incomplete`; a re-run adopts the already-created, tagged apps and finishes
//! wiring them.
//!
//! Split by phase: this file holds the commands and `run_restore`, which runs
//! the passes in order; `manifest` (schema and shape checks, echo bounds),
//! `plan` (the dry run and the approval classification), `adoption` (Pass 1:
//! create or adopt),
//! `wire` (Pass 2), `reconsent` (Pass 3), `enterprise` (Pass 4),
//! `managed_identities` (Pass 5) and `principals` (the per-run principal
//! resolution every pass shares).

mod adoption;
mod enterprise;
mod managed_identities;
mod manifest;
mod plan;
mod principals;
mod reconsent;
mod wire;

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use tauri::{AppHandle, State};

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_graph::GraphClient;

use crate::commands::applications::invalidate_app_lists;
use crate::commands::dispatch::SessionDead;
use crate::commands::progress::{ProgressSink, emit_progress};
use crate::dto::UiError;
use crate::dto::backup::{RestoreApproval, RestorePlan, RestoreReport, TenantBackup};
use crate::dto::bulk::BulkProgress;
use crate::state::{AppState, CancelToken};

use adoption::pass1_create_or_adopt;
use enterprise::pass4_enterprise;
use managed_identities::restore_managed_identities;
use manifest::{bound_report_text, cap_report_value, check_manifest_schema, validate_manifest};
use plan::{backup_apps, build_restore_plan, privileged_restore_items, unapproved_apps};
use principals::PrincipalMemo;
use reconsent::pass3_reconsent;
use wire::pass2_wire;

/// Dry-run analysis of restoring `backup` into the current tenant — counts,
/// warnings and the privileged grants, no writes. The frontend shows this
/// before the operator confirms the (irreversible) restore: the work of all
/// five passes, the hard blockers (a cross-cloud manifest, a too-new
/// `schema_version` and a malformed or repeated source appId, which
/// [`restore_tenant`] still enforces on its own), whether the destination is
/// the tenant the backup was taken from, and — read-only, against the
/// destination — what the file would grant ([`privileged_restore_items`]). A
/// blocked manifest still returns a plan — carrying the blocker — so the
/// operator sees why before Confirm.
#[tauri::command]
pub async fn plan_restore(
    state: State<'_, AppState>,
    tenant_id: String,
    backup: TenantBackup,
) -> Result<RestorePlan, UiError> {
    let mut plan = build_restore_plan(&backup, tenant_id.clone(), state.auth.cloud());
    if plan.is_blocked() {
        return Ok(plan);
    }
    let client = state.graph_for(&tenant_id);
    let session = SessionDead::new();
    plan.privileged = privileged_restore_items(&client, &backup, &session).await;
    // Every permission would read "unknown" — a plan that says so is no plan.
    if session.is_dead() {
        return Err(session.err("the restore plan"));
    }
    Ok(plan)
}

/// Replays the backup (app registrations, enterprise apps, managed-identity
/// permissions) into the current tenant. See the module docs for the pass
/// structure. Busts the destination list caches on a
/// run that created anything.
///
/// `approvals` are the `RestorePlan.privileged` items the operator approved,
/// by kind and source appId. An item that
/// [requires approval](crate::dto::backup::PrivilegedRestoreItem::requires_approval)
/// and is not named here is still created and wired, but gets no standing
/// access from the file: an app's admin consent, federated credentials,
/// owners and group memberships, a managed identity's app roles — each
/// withheld one a runbook item.
#[tauri::command]
pub async fn restore_tenant(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    backup: TenantBackup,
    approvals: Vec<RestoreApproval>,
) -> Result<RestoreReport, UiError> {
    check_manifest_schema(backup.schema_version)?;
    validate_manifest(&backup)?;

    // A cross-cloud restore is never valid: endpoints and well-known appIds
    // differ, so the remapped permissions would point at the wrong resources.
    let cloud = state.auth.cloud();
    if backup.cloud != cloud {
        return Err(UiError::validation(
            "cloud_mismatch",
            format!(
                "backup is from cloud '{}', but this build targets '{}' — set \
                 AZAPPTOOLKIT_CLOUD={} and relaunch azapptoolkit to restore it",
                backup.cloud.as_str(),
                cloud.as_str(),
                backup.cloud.as_str()
            ),
        ));
    }

    let client = state.graph_for(&tenant_id);
    // One cancel token for the whole restore, claimed before the first await.
    // Claiming per pass would take a new generation each time and lose a cancel
    // the operator issued during an earlier pass.
    let cancel = state.restore_cancel.claim();
    // The signed-in account's object id in the destination: the one owner an
    // app this restore created may have besides the manifest's own.
    let operator_oid = state.auth.tenant_context(&tenant_id).map(|t| t.account_oid);
    let approved: HashSet<RestoreApproval> = approvals.into_iter().collect();
    let (report, effects) = run_restore(
        &client,
        &app_handle,
        cancel,
        RestoreRun {
            backup: &backup,
            tenant_id: &tenant_id,
            cloud,
            operator_oid: operator_oid.as_deref(),
            approved: &approved,
        },
    )
    .await;
    // Anything created means the destination's lists/details/audit are stale.
    // Only on the success path (we're returning Ok). A run that created nothing
    // but re-bound a managed identity's roles changed what the audit scores.
    if effects.created_any {
        invalidate_app_lists(&state.cache, &tenant_id);
    } else if effects.rebound_any {
        crate::commands::audit::invalidate_audit_cache(&state.cache, &tenant_id);
    }
    Ok(report)
}

/// What a run changed in the destination that a cache may still describe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RestoreEffects {
    /// An app was created or adopted: the list tier is stale.
    created_any: bool,
    /// A managed identity's app roles were re-bound: the audit run is stale.
    rebound_any: bool,
}

/// What one restore run replays, and into where.
struct RestoreRun<'a> {
    backup: &'a TenantBackup,
    /// The destination tenant.
    tenant_id: &'a str,
    cloud: CloudEnvironment,
    operator_oid: Option<&'a str>,
    /// Items approved in the plan (see [`restore_tenant`]).
    approved: &'a HashSet<RestoreApproval>,
}

/// The borrowed inputs the per-app helpers of Passes 2-4 share, built once
/// Pass 1 has stopped changing the remap.
///
/// The principal memo stays a separate `&mut` parameter, and so does the
/// cancel token: the repo invariants find a pass helper as a cancel runner by
/// the `CancelToken` in its signature (`sources::cancel_runners`).
struct PassCtx<'a> {
    client: &'a GraphClient,
    /// The run's one dead-session latch; every failure is noted through it.
    session: &'a SessionDead,
    /// `source_app_id → new app id`, final once Pass 1 ends.
    app_id_remap: &'a HashMap<String, String>,
    cloud: CloudEnvironment,
    /// When the backup was taken: the cutoff for
    /// [`expired_at_backup`](wire::expired_at_backup).
    taken_at: DateTime<Utc>,
    /// The tenant the backup was taken from.
    source_tenant_id: &'a str,
    /// The destination tenant.
    dest_tenant_id: &'a str,
}

/// The five passes of [`restore_tenant`], split from the command the way
/// [`restore_managed_identities`] is, so the pass loop runs in a test against a
/// mock Graph. Returns the report and what the run changed ([`RestoreEffects`],
/// which the caller busts caches on).
///
/// Stops at the next item on `cancel` and on a dead session — in every pass,
/// and inside each pass's per-item loops; both flag the report.
///
/// Each pass's loop is a function in its phase's module, called here in order:
/// [`pass1_create_or_adopt`], [`pass2_wire`], [`pass3_reconsent`],
/// [`pass4_enterprise`], then [`restore_managed_identities`] for Pass 5.
async fn run_restore(
    client: &GraphClient,
    progress: &impl ProgressSink,
    cancel: CancelToken,
    run: RestoreRun<'_>,
) -> (RestoreReport, RestoreEffects) {
    // Every field is `Copy`, so `run` stays whole for Pass 1.
    let RestoreRun {
        backup,
        tenant_id,
        cloud,
        approved,
        ..
    } = run;
    // Where each pass's work ends, cumulatively — see `RestoreProgress`.
    let apps = backup.app_registrations.len();
    let consenting = backup
        .app_registrations
        .iter()
        .filter(|a| a.admin_consent_granted)
        .count();
    let pass2_end = 2 * apps;
    let pass3_end = pass2_end + consenting;
    let pass4_end = pass3_end + backup.enterprise_apps.len();
    let total = pass4_end + backup.managed_identities.len();
    let mut progress = RestoreProgress::start(progress, total);

    let mut report = RestoreReport::default();
    // Per-run principal-resolution memo (UPN/group display name → destination
    // object id), shared across passes so a principal reused across owners,
    // assignees, and group memberships is searched once, not per occurrence.
    let mut principals = PrincipalMemo::new();
    // One latch across all five passes: the first re-auth-fatal error stops the
    // rest instead of letting each remaining item fail the same way.
    let session = SessionDead::new();
    // The apps whose standing access passes 2-4 withhold — recomputed here,
    // before anything is created, from the same classification the plan
    // showed, rather than taken from the front end.
    let withheld = unapproved_apps(client, backup, approved, &session).await;

    // ---- Pass 1: create shells ----
    let (app_id_remap, created) = pass1_create_or_adopt(
        client,
        &mut progress,
        &cancel,
        &run,
        &session,
        &mut principals,
        &mut report,
    )
    .await;
    progress.reach(apps);

    // ---- Pass 2: wire references + regenerate secrets (per created app) ----
    // Every app the backup owns, recreated or not: a pre-authorized client in
    // here with no remap entry is one Pass 1 failed or refused, never foreign.
    let backup_apps = backup_apps(backup);
    // The remap is final from here on: Passes 2-4 share it read-only.
    let ctx = PassCtx {
        client,
        session: &session,
        app_id_remap: &app_id_remap,
        cloud,
        taken_at: backup.created_at,
        source_tenant_id: &backup.source_tenant_id,
        dest_tenant_id: tenant_id,
    };
    pass2_wire(
        &ctx,
        &created,
        &backup_apps,
        &withheld,
        &mut principals,
        &cancel,
        &mut report,
        &mut progress,
    )
    .await;
    // Apps Pass 1 refused or failed to create have nothing to wire.
    progress.reach(pass2_end);

    // ---- Pass 3: re-consent (after all apps wired, so resources exist) ----
    pass3_reconsent(
        &ctx,
        &created,
        &withheld,
        &cancel,
        &mut report,
        &mut progress,
    )
    .await;
    progress.reach(pass3_end);

    // ---- Pass 4: enterprise applications ----
    // Re-apply access (assignments + group memberships + settings) for SPs that
    // were recreated by the app-reg restore above. Foreign/gallery apps — and
    // paired apps that weren't restored — become runbook entries.
    pass4_enterprise(
        &ctx,
        &backup.enterprise_apps,
        approved,
        &mut principals,
        &cancel,
        &mut report,
        &mut progress,
    )
    .await;
    progress.reach(pass4_end);

    // ---- Pass 5: managed identities ----
    // MIs are Azure resources — they can't be created here. Re-bind Graph
    // app-roles to any MI already recreated (matched by name and sub-type); Azure RBAC and
    // not-yet-recreated MIs become runbook entries.
    if cancel.is_cancelled() {
        report.cancelled = true;
    } else if !backup.managed_identities.is_empty() && !session.is_dead() {
        restore_managed_identities(
            client,
            &backup.managed_identities,
            approved,
            &mut report,
            &session,
            &cancel,
            &mut progress,
        )
        .await;
    }

    // Unlike the read-only fan-outs, which return `session.err(..)` rather than
    // a partial result, a restore has already created objects in the tenant —
    // discarding the report would leave the operator with no record of what
    // exists. So the report comes back, flagged, with every app Pass 1 created
    // or adopted — one Pass 2 did not finish (or never reached) marked
    // `incomplete` — and the front end pairs the flag with the re-auth prompt.
    report.session_expired = session.is_dead();
    // Every text field echoes the file somewhere; bound them all once, here.
    bound_report_text(&mut report);
    progress.finish();
    let effects = RestoreEffects {
        created_any: !created.is_empty(),
        rebound_any: report
            .managed_identities
            .iter()
            .any(|m| m.app_roles_rebound > 0),
    };
    (report, effects)
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

/// Restore progress across all five passes, as `restore-progress` events.
///
/// `total` is every unit of work the run can do: each app twice (Pass 1
/// creates or adopts it, Pass 2 wires it), each app whose admin consent Pass 3
/// re-grants, and each enterprise app (Pass 4) and managed identity (Pass 5).
/// It once counted only Pass 1, so the bar sat full at "N/N" while the rest of
/// the run — wiring, secrets, consent, assignments, role re-binds — went on
/// with nothing moving. A pass [`tick`](Self::tick)s once per item it settles;
/// [`reach`](Self::reach) then moves past the items it had no work for (an app
/// Pass 1 did not create, one with no consent to re-grant), so `done` only
/// ever grows.
pub(super) struct RestoreProgress<'p, P> {
    sink: &'p P,
    done: usize,
    total: usize,
}

impl<'p, P: ProgressSink> RestoreProgress<'p, P> {
    /// Emits `0/total`.
    pub(super) fn start(sink: &'p P, total: usize) -> Self {
        let progress = Self {
            sink,
            done: 0,
            total,
        };
        progress.send(None);
        progress
    }

    /// One item settled — `name` is the file's name for it.
    pub(super) fn tick(&mut self, name: &str) {
        self.done = (self.done + 1).min(self.total);
        self.send(Some(name.to_string()));
    }

    /// The end of a pass, as a cumulative count: whatever it did not tick
    /// counts as settled.
    pub(super) fn reach(&mut self, end: usize) {
        let end = end.min(self.total);
        if end > self.done {
            self.done = end;
            self.send(None);
        }
    }

    /// The run is over, finished or stopped.
    fn finish(&mut self) {
        self.done = self.total;
        self.send(None);
    }

    fn send(&self, current_app: Option<String>) {
        emit(self.sink, self.done, self.total, current_app);
    }
}

fn emit(progress: &impl ProgressSink, done: usize, total: usize, current_app: Option<String>) {
    let payload = BulkProgress {
        done,
        total,
        // The file's display name, bounded like the report's.
        current_app: current_app.map(|mut name| {
            cap_report_value(&mut name);
            name
        }),
        cancelled: false,
        in_flight_cap: None,
    };
    emit_progress(progress, crate::dto::events::RESTORE_PROGRESS, payload);
}

#[cfg(test)]
mod tests;
