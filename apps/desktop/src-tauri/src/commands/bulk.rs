//! Bulk-operation admin actions.
//!
//! Every bulk command but the expired-credential sweep reuses a single-app
//! core (`permissions::grant_admin_consent_core`,
//! `applications::create_application_core`, the remediation cores, …) so the
//! semantics stay identical to the per-app path — bulk is a UX shortcut, not a
//! new code path. The sweep has no single-app core to call, but selects
//! credentials with the same shared expiry rule
//! ([`azapptoolkit_core::audit::is_expired`]) the audit scorer and the per-app
//! removal paths use — pinned by `expired_password_key_ids`'s test in
//! `azapptoolkit_core::audit`. Two drivers run them: [`run_bulk_seq`]
//! (sequential) for the cores that take `State` or borrow the command's locals,
//! and [`run_bulk_capped`] for the three whose work is `Send` — delete, consent
//! grant and the sweep — which fan out under the adaptive throttle.
//! Progress events ride the same `bulk-progress` channel so the frontend can
//! share a single listener.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use tauri::{AppHandle, State};

use azapptoolkit_core::audit::expired_password_key_ids;
use azapptoolkit_core::cache::Cache;
use azapptoolkit_core::models::{
    Application, DeletedApplication, DeletedServicePrincipal, RequiredResourceAccess,
    ServicePrincipal,
};
use azapptoolkit_graph::client::{DELETED_APPS_MAX, DELETED_SPS_MAX};

use crate::commands::dispatch::{SessionDead, batch_or_serial, dispatch_capped};
use crate::commands::progress::{ProgressSink, emit_progress};
use crate::commands::throttle::FanOutMeter;
use crate::dto::UiError;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::bulk::{
    AppRemovalSummary, BulkAddOwnerResult, BulkCreateOutcome, BulkCreateResult, BulkCreateSpec,
    BulkCreateStatus, BulkDeleteFailure, BulkDeleteResult, BulkDisableOutcome,
    BulkDisableSignInResult, BulkError, BulkGrantOutcome, BulkGrantResult, BulkOwnerOutcome,
    BulkProgress, BulkRemoveExpiredResult, BulkRemoveRedundantOutcome, BulkRemoveRedundantResult,
    BulkRestoreOutcome, BulkRestoreResult, BulkScopeOutcome, BulkScopeResult, BulkStageCertOutcome,
    BulkStageCertResult, INTERRUPTED, LOST_TASK,
};
use crate::dto::permissions::PermissionKind;
use crate::state::{AppState, CancelToken};

/// The starting in-flight cap of the three capped bulk writes (delete, consent
/// grant, the expired-secret sweep); [`FanOutMeter`]'s throttle halves it on a
/// 429 and recovers it when quiet. It bounds how many apps have Microsoft Graph
/// directory **writes** in flight — each item writes to `/applications`,
/// `/servicePrincipals` or their grants: one DELETE, a consent grant's role
/// assignments and scope grants, a run of `removePassword` calls — so it is the
/// cap Graph's throttling of those writes pushes back on. Reads and the ARM
/// control plane (`dispatch::ARM_CONCURRENCY`) have caps of their own.
const BULK_WRITE_CONCURRENCY: usize = 4;

/// Lets the bulk drivers ([`run_bulk_seq`], [`run_bulk_capped`]) ask an opaque
/// outcome whether the run should stop.
///
/// The drivers are generic over the outcome type, so they cannot reach into an
/// `error` field themselves. Implemented per outcome rather than passed as a
/// closure at each call site so the answer can't drift between the bulk
/// commands — they all mean the same thing by "the session died".
trait BulkOutcome {
    /// True when this item failed for a reason that makes every *remaining*
    /// item fail the same way. See [`BulkError::is_reauth_fatal`].
    fn session_fatal(&self) -> bool;
}

/// The common shape: one optional structured error per outcome.
macro_rules! bulk_outcome_error_field {
    ($($ty:ty),+ $(,)?) => {$(
        impl BulkOutcome for $ty {
            fn session_fatal(&self) -> bool {
                self.error.as_ref().is_some_and(BulkError::is_reauth_fatal)
            }
        }
    )+};
}

bulk_outcome_error_field!(
    AppRemovalSummary,
    BulkCreateOutcome,
    BulkGrantOutcome,
    BulkRemoveRedundantOutcome,
    BulkScopeOutcome,
    BulkOwnerOutcome,
    BulkDisableOutcome,
    BulkStageCertOutcome,
    BulkRestoreOutcome,
);

/// A bulk delete's outcome: the deleted id, or the failure. Its code is
/// optional on the wire, so the fatal check reads it through
/// `UiError::is_reauth_fatal` rather than `BulkError`'s.
impl BulkOutcome for Result<String, BulkDeleteFailure> {
    fn session_fatal(&self) -> bool {
        self.as_ref()
            .err()
            .and_then(|failure| failure.code.as_deref())
            .is_some_and(|code| UiError::new(code, String::new(), false).is_reauth_fatal())
    }
}

impl BulkOutcome for GrantItem {
    fn session_fatal(&self) -> bool {
        self.outcome.session_fatal()
    }
}

/// What [`run_bulk_capped`] needs from one item's outcome beyond
/// [`BulkOutcome`]. `Send + 'static` because every outcome crosses back from a
/// spawned task.
trait CappedOutcome: BulkOutcome + Send + 'static {
    /// The id the item was dispatched under — matched against the dispatched
    /// list to find the tasks that never reported.
    fn object_id(&self) -> &str;

    /// The `current_app` the item's progress event carries.
    fn progress_label(&self) -> String;
}

/// The delete and grant rows label progress by object id (the bar maps ids to
/// names); the sweep holds each app's display name, so it sends that.
impl CappedOutcome for Result<String, BulkDeleteFailure> {
    fn object_id(&self) -> &str {
        match self {
            Ok(id) => id,
            Err(failure) => &failure.object_id,
        }
    }

    fn progress_label(&self) -> String {
        self.object_id().to_string()
    }
}

impl CappedOutcome for GrantItem {
    fn object_id(&self) -> &str {
        &self.outcome.object_id
    }

    fn progress_label(&self) -> String {
        self.outcome.object_id.clone()
    }
}

impl CappedOutcome for SweepItem {
    fn object_id(&self) -> &str {
        &self.summary.object_id
    }

    fn progress_label(&self) -> String {
        self.summary.display_name.clone()
    }
}

impl BulkOutcome for SweepItem {
    fn session_fatal(&self) -> bool {
        self.summary.session_fatal()
    }
}

/// One app of the expired-secret sweep: its row, plus how many of its expired
/// secrets a Cancel or a dead session stopped it from trying. That count picks
/// the row's fate in [`finish_expired_sweep`] and never reaches the bar as a
/// number: an app stopped before its first `removePassword` was never checked
/// (no row, and not in `apps_checked`), one stopped part-way gets an
/// [`INTERRUPTED`] row.
struct SweepItem {
    summary: AppRemovalSummary,
    unattempted: usize,
}

/// Rejects a bulk-create spec that cannot possibly succeed, without touching
/// Graph. Split out of the command closure so the rules are unit-testable: a
/// wrong `signInAudience` is rejected here, and letting it through instead means
/// N failed round trips and N confusing per-item errors.
fn validate_create_spec(spec: &BulkCreateSpec) -> Option<BulkCreateOutcome> {
    let invalid = |message: String| {
        Some(BulkCreateOutcome {
            display_name: spec.display_name.clone(),
            status: BulkCreateStatus::Invalid,
            app_id: None,
            message: Some(message),
            // A local rejection never reached the backend, so it carries no wire
            // code and says nothing about the session.
            error: None,
        })
    };
    if spec.display_name.trim().is_empty() {
        return invalid("display name is required".into());
    }
    if let Some(aud) = &spec.sign_in_audience
        && !VALID_AUDIENCES.contains(&aud.as_str())
    {
        return invalid(format!("unrecognised signInAudience: {aud}"));
    }
    if let Some(upn) = spec.owner_upns.iter().find(|u| !u.contains('@')) {
        return invalid(format!("owner \"{upn}\" is not a user principal name"));
    }
    for p in &spec.permissions {
        if p.kind == PermissionKind::Unknown {
            return invalid(format!(
                "permission {}: kind must be Application or Delegated",
                p.value
            ));
        }
        if resource_app_id_for(&p.resource).is_none() {
            return invalid(format!(
                "unknown resource \"{}\" — give its appId, or a resource name from the permission picker",
                p.resource
            ));
        }
    }
    None
}

/// A bulk-create permission's resource as an `appId`: a GUID as given, else a
/// bundled-directory display name (case-insensitive). Anything else is
/// unknown — guessing at a resource the operator named loosely would declare a
/// permission on the wrong API.
fn resource_app_id_for(resource: &str) -> Option<String> {
    let resource = resource.trim();
    if azapptoolkit_core::guid::is_guid(resource) {
        return Some(resource.to_ascii_lowercase());
    }
    azapptoolkit_permissions::bundled_resources_slice()
        .iter()
        .find(|r| r.display_name.eq_ignore_ascii_case(resource))
        .map(|r| r.app_id.clone())
}

/// The id of the enabled permission `value` of `kind` on a resource SP: an app
/// role an application may hold, or a delegated scope. Exact match on `value`
/// — permission values are case-sensitive identifiers.
fn permission_id_on(sp: &ServicePrincipal, value: &str, kind: PermissionKind) -> Option<String> {
    let enabled = |e: Option<bool>| e != Some(false);
    match kind {
        PermissionKind::Application => sp
            .app_roles
            .iter()
            .find(|r| {
                r.value == value
                    && enabled(r.is_enabled)
                    && r.allowed_member_types.iter().any(|t| t == "Application")
            })
            .map(|r| r.id.clone()),
        PermissionKind::Delegated => sp
            .oauth2_permission_scopes
            .iter()
            .find(|s| s.value == value && enabled(s.is_enabled))
            .map(|s| s.id.clone()),
        PermissionKind::Unknown => None,
    }
}

/// A spec's Owners and Permissions, resolved live.
#[derive(Default)]
struct ResolvedCreateExtras {
    /// `(object id, UPN)`, deduplicated by id.
    owners: Vec<(String, String)>,
    required_resource_access: Vec<RequiredResourceAccess>,
}

/// Why a spec's extras did not resolve: the directory answered and the name is
/// not there (`Invalid` — the row is wrong), or the read itself failed
/// (`Failed` — carries the code, so a dead session stops the run).
enum Unresolved {
    Invalid(String),
    Failed(UiError),
}

/// Resolves every owner UPN and permission of an already statically-valid spec,
/// **before** anything is created: an inventory row naming a departed owner or
/// a misspelt permission is rejected whole rather than half-created.
async fn resolve_create_extras(
    client: &azapptoolkit_graph::GraphClient,
    spec: &BulkCreateSpec,
) -> Result<ResolvedCreateExtras, Unresolved> {
    let mut out = ResolvedCreateExtras::default();
    for upn in &spec.owner_upns {
        match client.find_user_by_upn(upn).await {
            Ok(Some(user)) => {
                if !out.owners.iter().any(|(id, _)| *id == user.id) {
                    out.owners.push((user.id, upn.clone()));
                }
            }
            Ok(None) => return Err(Unresolved::Invalid(format!("owner {upn} not found"))),
            Err(e) => return Err(Unresolved::Failed(e.into())),
        }
    }
    for p in &spec.permissions {
        // Validated by `validate_create_spec`, which runs first.
        let Some(app_id) = resource_app_id_for(&p.resource) else {
            return Err(Unresolved::Invalid(format!(
                "unknown resource {}",
                p.resource
            )));
        };
        let sp = match client.resolve_resource_sp(&app_id).await {
            Ok(Some(sp)) => sp,
            Ok(None) => {
                return Err(Unresolved::Invalid(format!(
                    "resource {} has no service principal in this tenant",
                    p.resource
                )));
            }
            Err(e) => return Err(Unresolved::Failed(e.into())),
        };
        let Some(id) = permission_id_on(&sp, &p.value, p.kind) else {
            let kind = match p.kind {
                PermissionKind::Delegated => "delegated",
                _ => "application",
            };
            return Err(Unresolved::Invalid(format!(
                "{} exposes no enabled {kind} permission {}",
                sp.display_name, p.value
            )));
        };
        let entry_type = match p.kind {
            PermissionKind::Delegated => "Scope",
            _ => "Role",
        };
        super::permissions::declare_resource_access(
            &mut out.required_resource_access,
            &app_id,
            &id,
            entry_type,
        );
    }
    Ok(out)
}

/// The row note for owners the create core could not add, by UPN.
fn owners_not_added(failed_ids: &[String], ids: &[String], upns: &[String]) -> Option<String> {
    let failed: Vec<&str> = ids
        .iter()
        .zip(upns)
        .filter(|(id, _)| failed_ids.contains(id))
        .map(|(_, upn)| upn.as_str())
        .collect();
    (!failed.is_empty()).then(|| format!("Owner(s) not added: {}.", failed.join(", ")))
}

/// Accepted `signInAudience` values for bulk-create validation.
const VALID_AUDIENCES: &[&str] = &[
    "AzureADMyOrg",
    "AzureADMultipleOrgs",
    "AzureADandPersonalMicrosoftAccount",
    "PersonalMicrosoftAccount",
];

/// Signals every in-flight bulk action (delete / grant / create / expired-secret
/// sweep / scoping / owner / sign-in) to stop at the next item boundary. Every
/// bulk run shares the kind flag [`AppState::bulk_cancel`]: the frontend admits
/// one bar run at a time (`TenantScopedUi::bulk_running`), so in practice the
/// flag holds one run plus any Recently-deleted restore started beside it, and
/// one Cancel stops both. It never touches the security audit or the AAP
/// migration, which have flags of their own.
/// Already in-flight per-item work finishes so partial results stay clean.
#[tauri::command]
pub fn cancel_bulk(state: State<'_, AppState>) {
    state.bulk_cancel.cancel();
}

/// Sweeps app registrations and deletes any password credential (secret) that
/// is expired per [`expired_password_key_ids`]'s whole-day rule. Note this is
/// **secrets-only** by design; the per-app one-click fix
/// (`commands::remediation::remediate_remove_expired_credentials`)
/// also removes expired *certificates*.
///
/// It sweeps exactly the selected apps (the Findings pane's "Fix all" and the
/// App Registrations bulk bar): they are fetched by id in one `$batch` per 20
/// (per-id reads if a whole batch fails), never a tenant walk, and an app that
/// cannot be read is reported as a failure row rather than silently left out.
/// There is no tenant-wide form: nothing in the UI called one, and the
/// expired-credentials finding's "Fix all" already sweeps every affected app.
/// The removals fan out through [`run_bulk_capped`];
/// cancellation flows through [`AppState::bulk_cancel`], stopped by
/// [`cancel_bulk`].
#[tauri::command]
pub async fn bulk_remove_expired_credentials(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkRemoveExpiredResult, UiError> {
    // Claimed before the first await: the batched selection read is an await,
    // and a token
    // claimed after it carries a higher generation than a cancel issued during
    // it, which `is_cancelled()` then discards. Pinned by
    // `repo_invariants::cancel`.
    let cancel = state.bulk_cancel.claim();
    let client = state.graph_for(&tenant_id);
    let session = SessionDead::new();
    let mut summaries: Vec<AppRemovalSummary> = Vec::new();

    // The read projects only what the sweep reads (`expired_password_key_ids`
    // touches `passwordCredentials`); the default projection drags in
    // `requiredResourceAccess` etc. — the bulk of a permission-heavy app's
    // payload.
    let ids = &object_ids;
    let apps: Vec<Application> = {
        // The selection path fetches exactly the selected ids. It used to
        // walk every page of `/applications` and then `retain` the
        // selection — tens of seconds on a large tenant for a "Fix all 12".
        let graph = client.as_ref();
        let batched = graph.batch_get_applications_credentials(ids).await;
        let fetched = batch_or_serial(
            "expired-credential sweep app",
            ids,
            batched,
            |oid: String| async move { graph.get_application(&oid).await },
        )
        .await;
        let mut apps = Vec::with_capacity(ids.len());
        for (id, read) in ids.iter().zip(fetched) {
            match read {
                Ok(app) => apps.push(app),
                Err(err) => {
                    // A selected app that could not be read is a failure
                    // row (the frontend lists it under its id), not a
                    // silent thinning of the operator's selection. A
                    // re-auth-fatal code latches the session so the
                    // dispatch below spawns nothing, and this row's code
                    // tells the bar why the run stopped.
                    let ui = UiError::from(err);
                    session.note_code(&ui.code);
                    summaries.push(AppRemovalSummary {
                        object_id: id.clone(),
                        display_name: id.clone(),
                        removed_key_ids: Vec::new(),
                        failed_key_ids: Vec::new(),
                        error: Some(ui.into()),
                    });
                }
            }
        }
        apps
    };
    // Apps actually evaluated; a selected app that failed to read is counted in
    // `summaries`, not here.
    let total = apps.len();

    // A lost task's row names its app the way a reported one does.
    let names: HashMap<String, String> = apps
        .iter()
        .map(|app| (app.id.clone(), app.display_name.clone()))
        .collect();

    // Adaptive 429 backoff (was a fixed cap with no observer): the throttle
    // halves the in-flight cap on a 429 and recovers when quiet, and the live
    // cap is surfaced via `in_flight_cap` so the UI can show the back-off.
    let meter = FanOutMeter::attach(client.clone(), BULK_WRITE_CONCURRENCY);

    let now = chrono::Utc::now();

    let run = run_bulk_capped(
        &app_handle,
        &cancel,
        &session,
        &meter,
        apps,
        |app| app.id.clone(),
        |app| {
            let client = client.clone();
            let cancel = cancel.clone();
            let session = session.clone();
            async move { sweep_one(&client, &cancel, &session, app, now).await }
        },
    )
    .await;

    // A run the session killed partway still returns what it did: the summary
    // that latched the dead session carries the fatal code, which is what the
    // bar reads to prompt re-authentication and to say the sweep stopped,
    // instead of presenting it as complete. An error here used to throw that
    // summary away along with the removals that had landed.
    Ok(finish_expired_sweep(
        &state.cache,
        &tenant_id,
        total,
        summaries,
        run,
        |id| names.get(id).cloned().unwrap_or_else(|| id.to_string()),
    ))
}

/// One app of the expired-secret sweep: removes each secret expired at `now`,
/// one `removePassword` at a time, checking Cancel and the dead-session latch
/// before every key — an app with many expired secrets is itself a loop the
/// operator must be able to stop.
async fn sweep_one(
    client: &azapptoolkit_graph::GraphClient,
    cancel: &CancelToken,
    session: &SessionDead,
    app: Application,
    now: chrono::DateTime<chrono::Utc>,
) -> SweepItem {
    let expired_key_ids = expired_password_key_ids(&app, now);
    let Application {
        id: object_id,
        display_name,
        ..
    } = app;
    let mut removed = Vec::new();
    let mut failed = Vec::new();
    let mut error: Option<BulkError> = None;
    for key_id in &expired_key_ids {
        if cancel.is_cancelled() || session.is_dead() {
            break;
        }
        match client.remove_password(&object_id, key_id).await {
            Ok(()) => removed.push(key_id.clone()),
            Err(err) => {
                failed.push(key_id.clone());
                let ui = UiError::from(err);
                // Latch here, not only when the driver collects this app: once
                // the session is dead every remaining key on every in-flight
                // app fails identically, so the sibling tasks' key loops stop
                // too, not just the dispatch.
                let fatal = session.note_code(&ui.code);
                // The app's one error slot keeps the first failure — unless a
                // later one is fatal: that code is what the bar reads to
                // prompt re-authentication, and an earlier `not_found` in its
                // place would hide a run the session killed.
                if fatal || error.is_none() {
                    error = Some(ui.into());
                }
                if fatal {
                    break;
                }
            }
        }
    }
    // Every key the loop broke before: a Cancel, a sibling's dead-session
    // latch, or this app's own fatal failure.
    let unattempted = expired_key_ids.len() - removed.len() - failed.len();
    SweepItem {
        summary: AppRemovalSummary {
            object_id,
            display_name,
            removed_key_ids: removed,
            failed_key_ids: failed,
            error,
        },
        unattempted,
    }
}

/// Folds an expired-secret sweep's capped run into its result and drops the
/// credential tier of every app whose secrets may have changed. Split from the
/// command so the lost-task path runs in a test.
///
/// `summaries` arrives holding the selected apps that could not be read. A
/// reported app joins it when it has something to say (a removal, a failure);
/// a lost one always does, as a [`LOST_TASK`] row named through `name_of`: its
/// task ended without reporting, and some of its removals may have landed.
///
/// A Cancel or a dead session can stop a dispatched app's key loop too. One
/// stopped before its first `removePassword` was never checked: it gets no
/// row and joins the unattempted tail. One stopped part-way keeps its row,
/// marked [`INTERRUPTED`] unless it already carries a failure, since its
/// remaining expired secrets are still there.
///
/// `apps_checked` is the unreadable apps plus every app the fan-out
/// dispatched, less those never started: what the sweep reached, so the bar
/// can name the tail a Cancel or a dead session left unattempted. `summaries`
/// cannot say it (a clean app is no row) and neither can `apps_scanned` (the
/// readable selection, dispatched or not).
fn finish_expired_sweep(
    cache: &Cache,
    tenant_id: &str,
    apps_scanned: usize,
    mut summaries: Vec<AppRemovalSummary>,
    run: CappedRun<SweepItem>,
    name_of: impl Fn(&str) -> String,
) -> BulkRemoveExpiredResult {
    let CappedRun {
        outcomes,
        lost,
        dispatched,
        cancelled,
    } = run;
    // Before any reported row joins: only the unreadable apps are in it yet.
    let unreadable = summaries.len();
    let mut never_started = 0usize;
    for SweepItem {
        mut summary,
        unattempted,
    } in outcomes
    {
        let tried_any = !summary.removed_key_ids.is_empty() || !summary.failed_key_ids.is_empty();
        if unattempted > 0 && !tried_any {
            never_started += 1;
            continue;
        }
        if unattempted > 0 && summary.error.is_none() {
            summary.error = Some(BulkError {
                code: INTERRUPTED.into(),
                message: if unattempted == 1 {
                    "the run stopped before 1 more expired secret was removed; re-run to finish"
                        .into()
                } else {
                    format!(
                        "the run stopped before {unattempted} more expired secrets were removed; \
                         re-run to finish"
                    )
                },
                retryable: false,
            });
        }
        if tried_any || summary.error.is_some() {
            summaries.push(summary);
        }
    }
    let apps_checked = unreadable + dispatched - never_started;

    // Invalidate however the run ended: the removals that already landed are
    // real, so the caches are stale either way. The only mutation here is
    // `remove_password` — a credential-only
    // change — so each mutated app takes the credential tier, which keeps the
    // shared SP/app-name indexes, the enterprise list and every mailbox-scope
    // verdict intact (`applications::cache::invalidate_app_credentials` explains
    // the cost of dropping them: a full tenant re-enumeration). The shared keys
    // it does drop are hash removals, so repeating them per app is free. A lost
    // app takes the same tier: nothing says which of its removals landed.
    for mutated in summaries.iter().filter(|s| !s.removed_key_ids.is_empty()) {
        super::applications::invalidate_app_credentials(cache, tenant_id, &mutated.object_id);
    }
    for object_id in &lost {
        super::applications::invalidate_app_credentials(cache, tenant_id, object_id);
    }
    summaries.extend(lost.into_iter().map(|object_id| {
        AppRemovalSummary {
            display_name: name_of(&object_id),
            object_id,
            removed_key_ids: Vec::new(),
            failed_key_ids: Vec::new(),
            error: Some(BulkError {
                code: LOST_TASK.into(),
                message:
                    "its expired-secret removal ended without reporting an outcome; check the \
                      app's credentials before re-running"
                        .into(),
                retryable: false,
            }),
        }
    }));

    BulkRemoveExpiredResult {
        apps_scanned,
        summaries,
        cancelled,
        apps_checked: Some(apps_checked),
    }
}

/// Whether a fan-out stopped because the operator pressed Cancel. A run the
/// dead session stopped reports `cancelled: false`: its failure list carries
/// the fatal code, and "(cancelled)" beside a re-authenticate prompt would
/// describe one stop two ways. `cancelled_early` is the dispatch latch
/// (`dispatch_capped` returned early), which covers both stops; the flag is
/// re-read because a cancel that landed after the last dispatch is still a
/// cancel.
fn stopped_by_cancel(cancelled_early: bool, cancel: &CancelToken, session: &SessionDead) -> bool {
    cancel.is_cancelled() || (cancelled_early && !session.is_dead())
}

/// Deletes every application in `object_ids`, fanning out through
/// [`run_bulk_capped`] under a `ConcurrencyThrottle` that halves the in-flight
/// cap on a 429 and recovers when quiet. (This ran sequentially once; the doc
/// comment outlived the change.) Failures are collected rather than aborting —
/// the UI shows a summary dialog.
///
/// Unlike the [`run_bulk_seq`] commands, the delete core is `Send`, so it *can*
/// cross into a spawn — which is why this one fans out and those stay serial.
#[tauri::command]
pub async fn bulk_delete_applications(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkDeleteResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let cancel = state.bulk_cancel.claim();

    // Bounded-concurrency fan-out with adaptive 429 backoff, replacing the old
    // serial loop + fixed 50ms pause (which slowed the healthy case yet never
    // backed off under throttling). The throttle halves the in-flight cap on a
    // 429 and recovers when quiet; `dispatch_capped` re-reads it between
    // completions so the cap takes effect mid-run.
    let meter = FanOutMeter::attach(client.clone(), BULK_WRITE_CONCURRENCY);
    let session = SessionDead::new();
    let run = run_bulk_capped(
        &app_handle,
        &cancel,
        &session,
        &meter,
        object_ids,
        String::clone,
        |id| {
            let client = client.clone();
            async move { delete_one(&client, id).await }
        },
    )
    .await;

    // Writes have landed, so the result is returned however the run ended: a
    // run the session killed partway reports the ids it deleted (they leave
    // the selection and can be restored) beside the failure that carries the
    // fatal code, which is what the bar reads to prompt re-authentication. An
    // error here used to drop `deleted` on the floor — the apps were gone,
    // the selection still held them, and there was no Undo.
    Ok(finish_bulk_delete(&state.cache, &tenant_id, run))
}

/// One bulk DELETE: the id on success, else a failure carrying the error's
/// wire code, classified here while the typed error still exists so the bar
/// can tell a dead session from an app-level failure.
async fn delete_one(
    client: &azapptoolkit_graph::GraphClient,
    object_id: String,
) -> Result<String, BulkDeleteFailure> {
    match client.delete_application(&object_id).await {
        Ok(()) => Ok(object_id),
        Err(err) => {
            let ui = UiError::from(err);
            Err(BulkDeleteFailure {
                object_id,
                message: ui.message,
                code: Some(ui.code),
            })
        }
    }
}

/// Folds a bulk delete's capped run into its result and updates the caches.
/// Split from the command so the lost-task path runs in a test.
fn finish_bulk_delete(
    cache: &Cache,
    tenant_id: &str,
    run: CappedRun<Result<String, BulkDeleteFailure>>,
) -> BulkDeleteResult {
    let CappedRun {
        outcomes,
        lost,
        dispatched: _,
        cancelled,
    } = run;
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(id) => deleted.push(id),
            Err(failure) => failed.push(failure),
        }
    }

    // A dispatched app that is in neither list lost its task. Reporting it as
    // a failure (rather than leaving it out) keeps the bar's "N were never
    // attempted" note honest: that app WAS attempted, and its DELETE may have
    // landed, so the operator is told to look rather than to re-run blind.
    let lost_any = !lost.is_empty();
    failed.extend(lost.into_iter().map(|object_id| {
        BulkDeleteFailure {
            object_id,
            message: "its delete ended without reporting an outcome; check Recently deleted \
                  before re-running"
                .into(),
            code: Some(LOST_TASK.into()),
        }
    }));

    // Update the caches first: the deletions that landed are real regardless of
    // how the run ended (see the sweep above). A clean run removes exactly the
    // deleted rows. A failed DELETE may still have landed, and only a rescan
    // can tell, so a run with deletions and failures busts the list tier — and
    // so does a lost task on its own, which reports no deletion to patch.
    if lost_any || (!deleted.is_empty() && !failed.is_empty()) {
        super::applications::invalidate_app_lists(cache, tenant_id);
    } else if !deleted.is_empty() {
        super::applications::record_deleted_apps(cache, tenant_id, &deleted);
    }
    BulkDeleteResult {
        deleted,
        failed,
        cancelled,
    }
}

/// Grants admin consent to each application in `object_ids`, reusing the same
/// orchestration as the single-app command. Bounded-concurrency fan-out through
/// [`run_bulk_capped`] with adaptive 429 backoff (each app issues several Graph
/// writes, so the throttle matters); cancellation rides
/// [`AppState::bulk_cancel`] and progress the shared `bulk-progress` stream.
#[tauri::command]
pub async fn bulk_grant_permissions(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkGrantResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let cancel = state.bulk_cancel.claim();

    // Bounded-concurrency fan-out with adaptive 429 backoff, replacing the old
    // serial loop + fixed 50ms pause. Each grant is a multi-write orchestration,
    // so backing off the in-flight cap under throttling matters more here than
    // for the delete sweep.
    let meter = FanOutMeter::attach(client.clone(), BULK_WRITE_CONCURRENCY);
    let session = SessionDead::new();
    let run = run_bulk_capped(
        &app_handle,
        &cancel,
        &session,
        &meter,
        object_ids,
        String::clone,
        |id| {
            let client = client.clone();
            async move {
                let res = super::permissions::grant_admin_consent_core(&client, &id).await;
                grant_item(id, res)
            }
        },
    )
    .await;

    // Bust first (the grants that landed are real), then return what landed
    // however the run ended: the outcome that latched the dead session carries
    // the fatal code, which is what the bar reads to prompt re-authentication
    // instead of presenting the remainder as consented.
    Ok(finish_bulk_grant(&state.cache, &tenant_id, run))
}

/// One consent grant's outcome, plus whether it created the app's client
/// service principal — which picks the run's cache tier and never reaches the
/// bar.
struct GrantItem {
    outcome: BulkGrantOutcome,
    sp_created: bool,
}

/// Maps the single-app consent core's result onto one bulk row.
fn grant_item(object_id: String, res: Result<super::permissions::GrantRun, UiError>) -> GrantItem {
    let failed_outright = |object_id: String, error: UiError, sp_created: bool| GrantItem {
        outcome: BulkGrantOutcome {
            object_id,
            granted: 0,
            skipped: 0,
            failed: 0,
            error: Some(error.into()),
        },
        sp_created,
    };
    match res {
        // The client SP was created and a later step failed: the row reports
        // the error, and `sp_created` still reaches the run's cache tier so the
        // new Enterprise App row is busted.
        Ok(super::permissions::GrantRun {
            error: Some(e),
            sp_created,
            ..
        }) => failed_outright(object_id, e, sp_created),
        Ok(run) => {
            let r = run.result;
            GrantItem {
                outcome: BulkGrantOutcome {
                    object_id,
                    granted: r.role_assignments_created.len() + r.scope_grants_upserted.len(),
                    skipped: r.role_assignments_skipped.len(),
                    failed: r.failures.len(),
                    error: r.failures.first().map(|f| BulkError {
                        code: "partial_failure".into(),
                        message: f.message.clone(),
                        retryable: false,
                    }),
                },
                sp_created: run.sp_created,
            }
        }
        Err(e) => failed_outright(object_id, e, false),
    }
}

/// Folds a bulk consent grant's capped run into its result and updates the
/// caches. Split from the command so the lost-task path runs in a test.
fn finish_bulk_grant(cache: &Cache, tenant_id: &str, run: CappedRun<GrantItem>) -> BulkGrantResult {
    let CappedRun {
        outcomes: items,
        lost,
        dispatched: _,
        cancelled,
    } = run;
    // True if any app's grant created a brand-new SP — that adds Enterprise App
    // rows / search-index entries, so the run must bust the full list caches.
    let mut any_sp_created = items.iter().any(|item| item.sp_created);
    let mut outcomes: Vec<BulkGrantOutcome> = items.into_iter().map(|item| item.outcome).collect();

    // A dispatched app with no outcome lost its task; some of its grant writes
    // may have landed — the client SP included, so the list tier is busted as
    // if one had been created. Reported as a failure so the bar's "never
    // attempted" note stays honest and the operator re-checks the app rather
    // than re-running blind.
    any_sp_created |= !lost.is_empty();
    outcomes.extend(lost.into_iter().map(|object_id| {
        BulkGrantOutcome {
            object_id,
            granted: 0,
            skipped: 0,
            failed: 0,
            error: Some(BulkError {
                code: LOST_TASK.into(),
                message: "its consent grant ended without reporting an outcome; check the app's \
                      permissions before re-running"
                    .into(),
                retryable: false,
            }),
        }
    }));

    // Consent really changed app-role/scope state for any app that granted >0, so
    // bust the detail + audit caches exactly like the single-app path
    // (permissions::grant_admin_consent). If any grant created a new SP, bust
    // the full list caches instead (new Enterprise App row / search-index
    // entry), matching grant_single_permission.
    if any_sp_created {
        super::applications::invalidate_app_lists(cache, tenant_id);
    } else if outcomes.iter().any(|o| o.granted > 0) {
        super::applications::invalidate_app_detail_state(cache, tenant_id);
    }
    BulkGrantResult {
        outcomes,
        cancelled,
    }
}

/// Creates each application in `specs`, reusing the single-app create path.
/// `validate_only` checks each spec (non-empty name, recognised
/// `signInAudience`) and reports without creating anything.
#[tauri::command]
pub async fn bulk_create_applications(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    specs: Vec<BulkCreateSpec>,
    validate_only: bool,
) -> Result<BulkCreateResult, UiError> {
    let cancel = state.bulk_cancel.claim();
    let client = state.graph_for(&tenant_id);
    // The registrations that landed cleanly, as Graph returned them, so the
    // list caches can be patched instead of rescanned.
    let created = parking_lot::Mutex::new(Vec::<Application>::new());
    // A registration that landed with a later step failed: see below.
    let partial = std::sync::atomic::AtomicBool::new(false);

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        specs,
        |spec| spec.display_name.clone(),
        |spec| {
            let client = client.clone();
            let (created, partial) = (&created, &partial);
            async move {
                if let Some(rejection) = validate_create_spec(&spec) {
                    return rejection;
                }
                // Resolved in a validate-only run too: "valid" has to mean every
                // owner and permission exists, or the dry run proves nothing
                // about an imported inventory. A spec without either makes no
                // Graph call here.
                let extras = match resolve_create_extras(&client, &spec).await {
                    Ok(extras) => extras,
                    Err(Unresolved::Invalid(message)) => {
                        return BulkCreateOutcome {
                            display_name: spec.display_name,
                            status: BulkCreateStatus::Invalid,
                            app_id: None,
                            message: Some(message),
                            error: None,
                        };
                    }
                    Err(Unresolved::Failed(e)) => {
                        return BulkCreateOutcome {
                            display_name: spec.display_name,
                            status: BulkCreateStatus::Failed,
                            app_id: None,
                            message: Some(e.message.clone()),
                            error: Some(e.into()),
                        };
                    }
                };
                if validate_only {
                    return BulkCreateOutcome {
                        display_name: spec.display_name,
                        status: BulkCreateStatus::Valid,
                        app_id: None,
                        message: None,
                        error: None,
                    };
                }
                let (owner_ids, owner_upns): (Vec<String>, Vec<String>) =
                    extras.owners.into_iter().unzip();
                let input = CreateApplicationInput {
                    display_name: spec.display_name.clone(),
                    sign_in_audience: spec.sign_in_audience,
                    description: spec.description,
                    initial_owner_ids: owner_ids.clone(),
                    ..Default::default()
                };
                let extras = super::applications::CreateExtras {
                    required_resource_access: extras.required_resource_access,
                    ..Default::default()
                };
                match super::applications::create_application_core_with(&client, input, extras)
                    .await
                {
                    // An owner add that failed without stopping the run (not
                    // re-auth-fatal) is listed on the row by UPN — the app is
                    // there, but not as the inventory described it.
                    Ok((r, None)) => {
                        created.lock().push(r.application.clone());
                        BulkCreateOutcome {
                            message: owners_not_added(&r.failed_owner_ids, &owner_ids, &owner_upns),
                            display_name: r.application.display_name,
                            status: BulkCreateStatus::Created,
                            app_id: Some(r.application.app_id),
                            error: None,
                        }
                    }
                    // The registration landed and a later step failed: the app
                    // exists (so the list caches change below) and the error
                    // still reaches the row — and `run_bulk_seq`, which stops
                    // on a re-auth-fatal code.
                    Ok((r, Some(e))) => {
                        partial.store(true, std::sync::atomic::Ordering::Relaxed);
                        BulkCreateOutcome {
                            display_name: r.application.display_name,
                            status: BulkCreateStatus::Created,
                            app_id: Some(r.application.app_id),
                            message: Some(
                                match owners_not_added(&r.failed_owner_ids, &owner_ids, &owner_upns)
                                {
                                    Some(owners) => format!("{} {owners}", e.message),
                                    None => e.message.clone(),
                                },
                            ),
                            error: Some(e.into()),
                        }
                    }
                    Err(e) => BulkCreateOutcome {
                        display_name: spec.display_name,
                        status: BulkCreateStatus::Failed,
                        app_id: None,
                        message: Some(e.message.clone()),
                        error: Some(e.into()),
                    },
                }
            }
        },
    )
    .await;

    // Every clean create is patched into the cached lists, so the reload that
    // follows is a cache hit. A partial create busts the list tier instead,
    // because the failed step may still have landed.
    if partial.into_inner() {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
    } else {
        let created = created.into_inner();
        if !created.is_empty() {
            let rows: Vec<_> = created
                .iter()
                .map(|application| super::applications::CreatedApp {
                    application,
                    service_principal: None,
                    added_password: None,
                })
                .collect();
            super::applications::record_created_apps(&state.cache, &tenant_id, &rows);
        }
    }
    Ok(BulkCreateResult {
        validate_only,
        outcomes,
        cancelled,
    })
}

/// Removes each selected app's *redundant* application permissions, reusing the
/// single-app remediation core ([`remediation::remediate_remove_redundant_permissions_core`])
/// so the live re-resolution + safety rules + per-app cache invalidation are
/// identical to the one-click fix. Runs sequentially (each call is a multi-read
/// manifest re-plan, and the selection is the admin's hand-picked set), polling
/// [`AppState::bulk_cancel`] between apps and degrading to a per-app `error` rather
/// than aborting. No `in_flight_cap` — there's no concurrent fan-out to back off.
#[tauri::command]
pub async fn bulk_remove_redundant_permissions(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkRemoveRedundantResult, UiError> {
    let cancel = state.bulk_cancel.claim();

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        object_ids,
        |id| id.clone(),
        |object_id| {
            let state = state.clone();
            let tenant_id = tenant_id.clone();
            async move {
                match super::remediation::remediate_remove_redundant_permissions_core(
                    &state, &tenant_id, &object_id,
                )
                .await
                {
                    Ok(r) => BulkRemoveRedundantOutcome {
                        object_id,
                        removed: r.removed,
                        skipped: r.skipped,
                        error: None,
                    },
                    Err(e) => BulkRemoveRedundantOutcome {
                        object_id,
                        removed: Vec::new(),
                        skipped: Vec::new(),
                        error: Some(e.into()),
                    },
                }
            }
        },
    )
    .await;

    Ok(BulkRemoveRedundantResult {
        outcomes,
        cancelled,
    })
}

/// Confines each selected app's org-wide mailbox permissions to the supplied
/// `groups` via Exchange RBAC, reusing the shared scoping core
/// ([`exchange::grant_exchange_mailbox_access`]) with `permissions: None` so
/// **every** mail permission the app holds is scoped (the bulk semantic — one
/// uniform group set across the whole selection). Grant-before-strip keeps each
/// app reachable; the core busts caches per app. Sequential + cancel-aware;
/// degrades to a per-app `error` (e.g. the signed-in user isn't an Exchange
/// admin) instead of aborting the run.
#[tauri::command]
pub async fn bulk_scope_mailbox_access(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
    groups: Vec<String>,
) -> Result<BulkScopeResult, UiError> {
    let cancel = state.bulk_cancel.claim();

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        object_ids,
        |id| id.clone(),
        |object_id| {
            let state = state.clone();
            let tenant_id = tenant_id.clone();
            let groups = groups.clone();
            async move {
                let error = super::exchange::grant_exchange_mailbox_access(
                    state,
                    tenant_id,
                    object_id.clone(),
                    None,
                    groups,
                    true,
                )
                .await
                .err()
                .map(BulkError::from);
                BulkScopeOutcome { object_id, error }
            }
        },
    )
    .await;

    Ok(BulkScopeResult {
        outcomes,
        cancelled,
    })
}

/// Converts each selected app's org-wide `Sites.*` access to the
/// `Sites.Selected` model on the supplied `site_urls` + `role`, reusing the
/// single-app remediation ([`remediation::remediate_scope_sharepoint_access`])
/// so the SP resolution, grant-before-strip, and cache busting match the
/// one-click fix. Sequential + cancel-aware; per-app `error` on failure (e.g.
/// `consent_required` when the SharePoint scope isn't consented).
#[tauri::command]
pub async fn bulk_scope_sharepoint_access(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
    site_urls: Vec<String>,
    role: String,
) -> Result<BulkScopeResult, UiError> {
    let cancel = state.bulk_cancel.claim();

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        object_ids,
        |id| id.clone(),
        |object_id| {
            let state = state.clone();
            let tenant_id = tenant_id.clone();
            let site_urls = site_urls.clone();
            let role = role.clone();
            async move {
                let error = super::remediation::remediate_scope_sharepoint_access(
                    state,
                    tenant_id,
                    object_id.clone(),
                    site_urls,
                    role,
                )
                .await
                .err()
                .map(BulkError::from);
                BulkScopeOutcome { object_id, error }
            }
        },
    )
    .await;

    Ok(BulkScopeResult {
        outcomes,
        cancelled,
    })
}

/// Adds `principal_id` as an owner of each selected app. Reuses the same
/// mutation as the per-app path (`add_application_owner`'s core), pre-reading
/// each app's live owners so an existing owner is reported `skipped` instead of
/// tripping Graph's already-an-owner 400. Sequential + cancel-aware (the
/// selection is a small admin-chosen set); degrades to a per-app `error`. One
/// detail-state invalidation after the loop covers detail + audit for every
/// changed app (owners are on no list payload).
#[tauri::command]
pub async fn bulk_add_owner(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
    principal_id: String,
) -> Result<BulkAddOwnerResult, UiError> {
    let cancel = state.bulk_cancel.claim();
    let client = state.graph_for(&tenant_id);

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        object_ids,
        |id| id.clone(),
        |object_id| {
            let client = client.clone();
            let principal_id = principal_id.clone();
            async move {
                match client.list_owners(&object_id).await {
                    Ok(owners) if owners.iter().any(|o| o.id == principal_id) => BulkOwnerOutcome {
                        object_id,
                        added: false,
                        skipped: true,
                        error: None,
                    },
                    Ok(_) => match client.add_owner(&object_id, &principal_id).await {
                        Ok(()) => BulkOwnerOutcome {
                            object_id,
                            added: true,
                            skipped: false,
                            error: None,
                        },
                        Err(e) => BulkOwnerOutcome {
                            object_id,
                            added: false,
                            skipped: false,
                            error: Some(UiError::from(e).into()),
                        },
                    },
                    Err(e) => BulkOwnerOutcome {
                        object_id,
                        added: false,
                        skipped: false,
                        error: Some(UiError::from(e).into()),
                    },
                }
            }
        },
    )
    .await;

    // One detail-state bust covers detail + audit for every changed app (owners
    // are on no list payload). Derived from the outcomes after the run.
    if outcomes.iter().any(|o| o.added) {
        super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    Ok(BulkAddOwnerResult {
        outcomes,
        cancelled,
    })
}

/// Disables sign-in for each selected (unused) app by looping the single-app
/// remediation ([`remediation::remediate_disable_sign_in`]) so the SP
/// resolution, reversibility semantics, and cache busting match the one-click
/// fix. Sequential + cancel-aware; per-app `error` on failure (e.g. an app
/// with no service principal).
#[tauri::command]
pub async fn bulk_disable_sign_in(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkDisableSignInResult, UiError> {
    let cancel = state.bulk_cancel.claim();

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        object_ids,
        |id| id.clone(),
        |object_id| {
            let state = state.clone();
            let tenant_id = tenant_id.clone();
            async move {
                let error = super::remediation::remediate_disable_sign_in(
                    state,
                    tenant_id,
                    object_id.clone(),
                )
                .await
                .err()
                .map(BulkError::from);
                BulkDisableOutcome { object_id, error }
            }
        },
    )
    .await;

    Ok(BulkDisableSignInResult {
        outcomes,
        cancelled,
    })
}

/// Restores deleted applications from the recycle bin — the Undo path behind
/// the bulk-delete confirmation and the "Recently deleted" dialog.
///
/// Restoring an application does NOT restore its paired service principals
/// (Graph documents the cascade as absent), and an app without its SP cannot
/// be assigned or signed in to, so each restore carries its paired deleted SPs
/// along. The pairing pre-read is best-effort: if the recycle-bin reads fail,
/// the run degrades to app-only restores (logged) rather than failing every
/// Undo outright.
///
/// Sequential on purpose (small admin-chosen selections, and an SP restore must
/// follow its app's) and cancel-aware; a re-auth-fatal code stops the run via
/// [`BulkOutcome::session_fatal`] like every other bulk command. The name is
/// `bulk_*` and it rides `state.bulk_cancel` so the existing `cancel_bulk`
/// stops it — the shape `repo_invariants::cancel` pins.
#[tauri::command]
pub async fn bulk_restore_deleted(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkRestoreResult, UiError> {
    // Claim before the first await (pinned by `repo_invariants::cancel`).
    let cancel = state.bulk_cancel.claim();
    let client = state.graph_for(&tenant_id);

    // Pairing + progress labels both come from the recycle-bin reads, done
    // once up front instead of per item. Truncation is ignored deliberately:
    // a capped bin read still pairs everything it saw; a restore beyond the
    // cap just lands as an app-only outcome the user can re-run.
    let pair_read = async {
        let (apps, _apps_truncated) = client.list_deleted_applications(DELETED_APPS_MAX).await?;
        let names: HashMap<String, String> = apps
            .iter()
            .map(|a| {
                (
                    a.id.clone(),
                    a.display_name.clone().unwrap_or_else(|| a.id.clone()),
                )
            })
            .collect();
        let (sps, _sps_truncated) = client
            .list_deleted_service_principals(DELETED_SPS_MAX)
            .await?;
        Ok::<_, azapptoolkit_graph::GraphError>((sp_pairs_for(&apps, &sps), names))
    };
    let (pairs, names) = match pair_read.await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "recycle-bin pairing pre-read failed; restoring apps without their paired \
                 service principals: {e}"
            );
            (HashMap::new(), HashMap::new())
        }
    };

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        object_ids,
        |id| names.get(id).cloned().unwrap_or_else(|| id.clone()),
        |object_id| {
            let client = client.clone();
            // Resolve the SP list before the async block so the pairing map is
            // not held across the awaits.
            let sp_ids: Vec<String> = pairs.get(&object_id).cloned().unwrap_or_default();
            async move {
                match client.restore_deleted_item(&object_id).await {
                    Err(e) => BulkRestoreOutcome {
                        object_id,
                        restored: false,
                        sp_restored: false,
                        error: Some(UiError::from(e).into()),
                    },
                    Ok(()) => {
                        // Paired SPs restore after their app, serially and
                        // fail-stop within the item: a second failure would
                        // only add noise, and the app — the user's target —
                        // is already back.
                        let mut sp_restored = false;
                        let mut error = None;
                        for sp_id in sp_ids {
                            match client.restore_deleted_item(&sp_id).await {
                                Ok(()) => sp_restored = true,
                                Err(e) => {
                                    error = Some(UiError::from(e).into());
                                    break;
                                }
                            }
                        }
                        BulkRestoreOutcome {
                            object_id,
                            restored: true,
                            sp_restored,
                            error,
                        }
                    }
                }
            }
        },
    )
    .await;

    // Restored apps are back in the live set: bust the list caches so the
    // App Registrations list and the pairing joins re-read. (The recycle bin
    // itself is never cached — see `commands::applications::deleted`.)
    if outcomes.iter().any(|o| o.restored) {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
    }

    Ok(BulkRestoreResult {
        outcomes,
        cancelled,
    })
}

/// Groups deleted service principals under the deleted application they pair
/// with (by `appId`). An SP entry that reports no `appId` — Graph's
/// "limited info" recycle-bin shape — cannot be paired and is left alone:
/// restoring it blindly could revive a principal whose app was never selected.
/// Apps with no pairing entry get none, which is the correct answer when the
/// SP was never deleted or its app id is unknown.
fn sp_pairs_for(
    apps: &[DeletedApplication],
    sps: &[DeletedServicePrincipal],
) -> HashMap<String, Vec<String>> {
    let mut by_app_id: HashMap<&str, Vec<&str>> = HashMap::new();
    for sp in sps {
        if let Some(app_id) = sp.app_id.as_deref() {
            by_app_id.entry(app_id).or_default().push(&sp.id);
        }
    }
    apps.iter()
        .filter_map(|a| {
            let ids = a.app_id.as_deref().and_then(|id| by_app_id.get(id))?;
            Some((a.id.clone(), ids.iter().map(|s| (*s).to_string()).collect()))
        })
        .collect()
}

/// Stages a fresh SAML token-signing certificate on each selected service
/// principal — **without activating any of them**.
///
/// This is the one rollover phase that is safe to run across many apps at once:
/// a staged certificate is additive and inactive, so nothing changes for users
/// until someone activates it per app. Activation stays deliberately per-app and
/// gated — flipping `preferredTokenSigningKeyThumbprint` across a selection would
/// be a coordinated outage, not a bulk action.
///
/// Re-resolves each app's live rollover state first and **skips** one that
/// already has a valid replacement staged, so re-running over a filter that
/// still lists a half-finished rollover doesn't mint a second spare certificate
/// on every pass.
///
/// Sequential + cancel-aware like the other bulk remediations, reusing the same
/// [`sso::mint_signing_certificate`] core as the create flow, the one-shot
/// rotate, and the per-app stage — so the subject and lifetime rules can't drift
/// between them.
///
/// [`sso::mint_signing_certificate`]: super::sso
#[tauri::command]
pub async fn bulk_stage_sso_certificates(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_ids: Vec<String>,
    subject: String,
    lifetime_days: Option<u32>,
) -> Result<BulkStageCertResult, UiError> {
    // Claimed once, before any suspension point: a token claimed later carries a
    // higher generation than a cancel issued in the meantime, which
    // `is_cancelled()` then discards. Pinned by `repo_invariants::cancel`.
    let cancel = state.bulk_cancel.claim();

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        service_principal_ids,
        |id| id.clone(),
        |sp_id| {
            let state = state.clone();
            let tenant_id = tenant_id.clone();
            let subject = subject.clone();
            async move {
                match super::sso::stage_if_not_already(
                    &state,
                    &tenant_id,
                    &sp_id,
                    &subject,
                    lifetime_days,
                )
                .await
                {
                    Ok(Some(cert)) => BulkStageCertOutcome {
                        object_id: sp_id,
                        thumbprint: Some(cert.thumbprint),
                        skipped: false,
                        error: None,
                    },
                    Ok(None) => BulkStageCertOutcome {
                        object_id: sp_id,
                        thumbprint: None,
                        skipped: true,
                        error: None,
                    },
                    Err(e) => BulkStageCertOutcome {
                        object_id: sp_id,
                        thumbprint: None,
                        skipped: false,
                        error: Some(BulkError::from(e)),
                    },
                }
            }
        },
    )
    .await;

    // The per-app core busts the board on each success, so this is belt-and-
    // braces for a run that staged nothing — but a cancelled run that DID stage
    // some must still leave the board truthful about those.
    if outcomes.iter().any(|o| o.thumbprint.is_some()) {
        super::sso::invalidate_sso_cert_board_by_cache(&state.cache, &tenant_id);
    }

    Ok(BulkStageCertResult {
        outcomes,
        cancelled,
    })
}

/// Shared scaffold for the **sequential** bulk commands — all eight: create /
/// remove-redundant / scope-mailbox / scope-sharepoint / add-owner /
/// disable-sign-in / restore-deleted / stage-SSO-certificates. These stay
/// sequential on purpose: most per-app cores take `State` or borrow the
/// command's locals (not `Send + 'static`, so they can't cross into a
/// `dispatch_capped` spawn), and the selection is a small admin-chosen set —
/// the win here is dedup, not concurrency. The three bulk writes whose work is
/// `Send` fan out through [`run_bulk_capped`] instead.
///
/// Runs `per_item` on each `items` element in order, emitting a `bulk-progress`
/// event (`done = i`, `in_flight_cap: None` — there's no fan-out to back off)
/// with `label(&item)` as the current app *before* each item, then a terminal
/// event whose `done` is the number of items actually processed (equal to
/// `total` only for a run that finished; a cancelled or session-halted run
/// reports how far it got). Polls the run's `CancelToken` between items
/// (already in-flight work finishes). Returns `(outcomes, cancelled)`; callers
/// apply their own cache invalidation from the outcomes. The caller claims the
/// token once, before its first await (pinned by `repo_invariants::cancel`),
/// and passes it in.
///
/// Takes a [`ProgressSink`] rather than an `&AppHandle` so the loop runs in a
/// test; see `progress::ProgressSink` for why that is the seam.
async fn run_bulk_seq<S: ProgressSink, T, O, Fut>(
    progress: &S,
    cancel: &CancelToken,
    items: Vec<T>,
    label: impl Fn(&T) -> String,
    per_item: impl Fn(T) -> Fut,
) -> (Vec<O>, bool)
where
    Fut: Future<Output = O>,
    O: BulkOutcome,
{
    let total = items.len();
    let mut outcomes = Vec::with_capacity(total);
    for (i, item) in items.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit_progress(
            progress,
            crate::dto::events::BULK_PROGRESS,
            BulkProgress {
                done: i,
                total,
                current_app: Some(label(&item)),
                cancelled: false,
                in_flight_cap: None,
            },
        );
        let outcome = per_item(item).await;
        // Stop the run when the SESSION died rather than this item. A dead
        // refresh token can't be re-minted silently, so every remaining item
        // would fail identically — turning one recoverable "re-authenticate"
        // into a wall of N indistinguishable failures, after mutating nothing.
        // Halting leaves the already-processed outcomes intact and surfaces the
        // fatal code to the UI, which drives in-place re-auth (never a sign-out
        // — that would drop every data cache; see AGENTS.md).
        let fatal = outcome.session_fatal();
        outcomes.push(outcome);
        if fatal {
            break;
        }
    }
    emit_progress(
        progress,
        crate::dto::events::BULK_PROGRESS,
        BulkProgress {
            done: outcomes.len(),
            total,
            current_app: None,
            cancelled: cancel.is_cancelled(),
            in_flight_cap: None,
        },
    );
    (outcomes, cancel.is_cancelled())
}

/// What [`run_bulk_capped`] hands back to its command.
struct CappedRun<O> {
    /// Every outcome a task reported, in completion order.
    outcomes: Vec<O>,
    /// Ids that were dispatched but whose task never reported (a panic or an
    /// abort). Its write may have landed, so the command reports each one as a
    /// [`LOST_TASK`] failure row and treats that app as mutated.
    lost: Vec<String>,
    /// How many items were dispatched: below `items.len()` only when Cancel or
    /// the dead session stopped the spawn gate. Delete and grant read their
    /// reach off their outcome lists; the expired-secret sweep cannot (a clean
    /// app reports nothing worth a row), so it reports this instead.
    dispatched: usize,
    /// Stopped by the operator's Cancel — never by the dead session, whose
    /// fatal code rides the outcomes instead (see [`stopped_by_cancel`]).
    cancelled: bool,
}

/// Shared scaffold for the **capped** bulk writes — delete, consent grant and
/// the expired-secret sweep — whose per-item work is `Send`, so it fans out
/// through [`dispatch_capped`] under the command's [`FanOutMeter`]. It replaces
/// three hand copies that had drifted: only two reconciled a lost task, so a
/// lost sweep task left the secrets it had removed in the credential caches.
///
/// It owns what the three share:
/// - the initial `done: 0` event, one event per joined task, and a terminal
///   event whose `done` counts every joined task (equal to `total` only for a
///   run that finished), each carrying the live cap;
/// - the spawn gate, `cancel.is_cancelled() || session.is_dead()`: a Cancel
///   or a dead session stops dispatch while the tasks in flight drain;
/// - the dead-session latch, noted from each outcome's
///   [`BulkOutcome::session_fatal`];
/// - the dispatched list (its length is `dispatched`), and `lost` =
///   dispatched − reported;
/// - `cancelled`, through [`stopped_by_cancel`].
///
/// It ticks and emits on the collect side, which the dispatcher runs serially,
/// so `done` never steps backwards (a task that ticked and emitted itself could
/// emit 6 before 5) and the sink need not be `Clone + Send` — a test passes the
/// `Recorder`. Each command keeps its own `FanOutMeter::attach` (the throttle
/// observer lives as long as the command) and its own cache tier. A task may
/// still note the latch itself: the sweep's does, so its siblings' key loops
/// stop between keys. The caller claims the token once, before its first
/// await (pinned by `repo_invariants::cancel`), and passes it in.
async fn run_bulk_capped<S, T, O, Fut>(
    progress: &S,
    cancel: &CancelToken,
    session: &SessionDead,
    meter: &FanOutMeter,
    items: Vec<T>,
    id_of: impl Fn(&T) -> String,
    per_item: impl Fn(T) -> Fut,
) -> CappedRun<O>
where
    S: ProgressSink,
    O: CappedOutcome,
    Fut: Future<Output = O> + Send + 'static,
{
    let total = items.len();
    emit_progress(
        progress,
        crate::dto::events::BULK_PROGRESS,
        BulkProgress {
            done: 0,
            total,
            current_app: None,
            cancelled: false,
            in_flight_cap: Some(meter.limit()),
        },
    );
    let ticker = meter.ticker();
    let mut outcomes: Vec<O> = Vec::with_capacity(total);
    // Every id a task was spawned for. A task that never reported back (a
    // panic or abort) may still have landed its write, and the only way to
    // name that app afterwards is to remember what was dispatched: a join
    // error carries no id.
    let mut dispatched: Vec<String> = Vec::new();
    let cancelled_early = dispatch_capped(
        items,
        || meter.limit(),
        |item| {
            if cancel.is_cancelled() || session.is_dead() {
                return None;
            }
            dispatched.push(id_of(&item));
            Some(tokio::spawn(per_item(item)))
        },
        |joined| {
            let (done, in_flight_cap) = ticker.tick();
            let current_app = match joined {
                Ok(outcome) => {
                    session.note_fatal(outcome.session_fatal());
                    let label = outcome.progress_label();
                    outcomes.push(outcome);
                    Some(label)
                }
                Err(err) => {
                    tracing::warn!(?err, "bulk task ended without reporting an outcome");
                    None
                }
            };
            emit_progress(
                progress,
                crate::dto::events::BULK_PROGRESS,
                BulkProgress {
                    done,
                    total,
                    current_app,
                    cancelled: cancel.is_cancelled(),
                    in_flight_cap: Some(in_flight_cap),
                },
            );
        },
    )
    .await;

    let dispatched_count = dispatched.len();
    // Dispatched minus reported. The set borrows the reported ids, so it is
    // scoped to end before `outcomes` moves into the result.
    let lost: Vec<String> = {
        let reported: HashSet<&str> = outcomes.iter().map(CappedOutcome::object_id).collect();
        dispatched
            .into_iter()
            .filter(|id| !reported.contains(id.as_str()))
            .collect()
    };
    let cancelled = stopped_by_cancel(cancelled_early, cancel, session);
    emit_progress(
        progress,
        crate::dto::events::BULK_PROGRESS,
        BulkProgress {
            // Every spawned task has joined, so the meter's count is final.
            done: meter.done(),
            total,
            current_app: None,
            cancelled,
            in_flight_cap: Some(meter.limit()),
        },
    );
    CappedRun {
        outcomes,
        lost,
        dispatched: dispatched_count,
        cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests build their own runs; the commands only ever hold a token.
    use crate::commands::test_support::Recorder;
    use crate::dto::bulk::BulkCreatePermission;
    use crate::state::CancelFlag;

    fn del_app(id: &str, app_id: Option<&str>) -> DeletedApplication {
        DeletedApplication {
            id: id.into(),
            app_id: app_id.map(str::to_string),
            display_name: None,
            deleted_date_time: None,
        }
    }

    fn del_sp(id: &str, app_id: Option<&str>) -> DeletedServicePrincipal {
        DeletedServicePrincipal {
            id: id.into(),
            app_id: app_id.map(str::to_string),
            display_name: None,
        }
    }

    #[test]
    fn sp_pairs_groups_by_app_id_and_skips_unpairable() {
        let apps = vec![
            del_app("app-1", Some("1111")),
            // Limited-info app (no appId): nothing can be paired to it.
            del_app("app-2", None),
        ];
        let sps = vec![
            del_sp("sp-1", Some("1111")),
            del_sp("sp-2", Some("1111")),
            // Limited-info SP shape — no appId to join on.
            del_sp("sp-3", None),
            // Orphan: its app is not part of this run's recycle-bin read.
            del_sp("sp-4", Some("2222")),
        ];
        let pairs = sp_pairs_for(&apps, &sps);
        assert_eq!(
            pairs.get("app-1").map(|v| v.as_slice()),
            Some(&["sp-1".to_string(), "sp-2".to_string()][..])
        );
        assert!(!pairs.contains_key("app-2"));
        // A degraded (or simply empty) pre-read yields no pairings at all, so
        // the run degrades to app-only restores rather than wrong restores.
        assert!(sp_pairs_for(&[], &sps).is_empty());
    }

    fn err(code: &str) -> BulkError {
        BulkError {
            code: code.into(),
            message: format!("{code} happened"),
            retryable: false,
        }
    }

    fn scope_outcome(object_id: &str, error: Option<BulkError>) -> BulkScopeOutcome {
        BulkScopeOutcome {
            object_id: object_id.into(),
            error,
        }
    }

    /// `(done, current_app)` per `bulk-progress` event, in order.
    fn events(rec: &Recorder) -> Vec<(usize, Option<String>)> {
        rec.payloads::<BulkProgress>(crate::dto::events::BULK_PROGRESS)
            .into_iter()
            .map(|p| (p.done, p.current_app))
            .collect()
    }

    async fn drive_with(
        rec: &Recorder,
        cancel: &CancelToken,
        items: Vec<BulkScopeOutcome>,
    ) -> (Vec<BulkScopeOutcome>, bool) {
        run_bulk_seq(
            rec,
            cancel,
            items,
            |o| o.object_id.clone(),
            |o| async move { o },
        )
        .await
    }

    async fn drive(
        cancel: &CancelToken,
        items: Vec<BulkScopeOutcome>,
    ) -> (Vec<BulkScopeOutcome>, bool) {
        drive_with(&Recorder::default(), cancel, items).await
    }

    #[tokio::test]
    async fn processes_every_item_and_reports_progress_before_each() {
        let cancel = CancelFlag::new().claim();
        let rec = Recorder::default();
        let (out, cancelled) = drive_with(
            &rec,
            &cancel,
            vec![
                scope_outcome("a", None),
                scope_outcome("b", None),
                scope_outcome("c", None),
            ],
        )
        .await;
        assert_eq!(out.len(), 3);
        assert!(!cancelled);
        // One event per item naming the app ABOUT to be processed (so the UI
        // shows what is happening, not what already happened), then a final
        // done == total with no current app.
        assert_eq!(
            events(&rec),
            vec![
                (0, Some("a".into())),
                (1, Some("b".into())),
                (2, Some("c".into())),
                (3, None),
            ]
        );
        // The channel name lives in the driver now, not in a per-sink impl:
        // every event it emits rides the one `bulk-progress` channel.
        assert!(
            rec.names()
                .iter()
                .all(|n| *n == crate::dto::events::BULK_PROGRESS)
        );
        assert_eq!(rec.names().len(), 4);
    }

    #[tokio::test]
    async fn a_cancel_before_the_first_item_processes_nothing() {
        // The flag is polled BEFORE each item, so a cancel that lands before the
        // loop starts must mutate nothing at all — the property that makes the
        // Cancel button safe on the destructive commands (delete, disable).
        let flag = CancelFlag::new();
        let cancel = flag.claim();
        flag.cancel();
        let rec = Recorder::default();
        let (out, cancelled) = drive_with(&rec, &cancel, vec![scope_outcome("a", None)]).await;
        assert!(out.is_empty(), "cancelled before item 1 ⇒ nothing ran");
        assert!(cancelled);
        // Only the terminal event: it reports nothing processed, and the
        // cancellation.
        assert_eq!(events(&rec), vec![(0, None)]);
        assert!(rec.payloads::<BulkProgress>(crate::dto::events::BULK_PROGRESS)[0].cancelled);
    }

    #[tokio::test]
    async fn a_cancel_mid_run_reports_how_far_it_got() {
        // The terminal event's `done` is the processed count, not `total`, so a
        // stopped run's bar shows how far it got instead of snapping to 100%.
        let flag = CancelFlag::new();
        let cancel = flag.claim();
        let rec = Recorder::default();
        let (out, cancelled) = run_bulk_seq(
            &rec,
            &cancel,
            vec![
                scope_outcome("a", None),
                scope_outcome("b", None),
                scope_outcome("c", None),
                scope_outcome("d", None),
            ],
            |o| o.object_id.clone(),
            |o| {
                if o.object_id == "b" {
                    flag.cancel();
                }
                async move { o }
            },
        )
        .await;
        assert_eq!(
            out.iter().map(|o| o.object_id.as_str()).collect::<Vec<_>>(),
            ["a", "b"],
            "the in-flight item finishes, the next one never starts"
        );
        assert!(cancelled);
        assert_eq!(
            events(&rec),
            vec![(0, Some("a".into())), (1, Some("b".into())), (2, None)]
        );
        assert!(
            rec.payloads::<BulkProgress>(crate::dto::events::BULK_PROGRESS)
                .last()
                .unwrap()
                .cancelled
        );
    }

    #[tokio::test]
    async fn per_item_errors_are_collected_and_do_not_stop_the_run() {
        // An ordinary per-item failure is data, not a halt: the remaining
        // selection still gets processed.
        let cancel = CancelFlag::new().claim();
        let (out, cancelled) = drive(
            &cancel,
            vec![
                scope_outcome("a", Some(err("forbidden"))),
                scope_outcome("b", None),
                scope_outcome("c", Some(err("app_not_found"))),
            ],
        )
        .await;
        assert_eq!(out.len(), 3, "a per-item error must not end the run");
        assert!(!cancelled);
        assert_eq!(out.iter().filter(|o| o.error.is_some()).count(), 2);
    }

    #[tokio::test]
    async fn a_dead_session_halts_the_run_instead_of_burning_the_selection() {
        // `refresh_missing` means the refresh token can't be re-minted silently,
        // so every remaining item fails identically. Continuing turned one
        // recoverable "re-authenticate" into a wall of N opaque failures.
        let cancel = CancelFlag::new().claim();
        let rec = Recorder::default();
        let (out, cancelled) = drive_with(
            &rec,
            &cancel,
            vec![
                scope_outcome("a", None),
                scope_outcome("b", Some(err("refresh_missing"))),
                scope_outcome("c", None),
                scope_outcome("d", None),
            ],
        )
        .await;
        assert_eq!(out.len(), 2, "stops AFTER recording the fatal outcome");
        assert_eq!(out[1].object_id, "b");
        assert!(
            out[1]
                .error
                .as_ref()
                .is_some_and(BulkError::is_reauth_fatal),
            "the fatal outcome is kept so the UI can offer re-auth"
        );
        // Not a user cancellation — the distinction drives different UI copy.
        assert!(!cancelled);
        assert_eq!(
            events(&rec).last(),
            Some(&(2, None)),
            "the terminal event reports how far the run got"
        );
    }

    /// A fan-out stopped by the dead session reports `cancelled: false` —
    /// its failure list says why — while the operator's Cancel is reported
    /// whether or not the session also died.
    #[test]
    fn a_dead_session_stop_is_not_a_cancel() {
        let flag = CancelFlag::new();
        let cancel = flag.claim();
        let live = SessionDead::new();
        let dead = SessionDead::new();
        dead.note_code("refresh_missing");
        assert!(!stopped_by_cancel(false, &cancel, &live), "ran to the end");
        assert!(
            stopped_by_cancel(true, &cancel, &live),
            "dispatch stopped with the session alive"
        );
        assert!(
            !stopped_by_cancel(true, &cancel, &dead),
            "dispatch stopped by the dead session"
        );
        flag.cancel();
        assert!(
            stopped_by_cancel(true, &cancel, &dead),
            "an explicit Cancel is still a cancel"
        );
    }

    #[test]
    fn only_session_death_is_fatal() {
        assert!(scope_outcome("a", Some(err("refresh_missing"))).session_fatal());
        assert!(scope_outcome("a", Some(err("not_signed_in"))).session_fatal());
        // Everything else is a per-item problem the run should survive —
        // `consent_required` especially: it is per-resource, and a later item
        // may well need a scope the caller already has.
        for code in [
            "forbidden",
            "throttled",
            "app_not_found",
            "consent_required",
        ] {
            assert!(
                !scope_outcome("a", Some(err(code))).session_fatal(),
                "{code} must not halt the run"
            );
        }
        assert!(!scope_outcome("a", None).session_fatal());
    }

    #[test]
    fn create_specs_with_a_bad_audience_are_rejected_before_any_round_trip() {
        let spec = |name: &str, aud: Option<&str>| BulkCreateSpec {
            display_name: name.into(),
            sign_in_audience: aud.map(str::to_string),
            ..Default::default()
        };

        assert!(validate_create_spec(&spec("Ok", None)).is_none());
        for aud in VALID_AUDIENCES {
            assert!(
                validate_create_spec(&spec("Ok", Some(aud))).is_none(),
                "{aud} is in VALID_AUDIENCES and must pass"
            );
        }

        let rejected = validate_create_spec(&spec("Ok", Some("AzureADandPersonal"))).unwrap();
        assert_eq!(rejected.status, BulkCreateStatus::Invalid);
        assert!(rejected.message.unwrap().contains("AzureADandPersonal"));
        // A local rejection carries no wire code, so it can never be mistaken
        // for a session failure by the run-level fatal check.
        assert!(rejected.error.is_none());

        // Whitespace-only names are rejected too — Graph would take the round
        // trip and fail.
        let blank = validate_create_spec(&spec("   ", None)).unwrap();
        assert_eq!(blank.status, BulkCreateStatus::Invalid);
    }

    const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

    fn perm(resource: &str, value: &str, kind: PermissionKind) -> BulkCreatePermission {
        BulkCreatePermission {
            resource: resource.into(),
            value: value.into(),
            kind,
        }
    }

    fn imported(owners: &[&str], permissions: Vec<BulkCreatePermission>) -> BulkCreateSpec {
        BulkCreateSpec {
            display_name: "Imported".into(),
            owner_upns: owners.iter().map(|o| o.to_string()).collect(),
            permissions,
            ..Default::default()
        }
    }

    #[test]
    fn imported_owners_and_permissions_are_checked_before_any_round_trip() {
        let ok = imported(
            &["a@contoso.com"],
            vec![
                perm(
                    "microsoft graph",
                    "User.Read.All",
                    PermissionKind::Application,
                ),
                perm(GRAPH_APP_ID, "openid", PermissionKind::Delegated),
            ],
        );
        assert!(validate_create_spec(&ok).is_none());

        for (spec, needle) in [
            (imported(&["alice"], vec![]), "not a user principal name"),
            (
                imported(
                    &[],
                    vec![perm("Graph-ish", "X", PermissionKind::Application)],
                ),
                "unknown resource",
            ),
            (
                imported(&[], vec![perm(GRAPH_APP_ID, "X", PermissionKind::Unknown)]),
                "Application or Delegated",
            ),
        ] {
            let rejected = validate_create_spec(&spec).expect(needle);
            assert_eq!(rejected.status, BulkCreateStatus::Invalid);
            assert!(rejected.message.unwrap().contains(needle), "{needle}");
            assert!(rejected.error.is_none());
        }
    }

    #[test]
    fn a_resource_is_an_app_id_or_a_bundled_name_never_a_guess() {
        assert_eq!(
            resource_app_id_for("Microsoft Graph").as_deref(),
            Some(GRAPH_APP_ID)
        );
        assert_eq!(
            resource_app_id_for(&GRAPH_APP_ID.to_uppercase()).as_deref(),
            Some(GRAPH_APP_ID)
        );
        assert_eq!(resource_app_id_for("Graph"), None);
    }

    #[test]
    fn permission_ids_match_kind_value_and_enabled_state() {
        let sp: ServicePrincipal = serde_json::from_value(serde_json::json!({
            "id": "sp-graph", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph",
            "appRoles": [
                { "id": "r-user", "value": "User.Read.All", "allowedMemberTypes": ["Application"], "isEnabled": true },
                { "id": "r-off", "value": "Old.Role", "allowedMemberTypes": ["Application"], "isEnabled": false },
                { "id": "r-users-only", "value": "Users.Only", "allowedMemberTypes": ["User"] }
            ],
            "oauth2PermissionScopes": [
                { "id": "s-user", "value": "User.Read.All", "isEnabled": true }
            ]
        }))
        .unwrap();
        let id = |v, k| permission_id_on(&sp, v, k);
        assert_eq!(
            id("User.Read.All", PermissionKind::Application).as_deref(),
            Some("r-user")
        );
        assert_eq!(
            id("User.Read.All", PermissionKind::Delegated).as_deref(),
            Some("s-user")
        );
        assert_eq!(id("user.read.all", PermissionKind::Application), None);
        assert_eq!(id("Old.Role", PermissionKind::Application), None);
        assert_eq!(id("Users.Only", PermissionKind::Application), None);
    }

    #[test]
    fn owners_not_added_names_the_failed_upns() {
        let ids = ["u-1".to_string(), "u-2".to_string()];
        let upns = ["a@c.com".to_string(), "b@c.com".to_string()];
        assert_eq!(owners_not_added(&[], &ids, &upns), None);
        assert_eq!(
            owners_not_added(&["u-2".into()], &ids, &upns).as_deref(),
            Some("Owner(s) not added: b@c.com.")
        );
    }

    /// The capped bulk writes' driver, `run_bulk_capped`, and the three
    /// commands' finishers — the counterparts of the `run_bulk_seq` tests above.
    mod capped {
        use super::*;
        use crate::commands::test_support::{
            detail_cached, dies_after, fixed_now, indexes_intact, mock_state_with_write_token,
            sample_app_json, seed_indexes_and_detail,
        };
        use crate::commands::throttle::FanOutMeter;
        use azapptoolkit_core::token::{BearerProvider, TokenError};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::method;
        use wiremock::{Mock, ResponseTemplate};

        const TENANT: &str = "tenant-bulk";

        /// An `AppState` whose cache the finishers write to. Nothing here
        /// reaches its Graph client, so the base URL is never dialled.
        fn state() -> AppState {
            AppState::for_test(TENANT, "http://127.0.0.1:9")
        }

        /// One delete's outcome: landed when `code` is `None`, else a failure
        /// carrying that wire code.
        fn delete_outcome(id: &str, code: Option<&str>) -> Result<String, BulkDeleteFailure> {
            match code {
                None => Ok(id.into()),
                Some(code) => Err(BulkDeleteFailure {
                    object_id: id.into(),
                    message: format!("{code} happened"),
                    code: Some(code.into()),
                }),
            }
        }

        fn deleted(id: &str) -> Result<String, BulkDeleteFailure> {
            delete_outcome(id, None)
        }

        fn removal(id: &str, removed: &[&str], error: Option<BulkError>) -> AppRemovalSummary {
            AppRemovalSummary {
                object_id: id.into(),
                display_name: format!("App {id}"),
                removed_key_ids: removed.iter().map(|k| (*k).to_string()).collect(),
                failed_key_ids: error.iter().map(|_| "k-failed".to_string()).collect(),
                error,
            }
        }

        /// A sweep task's outcome that tried every expired key it had.
        fn swept(id: &str, removed: &[&str], error: Option<BulkError>) -> SweepItem {
            SweepItem {
                summary: removal(id, removed, error),
                unattempted: 0,
            }
        }

        /// A sweep task's outcome stopped with `unattempted` keys left.
        fn stopped(id: &str, removed: &[&str], unattempted: usize) -> SweepItem {
            SweepItem {
                summary: removal(id, removed, None),
                unattempted,
            }
        }

        fn granted(id: &str, n: usize) -> GrantItem {
            GrantItem {
                outcome: BulkGrantOutcome {
                    object_id: id.into(),
                    granted: n,
                    skipped: 0,
                    failed: 0,
                    error: None,
                },
                sp_created: false,
            }
        }

        /// Drives `run_bulk_capped` over ready-made outcomes with `cap` in
        /// flight. The task whose id is `lose` panics instead of reporting — a
        /// task that ends without an outcome.
        async fn drive<O: CappedOutcome>(
            rec: &Recorder,
            cancel: &CancelToken,
            session: &SessionDead,
            cap: usize,
            items: Vec<O>,
            lose: Option<&'static str>,
        ) -> CappedRun<O> {
            let meter = FanOutMeter::detached(cap);
            run_bulk_capped(
                rec,
                cancel,
                session,
                &meter,
                items,
                |o| o.object_id().to_string(),
                |o| {
                    let lost = lose == Some(o.object_id());
                    async move {
                        assert!(!lost, "this task is lost on purpose");
                        o
                    }
                },
            )
            .await
        }

        fn progress(rec: &Recorder) -> Vec<BulkProgress> {
            rec.payloads::<BulkProgress>(crate::dto::events::BULK_PROGRESS)
        }

        #[tokio::test]
        async fn every_joined_task_ticks_in_order_between_an_initial_and_a_terminal_event() {
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let rec = Recorder::default();
            let run = drive(
                &rec,
                &cancel,
                &session,
                4,
                vec![deleted("a"), deleted("b"), deleted("c")],
                None,
            )
            .await;
            assert_eq!(run.outcomes.len(), 3);
            assert!(run.lost.is_empty());
            assert_eq!(run.dispatched, 3);
            assert!(!run.cancelled);

            let events = progress(&rec);
            // The bar shows the run started before anything completes, then one
            // tick per joined task. They are emitted on the collect side, so
            // `done` never steps backwards; the terminal event repeats the
            // final count with no app named.
            assert_eq!(
                events.iter().map(|e| e.done).collect::<Vec<_>>(),
                [0, 1, 2, 3, 3]
            );
            assert_eq!(events[0].current_app, None);
            let mut named: Vec<String> = events[1..4]
                .iter()
                .filter_map(|e| e.current_app.clone())
                .collect();
            named.sort();
            assert_eq!(named, ["a", "b", "c"]);
            let last = events.last().unwrap();
            assert_eq!(
                (last.total, last.current_app.as_deref(), last.cancelled),
                (3, None, false)
            );
            assert!(events.iter().all(|e| e.in_flight_cap == Some(4)));
        }

        #[tokio::test]
        async fn a_cancel_before_the_first_dispatch_spawns_nothing() {
            let flag = CancelFlag::new();
            let cancel = flag.claim();
            flag.cancel();
            let session = SessionDead::new();
            let rec = Recorder::default();
            let meter = FanOutMeter::detached(4);
            let spawned = AtomicUsize::new(0);
            let run = run_bulk_capped(
                &rec,
                &cancel,
                &session,
                &meter,
                vec![deleted("a"), deleted("b")],
                |o| o.object_id().to_string(),
                |o| {
                    spawned.fetch_add(1, Ordering::SeqCst);
                    async move { o }
                },
            )
            .await;
            assert_eq!(spawned.load(Ordering::SeqCst), 0, "nothing may be written");
            assert!(run.outcomes.is_empty() && run.lost.is_empty());
            assert_eq!(run.dispatched, 0);
            assert!(run.cancelled);
            // The initial event and the terminal one, which reports nothing
            // processed and the cancellation.
            assert_eq!(events(&rec), vec![(0, None), (0, None)]);
            assert!(progress(&rec)[1].cancelled);
        }

        #[tokio::test]
        async fn a_cancel_mid_run_lets_the_task_in_flight_finish_and_spawns_nothing_more() {
            let flag = CancelFlag::new();
            let cancel = flag.claim();
            let session = SessionDead::new();
            let rec = Recorder::default();
            // One in flight: `a` runs alone and presses Cancel while it does.
            let meter = FanOutMeter::detached(1);
            let spawned = AtomicUsize::new(0);
            let run = run_bulk_capped(
                &rec,
                &cancel,
                &session,
                &meter,
                vec![deleted("a"), deleted("b"), deleted("c")],
                |o| o.object_id().to_string(),
                |o| {
                    spawned.fetch_add(1, Ordering::SeqCst);
                    let presses = (o.object_id() == "a").then(|| flag.clone());
                    async move {
                        if let Some(flag) = presses {
                            flag.cancel();
                        }
                        o
                    }
                },
            )
            .await;
            assert_eq!(spawned.load(Ordering::SeqCst), 1, "`b` is never spawned");
            assert_eq!(run.dispatched, 1);
            assert_eq!(run.outcomes.len(), 1, "the in-flight `a` still reports");
            assert!(run.lost.is_empty());
            assert!(run.cancelled);
            let events = progress(&rec);
            assert_eq!(
                events.iter().map(|e| e.done).collect::<Vec<_>>(),
                [0, 1, 1],
                "the terminal event reports how far the run got"
            );
            assert!(events.last().is_some_and(|e| e.cancelled));
        }

        /// The application `sample_app_json` describes, holding a secret per
        /// key in `expired` that expired before `fixed_now`, plus one that is
        /// still valid and must never be touched.
        fn app_with_expired(expired: &[&str]) -> Application {
            let mut json = sample_app_json();
            let mut secrets: Vec<serde_json::Value> = expired
                .iter()
                .map(|k| serde_json::json!({ "keyId": k, "endDateTime": "2025-06-01T00:00:00Z" }))
                .collect();
            secrets.push(
                serde_json::json!({ "keyId": "k-live", "endDateTime": "2027-01-01T00:00:00Z" }),
            );
            json["passwordCredentials"] = serde_json::Value::Array(secrets);
            serde_json::from_value(json).expect("a valid application")
        }

        async fn remove_password_calls(server: &wiremock::MockServer) -> usize {
            server
                .received_requests()
                .await
                .expect("request recording is on")
                .iter()
                .filter(|r| r.url.path().ends_with("/removePassword"))
                .count()
        }

        #[tokio::test]
        async fn the_sweep_task_stops_between_keys_when_the_session_dies() {
            let (server, state) = mock_state_with_write_token(TENANT, dies_after(1)).await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;
            let client = state.graph_for(TENANT);
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let item = sweep_one(
                &client,
                &cancel,
                &session,
                app_with_expired(&["k1", "k2", "k3"]),
                fixed_now(),
            )
            .await;
            assert_eq!(item.unattempted, 1, "`k3` is never attempted");
            let summary = item.summary;
            assert_eq!(summary.removed_key_ids, ["k1"]);
            assert_eq!(summary.failed_key_ids, ["k2"], "`k3` is never attempted");
            assert_eq!(
                summary.error.as_ref().map(|e| e.code.as_str()),
                Some("refresh_missing")
            );
            // The task latches the session itself, so a sibling task stops
            // between its keys without waiting for the driver to collect this one.
            assert!(session.is_dead());
            assert_eq!(remove_password_calls(&server).await, 1);

            // ...and a sibling's latch stops a task before its first key.
            let item = sweep_one(
                &client,
                &cancel,
                &session,
                app_with_expired(&["k4"]),
                fixed_now(),
            )
            .await;
            let summary = &item.summary;
            assert!(summary.removed_key_ids.is_empty() && summary.failed_key_ids.is_empty());
            assert_eq!(item.unattempted, 1, "stopped before its first key");
            assert_eq!(remove_password_calls(&server).await, 1);
        }

        #[tokio::test]
        async fn a_fatal_failure_replaces_an_earlier_one_in_the_sweep_rows_error() {
            let (server, state) = mock_state_with_write_token(TENANT, dies_after(1)).await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "error": { "code": "Request_ResourceNotFound", "message": "gone" }
                })))
                .mount(&server)
                .await;
            let client = state.graph_for(TENANT);
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let summary = sweep_one(
                &client,
                &cancel,
                &session,
                app_with_expired(&["k1", "k2", "k3"]),
                fixed_now(),
            )
            .await
            .summary;
            assert!(summary.removed_key_ids.is_empty());
            assert_eq!(summary.failed_key_ids, ["k1", "k2"]);
            // `k1`'s 404 came first, but the row carries the code that tells
            // the bar to prompt re-authentication.
            assert_eq!(
                summary.error.as_ref().map(|e| e.code.as_str()),
                Some("refresh_missing")
            );
        }

        /// A write token that presses Cancel each time it is asked for a
        /// bearer, then serves one: the key in flight lands, and the check
        /// before the next key sees the cancel.
        struct CancelsOnWrite(CancelFlag);

        #[async_trait::async_trait]
        impl BearerProvider for CancelsOnWrite {
            async fn bearer(&self) -> Result<String, TokenError> {
                self.0.cancel();
                Ok("tok".to_string())
            }
        }

        #[tokio::test]
        async fn a_cancel_between_keys_stops_the_sweep_task() {
            let flag = CancelFlag::new();
            let cancel = flag.claim();
            let (server, state) =
                mock_state_with_write_token(TENANT, Arc::new(CancelsOnWrite(flag.clone()))).await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;
            let client = state.graph_for(TENANT);
            let session = SessionDead::new();
            let item = sweep_one(
                &client,
                &cancel,
                &session,
                app_with_expired(&["k1", "k2"]),
                fixed_now(),
            )
            .await;
            assert_eq!(item.summary.removed_key_ids, ["k1"]);
            assert!(item.summary.failed_key_ids.is_empty() && item.summary.error.is_none());
            assert_eq!(item.unattempted, 1);
            assert_eq!(
                remove_password_calls(&server).await,
                1,
                "`k2` is never sent"
            );
        }

        /// A Cancel or a dead session can stop a dispatched app's own key loop.
        /// Stopped before its first `removePassword`, the app was never
        /// checked: no row, and not in `apps_checked`, so the bar names it in
        /// the unattempted tail. Stopped part-way, it keeps a row saying its
        /// remaining expired secrets are still there.
        #[tokio::test]
        async fn an_app_stopped_before_its_first_removal_is_not_checked() {
            let state = state();
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let run = drive(
                &Recorder::default(),
                &cancel,
                &session,
                4,
                vec![
                    swept("a", &["k1"], None),
                    stopped("b", &["k2"], 2),
                    stopped("c", &[], 3),
                    swept("d", &[], None),
                ],
                None,
            )
            .await;
            assert_eq!(run.dispatched, 4);
            let result = finish_expired_sweep(&state.cache, TENANT, 4, Vec::new(), run, |id| {
                id.to_string()
            });

            assert_eq!(
                result.apps_checked,
                Some(3),
                "`c` was dispatched but stopped before its first key; `d` had nothing to remove"
            );
            let mut rows: Vec<(&str, Option<&str>)> = result
                .summaries
                .iter()
                .map(|s| {
                    (
                        s.object_id.as_str(),
                        s.error.as_ref().map(|e| e.code.as_str()),
                    )
                })
                .collect();
            rows.sort_unstable();
            assert_eq!(
                rows,
                [("a", None), ("b", Some(INTERRUPTED))],
                "`c` gets no row: it joins the unattempted tail"
            );
            let b = result
                .summaries
                .iter()
                .find(|s| s.object_id == "b")
                .unwrap();
            let message = &b.error.as_ref().unwrap().message;
            assert!(message.contains("2 more expired secrets"), "{message}");
            assert!(!b.error.as_ref().unwrap().is_reauth_fatal());
        }

        /// An app whose own fatal failure stopped it keeps the fatal code in
        /// its one error slot — that is what prompts re-authentication — rather
        /// than the interrupted marker.
        #[test]
        fn a_fatal_stop_keeps_its_code_over_the_interrupted_marker() {
            let state = state();
            let mut item = stopped("a", &[], 2);
            item.summary.failed_key_ids = vec!["k1".into()];
            item.summary.error = Some(err("refresh_missing"));
            let run = CappedRun {
                outcomes: vec![item],
                lost: Vec::new(),
                dispatched: 1,
                cancelled: false,
            };
            let result = finish_expired_sweep(&state.cache, TENANT, 1, Vec::new(), run, |id| {
                id.to_string()
            });
            assert_eq!(result.apps_checked, Some(1), "its first key was tried");
            assert_eq!(
                result.summaries[0].error.as_ref().map(|e| e.code.as_str()),
                Some("refresh_missing")
            );
        }

        /// The delete path end to end through its real per-item work: the
        /// session dies between the first and second DELETE.
        #[tokio::test]
        async fn a_dead_session_mid_delete_returns_the_landed_delete_and_the_fatal_code() {
            let (server, state) = mock_state_with_write_token(TENANT, dies_after(1)).await;
            Mock::given(method("DELETE"))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;
            seed_indexes_and_detail(&state, TENANT, "a");
            let client = state.graph_for(TENANT);
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let rec = Recorder::default();
            // One in flight, so the order is fixed: `a` lands, `b` meets the
            // dead session, and `c` is never dispatched.
            let meter = FanOutMeter::detached(1);
            let run = run_bulk_capped(
                &rec,
                &cancel,
                &session,
                &meter,
                vec!["a".to_string(), "b".to_string(), "c".to_string()],
                String::clone,
                |id| {
                    let client = client.clone();
                    async move { delete_one(&client, id).await }
                },
            )
            .await;
            assert!(session.is_dead(), "the collect side latched the session");
            let result = finish_bulk_delete(&state.cache, TENANT, run);

            assert_eq!(result.deleted, ["a"], "the landed DELETE is reported");
            assert_eq!(result.failed.len(), 1);
            assert_eq!(result.failed[0].object_id, "b");
            assert_eq!(result.failed[0].code.as_deref(), Some("refresh_missing"));
            assert!(!result.cancelled, "a dead session is not a Cancel");
            // `c` is in neither list: the bar counts it as never attempted.
            assert_eq!(progress(&rec).last().map(|e| e.done), Some(2));
            // A deletion beside a failure busts the list tier.
            assert!(!indexes_intact(&state, TENANT));
        }

        #[tokio::test]
        async fn a_dead_session_mid_grant_returns_the_landed_grant_and_the_fatal_code() {
            let state = state();
            seed_indexes_and_detail(&state, TENANT, "a");
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let dead = grant_item(
                "b".into(),
                Err(UiError::new("refresh_missing", "gone", false)),
            );
            let run = drive(
                &Recorder::default(),
                &cancel,
                &session,
                1,
                vec![granted("a", 2), dead, granted("c", 1)],
                None,
            )
            .await;
            let result = finish_bulk_grant(&state.cache, TENANT, run);

            let ids: Vec<&str> = result
                .outcomes
                .iter()
                .map(|o| o.object_id.as_str())
                .collect();
            assert_eq!(ids, ["a", "b"], "`c` is never dispatched");
            assert_eq!(result.outcomes[0].granted, 2);
            assert!(
                result.outcomes[1]
                    .error
                    .as_ref()
                    .is_some_and(BulkError::is_reauth_fatal)
            );
            assert!(!result.cancelled);
            // The landed grant busts the detail tier; no SP was created, so the
            // indexes stay.
            assert!(!detail_cached(&state, TENANT, "a"));
            assert!(indexes_intact(&state, TENANT));
        }

        #[tokio::test]
        async fn a_dead_session_mid_sweep_returns_the_landed_removals_and_the_fatal_code() {
            let state = state();
            seed_indexes_and_detail(&state, TENANT, "a");
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let run = drive(
                &Recorder::default(),
                &cancel,
                &session,
                1,
                vec![
                    swept("a", &["k1"], None),
                    swept("b", &["k2"], Some(err("refresh_missing"))),
                    swept("c", &["k3"], None),
                ],
                None,
            )
            .await;
            let result = finish_expired_sweep(&state.cache, TENANT, 3, Vec::new(), run, |id| {
                id.to_string()
            });

            let ids: Vec<&str> = result
                .summaries
                .iter()
                .map(|s| s.object_id.as_str())
                .collect();
            assert_eq!(ids, ["a", "b"], "`c` is never dispatched");
            assert!(
                result.summaries[1]
                    .error
                    .as_ref()
                    .is_some_and(BulkError::is_reauth_fatal)
            );
            assert_eq!(result.apps_scanned, 3);
            assert_eq!(
                result.apps_checked,
                Some(2),
                "`a` and `b` were dispatched; the dead session stopped `c`"
            );
            assert!(!result.cancelled);
            // The landed removal drops its app's credential tier, which keeps
            // the indexes.
            assert!(!detail_cached(&state, TENANT, "a"));
            assert!(indexes_intact(&state, TENANT));
        }

        /// A Cancel mid-sweep must not read as a sweep of the whole selection:
        /// `apps_scanned` is every readable app whether or not it was reached,
        /// and a clean app is no row, so `apps_checked` is the only count of
        /// what the sweep actually checked — the unreadable apps (each already
        /// a row) plus what it dispatched.
        #[tokio::test]
        async fn a_cancelled_sweep_reports_only_the_apps_it_checked() {
            let state = state();
            let flag = CancelFlag::new();
            let cancel = flag.claim();
            let session = SessionDead::new();
            // One in flight: `a` runs alone and presses Cancel while it does.
            let meter = FanOutMeter::detached(1);
            let run = run_bulk_capped(
                &Recorder::default(),
                &cancel,
                &session,
                &meter,
                vec![
                    swept("a", &["k1"], None),
                    swept("b", &["k2"], None),
                    swept("c", &[], None),
                    swept("d", &[], None),
                ],
                |o| o.object_id().to_string(),
                |o| {
                    let presses = (o.object_id() == "a").then(|| flag.clone());
                    async move {
                        if let Some(flag) = presses {
                            flag.cancel();
                        }
                        o
                    }
                },
            )
            .await;
            assert_eq!(run.dispatched, 1);
            // The fifth selected app could not be read: a row, and checked.
            let unreadable = vec![removal("x", &[], Some(err("not_found")))];
            let result = finish_expired_sweep(&state.cache, TENANT, 4, unreadable, run, |id| {
                id.to_string()
            });

            assert!(result.cancelled);
            assert_eq!(result.apps_scanned, 4);
            assert_eq!(
                result.apps_checked,
                Some(2),
                "the unreadable `x` and the dispatched `a` — never the 5 selected"
            );
            let ids: Vec<&str> = result
                .summaries
                .iter()
                .map(|s| s.object_id.as_str())
                .collect();
            assert_eq!(ids, ["x", "a"]);
        }

        #[tokio::test]
        async fn a_lost_delete_is_a_failure_row_and_busts_the_list_tier() {
            let rec = Recorder::default();
            for (items, landed) in [
                (vec![deleted("a"), deleted("b")], vec!["a"]),
                // A lost task alone still busts: its DELETE may have landed.
                (vec![deleted("b")], vec![]),
            ] {
                let state = state();
                seed_indexes_and_detail(&state, TENANT, "b");
                let cancel = CancelFlag::new().claim();
                let session = SessionDead::new();
                let total = items.len();
                let run = drive(&rec, &cancel, &session, 1, items, Some("b")).await;
                assert_eq!(run.lost, ["b"]);
                assert_eq!(
                    progress(&rec).last().map(|e| e.done),
                    Some(total),
                    "a lost task has joined, so the terminal count includes it"
                );
                let result = finish_bulk_delete(&state.cache, TENANT, run);
                assert_eq!(result.deleted, landed);
                assert_eq!(result.failed.len(), 1);
                assert_eq!(result.failed[0].object_id, "b");
                assert_eq!(result.failed[0].code.as_deref(), Some(LOST_TASK));
                assert!(!indexes_intact(&state, TENANT), "only a rescan can tell");
            }
        }

        #[tokio::test]
        async fn a_lost_sweep_task_is_a_row_and_drops_that_apps_credential_tier() {
            let state = state();
            seed_indexes_and_detail(&state, TENANT, "b");
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let run = drive(
                &Recorder::default(),
                &cancel,
                &session,
                1,
                vec![swept("a", &[], None), swept("b", &["k"], None)],
                Some("b"),
            )
            .await;
            let result = finish_expired_sweep(&state.cache, TENANT, 2, Vec::new(), run, |id| {
                format!("Name of {id}")
            });

            // `a` had nothing to remove, so it is no row; `b` is one although
            // it never reported.
            assert_eq!(result.summaries.len(), 1);
            let row = &result.summaries[0];
            assert_eq!(
                (row.object_id.as_str(), row.display_name.as_str()),
                ("b", "Name of b")
            );
            assert_eq!(row.error.as_ref().map(|e| e.code.as_str()), Some(LOST_TASK));
            // Some of its removals may have landed: its credential tier goes,
            // the indexes stay.
            assert!(!detail_cached(&state, TENANT, "b"));
            assert!(indexes_intact(&state, TENANT));
        }

        #[tokio::test]
        async fn a_lost_grant_is_a_row_and_busts_the_list_tier() {
            let state = state();
            seed_indexes_and_detail(&state, TENANT, "a");
            let cancel = CancelFlag::new().claim();
            let session = SessionDead::new();
            let run = drive(
                &Recorder::default(),
                &cancel,
                &session,
                1,
                vec![granted("a", 1), granted("b", 1)],
                Some("b"),
            )
            .await;
            let result = finish_bulk_grant(&state.cache, TENANT, run);
            let lost = result.outcomes.iter().find(|o| o.object_id == "b").unwrap();
            assert_eq!(
                lost.error.as_ref().map(|e| e.code.as_str()),
                Some(LOST_TASK)
            );
            // Its client SP may have been created, so the list tier goes.
            assert!(!indexes_intact(&state, TENANT));
        }

        #[test]
        fn a_lost_task_is_never_session_fatal() {
            assert!(delete_outcome("a", Some("refresh_missing")).session_fatal());
            assert!(!delete_outcome("a", Some(LOST_TASK)).session_fatal());
            assert!(!delete_outcome("a", Some("forbidden")).session_fatal());
            assert!(!deleted("a").session_fatal());
            assert!(
                !swept(
                    "a",
                    &[],
                    Some(BulkError {
                        code: INTERRUPTED.into(),
                        message: String::new(),
                        retryable: false,
                    })
                )
                .session_fatal()
            );
            assert!(
                !removal(
                    "a",
                    &[],
                    Some(BulkError {
                        code: LOST_TASK.into(),
                        message: String::new(),
                        retryable: false,
                    })
                )
                .session_fatal()
            );
        }
    }

    mod resolve {
        use super::*;
        use crate::commands::test_support::{dead_token, mock_graph, mock_graph_with};
        use azapptoolkit_core::cache::Cache;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        async fn graph_with_directory() -> MockServer {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v1.0/users"))
                .and(query_param("$filter", "userPrincipalName eq 'a@contoso.com'"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({ "value": [{ "id": "u-a", "userPrincipalName": "a@contoso.com" }] }),
                ))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1.0/users"))
                .and(query_param(
                    "$filter",
                    "userPrincipalName eq 'gone@contoso.com'",
                ))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1.0/servicePrincipals"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{
                        "id": "sp-graph", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph",
                        "appRoles": [{ "id": "r-user", "value": "User.Read.All", "allowedMemberTypes": ["Application"] }],
                        "oauth2PermissionScopes": [{ "id": "s-openid", "value": "openid" }]
                    }]
                })))
                .mount(&server)
                .await;
            server
        }

        #[tokio::test]
        async fn owners_and_permissions_resolve_into_ids_and_one_manifest() {
            let server = graph_with_directory().await;
            let client = mock_graph(&server);
            let spec = imported(
                &["a@contoso.com", "a@contoso.com"],
                vec![
                    perm(
                        "Microsoft Graph",
                        "User.Read.All",
                        PermissionKind::Application,
                    ),
                    perm(GRAPH_APP_ID, "openid", PermissionKind::Delegated),
                ],
            );
            let Ok(r) = resolve_create_extras(&client, &spec).await else {
                panic!("should resolve");
            };
            assert_eq!(r.owners, [("u-a".to_string(), "a@contoso.com".to_string())]);
            assert_eq!(
                r.required_resource_access.len(),
                1,
                "one entry per resource"
            );
            let access: Vec<(&str, &str)> = r.required_resource_access[0]
                .resource_access
                .iter()
                .map(|a| (a.id.as_str(), a.r#type.as_str()))
                .collect();
            assert_eq!(access, [("r-user", "Role"), ("s-openid", "Scope")]);
        }

        #[tokio::test]
        async fn a_missing_owner_or_permission_is_invalid_not_failed() {
            let server = graph_with_directory().await;
            let client = mock_graph(&server);
            for (spec, needle) in [
                (
                    imported(&["gone@contoso.com"], vec![]),
                    "owner gone@contoso.com not found",
                ),
                (
                    imported(
                        &[],
                        vec![perm(
                            "Microsoft Graph",
                            "Mail.Nope",
                            PermissionKind::Application,
                        )],
                    ),
                    "no enabled application permission Mail.Nope",
                ),
            ] {
                match resolve_create_extras(&client, &spec).await {
                    Err(Unresolved::Invalid(m)) => assert!(m.contains(needle), "{m}"),
                    _ => panic!("{needle}: expected Invalid"),
                }
            }
        }

        #[tokio::test]
        async fn a_dead_session_surfaces_as_a_fatal_failure() {
            let server = MockServer::start().await;
            let client = mock_graph_with(&server, dead_token(), Cache::new());
            match resolve_create_extras(&client, &imported(&["a@contoso.com"], vec![])).await {
                Err(Unresolved::Failed(e)) => assert!(e.is_reauth_fatal(), "{}", e.code),
                _ => panic!("expected Failed"),
            }
        }
    }
}
