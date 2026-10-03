//! Bulk-operation admin actions.
//!
//! Most bulk commands reuse the single-app cores
//! (`permissions::grant_admin_consent_core`, `applications::create_application_core`)
//! so the semantics stay identical to the per-app path — bulk is a UX
//! shortcut, not a new code path. The expired-credential sweep is the
//! exception: it runs its own concurrent loop for throughput, but selects
//! credentials with the same shared expiry rule
//! ([`azapptoolkit_core::audit::is_expired`]) the audit scorer and the
//! per-app removal paths use — pinned by `expired_password_key_ids`'s test in
//! `azapptoolkit_core::audit`.
//! Progress events ride the same `bulk-progress` channel so the frontend can
//! share a single listener.

use std::collections::HashMap;
use std::future::Future;

use tauri::{AppHandle, State};

use azapptoolkit_core::audit::expired_password_key_ids;
use azapptoolkit_core::models::{Application, DeletedApplication, DeletedServicePrincipal};
use azapptoolkit_graph::client::{AppListQuery, DELETED_APPS_MAX, DELETED_SPS_MAX};

use crate::commands::dispatch::{SessionDead, batch_or_serial, dispatch_capped};
use crate::commands::progress::{ProgressSink, emit_progress};
use crate::commands::throttle::FanOutMeter;
use crate::dto::UiError;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::bulk::{
    AppRemovalSummary, BulkAddOwnerResult, BulkCreateOutcome, BulkCreateResult, BulkCreateSpec,
    BulkDeleteFailure, BulkDeleteResult, BulkDisableOutcome, BulkDisableSignInResult, BulkError,
    BulkGrantOutcome, BulkGrantResult, BulkOwnerOutcome, BulkProgress, BulkRemoveExpiredResult,
    BulkRemoveRedundantOutcome, BulkRemoveRedundantResult, BulkRestoreOutcome, BulkRestoreResult,
    BulkScopeOutcome, BulkScopeResult, BulkStageCertOutcome, BulkStageCertResult,
};
use crate::state::{AppState, CancelToken};

const CONCURRENCY: usize = 4;

/// Lets [`run_bulk_seq`] ask an opaque outcome whether the run should stop.
///
/// The driver is generic over the outcome type, so it cannot reach into an
/// `error` field itself. Implemented per outcome rather than passed as a closure
/// at each call site so the answer can't drift between the six bulk commands —
/// they all mean the same thing by "the session died".
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

/// Rejects a bulk-create spec that cannot possibly succeed, without touching
/// Graph. Split out of the command closure so the rules are unit-testable: a
/// wrong `signInAudience` is rejected here, and letting it through instead means
/// N failed round trips and N confusing per-item errors.
fn validate_create_spec(spec: &BulkCreateSpec) -> Option<BulkCreateOutcome> {
    let invalid = |message: String| {
        Some(BulkCreateOutcome {
            display_name: spec.display_name.clone(),
            status: "invalid".into(),
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
    None
}

/// Accepted `signInAudience` values for bulk-create validation.
const VALID_AUDIENCES: &[&str] = &[
    "AzureADMyOrg",
    "AzureADMultipleOrgs",
    "AzureADandPersonalMicrosoftAccount",
    "PersonalMicrosoftAccount",
];

/// Signals every in-flight bulk action (delete / grant / create / expired-secret
/// sweep / scoping / owner / sign-in) to stop at the next item boundary. Runs
/// started from different bulk action bars share the kind flag
/// [`AppState::bulk_cancel`], so one Cancel stops all of them; it never touches
/// the security audit or the AAP migration, which have flags of their own.
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
/// Two read paths. When `object_ids` is `Some` (the UI scopes the sweep to the
/// user's selection — the Findings pane's "Fix all" and the App Registrations
/// bulk bar always do), exactly those apps are fetched by id in one `$batch`
/// per 20 (per-id reads if a whole batch fails), never a tenant walk; an app
/// that cannot be read is reported as a failure row rather than silently left
/// out. When `None`, every app in the tenant is walked, capped at
/// [`APPS_MAX`](super::applications::APPS_MAX) like every other tenant-wide
/// enumeration. Cancellation flows through [`AppState::bulk_cancel`], stopped by
/// [`cancel_bulk`].
#[tauri::command]
pub async fn bulk_remove_expired_credentials(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Option<Vec<String>>,
) -> Result<BulkRemoveExpiredResult, UiError> {
    // Claimed before the first await: the tenant walk below can cover 10 000
    // apps (and the batched selection read is an await too), and a token
    // claimed after it carries a higher generation than a cancel issued during
    // it, which `is_cancelled()` then discards. Pinned by
    // `repo_invariants::cancel`.
    let cancel = state.bulk_cancel.claim();
    let client = state.graph_for(&tenant_id);
    let session = SessionDead::new();
    let mut summaries: Vec<AppRemovalSummary> = Vec::new();

    // Both paths project only what the sweep reads (`expired_password_key_ids`
    // touches `passwordCredentials`); the default projection drags in
    // `requiredResourceAccess` etc. — the bulk of a permission-heavy app's
    // payload, multiplied across a full-tenant scan.
    let apps: Vec<Application> = match &object_ids {
        Some(ids) => {
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
                        // dispatch below spawns nothing and the command returns
                        // the dead-session error instead of a partial result.
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
        }
        None => {
            // `_truncated`: the cap applies only to this best-effort tenant
            // sweep, whose per-app outcomes are all reported individually — it
            // never claims to have covered every app. The selection path above
            // fetches exactly the selected ids, so the cap cannot apply there.
            let (apps, _truncated) = client
                .list_applications_all(
                    AppListQuery::default()
                        .with_top(azapptoolkit_graph::client::DEFAULT_APP_PAGE_SIZE)
                        .with_select(vec!["id", "appId", "displayName", "passwordCredentials"]),
                    Some(super::applications::APPS_MAX),
                )
                .await?;
            apps
        }
    };
    // Apps actually evaluated; a selected app that failed to read is counted in
    // `summaries`, not here.
    let total = apps.len();

    // Adaptive 429 backoff (was a fixed `CONCURRENCY` cap with no observer): the
    // throttle halves the in-flight cap on a 429 and recovers when quiet, and the
    // live cap is surfaced via `in_flight_cap` so the UI can show the back-off.
    let meter = FanOutMeter::attach(client.clone(), CONCURRENCY);

    emit_progress(
        &app_handle,
        "bulk-progress",
        BulkProgress {
            done: 0,
            total,
            current_app: None,
            cancelled: false,
            in_flight_cap: Some(meter.limit()),
        },
    );

    let now = chrono::Utc::now();

    let cancelled_early = dispatch_capped(
        apps,
        || meter.limit(),
        |app| {
            if cancel.is_cancelled() || session.is_dead() {
                return None;
            }
            let app_handle = app_handle.clone();
            let client = client.clone();
            let ticker = meter.ticker();
            let cancel = cancel.clone();
            let session = session.clone();
            let app_name = app.display_name.clone();
            let app_obj_id = app.id.clone();
            let expired_key_ids = expired_password_key_ids(&app, now);

            Some(tokio::spawn(async move {
                let mut removed = Vec::new();
                let mut failed = Vec::new();
                let mut error: Option<BulkError> = None;
                if !expired_key_ids.is_empty() {
                    for key_id in &expired_key_ids {
                        if cancel.is_cancelled() || session.is_dead() {
                            break;
                        }
                        match client.remove_password(&app_obj_id, key_id).await {
                            Ok(()) => removed.push(key_id.clone()),
                            Err(err) => {
                                failed.push(key_id.clone());
                                let ui = UiError::from(err);
                                // Latch before converting: once the session is
                                // dead every remaining key on every remaining
                                // app fails identically, so this app's own loop
                                // stops too, not just the dispatch.
                                let fatal = session.note_code(&ui.code);
                                if error.is_none() {
                                    error = Some(ui.into());
                                }
                                if fatal {
                                    break;
                                }
                            }
                        }
                    }
                }

                let (done, in_flight_cap) = ticker.tick();
                let progress = BulkProgress {
                    done,
                    total,
                    current_app: Some(app_name.clone()),
                    cancelled: cancel.is_cancelled(),
                    in_flight_cap: Some(in_flight_cap),
                };
                emit_progress(&app_handle, "bulk-progress", progress);

                AppRemovalSummary {
                    object_id: app_obj_id,
                    display_name: app_name,
                    removed_key_ids: removed,
                    failed_key_ids: failed,
                    error,
                }
            }))
        },
        |joined| match joined {
            Ok(summary) => {
                if !summary.removed_key_ids.is_empty()
                    || !summary.failed_key_ids.is_empty()
                    || summary.error.is_some()
                {
                    summaries.push(summary);
                }
            }
            Err(err) => tracing::warn!(?err, "bulk join error"),
        },
    )
    .await;

    // Terminal event, same contract as the delete/grant fan-outs: `done` is the
    // number of apps actually processed (every spawned task has joined).
    emit_progress(
        &app_handle,
        "bulk-progress",
        BulkProgress {
            done: meter.done(),
            total,
            current_app: None,
            cancelled: cancelled_early || cancel.is_cancelled(),
            in_flight_cap: Some(meter.limit()),
        },
    );

    // Invalidate BEFORE the dead-session check: the removals that already
    // landed are real, so the caches are stale either way. Returning the error
    // without busting them would leave the UI showing credentials this run
    // deleted. The only mutation here is `remove_password` — a credential-only
    // change — so each mutated app takes the credential tier, which keeps the
    // shared SP/app-name indexes, the enterprise list and every mailbox-scope
    // verdict intact (`applications::cache::invalidate_app_credentials` explains
    // the cost of dropping them: a full tenant re-enumeration). The shared keys
    // it does drop are hash removals, so repeating them per app is free.
    for mutated in summaries.iter().filter(|s| !s.removed_key_ids.is_empty()) {
        super::applications::invalidate_app_credentials(
            &state.cache,
            &tenant_id,
            &mutated.object_id,
        );
    }
    // A partial sweep reads as a complete one — the caller cannot tell "no
    // expired credentials left" from "the session died on app 40 of 900".
    if session.is_dead() {
        return Err(session.err("the expired-credential sweep"));
    }
    Ok(BulkRemoveExpiredResult {
        apps_scanned: total,
        summaries,
        cancelled: cancelled_early || cancel.is_cancelled(),
    })
}

/// Deletes every application in `object_ids`, fanning out through
/// [`dispatch_capped`] under a [`ConcurrencyThrottle`] that halves the in-flight
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
    let total = object_ids.len();
    let cancel = state.bulk_cancel.claim();

    // Bounded-concurrency fan-out with adaptive 429 backoff, replacing the old
    // serial loop + fixed 50ms pause (which slowed the healthy case yet never
    // backed off under throttling). The throttle halves the in-flight cap on a
    // 429 and recovers when quiet; `dispatch_capped` re-reads it between
    // completions so the cap takes effect mid-run.
    let meter = FanOutMeter::attach(client.clone(), CONCURRENCY);

    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    let session = SessionDead::new();
    let cancelled_early = dispatch_capped(
        object_ids,
        || meter.limit(),
        |id| {
            if cancel.is_cancelled() || session.is_dead() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let ticker = meter.ticker();
            let cancel = cancel.clone();
            let session = session.clone();
            Some(tokio::spawn(async move {
                let result = client.delete_application(&id).await;
                let (done, in_flight_cap) = ticker.tick();
                let progress = BulkProgress {
                    done,
                    total,
                    current_app: Some(id.clone()),
                    cancelled: cancel.is_cancelled(),
                    in_flight_cap: Some(in_flight_cap),
                };
                emit_progress(&app_handle, "bulk-progress", progress);
                match result {
                    Ok(()) => Ok(id),
                    Err(err) => {
                        // `BulkDeleteFailure` carries no wire code, so the
                        // classification has to happen here, while the typed
                        // error still exists.
                        let ui = UiError::from(err);
                        session.note_code(&ui.code);
                        Err(BulkDeleteFailure {
                            object_id: id,
                            message: ui.message,
                        })
                    }
                }
            }))
        },
        |joined| match joined {
            Ok(Ok(id)) => deleted.push(id),
            Ok(Err(f)) => failed.push(f),
            Err(err) => tracing::warn!(?err, "bulk delete join error"),
        },
    )
    .await;

    emit_progress(
        &app_handle,
        "bulk-progress",
        BulkProgress {
            // Items actually processed: `dispatch_capped` has joined every
            // spawned task, so the meter's count is final. Equal to `total`
            // only for a run that finished.
            done: meter.done(),
            total,
            current_app: None,
            cancelled: cancelled_early || cancel.is_cancelled(),
            in_flight_cap: Some(meter.limit()),
        },
    );

    // Bust first: the deletions that landed are real regardless of how the run
    // ended (see the sweep above).
    if !deleted.is_empty() {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
    }
    if session.is_dead() {
        return Err(session.err("the bulk delete"));
    }
    Ok(BulkDeleteResult {
        deleted,
        failed,
        cancelled: cancelled_early || cancel.is_cancelled(),
    })
}

/// Grants admin consent to each application in `object_ids`, reusing the same
/// orchestration as the single-app command. Bounded-concurrency fan-out with
/// adaptive 429 backoff (each app issues several Graph writes, so the throttle
/// matters); cancellation rides [`AppState::bulk_cancel`] and progress the
/// shared `bulk-progress` stream.
#[tauri::command]
pub async fn bulk_grant_permissions(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkGrantResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let total = object_ids.len();
    let cancel = state.bulk_cancel.claim();

    // Bounded-concurrency fan-out with adaptive 429 backoff, replacing the old
    // serial loop + fixed 50ms pause. Each grant is a multi-write orchestration,
    // so backing off the in-flight cap under throttling matters more here than
    // for the delete sweep.
    let meter = FanOutMeter::attach(client.clone(), CONCURRENCY);

    let mut outcomes = Vec::new();
    // True if any app's grant created a brand-new SP — that adds Enterprise App
    // rows / search-index entries, so the run must bust the full list caches.
    let mut any_sp_created = false;
    let session = SessionDead::new();
    let cancelled_early = dispatch_capped(
        object_ids,
        || meter.limit(),
        |id| {
            if cancel.is_cancelled() || session.is_dead() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let ticker = meter.ticker();
            let cancel = cancel.clone();
            let session = session.clone();
            Some(tokio::spawn(async move {
                let res = super::permissions::grant_admin_consent_core(&client, &id).await;
                let (done, in_flight_cap) = ticker.tick();
                let progress = BulkProgress {
                    done,
                    total,
                    current_app: Some(id.clone()),
                    cancelled: cancel.is_cancelled(),
                    in_flight_cap: Some(in_flight_cap),
                };
                emit_progress(&app_handle, "bulk-progress", progress);
                match res {
                    // The client SP was created and a later step failed: the
                    // row reports the error, and `sp_created` still reaches
                    // `any_sp_created` so the new Enterprise App row is busted.
                    Ok(super::permissions::GrantRun {
                        error: Some(e),
                        sp_created,
                        ..
                    }) => {
                        session.note_code(&e.code);
                        (
                            BulkGrantOutcome {
                                object_id: id,
                                granted: 0,
                                skipped: 0,
                                failed: 0,
                                error: Some(e.into()),
                            },
                            sp_created,
                        )
                    }
                    Ok(run) => {
                        let r = run.result;
                        (
                            BulkGrantOutcome {
                                object_id: id,
                                granted: r.role_assignments_created.len()
                                    + r.scope_grants_upserted.len(),
                                skipped: r.role_assignments_skipped.len(),
                                failed: r.failures.len(),
                                error: r.failures.first().map(|f| BulkError {
                                    code: "partial_failure".into(),
                                    message: f.message.clone(),
                                    retryable: false,
                                }),
                            },
                            run.sp_created,
                        )
                    }
                    Err(e) => {
                        session.note_code(&e.code);
                        (
                            BulkGrantOutcome {
                                object_id: id,
                                granted: 0,
                                skipped: 0,
                                failed: 0,
                                error: Some(e.into()),
                            },
                            false,
                        )
                    }
                }
            }))
        },
        |joined| match joined {
            Ok((outcome, sp_created)) => {
                any_sp_created |= sp_created;
                outcomes.push(outcome);
            }
            Err(err) => tracing::warn!(?err, "bulk grant join error"),
        },
    )
    .await;

    emit_progress(
        &app_handle,
        "bulk-progress",
        BulkProgress {
            // Items actually processed: `dispatch_capped` has joined every
            // spawned task, so the meter's count is final. Equal to `total`
            // only for a run that finished.
            done: meter.done(),
            total,
            current_app: None,
            cancelled: cancelled_early || cancel.is_cancelled(),
            in_flight_cap: Some(meter.limit()),
        },
    );

    // Consent really changed app-role/scope state for any app that granted >0, so
    // bust the detail + audit caches exactly like the single-app path
    // (permissions::grant_admin_consent). Only on this success path. If any grant
    // created a new SP, bust the full list caches instead (new Enterprise App
    // row / search-index entry), matching grant_single_permission.
    if any_sp_created {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
    } else if outcomes.iter().any(|o| o.granted > 0) {
        super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    // Bust first (the grants that landed are real), then refuse to present the
    // remainder as consented.
    if session.is_dead() {
        return Err(session.err("the bulk consent grant"));
    }

    Ok(BulkGrantResult {
        outcomes,
        cancelled: cancelled_early || cancel.is_cancelled(),
    })
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

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        specs,
        |spec| spec.display_name.clone(),
        |spec| {
            let client = client.clone();
            async move {
                if let Some(rejection) = validate_create_spec(&spec) {
                    return rejection;
                }
                if validate_only {
                    return BulkCreateOutcome {
                        display_name: spec.display_name,
                        status: "valid".into(),
                        app_id: None,
                        message: None,
                        error: None,
                    };
                }
                let input = CreateApplicationInput {
                    display_name: spec.display_name.clone(),
                    sign_in_audience: spec.sign_in_audience,
                    description: spec.description,
                    ..Default::default()
                };
                match super::applications::create_application_core(&client, input).await {
                    Ok((r, None)) => BulkCreateOutcome {
                        display_name: r.application.display_name,
                        status: "created".into(),
                        app_id: Some(r.application.app_id),
                        message: None,
                        error: None,
                    },
                    // The registration landed and a later step failed: the app
                    // exists (so `any_created` busts the list tier below) and
                    // the error still reaches the row — and `run_bulk_seq`,
                    // which stops on a re-auth-fatal code.
                    Ok((r, Some(e))) => BulkCreateOutcome {
                        display_name: r.application.display_name,
                        status: "created".into(),
                        app_id: Some(r.application.app_id),
                        message: Some(e.message.clone()),
                        error: Some(e.into()),
                    },
                    Err(e) => BulkCreateOutcome {
                        display_name: spec.display_name,
                        status: "failed".into(),
                        app_id: None,
                        message: Some(e.message.clone()),
                        error: Some(e.into()),
                    },
                }
            }
        },
    )
    .await;

    let any_created = !validate_only && outcomes.iter().any(|o| o.status == "created");
    if any_created {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
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

/// Shared scaffold for the **sequential** bulk commands (create / remove-redundant
/// / scope-mailbox / scope-sharepoint / add-owner / disable-sign-in). These stay
/// sequential on purpose: each per-app core takes `State` (not `Send`, so it can't
/// cross into a `dispatch_capped` spawn) and the selection is a small admin-chosen
/// set — the win here is dedup, not concurrency.
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
            "bulk-progress",
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
        "bulk-progress",
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

#[cfg(test)]
mod tests {
    use super::*;
    // Tests build their own runs; the commands only ever hold a token.
    use crate::commands::test_support::Recorder;
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
        rec.payloads::<BulkProgress>("bulk-progress")
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
        assert!(rec.names().iter().all(|n| *n == "bulk-progress"));
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
        assert!(rec.payloads::<BulkProgress>("bulk-progress")[0].cancelled);
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
            rec.payloads::<BulkProgress>("bulk-progress")
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
            description: None,
        };

        assert!(validate_create_spec(&spec("Ok", None)).is_none());
        for aud in VALID_AUDIENCES {
            assert!(
                validate_create_spec(&spec("Ok", Some(aud))).is_none(),
                "{aud} is in VALID_AUDIENCES and must pass"
            );
        }

        let rejected = validate_create_spec(&spec("Ok", Some("AzureADandPersonal"))).unwrap();
        assert_eq!(rejected.status, "invalid");
        assert!(rejected.message.unwrap().contains("AzureADandPersonal"));
        // A local rejection carries no wire code, so it can never be mistaken
        // for a session failure by the run-level fatal check.
        assert!(rejected.error.is_none());

        // Whitespace-only names are rejected too — Graph would take the round
        // trip and fail.
        let blank = validate_create_spec(&spec("   ", None)).unwrap();
        assert_eq!(blank.status, "invalid");
    }
}
