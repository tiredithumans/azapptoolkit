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

use std::future::Future;
use std::sync::Arc;

use tauri::{AppHandle, State};
use tokio::sync::Mutex;

use azapptoolkit_core::audit::expired_password_key_ids;
use azapptoolkit_graph::client::AppListQuery;

use crate::commands::dispatch::dispatch_capped;
use crate::commands::progress::emit_progress;
use crate::commands::throttle::{ConcurrencyThrottle, ThrottleGuard};
use crate::dto::UiError;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::bulk::{
    AppRemovalSummary, BulkAddOwnerResult, BulkCreateOutcome, BulkCreateResult, BulkCreateSpec,
    BulkDeleteFailure, BulkDeleteResult, BulkDisableOutcome, BulkDisableSignInResult, BulkError,
    BulkGrantOutcome, BulkGrantResult, BulkOwnerOutcome, BulkProgress, BulkRemoveExpiredResult,
    BulkRemoveRedundantOutcome, BulkRemoveRedundantResult, BulkScopeOutcome, BulkScopeResult,
};
use crate::state::{AppState, CancelFlag};

const CONCURRENCY: usize = 4;

/// Where [`run_bulk_seq`] sends its progress events.
///
/// The driver took an `&AppHandle`, which made it untestable without a Tauri
/// runtime — and `tauri`'s `test` feature (for `mock_app()`) breaks the Windows
/// test binary with STATUS_ENTRYPOINT_NOT_FOUND, since enabling it alongside the
/// WebView2 runtime mismatches an entrypoint at link time. The driver never
/// needed a runtime, only a sink; this is the narrower dependency, and it lets
/// the tests assert the progress sequence as well as the loop control.
trait ProgressSink {
    fn emit(&self, payload: BulkProgress);
}

impl<R: tauri::Runtime> ProgressSink for AppHandle<R> {
    fn emit(&self, payload: BulkProgress) {
        emit_progress(self, "bulk-progress", payload);
    }
}

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

/// Signals an in-progress bulk action (delete / grant / create / expired-secret
/// sweep) to stop at the next item boundary. Shares [`AppState::audit_cancel`]
/// with the security audit — the two long-running loops never run at once, so
/// one flag covers both; this intent-named command lets the Bulk Actions view
/// wire its own Cancel button without reaching for `cancel_audit`. Already
/// in-flight per-item work finishes so partial results stay clean.
#[tauri::command]
pub fn cancel_bulk(state: State<'_, AppState>) {
    state.audit_cancel.cancel();
}

/// Sweeps app registrations and deletes any password credential (secret) that
/// is expired per [`expired_password_key_ids`]'s whole-day rule. Note this is
/// **secrets-only** by design; the per-app one-click fix
/// (`commands::remediation::remediate_remove_expired_credentials`)
/// also removes expired *certificates*. When `object_ids` is `Some`, only those apps
/// are scanned (the UI scopes the sweep to the user's selection); when `None`,
/// every app in the tenant is swept. Cancellation flows through
/// [`AppState::audit_cancel`] — the audit and bulk loops share it so the UI
/// only needs one Cancel button concept.
#[tauri::command]
pub async fn bulk_remove_expired_credentials(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Option<Vec<String>>,
) -> Result<BulkRemoveExpiredResult, UiError> {
    state.audit_cancel.reset();

    let client = state.graph_for(&tenant_id);
    // Project only what the sweep reads (`expired_password_key_ids` touches
    // `passwordCredentials`); the default projection drags in
    // `requiredResourceAccess` etc. — the bulk of a permission-heavy app's
    // payload, multiplied across a full-tenant scan. Mirrors
    // `list_credential_expirations`.
    // `_truncated`: the sweep is either scoped to an explicit `object_ids` set
    // (below, where the cap cannot matter) or is a best-effort tenant sweep whose
    // per-app outcomes are all reported individually — it never claims to have
    // covered every app.
    let (mut apps, _truncated) = client
        .list_applications_all(
            AppListQuery::default()
                .with_top(azapptoolkit_graph::client::DEFAULT_APP_PAGE_SIZE)
                .with_select(vec!["id", "appId", "displayName", "passwordCredentials"]),
            Some(10_000),
        )
        .await?;
    // Scope the sweep to the selected apps, if any were provided. Reuses the
    // same list path so credential semantics stay identical to the full sweep.
    if let Some(ids) = &object_ids {
        apps.retain(|app| ids.contains(&app.id));
    }
    let total = apps.len();

    // Adaptive 429 backoff (was a fixed `CONCURRENCY` cap with no observer): the
    // throttle halves the in-flight cap on a 429 and recovers when quiet, and the
    // live cap is surfaced via `in_flight_cap` so the UI can show the back-off.
    let tracker = Arc::new(ConcurrencyThrottle::new(CONCURRENCY));
    let _throttle_guard = ThrottleGuard::attach(client.clone(), tracker.clone());

    emit_progress(
        &app_handle,
        "bulk-progress",
        BulkProgress {
            done: 0,
            total,
            current_app: None,
            cancelled: false,
            in_flight_cap: Some(tracker.current_limit()),
        },
    );

    let done = Arc::new(Mutex::new(0usize));
    let cancel = state.audit_cancel.clone();
    let now = chrono::Utc::now();

    let mut summaries: Vec<AppRemovalSummary> = Vec::new();
    let cancelled_early = dispatch_capped(
        apps,
        || tracker.current_limit(),
        |app| {
            if cancel.is_cancelled() {
                return None;
            }
            let app_handle = app_handle.clone();
            let client = client.clone();
            let tracker = tracker.clone();
            let done = done.clone();
            let cancel = cancel.clone();
            let app_name = app.display_name.clone();
            let app_obj_id = app.id.clone();
            let expired_key_ids = expired_password_key_ids(&app, now);

            Some(tokio::spawn(async move {
                let mut removed = Vec::new();
                let mut failed = Vec::new();
                let mut error: Option<BulkError> = None;
                if !expired_key_ids.is_empty() {
                    for key_id in &expired_key_ids {
                        if cancel.is_cancelled() {
                            break;
                        }
                        match client.remove_password(&app_obj_id, key_id).await {
                            Ok(()) => removed.push(key_id.clone()),
                            Err(err) => {
                                failed.push(key_id.clone());
                                if error.is_none() {
                                    error = Some(UiError::from(err).into());
                                }
                            }
                        }
                    }
                }

                let mut guard = done.lock().await;
                *guard += 1;
                let progress = BulkProgress {
                    done: *guard,
                    total,
                    current_app: Some(app_name.clone()),
                    cancelled: cancel.is_cancelled(),
                    in_flight_cap: Some(tracker.current_limit()),
                };
                drop(guard);
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

    let any_removed = summaries.iter().any(|s| !s.removed_key_ids.is_empty());
    if any_removed {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
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
    state.audit_cancel.reset();

    let client = state.graph_for(&tenant_id);
    let total = object_ids.len();
    let cancel = state.audit_cancel.clone();

    // Bounded-concurrency fan-out with adaptive 429 backoff, replacing the old
    // serial loop + fixed 50ms pause (which slowed the healthy case yet never
    // backed off under throttling). The throttle halves the in-flight cap on a
    // 429 and recovers when quiet; `dispatch_capped` re-reads it between
    // completions so the cap takes effect mid-run.
    let tracker = Arc::new(ConcurrencyThrottle::new(CONCURRENCY));
    let _throttle_guard = ThrottleGuard::attach(client.clone(), tracker.clone());
    let done = Arc::new(Mutex::new(0usize));

    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    let cancelled_early = dispatch_capped(
        object_ids,
        || tracker.current_limit(),
        |id| {
            if cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let cancel = cancel.clone();
            let tracker = tracker.clone();
            Some(tokio::spawn(async move {
                let result = client.delete_application(&id).await;
                let mut guard = done.lock().await;
                *guard += 1;
                let progress = BulkProgress {
                    done: *guard,
                    total,
                    current_app: Some(id.clone()),
                    cancelled: cancel.is_cancelled(),
                    in_flight_cap: Some(tracker.current_limit()),
                };
                drop(guard);
                emit_progress(&app_handle, "bulk-progress", progress);
                match result {
                    Ok(()) => Ok(id),
                    Err(err) => Err(BulkDeleteFailure {
                        object_id: id,
                        message: err.to_string(),
                    }),
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
            done: total,
            total,
            current_app: None,
            cancelled: cancelled_early || cancel.is_cancelled(),
            in_flight_cap: Some(tracker.current_limit()),
        },
    );

    if !deleted.is_empty() {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
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
/// matters); cancellation and progress share the audit/bulk plumbing.
#[tauri::command]
pub async fn bulk_grant_permissions(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkGrantResult, UiError> {
    state.audit_cancel.reset();

    let client = state.graph_for(&tenant_id);
    let total = object_ids.len();
    let cancel = state.audit_cancel.clone();

    // Bounded-concurrency fan-out with adaptive 429 backoff, replacing the old
    // serial loop + fixed 50ms pause. Each grant is a multi-write orchestration,
    // so backing off the in-flight cap under throttling matters more here than
    // for the delete sweep.
    let tracker = Arc::new(ConcurrencyThrottle::new(CONCURRENCY));
    let _throttle_guard = ThrottleGuard::attach(client.clone(), tracker.clone());
    let done = Arc::new(Mutex::new(0usize));

    let mut outcomes = Vec::new();
    // True if any app's grant created a brand-new SP — that adds Enterprise App
    // rows / search-index entries, so the run must bust the full list caches.
    let mut any_sp_created = false;
    let cancelled_early = dispatch_capped(
        object_ids,
        || tracker.current_limit(),
        |id| {
            if cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let cancel = cancel.clone();
            let tracker = tracker.clone();
            Some(tokio::spawn(async move {
                let res = super::permissions::grant_admin_consent_core(&client, &id).await;
                let mut guard = done.lock().await;
                *guard += 1;
                let progress = BulkProgress {
                    done: *guard,
                    total,
                    current_app: Some(id.clone()),
                    cancelled: cancel.is_cancelled(),
                    in_flight_cap: Some(tracker.current_limit()),
                };
                drop(guard);
                emit_progress(&app_handle, "bulk-progress", progress);
                match res {
                    Ok((r, sp_created)) => (
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
                        sp_created,
                    ),
                    Err(e) => (
                        BulkGrantOutcome {
                            object_id: id,
                            granted: 0,
                            skipped: 0,
                            failed: 0,
                            error: Some(e.into()),
                        },
                        false,
                    ),
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
            done: total,
            total,
            current_app: None,
            cancelled: cancelled_early || cancel.is_cancelled(),
            in_flight_cap: Some(tracker.current_limit()),
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
    state.audit_cancel.reset();
    let cancel = state.audit_cancel.clone();
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
                    Ok(r) => BulkCreateOutcome {
                        display_name: r.application.display_name,
                        status: "created".into(),
                        app_id: Some(r.application.app_id),
                        message: None,
                        error: None,
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
/// single-app remediation core ([`remediation::remediate_remove_redundant_permissions`])
/// so the live re-resolution + safety rules + per-app cache invalidation are
/// identical to the one-click fix. Runs sequentially (each call is a multi-read
/// manifest re-plan, and the selection is the admin's hand-picked set), polling
/// the shared cancel flag between apps and degrading to a per-app `error` rather
/// than aborting. No `in_flight_cap` — there's no concurrent fan-out to back off.
#[tauri::command]
pub async fn bulk_remove_redundant_permissions(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    object_ids: Vec<String>,
) -> Result<BulkRemoveRedundantResult, UiError> {
    state.audit_cancel.reset();
    let cancel = state.audit_cancel.clone();

    let (outcomes, cancelled) = run_bulk_seq(
        &app_handle,
        &cancel,
        object_ids,
        |id| id.clone(),
        |object_id| {
            let state = state.clone();
            let tenant_id = tenant_id.clone();
            async move {
                match super::remediation::remediate_remove_redundant_permissions(
                    state,
                    tenant_id,
                    object_id.clone(),
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
    state.audit_cancel.reset();
    let cancel = state.audit_cancel.clone();

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
    state.audit_cancel.reset();
    let cancel = state.audit_cancel.clone();

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
    state.audit_cancel.reset();
    let cancel = state.audit_cancel.clone();
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
    state.audit_cancel.reset();
    let cancel = state.audit_cancel.clone();

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

/// Shared scaffold for the **sequential** bulk commands (create / remove-redundant
/// / scope-mailbox / scope-sharepoint / add-owner / disable-sign-in). These stay
/// sequential on purpose: each per-app core takes `State` (not `Send`, so it can't
/// cross into a `dispatch_capped` spawn) and the selection is a small admin-chosen
/// set — the win here is dedup, not concurrency.
///
/// Runs `per_item` on each `items` element in order, emitting a `bulk-progress`
/// event (`done = i`, `in_flight_cap: None` — there's no fan-out to back off)
/// with `label(&item)` as the current app *before* each item, then a final
/// `done = total` event. Polls the shared cancel flag between items (already
/// in-flight work finishes). Returns `(outcomes, cancelled)`; callers apply their
/// own cache invalidation from the outcomes. The caller resets the flag and
/// clones it (the `reset()` must stay at the command top, the AGENTS.md footgun).
async fn run_bulk_seq<S: ProgressSink, T, O, Fut>(
    progress: &S,
    cancel: &CancelFlag,
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
        progress.emit(BulkProgress {
            done: i,
            total,
            current_app: Some(label(&item)),
            cancelled: false,
            in_flight_cap: None,
        });
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
    progress.emit(BulkProgress {
        done: total,
        total,
        current_app: None,
        cancelled: cancel.is_cancelled(),
        in_flight_cap: None,
    });
    (outcomes, cancel.is_cancelled())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Records what the driver would have emitted over IPC.
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<BulkProgress>>);

    impl ProgressSink for Recorder {
        fn emit(&self, payload: BulkProgress) {
            self.0.lock().unwrap().push(payload);
        }
    }

    impl Recorder {
        /// `(done, current_app)` per event, in order.
        fn events(&self) -> Vec<(usize, Option<String>)> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|p| (p.done, p.current_app.clone()))
                .collect()
        }
    }

    async fn drive_with(
        rec: &Recorder,
        cancel: &CancelFlag,
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
        cancel: &CancelFlag,
        items: Vec<BulkScopeOutcome>,
    ) -> (Vec<BulkScopeOutcome>, bool) {
        drive_with(&Recorder::default(), cancel, items).await
    }

    #[tokio::test]
    async fn processes_every_item_and_reports_progress_before_each() {
        let cancel = CancelFlag::default();
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
            rec.events(),
            vec![
                (0, Some("a".into())),
                (1, Some("b".into())),
                (2, Some("c".into())),
                (3, None),
            ]
        );
    }

    #[tokio::test]
    async fn a_cancel_before_the_first_item_processes_nothing() {
        // The flag is polled BEFORE each item, so a cancel that lands before the
        // loop starts must mutate nothing at all — the property that makes the
        // Cancel button safe on the destructive commands (delete, disable).
        let cancel = CancelFlag::default();
        cancel.cancel();
        let rec = Recorder::default();
        let (out, cancelled) = drive_with(&rec, &cancel, vec![scope_outcome("a", None)]).await;
        assert!(out.is_empty(), "cancelled before item 1 ⇒ nothing ran");
        assert!(cancelled);
        // Only the terminal event, and it reports the cancellation.
        assert_eq!(rec.events(), vec![(1, None)]);
        assert!(rec.0.lock().unwrap()[0].cancelled);
    }

    #[tokio::test]
    async fn per_item_errors_are_collected_and_do_not_stop_the_run() {
        // An ordinary per-item failure is data, not a halt: the remaining
        // selection still gets processed.
        let cancel = CancelFlag::default();
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
        let cancel = CancelFlag::default();
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
