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

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use azapptoolkit_core::audit::expired_password_key_ids;
use azapptoolkit_graph::client::AppListQuery;

use crate::commands::dispatch::dispatch_capped;
use crate::commands::throttle::{ConcurrencyThrottle, ThrottleGuard};
use crate::dto::UiError;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::bulk::{
    AppRemovalSummary, BulkAddOwnerResult, BulkCreateOutcome, BulkCreateResult, BulkCreateSpec,
    BulkDeleteFailure, BulkDeleteResult, BulkDisableOutcome, BulkDisableSignInResult,
    BulkGrantOutcome, BulkGrantResult, BulkOwnerOutcome, BulkProgress, BulkRemoveExpiredResult,
    BulkRemoveRedundantOutcome, BulkRemoveRedundantResult, BulkScopeOutcome, BulkScopeResult,
};
use crate::state::AppState;

const CONCURRENCY: usize = 4;

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
    let mut apps = client
        .list_applications_all(
            AppListQuery::default().with_top(100).with_select(vec![
                "id",
                "appId",
                "displayName",
                "passwordCredentials",
            ]),
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

    emit(
        &app_handle,
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
                let mut error: Option<String> = None;
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
                                    error = Some(err.to_string());
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
                emit(&app_handle, progress);

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

/// Deletes every application in `object_ids` sequentially. Failures are
/// collected rather than aborting — the UI shows a summary dialog.
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
                emit(&app_handle, progress);
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

    emit(
        &app_handle,
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
                emit(&app_handle, progress);
                match res {
                    Ok((r, sp_created)) => (
                        BulkGrantOutcome {
                            object_id: id,
                            granted: r.role_assignments_created.len()
                                + r.scope_grants_upserted.len(),
                            skipped: r.role_assignments_skipped.len(),
                            failed: r.failures.len(),
                            error: r.failures.first().map(|f| f.message.clone()),
                        },
                        sp_created,
                    ),
                    Err(e) => (
                        BulkGrantOutcome {
                            object_id: id,
                            granted: 0,
                            skipped: 0,
                            failed: 0,
                            error: Some(e.message),
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

    emit(
        &app_handle,
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

    let client = state.graph_for(&tenant_id);
    let total = specs.len();
    let cancel = state.audit_cancel.clone();
    let mut outcomes = Vec::new();

    for (i, spec) in specs.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit(
            &app_handle,
            BulkProgress {
                done: i,
                total,
                current_app: Some(spec.display_name.clone()),
                cancelled: false,
                in_flight_cap: None,
            },
        );

        // Validate.
        if spec.display_name.trim().is_empty() {
            outcomes.push(BulkCreateOutcome {
                display_name: spec.display_name,
                status: "invalid".into(),
                app_id: None,
                message: Some("display name is required".into()),
            });
            continue;
        }
        if let Some(aud) = &spec.sign_in_audience
            && !VALID_AUDIENCES.contains(&aud.as_str())
        {
            outcomes.push(BulkCreateOutcome {
                display_name: spec.display_name,
                status: "invalid".into(),
                app_id: None,
                message: Some(format!("unrecognised signInAudience: {aud}")),
            });
            continue;
        }
        if validate_only {
            outcomes.push(BulkCreateOutcome {
                display_name: spec.display_name,
                status: "valid".into(),
                app_id: None,
                message: None,
            });
            continue;
        }

        let input = CreateApplicationInput {
            display_name: spec.display_name.clone(),
            sign_in_audience: spec.sign_in_audience,
            description: spec.description,
            ..Default::default()
        };
        match super::applications::create_application_core(&client, input).await {
            Ok(r) => outcomes.push(BulkCreateOutcome {
                display_name: r.application.display_name,
                status: "created".into(),
                app_id: Some(r.application.app_id),
                message: None,
            }),
            Err(e) => outcomes.push(BulkCreateOutcome {
                display_name: spec.display_name,
                status: "failed".into(),
                app_id: None,
                message: Some(e.message),
            }),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    emit(
        &app_handle,
        BulkProgress {
            done: total,
            total,
            current_app: None,
            cancelled: cancel.is_cancelled(),
            in_flight_cap: None,
        },
    );

    let any_created = !validate_only && outcomes.iter().any(|o| o.status == "created");
    if any_created {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
    }
    Ok(BulkCreateResult {
        validate_only,
        outcomes,
        cancelled: cancel.is_cancelled(),
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
    let total = object_ids.len();
    let mut outcomes = Vec::new();

    for (i, object_id) in object_ids.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit(
            &app_handle,
            BulkProgress {
                done: i,
                total,
                current_app: Some(object_id.clone()),
                cancelled: false,
                in_flight_cap: None,
            },
        );
        let outcome = match super::remediation::remediate_remove_redundant_permissions(
            state.clone(),
            tenant_id.clone(),
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
                error: Some(e.message),
            },
        };
        outcomes.push(outcome);
    }

    emit(
        &app_handle,
        BulkProgress {
            done: total,
            total,
            current_app: None,
            cancelled: cancel.is_cancelled(),
            in_flight_cap: None,
        },
    );
    Ok(BulkRemoveRedundantResult {
        outcomes,
        cancelled: cancel.is_cancelled(),
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
    let total = object_ids.len();
    let mut outcomes = Vec::new();

    for (i, object_id) in object_ids.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit(
            &app_handle,
            BulkProgress {
                done: i,
                total,
                current_app: Some(object_id.clone()),
                cancelled: false,
                in_flight_cap: None,
            },
        );
        let error = super::exchange::grant_exchange_mailbox_access(
            state.clone(),
            tenant_id.clone(),
            object_id.clone(),
            None,
            groups.clone(),
            true,
        )
        .await
        .err()
        .map(|e| e.message);
        outcomes.push(BulkScopeOutcome { object_id, error });
    }

    emit(
        &app_handle,
        BulkProgress {
            done: total,
            total,
            current_app: None,
            cancelled: cancel.is_cancelled(),
            in_flight_cap: None,
        },
    );
    Ok(BulkScopeResult {
        outcomes,
        cancelled: cancel.is_cancelled(),
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
    let total = object_ids.len();
    let mut outcomes = Vec::new();

    for (i, object_id) in object_ids.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit(
            &app_handle,
            BulkProgress {
                done: i,
                total,
                current_app: Some(object_id.clone()),
                cancelled: false,
                in_flight_cap: None,
            },
        );
        let error = super::remediation::remediate_scope_sharepoint_access(
            state.clone(),
            tenant_id.clone(),
            object_id.clone(),
            site_urls.clone(),
            role.clone(),
        )
        .await
        .err()
        .map(|e| e.message);
        outcomes.push(BulkScopeOutcome { object_id, error });
    }

    emit(
        &app_handle,
        BulkProgress {
            done: total,
            total,
            current_app: None,
            cancelled: cancel.is_cancelled(),
            in_flight_cap: None,
        },
    );
    Ok(BulkScopeResult {
        outcomes,
        cancelled: cancel.is_cancelled(),
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
    let total = object_ids.len();
    let mut outcomes = Vec::new();
    let mut any_added = false;

    for (i, object_id) in object_ids.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit(
            &app_handle,
            BulkProgress {
                done: i,
                total,
                current_app: Some(object_id.clone()),
                cancelled: false,
                in_flight_cap: None,
            },
        );
        let outcome = match client.list_owners(&object_id).await {
            Ok(owners) if owners.iter().any(|o| o.id == principal_id) => BulkOwnerOutcome {
                object_id,
                added: false,
                skipped: true,
                error: None,
            },
            Ok(_) => match client.add_owner(&object_id, &principal_id).await {
                Ok(()) => {
                    any_added = true;
                    BulkOwnerOutcome {
                        object_id,
                        added: true,
                        skipped: false,
                        error: None,
                    }
                }
                Err(e) => BulkOwnerOutcome {
                    object_id,
                    added: false,
                    skipped: false,
                    error: Some(UiError::from(e).message),
                },
            },
            Err(e) => BulkOwnerOutcome {
                object_id,
                added: false,
                skipped: false,
                error: Some(UiError::from(e).message),
            },
        };
        outcomes.push(outcome);
    }

    if any_added {
        super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    emit(
        &app_handle,
        BulkProgress {
            done: total,
            total,
            current_app: None,
            cancelled: cancel.is_cancelled(),
            in_flight_cap: None,
        },
    );
    Ok(BulkAddOwnerResult {
        outcomes,
        cancelled: cancel.is_cancelled(),
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
    let total = object_ids.len();
    let mut outcomes = Vec::new();

    for (i, object_id) in object_ids.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit(
            &app_handle,
            BulkProgress {
                done: i,
                total,
                current_app: Some(object_id.clone()),
                cancelled: false,
                in_flight_cap: None,
            },
        );
        let error = super::remediation::remediate_disable_sign_in(
            state.clone(),
            tenant_id.clone(),
            object_id.clone(),
        )
        .await
        .err()
        .map(|e| e.message);
        outcomes.push(BulkDisableOutcome { object_id, error });
    }

    emit(
        &app_handle,
        BulkProgress {
            done: total,
            total,
            current_app: None,
            cancelled: cancel.is_cancelled(),
            in_flight_cap: None,
        },
    );
    Ok(BulkDisableSignInResult {
        outcomes,
        cancelled: cancel.is_cancelled(),
    })
}

fn emit(app_handle: &AppHandle, progress: BulkProgress) {
    if let Err(err) = app_handle.emit("bulk-progress", progress) {
        tracing::warn!(?err, "bulk-progress emit failed");
    }
}
