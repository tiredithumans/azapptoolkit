//! Bulk-operation admin actions.
//!
//! Most bulk commands reuse the single-app cores
//! (`permissions::grant_admin_consent_core`, `applications::create_application_core`)
//! so the semantics stay identical to the per-app path — bulk is a UX
//! shortcut, not a new code path. The expired-credential sweep is the
//! exception: it runs its own concurrent loop for throughput, but selects
//! credentials with the same shared expiry rule
//! ([`azapptoolkit_core::audit::is_expired`]) the audit scorer and the
//! per-app removal paths use — pinned by [`expired_password_key_ids`]'s test.
//! Progress events ride the same `bulk-progress` channel so the frontend can
//! share a single listener.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use azapptoolkit_core::audit::is_expired;
use azapptoolkit_core::models::Application;
use azapptoolkit_graph::client::AppListQuery;

use crate::commands::dispatch::dispatch_capped;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::bulk::{
    AppRemovalSummary, BulkCreateOutcome, BulkCreateResult, BulkCreateSpec, BulkDeleteFailure,
    BulkDeleteResult, BulkGrantOutcome, BulkGrantResult, BulkProgress, BulkRemoveExpiredResult,
};
use crate::dto::UiError;
use crate::state::AppState;

const CONCURRENCY: usize = 4;

/// Accepted `signInAudience` values for bulk-create validation.
const VALID_AUDIENCES: &[&str] = &[
    "AzureADMyOrg",
    "AzureADMultipleOrgs",
    "AzureADandPersonalMicrosoftAccount",
    "PersonalMicrosoftAccount",
];

/// keyIds of the app's expired secrets, by the audit's shared whole-day rule —
/// the same set the audit flags and the per-app paths remove, so the sweep is
/// a throughput shortcut, not a different deletion policy.
fn expired_password_key_ids(app: &Application, now: DateTime<Utc>) -> Vec<String> {
    app.password_credentials
        .iter()
        .filter(|c| is_expired(c.end_date_time, now))
        .map(|c| c.key_id.clone())
        .collect()
}

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
    let mut apps = client
        .list_applications_all(AppListQuery::default().with_top(100), Some(10_000))
        .await?;
    // Scope the sweep to the selected apps, if any were provided. Reuses the
    // same list path so credential semantics stay identical to the full sweep.
    if let Some(ids) = &object_ids {
        apps.retain(|app| ids.contains(&app.id));
    }
    let total = apps.len();

    emit(
        &app_handle,
        BulkProgress {
            done: 0,
            total,
            current_app: None,
            cancelled: false,
            in_flight_cap: None,
        },
    );

    let done = Arc::new(Mutex::new(0usize));
    let cancel = state.audit_cancel.clone();
    let now = chrono::Utc::now();

    let mut summaries: Vec<AppRemovalSummary> = Vec::new();
    let cancelled_early = dispatch_capped(
        apps,
        || CONCURRENCY,
        |app| {
            if cancel.is_cancelled() {
                return None;
            }
            let app_handle = app_handle.clone();
            let client = client.clone();
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
                    in_flight_cap: None,
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

    let mut deleted = Vec::new();
    let mut failed = Vec::new();

    for (i, id) in object_ids.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit(
            &app_handle,
            BulkProgress {
                done: i,
                total,
                current_app: Some(id.clone()),
                cancelled: false,
                in_flight_cap: None,
            },
        );
        match client.delete_application(&id).await {
            Ok(()) => deleted.push(id),
            Err(err) => failed.push(BulkDeleteFailure {
                object_id: id,
                message: err.to_string(),
            }),
        }
        // Small pause so we don't sprint through a 100-app deletion and burn
        // the tenant-level request budget.
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

    if !deleted.is_empty() {
        super::applications::invalidate_app_lists(&state.cache, &tenant_id);
    }
    Ok(BulkDeleteResult {
        deleted,
        failed,
        cancelled: cancel.is_cancelled(),
    })
}

/// Grants admin consent to each application in `object_ids`, reusing the same
/// orchestration as the single-app command. Sequential (each app issues
/// several Graph writes) with a small inter-app pause; cancellation and
/// progress share the audit/bulk plumbing.
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
    let mut outcomes = Vec::new();
    // True if any app's grant created a brand-new SP — that adds Enterprise App
    // rows / search-index entries, so the run must bust the full list caches.
    let mut any_sp_created = false;

    for (i, id) in object_ids.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        emit(
            &app_handle,
            BulkProgress {
                done: i,
                total,
                current_app: Some(id.clone()),
                cancelled: false,
                in_flight_cap: None,
            },
        );
        let outcome = match super::permissions::grant_admin_consent_core(&client, &id).await {
            Ok((r, sp_created)) => {
                any_sp_created |= sp_created;
                BulkGrantOutcome {
                    object_id: id,
                    granted: r.role_assignments_created.len() + r.scope_grants_upserted.len(),
                    skipped: r.role_assignments_skipped.len(),
                    failed: r.failures.len(),
                    error: r.failures.first().map(|f| f.message.clone()),
                }
            }
            Err(e) => BulkGrantOutcome {
                object_id: id,
                granted: 0,
                skipped: 0,
                failed: 0,
                error: Some(e.message),
            },
        };
        outcomes.push(outcome);
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
        cancelled: cancel.is_cancelled(),
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
        if let Some(aud) = &spec.sign_in_audience {
            if !VALID_AUDIENCES.contains(&aud.as_str()) {
                outcomes.push(BulkCreateOutcome {
                    display_name: spec.display_name,
                    status: "invalid".into(),
                    app_id: None,
                    message: Some(format!("unrecognised signInAudience: {aud}")),
                });
                continue;
            }
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

fn emit(app_handle: &AppHandle, progress: BulkProgress) {
    if let Err(err) = app_handle.emit("bulk-progress", progress) {
        tracing::warn!(?err, "bulk-progress emit failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::PasswordCredential;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 22, 12, 0, 0).unwrap()
    }

    fn secret(key_id: &str, end: Option<DateTime<Utc>>) -> PasswordCredential {
        PasswordCredential {
            key_id: key_id.into(),
            end_date_time: end,
            ..Default::default()
        }
    }

    #[test]
    fn bulk_expiry_rule_matches_the_audit_scorer() {
        // The sweep must delete exactly the set the audit flags as Expired: a
        // secret lapsed under 24h is "expiring soon" (no Fix offered, left by
        // the per-app remediation) and must survive the bulk sweep too.
        let app = Application {
            password_credentials: vec![
                secret("just-lapsed", Some(now() - Duration::hours(12))),
                secret("day-old", Some(now() - Duration::days(1))),
                secret("active", Some(now() + Duration::days(30))),
                secret("no-expiry", None),
            ],
            ..Default::default()
        };
        assert_eq!(expired_password_key_ids(&app, now()), vec!["day-old"]);
    }
}
