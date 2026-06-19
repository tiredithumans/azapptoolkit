//! Security audit orchestration.
//!
//! [`run_audit`] streams every application in the tenant (following
//! `@odata.nextLink` until exhausted), resolves permission names +
//! service-principal state + consent flags, feeds them into
//! [`azapptoolkit_core::audit::score_application`], and emits `audit-progress`
//! Tauri events after each app. Completed results land in the shared cache
//! under [`CacheKind::Audit`] keyed `{tenant_id}|audit_run` so the dashboard
//! can re-render without re-scanning.
//!
//! Adaptive concurrency: a [`AuditThrottleTracker`] wired as the Graph
//! client's `ThrottleObserver` decrements the in-flight cap on every 429 and
//! gradually recovers it after 30s of quiet. Cancellation is signalled via
//! `AppState.audit_cancel`; the loop polls it between task dispatches.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use azapptoolkit_core::audit::{score_application, unused_app_advisory, AppPermissions, AuditItem};
use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{Application, RequiredResourceAccess};
use azapptoolkit_core::scoping::is_scopable_exchange_permission;
use azapptoolkit_exchange::{ExchangeClient, ExchangeError};
use azapptoolkit_graph::client::AppListQuery;
use azapptoolkit_graph::{GraphClient, ThrottleObserver};
use chrono::{DateTime, Utc};

use crate::commands::dispatch::dispatch_capped;
use crate::commands::exchange::{exchange_client, resolve_mail_scopes_audit_cached};
use crate::commands::graph_roles::graph_role_index;
use crate::dto::audit::{AuditProgress, AuditRunResult};
use crate::dto::UiError;
use crate::state::AppState;

/// Upper bound on in-flight per-app lookups when the tenant is healthy.
const INITIAL_CONCURRENCY: usize = 8;
/// Minimum in-flight floor: a single request still makes forward progress.
const MIN_CONCURRENCY: usize = 1;
/// Page size — Graph caps `$top` at 100 on `/applications`.
const PAGE_SIZE: u32 = 100;
/// Safety cap on the total app count per run. Prevents a misconfigured tenant
/// or runaway pagination loop from OOMing the app; raise or pass `None` if a
/// user hits this legitimately.
const MAX_APPS_PER_RUN: usize = 10_000;
/// Tenant-prefixed audit-run cache key — the same `{tenant_id}|` convention as
/// every other kind, so sign-out's prefix invalidation reaches it. (The
/// original `run:{tenant}` suffix shape was invisible to the prefix idiom.)
pub(crate) fn audit_cache_key(tenant_id: &str) -> String {
    format!("{tenant_id}|audit_run")
}

/// Runs a full audit scan. Blocks until every app has been scored (or the
/// user calls [`cancel_audit`]). Emits a `audit-progress` event after each
/// completed app. Caches the full result under `CacheKind::Audit` with the
/// default 60-minute TTL.
#[tauri::command]
pub async fn run_audit(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<AuditRunResult, UiError> {
    state.audit_cancel.reset();

    let client = state.graph_for(&tenant_id);
    let tracker = Arc::new(AuditThrottleTracker::new(INITIAL_CONCURRENCY));
    client.set_throttle_observer(tracker.clone());
    // Detach the observer however the run exits — the early `?` returns
    // (e.g. app paging failure) previously left a stale tracker attached to
    // the shared per-tenant client, halving its cap on unrelated 429s until
    // the next audit replaced it.
    struct ObserverGuard(Arc<GraphClient>);
    impl Drop for ObserverGuard {
        fn drop(&mut self) {
            self.0.clear_throttle_observer();
        }
    }
    let _observer_guard = ObserverGuard(client.clone());

    // Effective Exchange mailbox-scoping is resolved on every run so a mail
    // permission confined to specific mailboxes scores below an org-wide one.
    // Best-effort: if the Exchange client can't be built (signed-in user is not
    // an Exchange admin / no UPN for the anchor mailbox), scoping simply isn't
    // resolved and mail permissions score at their full org-wide weight.
    let exo: Option<Arc<ExchangeClient>> = match exchange_client(&state, &tenant_id) {
        Ok(exo) => Some(exo),
        Err(err) => {
            tracing::info!(?err, "audit: Exchange scoping unavailable");
            None
        }
    };

    let apps = client
        .list_applications_all(
            // `$expand=owners` brings owner ids inline so the ownership audit
            // rules need no per-app round trip.
            AppListQuery::default()
                .with_top(PAGE_SIZE)
                .with_expand("owners($select=id)"),
            Some(MAX_APPS_PER_RUN),
        )
        .await?;
    let total = apps.len();

    // Pre-resolve every app's service principal in one $batch per 20 so each
    // score_one SP lookup is a cache hit, not a round trip. Best-effort: a batch
    // failure just leaves the per-app lookups to resolve as before.
    let app_ids: Vec<String> = apps.iter().map(|a| a.app_id.clone()).collect();
    client.prewarm_service_principals_lean(&app_ids).await;

    // Admin-consent flags come from ONE tenant-wide oauth2PermissionGrants read
    // instead of a per-app GET inside the scoring loop (an N+1 that dominated
    // large runs' request budget and 429 pressure). Best-effort, matching the
    // per-app path it replaces (whose errors were swallowed per app): on
    // failure no app gets the flag and the audit proceeds.
    let admin_consent_clients: Arc<HashSet<String>> =
        Arc::new(match client.list_all_oauth2_grants().await {
            Ok(grants) => grants
                .into_iter()
                .filter(|g| g.consent_type == "AllPrincipals")
                .map(|g| g.client_id)
                .collect(),
            Err(err) => {
                tracing::info!(
                    ?err,
                    "audit: tenant-wide grants read failed; admin-consent flags unavailable"
                );
                HashSet::new()
            }
        });

    // Org-wide mail grants for the scoped-mail reconciliation come from ONE
    // tenant-wide appRoleAssignedTo read on the Microsoft Graph SP, instead of a
    // per-app appRoleAssignments GET inside the scoring loop (the last per-app
    // N+1 — `consent`/`permission_tester` already read this matrix in one call).
    // Built only when Exchange scoping is available (otherwise the reconciliation
    // is never consulted). Best-effort: an empty map ⇒ no reconciliation,
    // identical to the per-app path's swallowed-error behavior.
    let orgwide_mail_by_sp: Arc<HashMap<String, HashSet<String>>> = Arc::new(if exo.is_some() {
        match graph_role_index(&client).await {
            Ok((graph_sp_id, role_value_by_id)) => {
                match client.list_app_role_assigned_to(&graph_sp_id).await {
                    Ok(assigned) => {
                        let mut m: HashMap<String, HashSet<String>> = HashMap::new();
                        for a in assigned {
                            // App permissions held by an app's SP — Users/Groups
                            // can't hold Graph app roles relevant to mail scoping.
                            if a.principal_type.as_deref() != Some("ServicePrincipal") {
                                continue;
                            }
                            if let Some(v) = role_value_by_id.get(&a.app_role_id) {
                                if is_scopable_exchange_permission(v) {
                                    m.entry(a.principal_id).or_default().insert(v.clone());
                                }
                            }
                        }
                        m
                    }
                    Err(err) => {
                        tracing::info!(
                                ?err,
                                "audit: tenant-wide app-role assignments read failed; org-wide mail reconciliation unavailable"
                            );
                        HashMap::new()
                    }
                }
            }
            Err(_) => HashMap::new(),
        }
    } else {
        HashMap::new()
    });

    // Exchange circuit breaker: a genuine auth failure (401 / 403) from the
    // admin API recurs for every app in the run, so the first one opens the
    // breaker and the remaining apps skip the doomed 1-5s cmdlet probes.
    // Scoring is unchanged — an open breaker leaves `mail_scopes` empty, the
    // same org-wide-weight default as the swallowed error (never under-reports).
    let exo_tripped = Arc::new(AtomicBool::new(false));

    // Sign-in activity report (needs AuditLog.Read.All + Entra ID P1/P2 + a
    // supported directory role). Pre-acquire the AuditLog scope with a typed call
    // so a *missing-consent* failure is distinguishable from a license/availability
    // one — the former surfaces a "Grant consent" button in the audit view. On
    // either failure the audit proceeds without unused-app detection
    // (`sign_in_available = false` ⇒ no app is flagged "unused"); only a missing
    // consent sets `sign_in_consent_required`.
    let (sign_in_available, sign_in_consent_required, sign_in_map) =
        match state.ensure_audit_log_token(&tenant_id).await {
            Ok(()) => match client.list_service_principal_sign_in_activities().await {
                Ok(items) => {
                    let map: HashMap<String, Option<DateTime<Utc>>> = items
                        .into_iter()
                        .filter_map(|a| {
                            a.app_id.map(|id| {
                                (
                                    id,
                                    a.last_sign_in_activity
                                        .and_then(|s| s.last_sign_in_date_time),
                                )
                            })
                        })
                        .collect();
                    (true, false, Arc::new(map))
                }
                Err(err) => {
                    tracing::info!(
                        ?err,
                        "sign-in activity report unavailable; skipping unused-app detection"
                    );
                    (false, false, Arc::new(HashMap::new()))
                }
            },
            Err(err) => {
                let ui = UiError::from(err);
                let consent_required = ui.code == "consent_required";
                tracing::info!(
                    code = %ui.code,
                    "AuditLog.Read.All token unavailable; skipping unused-app detection"
                );
                (false, consent_required, Arc::new(HashMap::new()))
            }
        };

    emit_progress(
        &app_handle,
        AuditProgress {
            done: 0,
            total,
            current_app: None,
            in_flight_cap: tracker.current_limit(),
            cancelled: false,
        },
    );

    let resolver = Arc::new(ResourceResolver::new(client.clone()));
    let done = Arc::new(Mutex::new(0usize));
    let cancel = state.audit_cancel.clone();
    // Cloned into each scoring task for the cached mailbox-scope lookups. The
    // State<'_, AppState> handle can't cross into the 'static spawned tasks, so
    // capture the Arc<Cache> and tenant id here.
    let cache = state.cache.clone();
    let tenant_for_tasks = tenant_id.clone();

    let mut items: Vec<AuditItem> = Vec::with_capacity(total);
    // Dynamic in-flight cap: the tracker shrinks it on 429s mid-run.
    let cancelled_before_all_dispatched = dispatch_capped(
        apps,
        || tracker.current_limit(),
        |app| {
            if cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let resolver = resolver.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let tracker_for_task = tracker.clone();
            let cancel_for_task = cancel.clone();
            let sign_in_map = sign_in_map.clone();
            let exo = exo.clone();
            let admin_consent_clients = admin_consent_clients.clone();
            let orgwide_mail_by_sp = orgwide_mail_by_sp.clone();
            let exo_tripped = exo_tripped.clone();
            let cache = cache.clone();
            let tenant_for_task = tenant_for_tasks.clone();
            Some(tokio::spawn(async move {
                if cancel_for_task.is_cancelled() {
                    return Err(UiError::validation("cancelled", "audit cancelled"));
                }
                // Outer `None` = report unavailable (skip). Otherwise the app's
                // recorded last sign-in; absent from the report ⇒ `Some(None)` =
                // no sign-in observed.
                let last_sign_in = if sign_in_available {
                    Some(sign_in_map.get(&app.app_id).copied().flatten())
                } else {
                    None
                };
                let result = score_one(
                    &client,
                    &cache,
                    &tenant_for_task,
                    &resolver,
                    &app,
                    last_sign_in,
                    exo.as_deref(),
                    &admin_consent_clients,
                    &orgwide_mail_by_sp,
                    &exo_tripped,
                )
                .await;
                let mut guard = done.lock().await;
                *guard += 1;
                let progress = AuditProgress {
                    done: *guard,
                    total,
                    current_app: Some(app.display_name.clone()),
                    in_flight_cap: tracker_for_task.current_limit(),
                    cancelled: cancel_for_task.is_cancelled(),
                };
                drop(guard);
                emit_progress(&app_handle, progress);
                result
            }))
        },
        |joined| match joined {
            Ok(Ok(item)) => items.push(item),
            Ok(Err(err)) if err.code == "cancelled" => {}
            Ok(Err(err)) => tracing::warn!(?err, "audit scoring failed for one app"),
            Err(err) => tracing::warn!(?err, "audit join error"),
        },
    )
    .await;

    let cancelled = cancelled_before_all_dispatched || cancel.is_cancelled();
    items.sort_by_key(|i| std::cmp::Reverse(i.risk_score));

    if !cancelled {
        state
            .cache
            .put(CacheKind::Audit, audit_cache_key(&tenant_id), &items);
    }

    Ok(AuditRunResult {
        tenant_id,
        total_apps: items.len(),
        items,
        cancelled,
        sign_in_report_available: sign_in_available,
        sign_in_consent_required,
    })
}

/// Signals an in-progress audit to stop at the next dispatch boundary.
/// Already in-flight per-app lookups are allowed to finish so their partial
/// results don't corrupt the cache.
#[tauri::command]
pub fn cancel_audit(state: State<'_, AppState>) {
    state.audit_cancel.cancel();
}

/// Drops the cached audit for `tenant_id` so the next read re-scans. Call (on
/// `Ok` only) after any mutation that changes audit-relevant state — app
/// create/delete, credentials, owners, or permission/consent grants — so the
/// audit view and the home dashboard's posture card don't show stale risk.
pub(crate) fn invalidate_audit_cache(cache: &azapptoolkit_core::cache::Cache, tenant_id: &str) {
    cache.invalidate(CacheKind::Audit, &audit_cache_key(tenant_id));
}

/// Returns the cached audit for this tenant, if one was run within the last
/// 60 minutes.
#[tauri::command]
pub fn get_cached_audit(state: State<'_, AppState>, tenant_id: String) -> Option<AuditRunResult> {
    let key = audit_cache_key(&tenant_id);
    let items: Vec<AuditItem> = state.cache.get(CacheKind::Audit, &key)?;
    // Report availability is reconstructed from the cached items (every item
    // carries the run's `sign_in_report_available`); a cached run never re-prompts
    // for consent, so `sign_in_consent_required` is false on a cache hit.
    let sign_in_report_available = items.iter().any(|i| i.sign_in_report_available);
    Some(AuditRunResult {
        tenant_id,
        total_apps: items.len(),
        items,
        cancelled: false,
        sign_in_report_available,
        sign_in_consent_required: false,
    })
}

/// Opens the OS save-file dialog and writes the audit in the requested
/// `format` (`csv`, `json`, or `html`) to the chosen path. Returns the path,
/// or `None` if the user cancelled. Exports **by reference**: with
/// `items: None` the backend serves its own cached run, so the multi-MB item
/// vector never round-trips the IPC bridge; a *cancelled* run — which is
/// never cached — passes its items explicitly.
#[tauri::command]
pub async fn save_audit_to_file(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    items: Option<Vec<AuditItem>>,
    format: String,
) -> Result<Option<String>, UiError> {
    let items: Vec<AuditItem> = match items {
        Some(items) => items,
        None => state
            .cache
            .get(CacheKind::Audit, &audit_cache_key(&tenant_id))
            .ok_or_else(|| {
                UiError::validation(
                    "no_cached_audit",
                    "no cached audit to export — run the audit again",
                )
            })?,
    };
    let (content, ext, filter_name) = match format.as_str() {
        "csv" => (export_audit_csv(items), "csv", "CSV"),
        "json" => (audit_to_json(&items)?, "json", "JSON"),
        "html" => (audit_to_html(&items), "html", "HTML"),
        other => {
            return Err(UiError::validation(
                "unsupported_format",
                format!("unsupported export format: {other}"),
            ))
        }
    };
    let default_name = format!("audit-{}.{ext}", chrono::Utc::now().format("%Y%m%dT%H%M%S"));
    write_via_dialog(app_handle, filter_name, ext, default_name, content).await
}

/// Serializes audit items as pretty-printed JSON. Propagates a serialize error
/// instead of writing an empty `"[]"` file — a silent empty export reads as
/// "nothing to report" rather than "the export failed".
fn audit_to_json(items: &[AuditItem]) -> Result<String, UiError> {
    serde_json::to_string_pretty(items).map_err(|e| UiError::serde(e.to_string()))
}

/// Renders a standalone HTML report — a styled table of the key audit columns.
fn audit_to_html(items: &[AuditItem]) -> String {
    let mut rows = String::new();
    for item in items {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&item.application_name),
            html_escape(&item.app_id),
            item.risk_score,
            html_escape(item.risk_level.as_str()),
            html_escape(item.credential_status.as_str()),
            html_escape(&item.issues.join("; ")),
        ));
    }
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>azapptoolkit Security Audit</title>\
<style>body{{font-family:system-ui,sans-serif;margin:2rem}}\
table{{border-collapse:collapse;width:100%}}\
th,td{{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:14px;vertical-align:top}}\
th{{background:#f3f3f3}}</style></head>\
<body><h1>Security Audit</h1><p>{count} application(s) — generated {generated}</p>\
<table><thead><tr><th>Application</th><th>App ID</th><th>Risk score</th>\
<th>Level</th><th>Credentials</th><th>Issues</th></tr></thead>\
<tbody>{rows}</tbody></table></body></html>",
        count = items.len(),
        generated = chrono::Utc::now().to_rfc3339(),
        rows = rows,
    )
}

fn html_escape(s: &str) -> String {
    // `'` included for completeness: every interpolation today is element
    // text content (where &<> suffice), but the export opens outside the app
    // CSP, so a future single-quoted attribute must not become an injection.
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Serializes a set of [`AuditItem`]s as CSV. Kept as a separate command so
/// callers that want the text (e.g. clipboard, log) don't need a save dialog.
#[tauri::command]
pub fn export_audit_csv(items: Vec<AuditItem>) -> String {
    let mut out = String::new();
    out.push_str("ApplicationName,AppId,ObjectId,CreatedDate,Publisher,SignInAudience,RiskScore,RiskLevel,CredentialStatus,PermissionCount,DaysSinceCreated,ServicePrincipalEnabled,Issues,Recommendations\n");
    for item in items {
        let row = [
            csv_field(&item.application_name),
            csv_field(&item.app_id),
            csv_field(&item.object_id),
            csv_field(
                &item
                    .created_date
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            ),
            csv_field(item.publisher.as_deref().unwrap_or("")),
            csv_field(item.sign_in_audience.as_deref().unwrap_or("")),
            item.risk_score.to_string(),
            csv_field(item.risk_level.as_str()),
            csv_field(item.credential_status.as_str()),
            item.permission_count.to_string(),
            item.days_since_created
                .map(|d| d.to_string())
                .unwrap_or_default(),
            item.service_principal_enabled
                .map(|b| b.to_string())
                .unwrap_or_default(),
            csv_field(&item.issues.join("; ")),
            csv_field(&item.recommendations.join("; ")),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

// ---------------- adaptive throttling ----------------

/// Minimum seconds between cap halvings. The transport notifies the observer
/// on *every* 429 — including each retry of one hot request — so without a
/// window a single request retrying three times collapsed the cap 8→1 while
/// the other lanes were healthy.
const HALVE_WINDOW_SECS: u64 = 2;
/// Quiet seconds required before a permit is restored; also the recovery
/// loop's tick interval.
const RECOVERY_SECS: u64 = 30;

/// Shared mutable state for the tracker. Held by `Arc` so the background
/// recovery loop can adjust `current` while the run holds the tracker.
struct ThrottleInner {
    current: AtomicUsize,
    max: usize,
    /// Most recent throttle event (`tokio::time::Instant`, so paused-clock
    /// tests can drive it). Gates both the halve window and recovery quiet.
    last_throttle: std::sync::Mutex<Option<tokio::time::Instant>>,
}

/// Adjusts the audit's in-flight concurrency cap in response to Graph's 429s.
/// A throttle event halves the cap (floored at [`MIN_CONCURRENCY`]) at most
/// once per [`HALVE_WINDOW_SECS`]; one long-lived recovery loop restores one
/// permit per [`RECOVERY_SECS`] tick once the last tick's window was quiet,
/// capped at the initial value. (The previous spawn-a-timer-per-429 shape made
/// a throttle storm snap the cap from the floor back to max in a single burst
/// ~30s later, re-triggering the storm — a sawtooth.)
pub struct AuditThrottleTracker {
    inner: Arc<ThrottleInner>,
}

impl AuditThrottleTracker {
    /// Must be called from a Tokio runtime context (spawns the recovery loop).
    fn new(initial: usize) -> Self {
        let inner = Arc::new(ThrottleInner {
            current: AtomicUsize::new(initial.max(MIN_CONCURRENCY)),
            max: initial,
            last_throttle: std::sync::Mutex::new(None),
        });
        // The loop holds only a Weak: it exits when the run drops its last
        // tracker handle, so it can't outlive the audit it serves.
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(RECOVERY_SECS)).await;
                let Some(inner) = weak.upgrade() else { break };
                let quiet = inner
                    .last_throttle
                    .lock()
                    .expect("tracker mutex poisoned")
                    .is_some_and(|t| t.elapsed().as_secs() >= RECOVERY_SECS);
                if quiet {
                    let prev = inner.current.load(Ordering::Acquire);
                    let next = (prev + 1).min(inner.max);
                    if next > prev {
                        inner.current.store(next, Ordering::Release);
                        tracing::info!(from = prev, to = next, "audit: recovering in-flight cap");
                    }
                }
            }
        });
        Self { inner }
    }

    fn current_limit(&self) -> usize {
        self.inner.current.load(Ordering::Acquire)
    }
}

impl ThrottleObserver for AuditThrottleTracker {
    fn on_throttle(&self, retry_after_secs: Option<u64>) {
        let now = tokio::time::Instant::now();
        let within_window = {
            let mut last = self
                .inner
                .last_throttle
                .lock()
                .expect("tracker mutex poisoned");
            let within = last.is_some_and(|t| now.duration_since(t).as_secs() < HALVE_WINDOW_SECS);
            *last = Some(now);
            within
        };
        if within_window {
            // One halving per pressure window — retries of a single hot
            // request must not cascade the cap to the floor.
            return;
        }
        let prev = self.inner.current.load(Ordering::Acquire);
        let next = (prev / 2).max(MIN_CONCURRENCY);
        if next < prev {
            self.inner.current.store(next, Ordering::Release);
            tracing::info!(
                from = prev,
                to = next,
                ?retry_after_secs,
                "audit: throttled, reducing in-flight cap"
            );
        }
    }
}

// ---------------- internals ----------------

pub(crate) fn csv_field(s: &str) -> String {
    // Formula-injection guard (CWE-1236): a field beginning with one of these
    // characters is interpreted as a formula by Excel / Sheets when the CSV is
    // opened. App display names are attacker-controllable, so prefix such a
    // value with a single quote to force it to be treated as text.
    let neutralized = match s.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => {
            let mut out = String::with_capacity(s.len() + 1);
            out.push('\'');
            out.push_str(s);
            std::borrow::Cow::Owned(out)
        }
        _ => std::borrow::Cow::Borrowed(s),
    };
    if neutralized.contains(',') || neutralized.contains('"') || neutralized.contains('\n') {
        let escaped = neutralized.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        neutralized.into_owned()
    }
}

/// Shared "export to CSV/JSON via the OS save dialog" plumbing for the inventory
/// list exports. Picks the serializer by `format`, opens the save dialog with a
/// timestamped default name (`{default_stem}-YYYYMMDDThhmmss.{ext}`), and writes
/// the file. Returns the chosen path, or `None` if the user cancelled. The
/// serializers are closures so each list can pass its own column layout while
/// sharing the format-match / dialog / write boilerplate.
pub(crate) async fn save_export_via_dialog(
    app_handle: &AppHandle,
    default_stem: &str,
    format: &str,
    to_csv: impl FnOnce() -> String,
    to_json: impl FnOnce() -> String,
) -> Result<Option<String>, UiError> {
    let (content, ext, filter_name) = match format {
        "csv" => (to_csv(), "csv", "CSV"),
        "json" => (to_json(), "json", "JSON"),
        other => {
            return Err(UiError::validation(
                "unsupported_format",
                format!("unsupported export format: {other}"),
            ))
        }
    };
    let default_name = format!(
        "{default_stem}-{}.{ext}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S")
    );
    write_via_dialog(app_handle.clone(), filter_name, ext, default_name, content).await
}

/// Save dialog + file write on a blocking thread. In Tauri 2 a *synchronous*
/// command executes on the main thread, where `blocking_save_file` plus a
/// multi-MB `std::fs::write` froze the whole webview until the write finished
/// — every file-export command rides this instead.
pub(crate) async fn write_via_dialog(
    app_handle: AppHandle,
    filter_name: &'static str,
    ext: &'static str,
    default_name: String,
    content: String,
) -> Result<Option<String>, UiError> {
    use tauri_plugin_dialog::DialogExt;
    tauri::async_runtime::spawn_blocking(move || {
        let chosen = app_handle
            .dialog()
            .file()
            .add_filter(filter_name, &[ext])
            .set_file_name(&default_name)
            .blocking_save_file();
        let Some(path) = chosen else {
            return Ok(None);
        };
        let path_buf = path
            .into_path()
            .map_err(|e| UiError::validation("invalid_path", e.to_string()))?;
        std::fs::write(&path_buf, content).map_err(|e| UiError::io(e.to_string()))?;
        Ok(Some(path_buf.display().to_string()))
    })
    .await
    .map_err(|e| UiError::io(e.to_string()))?
}

fn emit_progress(app_handle: &AppHandle, progress: AuditProgress) {
    if let Err(err) = app_handle.emit("audit-progress", progress) {
        tracing::warn!(?err, "failed to emit audit-progress event");
    }
}

struct ResourceResolver {
    client: Arc<GraphClient>,
    cache: Mutex<HashMap<String, ResourceIndex>>,
}

#[derive(Debug, Clone, Default)]
struct ResourceIndex {
    /// id → value for both roles and scopes, since ids are globally unique.
    by_id: HashMap<String, String>,
}

impl ResourceResolver {
    fn new(client: Arc<GraphClient>) -> Self {
        Self {
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn index(&self, resource_app_id: &str) -> ResourceIndex {
        {
            let cache = self.cache.lock().await;
            if let Some(hit) = cache.get(resource_app_id) {
                return hit.clone();
            }
        }

        // Permission definitions are resolved live from Graph (cached under
        // `CacheKind::Permissions`, and again per-run in `self.cache`); the
        // bundled catalog is only a resource directory and carries no
        // per-permission data.
        let mut index = ResourceIndex::default();
        if let Ok(Some(sp)) = self.client.resolve_resource_sp(resource_app_id).await {
            for r in &sp.app_roles {
                index.by_id.insert(r.id.clone(), r.value.clone());
            }
            for s in &sp.oauth2_permission_scopes {
                index.by_id.insert(s.id.clone(), s.value.clone());
            }
        }

        let mut cache = self.cache.lock().await;
        cache.insert(resource_app_id.to_string(), index.clone());
        index
    }
}

async fn resolve_permissions(
    resolver: &ResourceResolver,
    access: &[RequiredResourceAccess],
) -> AppPermissions {
    let resources: HashSet<String> = access.iter().map(|r| r.resource_app_id.clone()).collect();
    let mut indexes: HashMap<String, ResourceIndex> = HashMap::new();
    for id in resources {
        indexes.insert(id.clone(), resolver.index(&id).await);
    }

    let mut out = AppPermissions::default();
    for resource in access {
        let index = match indexes.get(&resource.resource_app_id) {
            Some(i) => i,
            None => continue,
        };
        for perm in &resource.resource_access {
            let value = match index.by_id.get(&perm.id) {
                Some(v) => v.clone(),
                None => continue,
            };
            match perm.r#type.as_str() {
                "Role" => out.app_role_values.push(value),
                "Scope" => out.scope_values.push(value),
                _ => {}
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
async fn score_one(
    client: &GraphClient,
    cache: &Cache,
    tenant_id: &str,
    resolver: &ResourceResolver,
    app: &Application,
    last_sign_in: Option<Option<DateTime<Utc>>>,
    exo: Option<&ExchangeClient>,
    admin_consent_clients: &HashSet<String>,
    orgwide_mail_by_sp: &HashMap<String, HashSet<String>>,
    exo_tripped: &AtomicBool,
) -> Result<AuditItem, UiError> {
    // Lean lookup: the audit reads only `sp.id` and `sp.account_enabled`. The
    // prewarm above seeds the matching `|lean` cache key, so this is a hit.
    let sp = match client
        .get_service_principal_by_app_id_lean(&app.app_id)
        .await
    {
        Ok(sp) => sp,
        Err(err) => {
            tracing::warn!(app = %app.display_name, ?err, "audit: SP lookup failed");
            None
        }
    };

    let mut perms = resolve_permissions(resolver, &app.required_resource_access).await;

    // Admin-consent flag: true if any AllPrincipals grant names this SP as the
    // client (membership in the run's one tenant-wide prefetch).
    if let Some(ref sp) = sp {
        perms.has_admin_consent = admin_consent_clients.contains(&sp.id);
    }

    // Resolve effective Exchange mailbox scoping so a mail permission confined to
    // specific mailboxes scores below an org-wide one. Skips the Exchange round
    // trip entirely for apps with no scopable mail permissions (the resolver
    // returns an empty map), and for the rest of the run once the circuit
    // breaker has tripped (an auth failure recurs for every app; an open
    // breaker scores identically to the swallowed error — org-wide weight).
    // `enrich=false` — the audit needs only the org-wide/scoped distinction,
    // not the recipient filter.
    let exo = if exo_tripped.load(Ordering::Acquire) {
        None
    } else {
        exo
    };
    if let Some(exo) = exo {
        // Reconcile a scoped RBAC verdict against an un-stripped org-wide Entra
        // grant — `Test-ServicePrincipalAuthorization` can't see Entra grants, so
        // a scoped role coexisting with the org-wide grant still reaches every
        // mailbox. Only worth the extra read when the app declares a scopable mail
        // permission and its SP resolved.
        let orgwide = match &sp {
            Some(sp)
                if perms
                    .app_role_values
                    .iter()
                    .any(|p| is_scopable_exchange_permission(p)) =>
            {
                // One tenant-wide read (above) replaces the former per-app
                // appRoleAssignments GET; a map miss ⇒ empty set, same as before.
                orgwide_mail_by_sp.get(&sp.id).cloned().unwrap_or_default()
            }
            _ => HashSet::new(),
        };
        // Degrade gracefully: an Exchange failure (e.g. a 403 from missing
        // Exchange RBAC) leaves `mail_scopes` empty, so every mail permission
        // scores at full org-wide weight — never under-reporting risk. An
        // auth failure additionally trips the run-wide breaker: it would
        // recur for every remaining app, each one a doomed cmdlet POST.
        // Cached lean verdict: a re-run within the TTL (no intervening mutation)
        // skips the 1-5s Test-ServicePrincipalAuthorization probe. Distinct key
        // from the Permissions tab's verdicts — see resolve_mail_scopes_audit_cached.
        perms.mail_scopes = match resolve_mail_scopes_audit_cached(
            cache,
            tenant_id,
            exo,
            &app.app_id,
            &perms.app_role_values,
            &orgwide,
        )
        .await
        {
            Ok(scopes) => scopes,
            Err(err) => {
                if matches!(
                    err,
                    ExchangeError::Unauthorized | ExchangeError::Forbidden { .. }
                ) {
                    exo_tripped.store(true, Ordering::Release);
                    tracing::info!(
                            ?err,
                            "audit: Exchange authorization failed; skipping mailbox-scope probes for the rest of the run"
                        );
                }
                HashMap::new()
            }
        };
    }

    let sp_enabled = sp.as_ref().and_then(|s| s.account_enabled);
    let now = chrono::Utc::now();
    let mut item = score_application(app, sp_enabled, &perms, now);
    // Carry the sign-in signal as structured fields (the "Unused" facet keys off
    // `unused`, the table shows `last_sign_in`) and keep the human-readable
    // advisory in `issues` for export/detail. Outer `Some` = report available.
    item.sign_in_report_available = last_sign_in.is_some();
    item.last_sign_in = last_sign_in.flatten();
    if let Some((issue, rec)) = unused_app_advisory(last_sign_in.into(), app.created_date_time, now)
    {
        item.unused = true;
        item.issues.push(issue);
        item.recommendations.push(rec);
    }
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::{CredentialStatus, RiskLevel};

    // ---------------- throttle tracker ----------------

    #[tokio::test(start_paused = true)]
    async fn on_throttle_halves_once_per_window_and_floors_at_one() {
        let tracker = AuditThrottleTracker::new(8);
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), 4);
        // Same pressure window — the retries of one hot request must not
        // cascade the cap toward the floor.
        tracker.on_throttle(None);
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), 4);
        // Past the window: a fresh pressure event halves again, flooring at 1.
        tokio::time::advance(std::time::Duration::from_secs(HALVE_WINDOW_SECS + 1)).await;
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), 2);
        tokio::time::advance(std::time::Duration::from_secs(HALVE_WINDOW_SECS + 1)).await;
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), 1);
        tokio::time::advance(std::time::Duration::from_secs(HALVE_WINDOW_SECS + 1)).await;
        tracker.on_throttle(None);
        assert_eq!(tracker.current_limit(), MIN_CONCURRENCY);
    }

    /// Advances the paused clock, then yields so a timer-woken task (the
    /// tracker's recovery loop) actually runs — `advance()` alone only moves
    /// the timer wheel.
    async fn advance_and_run(secs: u64) {
        tokio::time::advance(std::time::Duration::from_secs(secs)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_restores_one_permit_per_quiet_tick_capped_at_initial() {
        let tracker = AuditThrottleTracker::new(4);
        // Let the recovery loop register its first sleep before time moves, so
        // the tick timeline below is deterministic (t = 30, 60, 90, …).
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        tracker.on_throttle(None); // 4 → 2 at t≈0
        advance_and_run(HALVE_WINDOW_SECS + 1).await;
        tracker.on_throttle(None); // 2 → 1 at t≈3
        assert_eq!(tracker.current_limit(), 1);
        // First recovery tick (t=30) sees only ~27 quiet seconds — no permit
        // yet; recovery requires a full quiet window, not just elapsed time.
        advance_and_run(27).await;
        assert_eq!(tracker.current_limit(), 1);
        // Each subsequent quiet tick restores exactly one permit (never the
        // old burst-back-to-max sawtooth), capped at the initial value.
        advance_and_run(30).await;
        assert_eq!(tracker.current_limit(), 2);
        advance_and_run(30).await;
        assert_eq!(tracker.current_limit(), 3);
        advance_and_run(30).await;
        assert_eq!(tracker.current_limit(), 4);
        advance_and_run(30).await;
        assert_eq!(tracker.current_limit(), 4, "never recovers past initial");
    }

    fn sample(name: &str) -> AuditItem {
        AuditItem {
            application_name: name.to_string(),
            app_id: "00000000-0000-0000-0000-000000000001".to_string(),
            object_id: "obj-1".to_string(),
            created_date: None,
            publisher: None,
            sign_in_audience: Some("AzureADMyOrg".to_string()),
            risk_score: 7,
            risk_level: RiskLevel::Medium,
            issues: vec!["one".to_string(), "two".to_string()],
            recommendations: vec![],
            remediations: vec![],
            credential_status: CredentialStatus::Active,
            permission_count: 2,
            service_principal_enabled: Some(true),
            days_since_created: Some(30),
            certificates: vec![],
            secrets: vec![],
            last_sign_in: None,
            unused: false,
            sign_in_report_available: false,
        }
    }

    #[test]
    fn csv_field_quotes_delimiters_and_doubles_quotes() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_field_neutralizes_formula_injection() {
        // CWE-1236: leading =,+,-,@ (and tab/CR) must be defused with a leading
        // quote so a spreadsheet treats the value as text, not a formula.
        assert_eq!(
            csv_field("=HYPERLINK(\"http://x\")"),
            "\"'=HYPERLINK(\"\"http://x\"\")\""
        );
        assert_eq!(csv_field("+1"), "'+1");
        assert_eq!(csv_field("-2"), "'-2");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        // A formula char in the MIDDLE is harmless and left untouched.
        assert_eq!(csv_field("a=b"), "a=b");
    }

    #[test]
    fn export_audit_csv_has_header_and_one_row_per_item() {
        let csv = export_audit_csv(vec![sample("App A"), sample("App B")]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("ApplicationName,AppId,ObjectId"));
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[1].starts_with("App A,"));
        // Issues are joined with "; " and the field is quoted (contains no comma
        // here, so it stays bare) — just confirm both issues survive.
        assert!(csv.contains("one; two"));
    }

    #[test]
    fn export_audit_csv_neutralizes_malicious_display_name() {
        // Comma in the name forces CSV quoting AND the leading '=' is defused,
        // so the cell can never be parsed as a formula by a spreadsheet.
        let csv = export_audit_csv(vec![sample("=cmd|'/c calc',A1")]);
        assert!(csv.contains("\"'=cmd|'/c calc',A1\""));
        // No data row begins with a bare formula character.
        assert!(!csv.lines().skip(1).any(|l| l.starts_with('=')));
    }

    #[test]
    fn html_escape_covers_the_five_entities() {
        assert_eq!(
            html_escape("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn audit_to_html_escapes_a_script_payload_in_the_name() {
        let html = audit_to_html(&[sample("<script>alert(1)</script>")]);
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn audit_to_json_round_trips() {
        let items = vec![sample("App A")];
        let json = audit_to_json(&items).expect("audit items serialize");
        let back: Vec<AuditItem> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].application_name, "App A");
    }
}
