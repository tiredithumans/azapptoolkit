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
//! Adaptive concurrency: a [`ConcurrencyThrottle`](crate::commands::throttle)
//! wired as the Graph client's `ThrottleObserver` decrements the in-flight cap
//! on every 429 and gradually recovers it after 30s of quiet. Cancellation is
//! signalled via `AppState.audit_cancel`; the loop polls it between dispatches.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use azapptoolkit_core::audit::{
    AppPermissions, AuditItem, SpAuditInput, score_application, score_service_principal,
    unused_app_advisory,
};
use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{Application, RequiredResourceAccess, ServicePrincipal};
use azapptoolkit_core::scoping::is_scopable_exchange_permission;
use azapptoolkit_exchange::{ExchangeClient, ExchangeError};
use azapptoolkit_graph::GraphClient;
use azapptoolkit_graph::client::AppListQuery;
use chrono::{DateTime, Utc};

use crate::commands::applications::sp_index_key;
use crate::commands::dispatch::dispatch_capped;
use crate::commands::exchange::{exchange_client, resolve_mail_scopes_audit_cached};
use crate::commands::graph_roles::graph_role_index;
use crate::commands::throttle::{ConcurrencyThrottle, ThrottleGuard};
use crate::dto::UiError;
use crate::dto::audit::{AuditProgress, AuditRunResult};
use crate::state::AppState;

/// Upper bound on in-flight per-app lookups when the tenant is healthy.
const INITIAL_CONCURRENCY: usize = 8;
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
    let tracker = Arc::new(ConcurrencyThrottle::new(INITIAL_CONCURRENCY));
    // Detach the observer however the run exits — an early `?` return (e.g. app
    // paging failure) previously left a stale tracker attached to the shared
    // per-tenant client, halving its cap on unrelated 429s until the next audit
    // replaced it. (RAII guard shared with the bulk fan-out commands.)
    let _observer_guard = ThrottleGuard::attach(client.clone(), tracker.clone());

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

    // Pre-resolve every app's service principal in one $batch per 20 so each
    // score_one SP lookup is a cache hit, not a round trip. Best-effort: a batch
    // failure just leaves the per-app lookups to resolve as before.
    let app_ids: Vec<String> = apps.iter().map(|a| a.app_id.clone()).collect();
    client.prewarm_service_principals_lean(&app_ids).await;

    // Admin-consent flags and delegated scopes come from ONE tenant-wide
    // oauth2PermissionGrants read instead of a per-app GET inside the scoring
    // loop (an N+1 that dominated large runs' request budget and 429 pressure).
    // The AllPrincipals scope strings are kept per client so the SP-only phase
    // below can score high-risk delegated permissions (an SP has no manifest to
    // resolve them from). Best-effort: on failure no principal gets the flag
    // and the audit proceeds.
    let (admin_consent_clients, delegated_scopes_by_client) =
        match client.list_all_oauth2_grants().await {
            Ok(grants) => {
                let mut clients: HashSet<String> = HashSet::new();
                let mut scopes: HashMap<String, Vec<String>> = HashMap::new();
                for g in grants {
                    if g.consent_type != "AllPrincipals" {
                        continue;
                    }
                    scopes
                        .entry(g.client_id.clone())
                        .or_default()
                        .extend(g.scope.split_whitespace().map(str::to_string));
                    clients.insert(g.client_id);
                }
                (clients, scopes)
            }
            Err(err) => {
                tracing::info!(
                    ?err,
                    "audit: tenant-wide grants read failed; admin-consent flags unavailable"
                );
                (HashSet::new(), HashMap::new())
            }
        };
    let admin_consent_clients = Arc::new(admin_consent_clients);

    // ONE tenant-wide appRoleAssignedTo read on the Microsoft Graph SP does
    // double duty (formerly gated on Exchange availability): the full per-SP
    // granted Graph role values feed the SP-only scoring phase below, and the
    // mail-scopable subset keeps feeding score_one's scoped-mail reconciliation
    // exactly as before. Best-effort: an empty map ⇒ no SP items this run and
    // no reconciliation — identical to the swallowed-error behavior.
    let mut graph_roles_by_sp: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok((graph_sp_id, role_value_by_id)) = graph_role_index(&client).await {
        match client.list_app_role_assigned_to(&graph_sp_id).await {
            Ok(assigned) => {
                for a in assigned {
                    // App permissions held by an app's SP — Users/Groups
                    // can't hold Graph app roles.
                    if a.principal_type.as_deref() != Some("ServicePrincipal") {
                        continue;
                    }
                    if let Some(v) = role_value_by_id.get(&a.app_role_id) {
                        graph_roles_by_sp
                            .entry(a.principal_id)
                            .or_default()
                            .push(v.clone());
                    }
                }
            }
            Err(err) => {
                tracing::info!(
                    ?err,
                    "audit: tenant-wide app-role assignments read failed; SP coverage and org-wide mail reconciliation unavailable"
                );
            }
        }
    }
    let orgwide_mail_by_sp: Arc<HashMap<String, HashSet<String>>> = Arc::new(
        graph_roles_by_sp
            .iter()
            .map(|(sp_id, values)| {
                let mail: HashSet<String> = values
                    .iter()
                    .filter(|v| is_scopable_exchange_permission(v))
                    .cloned()
                    .collect();
                (sp_id.clone(), mail)
            })
            .filter(|(_, mail)| !mail.is_empty())
            .collect(),
    );

    // SP-only phase candidates: service principals whose appId has NO local
    // application object (foreign enterprise apps, managed identities, orphaned
    // SPs) and that hold at least one Graph application-permission grant — the
    // filter that keeps the hundreds of grantless first-party Microsoft SPs out
    // of the results. Reuses the shared SP index (same get-or-fetch as
    // list_enterprise_applications). Best-effort: on failure the run covers app
    // registrations only.
    let index_key = sp_index_key(&tenant_id);
    let sp_index: Vec<ServicePrincipal> = match state
        .cache
        .get::<Vec<ServicePrincipal>>(CacheKind::Lists, &index_key)
    {
        Some(cached) => cached,
        None => match client.list_service_principals_index().await {
            Ok(sps) => {
                state.cache.put(CacheKind::Lists, index_key, &sps);
                sps
            }
            Err(err) => {
                tracing::info!(
                    ?err,
                    "audit: SP index unavailable; scanning app registrations only"
                );
                Vec::new()
            }
        },
    };
    let local_app_ids: HashSet<String> = apps.iter().map(|a| a.app_id.clone()).collect();
    let sp_candidates = sp_audit_candidates(sp_index, &local_app_ids, &graph_roles_by_sp);
    let total = apps.len() + sp_candidates.len();

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

    // Phase 2: score the SP-only candidates (foreign enterprise apps, managed
    // identities, orphaned SPs). Every input is already resolved tenant-wide —
    // granted roles from the appRoleAssignedTo matrix, consent + delegated
    // scopes from the grants read, sign-ins from the appId-keyed report — so
    // this is pure scoring: no per-item Graph traffic, no fan-out needed.
    // mail_scopes stays empty ON PURPOSE: a held mail value here IS an
    // un-stripped org-wide Entra grant (it comes from the grant matrix), and
    // grant ∪ RBAC reach is always org-wide, so the reconciliation score_one
    // applies would force OrgWide regardless of any RBAC verdict — an empty map
    // scores identically without the 1-5s Exchange probe per SP. A principal
    // whose grant the scoping flow stripped no longer holds the value and drops
    // out of the candidate set entirely.
    if !cancelled_before_all_dispatched && !cancel.is_cancelled() {
        let mut done_count = *done.lock().await;
        let now = chrono::Utc::now();
        for sp in sp_candidates {
            if cancel.is_cancelled() {
                break;
            }
            let perms = AppPermissions {
                app_role_values: graph_roles_by_sp.get(&sp.id).cloned().unwrap_or_default(),
                scope_values: delegated_scopes_by_client
                    .get(&sp.id)
                    .cloned()
                    .unwrap_or_default(),
                has_admin_consent: admin_consent_clients.contains(&sp.id),
                mail_scopes: HashMap::new(),
            };
            let input = SpAuditInput {
                display_name: sp.display_name.clone(),
                app_id: sp.app_id.clone(),
                sp_object_id: sp.id.clone(),
                created_date_time: sp.created_date_time,
                account_enabled: sp.account_enabled,
                app_owner_organization_id: sp.app_owner_organization_id.clone(),
                service_principal_type: sp.service_principal_type.clone(),
            };
            let mut item = score_service_principal(&input, &perms, now);
            let last_sign_in = if sign_in_available {
                Some(sign_in_map.get(&sp.app_id).copied().flatten())
            } else {
                None
            };
            item.sign_in_report_available = last_sign_in.is_some();
            item.last_sign_in = last_sign_in.flatten();
            if let Some((issue, rec)) =
                unused_app_advisory(last_sign_in.into(), sp.created_date_time, now)
            {
                item.unused = true;
                item.issues.push(issue);
                item.recommendations.push(rec);
            }
            done_count += 1;
            emit_progress(
                &app_handle,
                AuditProgress {
                    done: done_count,
                    total,
                    current_app: Some(item.application_name.clone()),
                    in_flight_cap: tracker.current_limit(),
                    cancelled: false,
                },
            );
            items.push(item);
        }
    }

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
            ));
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
    out.push_str("ApplicationName,AppId,ObjectId,CreatedDate,Publisher,SignInAudience,RiskScore,RiskLevel,CredentialStatus,PermissionCount,DaysSinceCreated,ServicePrincipalEnabled,Issues,Recommendations,PrincipalKind\n");
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
            csv_field(item.principal_kind.as_str()),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

// ---------------- internals ----------------

/// The SP-only scoring candidates: service principals whose `appId` has no
/// local application object (foreign enterprise apps, managed identities,
/// orphaned SPs — paired SPs are already scored via the app-registration
/// phase) AND that hold at least one Graph application-permission grant. The
/// grant requirement is the noise filter: it drops the hundreds of grantless
/// first-party Microsoft SPs every tenant carries. Disabled SPs stay in (Rule
/// 4 flags them). Known limitation: roles held only on non-Graph resources
/// aren't in the matrix, so such an SP is not scored.
fn sp_audit_candidates(
    sp_index: Vec<ServicePrincipal>,
    local_app_ids: &HashSet<String>,
    graph_roles_by_sp: &HashMap<String, Vec<String>>,
) -> Vec<ServicePrincipal> {
    sp_index
        .into_iter()
        .filter(|sp| !local_app_ids.contains(&sp.app_id))
        .filter(|sp| graph_roles_by_sp.get(&sp.id).is_some_and(|v| !v.is_empty()))
        .collect()
}

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
            ));
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
    // Resolve each distinct resource's index concurrently rather than one serial
    // await at a time (mirrors `resolve_required_resource_access` in
    // applications.rs). Each lookup is independent and Permissions-cached, so on a
    // cold cache this collapses N serial round-trips into one concurrent batch;
    // warm hits cost nothing.
    let indexes: HashMap<String, ResourceIndex> =
        futures::future::join_all(resources.into_iter().map(|id| async move {
            let index = resolver.index(&id).await;
            (id, index)
        }))
        .await
        .into_iter()
        .collect();

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
    use azapptoolkit_core::audit::{AuditPrincipalKind, CredentialStatus, RiskLevel};

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
            principal_kind: AuditPrincipalKind::Application,
        }
    }

    fn sp(id: &str, app_id: &str, sp_type: Option<&str>) -> ServicePrincipal {
        ServicePrincipal {
            id: id.to_string(),
            app_id: app_id.to_string(),
            service_principal_type: sp_type.map(str::to_string),
            ..ServicePrincipal::default()
        }
    }

    // The SP-only candidate filter: no local application AND ≥1 Graph
    // application grant. Managed identities and disabled SPs are candidates;
    // paired and grantless SPs are not.
    #[test]
    fn sp_audit_candidates_filters_paired_and_grantless() {
        let local_app_ids: HashSet<String> = ["paired-app".to_string()].into();
        let roles: HashMap<String, Vec<String>> = [
            ("sp-foreign".to_string(), vec!["Mail.Read".to_string()]),
            ("sp-paired".to_string(), vec!["Mail.Read".to_string()]),
            ("sp-mi".to_string(), vec!["User.Read.All".to_string()]),
            ("sp-empty".to_string(), Vec::new()),
        ]
        .into();
        let index = vec![
            sp("sp-foreign", "foreign-app", Some("Application")),
            sp("sp-paired", "paired-app", Some("Application")),
            sp("sp-mi", "mi-app", Some("ManagedIdentity")),
            sp("sp-grantless", "gallery-app", Some("Application")),
            sp("sp-empty", "empty-app", Some("Application")),
        ];
        let got: Vec<String> = sp_audit_candidates(index, &local_app_ids, &roles)
            .into_iter()
            .map(|s| s.id)
            .collect();
        // Paired (has a local app), grantless (not in the matrix), and
        // empty-role-list SPs are all excluded; the foreign SP and the MI stay.
        assert_eq!(got, vec!["sp-foreign".to_string(), "sp-mi".to_string()]);
    }

    #[test]
    fn export_audit_csv_ends_rows_with_principal_kind() {
        let mut item = sample("SP App");
        item.principal_kind = AuditPrincipalKind::ServicePrincipal;
        let csv = export_audit_csv(vec![item]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].ends_with(",PrincipalKind"));
        assert!(lines[1].ends_with(",ServicePrincipal"));
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
