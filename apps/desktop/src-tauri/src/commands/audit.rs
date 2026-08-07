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

use tauri::{AppHandle, State};
use tokio::sync::Mutex;

use azapptoolkit_core::audit::{
    AppPermissions, AuditItem, MailPermissionScope, ResourcePermission, SpAuditInput,
    score_application, score_service_principal, unused_app_advisory,
};
use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{Application, RequiredResourceAccess, ServicePrincipal};
use azapptoolkit_core::scoping::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
    is_scopable_exchange_resource_permission,
};
use azapptoolkit_exchange::{ExchangeClient, ExchangeError};
use azapptoolkit_graph::GraphClient;
use azapptoolkit_graph::client::AppListQuery;
use chrono::{DateTime, Utc};

use crate::commands::dispatch::dispatch_capped;
use crate::commands::exchange::{
    aap_verdict_for, apply_legacy_policy_verdict, exchange_client, resolve_mail_scopes_audit_cached,
};
use crate::commands::export::{csv_field, write_via_dialog};
use crate::commands::graph_roles::graph_role_index;
use crate::commands::progress::emit_progress;
use crate::commands::throttle::{ConcurrencyThrottle, ThrottleGuard};
use crate::dto::UiError;
use crate::dto::audit::{AuditCoverageGap, AuditProgress, AuditRunResult};
use crate::state::AppState;

/// What the audit's per-app collector should do with one failed scoring task.
///
/// Extracted from the `dispatch_capped` collector so the rule "a dead session
/// stops the run" is unit-testable — the collector itself closes over `State`,
/// a Graph client and a tenant, and so is only reachable from a live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditFailure {
    /// The user cancelled; the run already accounts for this separately.
    Cancelled,
    /// The session is dead — every remaining app would fail identically, so the
    /// run must stop and must not cache what it managed to score.
    SessionDead,
    /// This one app failed. Warn, keep the rest of the run.
    Transient,
}

fn classify_audit_failure(err: &UiError) -> AuditFailure {
    if err.code == "cancelled" {
        AuditFailure::Cancelled
    } else if err.is_reauth_fatal() {
        AuditFailure::SessionDead
    } else {
        AuditFailure::Transient
    }
}

/// Upper bound on in-flight per-app lookups when the tenant is healthy.
const INITIAL_CONCURRENCY: usize = 8;
/// Page size — the shared `/applications` maximum.
const PAGE_SIZE: u32 = azapptoolkit_graph::client::DEFAULT_APP_PAGE_SIZE;
/// Safety cap on the total app count per run. Prevents a misconfigured tenant
/// or runaway pagination loop from OOMing the app; raise or pass `None` if a
/// user hits this legitimately.
const MAX_APPS_PER_RUN: usize = crate::commands::applications::APPS_MAX;
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
    let exo = audit_exchange_client(&state, &tenant_id);

    // These six tenant-wide reads are INDEPENDENT — every join between them
    // (`seed_lean_sps_from_index`, `derive_orgwide_mail_scopes`,
    // `sp_audit_candidates`) is synchronous and runs below, after all six land.
    // Awaiting them serially made a large tenant wait out five full page-walks
    // before the progress bar left 0/N; overlapped, that is one wait instead of
    // the sum. Five of the six are best-effort (they swallow errors and return
    // empty), so overlapping changes no failure semantics, and the
    // `ThrottleGuard` attached above plus the transport's Retry-After handling
    // already absorb the extra concurrent 429 pressure.
    //
    // Keep this a `join!`, not a `try_join!`: only the app listing is fallible,
    // and short-circuiting it would abandon the other five mid-flight.
    let (
        apps,
        sp_index,
        consent_grants,
        graph_roles_by_sp,
        ews_full_access_sps,
        sign_in,
        legacy_policies,
    ) = futures::join!(
        client.list_applications_all(
            // `$expand=owners` brings owner ids inline so the ownership audit
            // rules need no per-app round trip.
            //
            // LIMIT: `$expand` on a directory-object relationship returns at
            // most 20 items and carries no `@odata.nextLink`, so this owner list
            // is TRUNCATED for any app with more than 20 owners. That is safe
            // for the only rule reading it (the ownership gap fires on 0 or 1
            // owner, and a truncated list still has 20). A future rule that
            // needs a COMPLETE owner set must not read this field — it has to
            // page `/applications/{id}/owners` per app instead.
            AppListQuery::default()
                .with_top(PAGE_SIZE)
                .with_expand("owners($select=id)"),
            Some(MAX_APPS_PER_RUN),
        ),
        // ONE tenant-wide service-principal enumeration feeds BOTH the SP-only
        // audit phase (below) and every per-app SP lookup score_one makes: its
        // projection (id/appId/accountEnabled/…) is a superset of the lean
        // fields score_one reads, so seeding the audit's lean SP cache FROM it
        // makes each score_one lookup a cache hit at zero extra Graph cost. This
        // replaces the former batched lean prewarm (~1 $batch POST per 20 apps)
        // that re-fetched the very directory objects this index scan already
        // returns. A cold/failed index (empty vec) simply leaves the per-app
        // lean lookups to resolve as before.
        prefetch_sp_index(&state.cache, &client, &tenant_id),
        // Admin-consent flags + delegated scopes from ONE tenant-wide
        // oauth2PermissionGrants read, replacing a per-app GET inside the
        // scoring loop (an N+1 that dominated large runs' request budget and 429
        // pressure).
        prefetch_admin_consent_grants(&client),
        // ONE tenant-wide appRoleAssignedTo read on the Microsoft Graph SP does
        // double duty: the full per-SP granted Graph role values feed the SP-only
        // scoring phase below, and the mail-scopable subset feeds score_one's
        // scoped-mail reconciliation.
        prefetch_graph_app_roles(&client),
        // ONE tenant-wide appRoleAssignedTo read on the legacy Office 365 Exchange
        // Online SP, for the EWS `full_access_as_app` grants the Graph matrix
        // can't see. Kept SEPARATE from the Graph matrix on purpose (the two
        // resources' role values are not interchangeable), but it feeds BOTH
        // score_one's reconciliation AND the SP-only phase: a principal holding
        // only this scope has no Graph role at all, yet reaches every mailbox.
        prefetch_ews_full_access_grants(&client),
        // Sign-in activity report (needs AuditLog.Read.All + Entra ID P1/P2 + a
        // supported directory role). A *missing consent* (distinct from a
        // license/availability failure) sets `sign_in_consent_required`,
        // surfacing a "Grant consent" button; either failure disables unused-app
        // detection.
        prefetch_sign_in_activity(&state, &client, &tenant_id),
        // ONE tenant-wide `Get-ApplicationAccessPolicy` read → the legacy-policy
        // verdict per appId. The per-app RBAC probe deliberately skips the AAP
        // lookup on this path (it would be an extra admin-API call per app), so
        // without this an app confined ONLY by a policy read as org-wide.
        prefetch_legacy_access_policies(exo.as_deref()),
    );

    // The audit is the one caller that CANNOT swallow truncation: it caches its
    // result and the UI presents that as the tenant's risk posture. A scan
    // capped at MAX_APPS_PER_RUN has not seen every app, so "no findings" from
    // it is "nothing found YET", exactly like a cancelled run.
    let (apps, truncated) = apps?;
    let (admin_consent_clients, delegated_scopes_by_client) = consent_grants;
    let (sign_in_available, sign_in_consent_required, sign_in_map) = sign_in;
    // Third way a run can be partial, alongside `cancelled` and `truncated`:
    // the scan reached every app, but with part of the analysis switched off
    // because a tenant-wide read failed. Collected here so the result can say
    // so instead of reading as a clean scan (see `AuditRunResult::degraded`).
    let (graph_roles_by_sp, graph_roles_gap) = graph_roles_by_sp;
    let (ews_full_access_sps, ews_gap) = ews_full_access_sps;
    // `mut` because a third kind of gap — per-principal scoring failures — can
    // only be known after the fan-out below has run.
    let mut degraded: Vec<AuditCoverageGap> =
        [graph_roles_gap, ews_gap].into_iter().flatten().collect();

    let app_ids: Vec<String> = apps.iter().map(|a| a.app_id.clone()).collect();
    client.seed_lean_sps_from_index(&app_ids, &sp_index);

    let admin_consent_clients = Arc::new(admin_consent_clients);
    let legacy_policies = Arc::new(legacy_policies);
    let orgwide_mail_by_sp = Arc::new(derive_orgwide_mail_scopes(
        &graph_roles_by_sp,
        &ews_full_access_sps,
    ));

    // SP-only phase candidates: service principals whose appId has NO local
    // application object (foreign enterprise apps, managed identities, orphaned
    // SPs) and that hold at least one Graph application-permission grant.
    let local_app_ids: HashSet<String> = apps.iter().map(|a| a.app_id.clone()).collect();
    let sp_candidates = sp_audit_candidates(
        &sp_index,
        &local_app_ids,
        &graph_roles_by_sp,
        &ews_full_access_sps,
    );
    let total = apps.len() + sp_candidates.len();

    // Exchange circuit breaker: a genuine auth failure (401 / 403) from the
    // admin API recurs for every app in the run, so the first one opens the
    // breaker and the remaining apps skip the doomed 1-5s cmdlet probes.
    // Scoring is unchanged — an open breaker leaves `mail_scopes` empty, the
    // same org-wide-weight default as the swallowed error (never under-reports).
    let exo_tripped = Arc::new(AtomicBool::new(false));

    emit_progress(
        &app_handle,
        "audit-progress",
        AuditProgress {
            done: 0,
            total,
            current_app: None,
            in_flight_cap: tracker.current_limit(),
            cancelled: false,
        },
    );

    // All shared scoring inputs travel as one `Arc<ScoreCtx>` cloned into each
    // task, replacing the ~dozen individual clones the closure used to make.
    let ctx = Arc::new(ScoreCtx {
        client: client.clone(),
        cache: state.cache.clone(),
        tenant_id: tenant_id.clone(),
        resolver: Arc::new(ResourceResolver::new(client.clone())),
        exo,
        admin_consent_clients,
        orgwide_mail_by_sp,
        legacy_policies,
        exo_tripped,
        sign_in_available,
        sign_in_map,
    });
    let done = Arc::new(Mutex::new(0usize));
    let cancel = state.audit_cancel.clone();

    let mut items: Vec<AuditItem> = Vec::with_capacity(total);
    // A dead session makes every remaining app fail identically, so the run must
    // stop rather than warn its way to a truncated report. Two halves because
    // `dispatch_capped` holds both closures at once: the flag is what the spawn
    // side can read, the error itself is only ever touched by the collect side.
    let reauth_fatal = Arc::new(AtomicBool::new(false));
    let reauth_fatal_spawn = reauth_fatal.clone();
    let mut fatal_err: Option<UiError> = None;
    // Apps this run set out to score but dropped. Counted rather than merely
    // logged: an app missing from `items` is invisible in the result, so
    // without this the run reports a clean, complete scan that simply never
    // looked at the principals whose scoring failed.
    let mut unscored: usize = 0;
    // Dynamic in-flight cap: the tracker shrinks it on 429s mid-run.
    let cancelled_before_all_dispatched = dispatch_capped(
        apps,
        || tracker.current_limit(),
        |app| {
            if cancel.is_cancelled() || reauth_fatal_spawn.load(Ordering::Relaxed) {
                return None;
            }
            let ctx = ctx.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let tracker_for_task = tracker.clone();
            let cancel_for_task = cancel.clone();
            Some(tokio::spawn(async move {
                if cancel_for_task.is_cancelled() {
                    return Err(UiError::validation("cancelled", "audit cancelled"));
                }
                let last_sign_in = ctx.last_sign_in_for(&app.app_id);
                let result = score_one(&ctx, &app, last_sign_in).await;
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
                emit_progress(&app_handle, "audit-progress", progress);
                result
            }))
        },
        |joined| match joined {
            Ok(Ok(item)) => items.push(item),
            Ok(Err(err)) => match classify_audit_failure(&err) {
                AuditFailure::Cancelled => {}
                // Latch the first one, stop dispatching, and let the caller
                // surface the code so the shell can re-auth in place.
                AuditFailure::SessionDead => {
                    reauth_fatal.store(true, Ordering::Relaxed);
                    if fatal_err.is_none() {
                        tracing::warn!(?err, "audit stopped: session is dead");
                        fatal_err = Some(err);
                    }
                }
                AuditFailure::Transient => {
                    unscored += 1;
                    tracing::warn!(?err, "audit scoring failed for one app")
                }
            },
            Err(err) => {
                unscored += 1;
                tracing::warn!(?err, "audit join error")
            }
        },
    )
    .await;

    // A dropped app is a hole in the analysis exactly like a failed tenant-wide
    // read, so it travels the same way: named in `degraded`, and therefore never
    // cached and never presented as an all-clear.
    if unscored > 0 {
        tracing::warn!(unscored, "audit completed with unscored principals");
        degraded.push(AuditCoverageGap::PerPrincipalScoring);
    }

    // Before phase 2 and before any cache write: a partial audit served as
    // authoritative is worse than a failed one, because a risk report silently
    // missing apps reads as clean.
    if let Some(err) = fatal_err {
        return Err(err);
    }

    // Phase 2: score the SP-only candidates (foreign enterprise apps, managed
    // identities, orphaned SPs) sequentially. Every input is already resolved
    // tenant-wide, so `score_sp_only` is pure scoring — no per-item Graph
    // traffic, no fan-out needed.
    if !cancelled_before_all_dispatched && !cancel.is_cancelled() {
        let mut done_count = *done.lock().await;
        let now = chrono::Utc::now();
        for sp in sp_candidates {
            if cancel.is_cancelled() {
                break;
            }
            let item = score_sp_only(
                &sp,
                &ctx,
                &graph_roles_by_sp,
                &delegated_scopes_by_client,
                &ews_full_access_sps,
                now,
            );
            done_count += 1;
            emit_progress(
                &app_handle,
                "audit-progress",
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

    // A truncated run is cached no more than a cancelled one: both scored an
    // arbitrary subset of the tenant, and a cached subset is indistinguishable
    // from a clean full scan on the next read.
    // ...and neither is a degraded one, for the same reason: a cached partial
    // analysis is indistinguishable from a full one on the next read, and this
    // one under-reports risk rather than merely covering fewer apps.
    if !cancelled && !truncated && degraded.is_empty() {
        state
            .cache
            .put(CacheKind::Audit, audit_cache_key(&tenant_id), &items);
    }

    Ok(AuditRunResult {
        tenant_id,
        // The number of principals this run SET OUT to score, which is what the
        // field name claims and what a cancelled run needs as its denominator —
        // `items.len()` (what this used to be) is the number actually scored, so
        // the two were identical on a full run and indistinguishable on a
        // cancelled one, leaving the UI no way to express coverage.
        total_apps: total,
        items,
        cancelled,
        sign_in_report_available: sign_in_available,
        sign_in_consent_required,
        truncated,
        degraded,
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
        // A truncated run is never cached (see `run_audit`), so anything read
        // back from here covered the whole tenant by construction.
        truncated: false,
        // Nor is a degraded one, for the same reason.
        degraded: Vec::new(),
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

/// Serializes a set of [`AuditItem`]s as CSV.
///
/// An internal helper, not an IPC command: `save_audit_to_file` is the only
/// caller and the only way the frontend exports an audit. It was registered as
/// a command "so callers that want the text don't need a save dialog", but no
/// such caller was ever written — leaving an unreachable entry point on the IPC
/// boundary.
pub(crate) fn export_audit_csv(items: Vec<AuditItem>) -> String {
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

/// Shared, read-only scoring inputs, resolved tenant-wide before the fan-out and
/// cloned once (as an `Arc`) into every phase-1 scoring task — replacing the
/// ~dozen individual clones the dispatch closure used to make. Only the per-app
/// [`Application`] and its `last_sign_in` vary per task.
struct ScoreCtx {
    client: Arc<GraphClient>,
    cache: Arc<Cache>,
    tenant_id: String,
    resolver: Arc<ResourceResolver>,
    /// Best-effort Exchange client for mailbox-scope resolution; `None` degrades
    /// every mail permission to full org-wide weight.
    exo: Option<Arc<ExchangeClient>>,
    admin_consent_clients: Arc<HashSet<String>>,
    orgwide_mail_by_sp: Arc<HashMap<String, HashSet<String>>>,
    /// `appId -> Scoped { LegacyApplicationAccessPolicy }` for every app a
    /// `RestrictAccess` Application Access Policy confines, from the run's one
    /// tenant-wide policy read. Empty when Exchange is unavailable — every mail
    /// permission then scores at its full org-wide weight, exactly as before.
    legacy_policies: Arc<HashMap<String, MailPermissionScope>>,
    /// Exchange circuit breaker — flipped once an auth failure recurs, skipping
    /// the doomed cmdlet probes for the rest of the run.
    exo_tripped: Arc<AtomicBool>,
    sign_in_available: bool,
    sign_in_map: Arc<HashMap<String, Option<DateTime<Utc>>>>,
}

impl ScoreCtx {
    /// The principal's recorded last sign-in for the unused-app advisory. Outer
    /// `None` = report unavailable (skip). Otherwise the recorded time; absent
    /// from the report ⇒ `Some(None)` = no sign-in observed.
    fn last_sign_in_for(&self, app_id: &str) -> Option<Option<DateTime<Utc>>> {
        if self.sign_in_available {
            Some(self.sign_in_map.get(app_id).copied().flatten())
        } else {
            None
        }
    }
}

/// Best-effort Exchange client for mailbox-scoping resolution. `None` (with an
/// info log) when the Exchange client can't be built — the signed-in user isn't
/// an Exchange admin, or there's no UPN for the anchor mailbox — so mail
/// permissions score at their full org-wide weight.
fn audit_exchange_client(state: &AppState, tenant_id: &str) -> Option<Arc<ExchangeClient>> {
    match exchange_client(state, tenant_id) {
        Ok(exo) => Some(exo),
        Err(err) => {
            tracing::info!(?err, "audit: Exchange scoping unavailable");
            None
        }
    }
}

/// ONE tenant-wide `oauth2PermissionGrants` read → (AllPrincipals client ids,
/// per-client delegated scope values). The scope strings are kept per client so
/// the SP-only phase can score high-risk delegated permissions (an SP has no
/// manifest to resolve them from). Best-effort: on failure no principal gets the
/// admin-consent flag and the audit proceeds.
async fn prefetch_admin_consent_grants(
    client: &GraphClient,
) -> (HashSet<String>, HashMap<String, Vec<String>>) {
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
    }
}

/// ONE tenant-wide `appRoleAssignedTo` read on the Microsoft Graph SP →
/// `spObjectId -> granted Graph permission values`. Feeds both the SP-only
/// scoring phase and (via [`derive_orgwide_mail_scopes`]) score_one's scoped-mail
/// reconciliation.
///
/// Still best-effort — a failure must not abort the whole audit — but it now
/// REPORTS the failure alongside the empty map. An empty map is
/// indistinguishable from "this tenant has no such grants", so swallowing the
/// error made the run score LOWER risk and present the result as complete.
async fn prefetch_graph_app_roles(
    client: &GraphClient,
) -> (HashMap<String, Vec<String>>, Option<AuditCoverageGap>) {
    let mut graph_roles_by_sp: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok((graph_sp_id, role_value_by_id)) = graph_role_index(client).await {
        match client.list_app_role_assigned_to(&graph_sp_id).await {
            Ok(assigned) => {
                for a in assigned {
                    // App permissions held by an app's SP — Users/Groups can't
                    // hold Graph app roles.
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
                return (
                    graph_roles_by_sp,
                    Some(AuditCoverageGap::GraphAppRoleAssignments),
                );
            }
        }
    } else {
        // The role index itself failed, so nothing below could run either.
        return (
            graph_roles_by_sp,
            Some(AuditCoverageGap::GraphAppRoleAssignments),
        );
    }
    (graph_roles_by_sp, None)
}

/// Service principals holding the EWS `full_access_as_app` scope as an org-wide
/// grant, from ONE tenant-wide `appRoleAssignedTo` read on the legacy Office 365
/// Exchange Online resource.
///
/// That resource is not Microsoft Graph, so [`prefetch_graph_app_roles`] can't see
/// these grants — and a surviving one reaches **every** mailbox with full access,
/// which defeats any RBAC mailbox scope on the same principal. Without it the
/// audit reported a scoped verdict (and the reduced scoped-mail weight) for a
/// principal that still had org-wide reach.
///
/// Best-effort: a tenant with no EWS-consenting app has no service principal for
/// the resource at all, which is normal — an empty set simply means no blanket
/// grant to reconcile against.
async fn prefetch_ews_full_access_grants(
    client: &GraphClient,
) -> (HashSet<String>, Option<AuditCoverageGap>) {
    let mut out = HashSet::new();
    // A tenant with no EWS-consenting app has no service principal for the
    // resource at all. That is an ordinary empty answer, NOT a gap — reporting
    // it as one would flag most tenants as degraded and teach operators to
    // ignore the banner.
    let Ok(Some(sp)) = client
        .resolve_resource_sp(OFFICE365_EXCHANGE_ONLINE_APP_ID)
        .await
    else {
        return (out, None);
    };
    let full_access_role_ids: HashSet<&str> = sp
        .app_roles
        .iter()
        .filter(|r| r.value == EWS_FULL_ACCESS_AS_APP)
        .map(|r| r.id.as_str())
        .collect();
    if full_access_role_ids.is_empty() {
        return (out, None);
    }
    match client.list_app_role_assigned_to(&sp.id).await {
        Ok(assigned) => {
            for a in assigned {
                if a.principal_type.as_deref() == Some("ServicePrincipal")
                    && full_access_role_ids.contains(a.app_role_id.as_str())
                {
                    out.insert(a.principal_id);
                }
            }
        }
        Err(err) => {
            tracing::info!(
                ?err,
                "audit: Office 365 Exchange Online app-role assignments read failed; \
                 org-wide EWS reconciliation unavailable"
            );
            // The SP exists, so this tenant DOES use the resource — the read
            // genuinely failed, and a principal that looks scoped may hold
            // blanket mailbox access.
            return (out, Some(AuditCoverageGap::EwsFullAccessGrants));
        }
    }
    (out, None)
}

/// ONE tenant-wide `Get-ApplicationAccessPolicy` read → the legacy scoping
/// verdict per **appId**: `Scoped { LegacyApplicationAccessPolicy }` for every
/// app a `RestrictAccess` policy confines (`DenyAccess` is a blocklist — still
/// effectively org-wide — so [`aap_verdict_for`] leaves it out).
///
/// A policy gates the whole application, so one cmdlet answers for every app in
/// the tenant. The per-app RBAC probe skips this lookup on the audit path (it
/// would be an extra admin-API call per app), which is why an app confined only
/// by a policy used to read org-wide here while the Permissions tab reported it
/// scoped.
///
/// Best-effort: no Exchange client, no Exchange-admin rights, or a failed read
/// all yield an empty map — every mail permission then scores at its full
/// org-wide weight, the same never-under-report degradation the rest of the
/// Exchange path takes.
async fn prefetch_legacy_access_policies(
    exo: Option<&ExchangeClient>,
) -> HashMap<String, MailPermissionScope> {
    let mut out = HashMap::new();
    let Some(exo) = exo else { return out };
    let policies = match exo.get_application_access_policies().await {
        Ok(policies) => policies,
        Err(err) => {
            tracing::info!(
                code = err.ui_code(),
                "audit: legacy Application Access Policy read failed; legacy-scoping findings unavailable"
            );
            return out;
        }
    };
    for app_id in policies.iter().filter_map(|p| p.app_id.clone()) {
        if out.contains_key(&app_id) {
            continue;
        }
        if let Some(verdict) = aap_verdict_for(&policies, &app_id) {
            out.insert(app_id, verdict);
        }
    }
    out
}

/// The org-wide-granted mailbox permissions `score_one` reconciles against a
/// scoped RBAC verdict: the mail-scopable subset of each SP's granted Graph roles,
/// **plus** the EWS `full_access_as_app` scope for the principals in
/// `ews_full_access_sps`. Empty sets are dropped.
fn derive_orgwide_mail_scopes(
    graph_roles_by_sp: &HashMap<String, Vec<String>>,
    ews_full_access_sps: &HashSet<String>,
) -> HashMap<String, HashSet<String>> {
    let mut out: HashMap<String, HashSet<String>> = graph_roles_by_sp
        .iter()
        .map(|(sp_id, values)| {
            // `graph_roles_by_sp` holds Microsoft Graph roles by construction,
            // so name that resource rather than testing the bare value: the
            // value-only form also answers `true` for Office 365 Exchange
            // Online's identically-named legacy appRoles, which RBAC for
            // Applications cannot confine.
            let mail: HashSet<String> = values
                .iter()
                .filter(|v| {
                    is_scopable_exchange_resource_permission(Some(MICROSOFT_GRAPH_APP_ID), v)
                })
                .cloned()
                .collect();
            (sp_id.clone(), mail)
        })
        .filter(|(_, mail)| !mail.is_empty())
        .collect();
    // A principal can hold the EWS scope and no Graph mail role at all, so this
    // inserts as well as extends.
    for sp_id in ews_full_access_sps {
        out.entry(sp_id.clone())
            .or_default()
            .insert(EWS_FULL_ACCESS_AS_APP.to_string());
    }
    out
}

/// The tenant's service-principal index (get-or-fetch, cached under
/// `CacheKind::Lists` — the same shared index as `list_enterprise_applications`),
/// the candidate pool for the SP-only scoring phase. Best-effort: on failure the
/// run covers app registrations only.
async fn prefetch_sp_index(
    cache: &Cache,
    client: &GraphClient,
    tenant_id: &str,
) -> Arc<Vec<ServicePrincipal>> {
    if let Some(cached) = crate::commands::applications::sp_index_hit(cache, tenant_id) {
        return cached;
    }
    // Captured BEFORE the scan: it takes seconds under no lock, and re-pinning
    // a pre-mutation snapshot would outlive the invalidation it raced.
    let watch = cache.generation_for(
        azapptoolkit_core::cache::CacheKind::Lists,
        &crate::commands::applications::sp_index_key(tenant_id),
    );
    match client.list_service_principals_index().await {
        Ok(sps) => crate::commands::applications::sp_index_store_if_current(cache, sps, watch),
        Err(err) => {
            tracing::info!(
                ?err,
                "audit: SP index unavailable; scanning app registrations only"
            );
            Arc::new(Vec::new())
        }
    }
}

/// The `servicePrincipalSignInActivities` report → `(available,
/// consent_required, appId -> last sign-in)`. Pre-acquires the
/// `AuditLog.Read.All` token with a typed call so a *missing-consent* failure (→
/// `consent_required`, a "Grant consent" button) is distinguishable from a
/// license/availability one. Either failure disables unused-app detection
/// (`available = false` ⇒ no app is flagged "unused").
async fn prefetch_sign_in_activity(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> (bool, bool, Arc<HashMap<String, Option<DateTime<Utc>>>>) {
    match state.ensure_audit_log_token(tenant_id).await {
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
    }
}

/// Scores one SP-only candidate (foreign enterprise app, managed identity,
/// orphaned SP). Pure scoring — every input was resolved tenant-wide, so there's
/// no per-item Graph traffic. No **RBAC** verdict is resolved ON PURPOSE: a held
/// mail value here IS an un-stripped org-wide Entra grant (it comes from the
/// grant matrix), and grant ∪ RBAC reach is always org-wide, so the
/// reconciliation score_one applies would force OrgWide regardless of any RBAC
/// verdict — skipping the 1-5s Exchange probe per SP scores identically. A
/// principal whose grant the scoping flow stripped no longer holds the value and
/// drops out of the candidate set entirely.
///
/// A legacy Application Access Policy is the one exception, and it comes free
/// from the run's tenant-wide policy read: unlike an RBAC scope, a policy DOES
/// constrain the org-wide Entra grant these rows are scored from, so a confined
/// foreign app / managed identity would otherwise be reported org-wide.
fn score_sp_only(
    sp: &ServicePrincipal,
    ctx: &ScoreCtx,
    graph_roles_by_sp: &HashMap<String, Vec<String>>,
    delegated_scopes_by_client: &HashMap<String, Vec<String>>,
    ews_full_access_sps: &HashSet<String>,
    now: DateTime<Utc>,
) -> AuditItem {
    // The Graph matrix holds Microsoft Graph roles by construction; the EWS
    // blanket scope lives on the legacy Office 365 Exchange Online resource and
    // is tracked separately, so it has to be re-attached here with its own
    // resource or the scorer cannot see the tenant's broadest mailbox grant.
    let mut app_role_grants: Vec<ResourcePermission> = graph_roles_by_sp
        .get(&sp.id)
        .map(|values| {
            values
                .iter()
                .map(ResourcePermission::graph)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if ews_full_access_sps.contains(&sp.id) {
        app_role_grants.push(ResourcePermission::exchange_online(EWS_FULL_ACCESS_AS_APP));
    }
    let mut perms = AppPermissions {
        app_role_grants,
        scope_values: delegated_scopes_by_client
            .get(&sp.id)
            .cloned()
            .unwrap_or_default(),
        has_admin_consent: ctx.admin_consent_clients.contains(&sp.id),
        mail_scopes: HashMap::new(),
    };
    let granted_grants = perms.app_role_grants.clone();
    apply_legacy_policy_verdict(
        &mut perms.mail_scopes,
        &granted_grants,
        ctx.legacy_policies.get(&sp.app_id),
    );
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
    let last_sign_in = ctx.last_sign_in_for(&sp.app_id);
    item.sign_in_report_available = last_sign_in.is_some();
    item.last_sign_in = last_sign_in.flatten();
    if let Some((issue, rec)) = unused_app_advisory(last_sign_in.into(), sp.created_date_time, now)
    {
        item.unused = true;
        item.issues.push(issue);
        item.recommendations.push(rec);
    }
    item
}

/// The SP-only scoring candidates: service principals whose `appId` has no
/// local application object (foreign enterprise apps, managed identities,
/// orphaned SPs — paired SPs are already scored via the app-registration
/// phase) AND that hold at least one Graph application-permission grant. The
/// grant requirement is the noise filter: it drops the hundreds of grantless
/// first-party Microsoft SPs every tenant carries. Disabled SPs stay in (Rule
/// 4 flags them).
///
/// "Holds a grant" spans **both** mailbox resources: an SP holding only the EWS
/// `full_access_as_app` scope has no Graph role at all, yet reaches every mailbox
/// in the tenant — filtering on the Graph matrix alone dropped exactly the
/// principal most worth scoring. Known limitation: roles held only on *other*
/// non-Graph resources still aren't in any matrix, so such an SP is not scored.
fn sp_audit_candidates(
    sp_index: &[ServicePrincipal],
    local_app_ids: &HashSet<String>,
    graph_roles_by_sp: &HashMap<String, Vec<String>>,
    ews_full_access_sps: &HashSet<String>,
) -> Vec<ServicePrincipal> {
    sp_index
        .iter()
        .filter(|sp| !local_app_ids.contains(&sp.app_id))
        .filter(|sp| {
            graph_roles_by_sp.get(&sp.id).is_some_and(|v| !v.is_empty())
                || ews_full_access_sps.contains(&sp.id)
        })
        .cloned()
        .collect()
}

struct ResourceResolver {
    client: Arc<GraphClient>,
    cache: Mutex<HashMap<String, Arc<ResourceIndex>>>,
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

    /// Returns a SHARED handle, not a copy. The Microsoft Graph resource index
    /// is ~1500 `(String, String)` pairs, and this is called once per distinct
    /// resource per app: handing out clones meant a 10 000-app run allocated
    /// tens of millions of strings for a read-only lookup table, inside the
    /// spawned scoring tasks (so it saturated every worker, not one).
    async fn index(&self, resource_app_id: &str) -> Arc<ResourceIndex> {
        {
            let cache = self.cache.lock().await;
            if let Some(hit) = cache.get(resource_app_id) {
                return Arc::clone(hit);
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

        let index = Arc::new(index);
        let mut cache = self.cache.lock().await;
        cache.insert(resource_app_id.to_string(), Arc::clone(&index));
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
    let indexes: HashMap<String, Arc<ResourceIndex>> =
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
                // Carry the resource, don't drop it: two resources expose an
                // identically named `Mail.Read`/`Mail.Send`/`Contacts.*` and only
                // Microsoft Graph's are confinable by RBAC for Applications. The
                // scorer gates every mailbox verdict on this id.
                "Role" => out
                    .app_role_grants
                    .push(ResourcePermission::on(&resource.resource_app_id, value)),
                "Scope" => out.scope_values.push(value),
                _ => {}
            }
        }
    }
    out
}

async fn score_one(
    ctx: &ScoreCtx,
    app: &Application,
    last_sign_in: Option<Option<DateTime<Utc>>>,
) -> Result<AuditItem, UiError> {
    // Lean lookup: the audit reads only `sp.id` and `sp.account_enabled`. The
    // prewarm above seeds the matching `|lean` cache key, so this is a hit.
    let sp = match ctx
        .client
        .get_service_principal_by_app_id_lean(&app.app_id)
        .await
    {
        Ok(sp) => sp,
        Err(err) => {
            tracing::warn!(app = %app.display_name, ?err, "audit: SP lookup failed");
            None
        }
    };

    let mut perms = resolve_permissions(&ctx.resolver, &app.required_resource_access).await;

    // Admin-consent flag: true if any AllPrincipals grant names this SP as the
    // client (membership in the run's one tenant-wide prefetch).
    if let Some(ref sp) = sp {
        perms.has_admin_consent = ctx.admin_consent_clients.contains(&sp.id);
    }

    // Resolve effective Exchange mailbox scoping so a mail permission confined to
    // specific mailboxes scores below an org-wide one. Skips the Exchange round
    // trip entirely for apps with no scopable mail permissions (the resolver
    // returns an empty map), and for the rest of the run once the circuit
    // breaker has tripped (an auth failure recurs for every app; an open
    // breaker scores identically to the swallowed error — org-wide weight).
    // `enrich=false` — the audit needs only the org-wide/scoped distinction,
    // not the recipient filter.
    let exo = if ctx.exo_tripped.load(Ordering::Acquire) {
        None
    } else {
        ctx.exo.as_deref()
    };
    let declared_values = perms.app_role_values();
    if let Some(exo) = exo {
        // Reconcile a scoped RBAC verdict against an un-stripped org-wide Entra
        // grant — `Test-ServicePrincipalAuthorization` can't see Entra grants, so
        // a scoped role coexisting with the org-wide grant still reaches every
        // mailbox. Only worth the extra read when the app declares a scopable mail
        // permission and its SP resolved.
        let orgwide = match &sp {
            Some(sp)
                if perms.app_role_grants.iter().any(|g| {
                    is_scopable_exchange_resource_permission(g.resource_app_id.as_deref(), &g.value)
                }) =>
            {
                // One tenant-wide read (above) replaces the former per-app
                // appRoleAssignments GET; a map miss ⇒ empty set, same as before.
                ctx.orgwide_mail_by_sp
                    .get(&sp.id)
                    .cloned()
                    .unwrap_or_default()
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
            &ctx.cache,
            &ctx.tenant_id,
            exo,
            &app.app_id,
            &declared_values,
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
                    ctx.exo_tripped.store(true, Ordering::Release);
                    tracing::info!(
                        ?err,
                        "audit: Exchange authorization failed; skipping mailbox-scope probes for the rest of the run"
                    );
                }
                HashMap::new()
            }
        };
    }

    // Fold in the run's tenant-wide legacy-policy verdict. Outside the Exchange
    // block on purpose: the policy read already happened (before the breaker
    // could trip), and a `RestrictAccess` policy confines the app whether or not
    // this app's RBAC probe ran, failed, or was skipped.
    let declared_grants = perms.app_role_grants.clone();
    apply_legacy_policy_verdict(
        &mut perms.mail_scopes,
        &declared_grants,
        ctx.legacy_policies.get(&app.app_id),
    );

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
        // Attached here rather than in `score_application` because `unused` is
        // this post-pass's flag. Skip when there's no SP to disable, or the SP
        // is already disabled — either way the fix has nothing to do.
        if sp.is_some() && item.service_principal_enabled != Some(false) {
            item.remediations
                .push(azapptoolkit_core::audit::disable_sign_in_remediation());
        }
    }
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::{AuditPrincipalKind, CredentialStatus, RiskLevel};

    #[test]
    fn a_dead_session_stops_the_audit_but_one_bad_app_does_not() {
        // Regression: every non-cancelled failure used to collapse to a warning,
        // so a session that died mid-run produced a report silently missing apps
        // — and then cached it under CacheKind::Audit as authoritative.
        let cases = [
            ("cancelled", AuditFailure::Cancelled),
            ("refresh_missing", AuditFailure::SessionDead),
            ("not_signed_in", AuditFailure::SessionDead),
            ("forbidden", AuditFailure::Transient),
            ("throttled", AuditFailure::Transient),
            ("graph", AuditFailure::Transient),
        ];
        for (code, expected) in cases {
            let err = UiError::new(code, "boom", false);
            assert_eq!(
                classify_audit_failure(&err),
                expected,
                "{code} should classify as {expected:?}"
            );
        }
    }

    #[test]
    fn session_dead_classification_tracks_the_shared_definition() {
        // `UiError::is_reauth_fatal` is the single definition (azapptoolkit-dto,
        // shared by both tiers). Adding a code there must extend the audit's stop
        // condition automatically — this asserts the coupling rather than a list.
        for code in ["refresh_missing", "not_signed_in", "forbidden", "cancelled"] {
            let err = UiError::new(code, "boom", false);
            let expected_stop = err.is_reauth_fatal();
            let stops = classify_audit_failure(&err) == AuditFailure::SessionDead;
            assert_eq!(stops, expected_stop, "{code} diverged from is_reauth_fatal");
        }
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

    #[test]
    fn orgwide_mail_scopes_include_the_ews_scope_from_the_legacy_resource() {
        // The EWS `full_access_as_app` grant lives on Office 365 Exchange Online,
        // not Microsoft Graph, so the Graph matrix can't see it. Without it a
        // principal with a scoped RBAC role but a surviving org-wide EWS grant
        // scored as scoped — an under-report, since it still reaches every mailbox.
        let graph_roles: HashMap<String, Vec<String>> = [
            (
                "sp-mixed".to_string(),
                vec!["Mail.Read".to_string(), "User.Read.All".to_string()],
            ),
            // Holds no mail role at all: the EWS grant must still register, so this
            // has to insert rather than only extend.
            ("sp-ews-only".to_string(), vec!["User.Read.All".to_string()]),
        ]
        .into();
        let ews: HashSet<String> = ["sp-mixed".to_string(), "sp-ews-only".to_string()].into();

        let out = derive_orgwide_mail_scopes(&graph_roles, &ews);

        assert_eq!(
            out.get("sp-mixed"),
            Some(
                &["Mail.Read".to_string(), EWS_FULL_ACCESS_AS_APP.to_string()]
                    .into_iter()
                    .collect::<HashSet<_>>()
            ),
            "the Graph mail role and the EWS scope must both be reconciled against"
        );
        assert_eq!(
            out.get("sp-ews-only"),
            Some(&[EWS_FULL_ACCESS_AS_APP.to_string()].into_iter().collect())
        );
    }

    #[test]
    fn orgwide_mail_scopes_drop_principals_with_no_mailbox_grant() {
        // Non-mail roles alone leave nothing to reconcile — the entry is dropped so
        // the map stays the mail-relevant subset it claims to be.
        let graph_roles: HashMap<String, Vec<String>> =
            [("sp-1".to_string(), vec!["Directory.Read.All".to_string()])].into();
        assert!(derive_orgwide_mail_scopes(&graph_roles, &HashSet::new()).is_empty());
    }

    // The SP-only candidate filter: no local application AND ≥1 application
    // grant on either mailbox-bearing resource. Managed identities and disabled
    // SPs are candidates; paired and grantless SPs are not.
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
        let got: Vec<String> = sp_audit_candidates(&index, &local_app_ids, &roles, &HashSet::new())
            .into_iter()
            .map(|s| s.id)
            .collect();
        // Paired (has a local app), grantless (not in the matrix), and
        // empty-role-list SPs are all excluded; the foreign SP and the MI stay.
        assert_eq!(got, vec!["sp-foreign".to_string(), "sp-mi".to_string()]);
    }

    #[test]
    fn sp_holding_only_the_ews_blanket_scope_is_still_a_candidate() {
        // `full_access_as_app` lives on Office 365 Exchange Online, so such a
        // principal has NO Graph role and was filtered out of the SP-only phase
        // entirely — despite holding full access to every mailbox in the tenant,
        // which is the single most audit-worthy grant there is.
        let index = vec![sp("sp-ews", "ews-app", Some("Application"))];
        let ews: HashSet<String> = ["sp-ews".to_string()].into();
        let got: Vec<String> = sp_audit_candidates(
            &index,
            &HashSet::new(),
            &HashMap::new(), // no Graph grants at all
            &ews,
        )
        .into_iter()
        .map(|s| s.id)
        .collect();
        assert_eq!(got, vec!["sp-ews".to_string()]);
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
