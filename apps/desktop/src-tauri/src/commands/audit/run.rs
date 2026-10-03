//! The audit run itself: the capped, cancellable per-app fan-out and its
//! Cancel counterpart.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, State};

use azapptoolkit_core::audit::AuditItem;
use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_graph::client::AppListQuery;
use chrono::Utc;

use crate::commands::dispatch::dispatch_capped;
use crate::commands::progress::emit_progress;
use crate::commands::throttle::FanOutMeter;
use crate::dto::UiError;
use crate::dto::audit::{AuditCoverageGap, AuditProgress, AuditRunResult};
use crate::state::AppState;

use super::cache::{CachedAuditRun, audit_cache_key, run_is_cacheable};
use super::prefetch::{
    audit_exchange_client, prefetch_admin_consent_grants, prefetch_ews_full_access_grants,
    prefetch_graph_app_roles, prefetch_legacy_access_policies, prefetch_risky_service_principals,
    prefetch_sign_in_activity, prefetch_sp_index,
};
use super::score::{derive_orgwide_mail_scopes, score_one, score_sp_only, sp_audit_candidates};
use super::{AuditFailure, ResourceResolver, ScoreCtx, classify_audit_failure};

/// Upper bound on in-flight per-app lookups when the tenant is healthy.
const INITIAL_CONCURRENCY: usize = 8;
/// Page size — the shared `/applications` maximum.
const PAGE_SIZE: u32 = azapptoolkit_graph::client::DEFAULT_APP_PAGE_SIZE;
/// Safety cap on the total app count per run. Prevents a misconfigured tenant
/// or runaway pagination loop from OOMing the app; raise or pass `None` if a
/// user hits this legitimately.
const MAX_APPS_PER_RUN: usize = crate::commands::applications::APPS_MAX;

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
    let started = std::time::Instant::now();
    tracing::info!(tenant = %tenant_id, "audit started");
    let client = state.graph_for(&tenant_id);
    let meter = FanOutMeter::attach(client.clone(), INITIAL_CONCURRENCY);
    // Detach the observer however the run exits — an early `?` return (e.g. app
    // paging failure) previously left a stale tracker attached to the shared
    // per-tenant client, halving its cap on unrelated 429s until the next audit
    // replaced it. (RAII guard shared with the bulk fan-out commands.)

    // Claimed BEFORE the prefetch below, not after it. `claim()` takes a fresh
    // generation and `cancel()` stamps whatever generation is current at the
    // moment it runs, so a token claimed *after* the seven-way join carries a
    // HIGHER generation than the cancel the operator issued during it — and
    // `is_cancelled()` compares `cancelled >= generation`, so that cancel was
    // silently discarded. The prefetch is the longest phase of a large run, so
    // this was the most likely moment for an operator to press Cancel and the
    // one window where it did nothing.
    let cancel = state.audit_cancel.claim();

    // Effective Exchange mailbox-scoping is resolved on every run so a mail
    // permission confined to specific mailboxes scores below an org-wide one.
    let exo = audit_exchange_client(&state, &tenant_id);

    // The prefetch below is the longest phase of a large run, and until now the
    // first event came only after it. `total == 0` is what tells the webview to
    // render this as a phase label rather than a "0 / 0" fraction.
    emit_progress(
        &app_handle,
        "audit-progress",
        AuditProgress {
            done: 0,
            total: 0,
            current_app: Some("Reading tenant-wide directory data…".to_string()),
            in_flight_cap: meter.limit(),
            cancelled: false,
        },
    );

    // These seven tenant-wide reads are INDEPENDENT — every join between them
    // (`seed_lean_sps_from_index`, `derive_orgwide_mail_scopes`,
    // `sp_audit_candidates`) is synchronous and runs below, after all seven land.
    // Awaiting them serially made a large tenant wait out six full page-walks
    // before the progress bar left 0/N; overlapped, that is one wait instead of
    // the sum. Six of the seven are best-effort (they swallow errors and return
    // empty), so overlapping changes no failure semantics, and the
    // `ThrottleGuard` attached above plus the transport's Retry-After handling
    // already absorb the extra concurrent 429 pressure.
    //
    // Keep this a `join!`, not a `try_join!`: only the app listing is fallible,
    // and short-circuiting it would abandon the other six mid-flight.
    let (
        apps,
        sp_index,
        consent_grants,
        graph_roles_by_sp,
        ews_full_access_sps,
        sign_in,
        risky_sps,
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
        // ONE tenant-wide Identity Protection risky-service-principal read
        // (needs IdentityRiskyServicePrincipal.Read.All + a Workload Identities
        // premium license). Feeds Rule 22 for BOTH phases: risky grantless SPs
        // are admitted to the SP-only candidate set by this map, not by grants.
        prefetch_risky_service_principals(&state, &client, &tenant_id),
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
    let (admin_consent_clients, delegated_scopes_by_client, consent_grants_read) = consent_grants;
    let (sign_in_available, sign_in_consent_required, sign_in_map) = sign_in;
    let (risky_available, risky_by_sp, risky_gap) = risky_sps;
    let (legacy_policies, legacy_read_failed) = legacy_policies;
    // Third way a run can be partial, alongside `cancelled` and `truncated`:
    // the scan reached every app, but with part of the analysis switched off
    // because a tenant-wide read failed. Collected here so the result can say
    // so instead of reading as a clean scan (see `AuditRunResult::degraded`).
    let (graph_roles_by_sp, graph_roles_gap) = graph_roles_by_sp;
    let (ews_full_access_sps, ews_gap) = ews_full_access_sps;
    let (sp_index, sp_index_gap) = sp_index;
    // `mut` because a third kind of gap — per-principal scoring failures — can
    // only be known after the fan-out below has run.
    let mut degraded: Vec<AuditCoverageGap> = [graph_roles_gap, ews_gap, sp_index_gap, risky_gap]
        .into_iter()
        .flatten()
        .collect();

    let app_ids: Vec<String> = apps.iter().map(|a| a.app_id.clone()).collect();
    client.seed_lean_sps_from_index(&app_ids, &sp_index);

    let admin_consent_clients = Arc::new(admin_consent_clients);
    let delegated_scopes_by_client = Arc::new(delegated_scopes_by_client);
    let legacy_policies = Arc::new(legacy_policies);
    let orgwide_mail_by_sp = Arc::new(derive_orgwide_mail_scopes(
        &graph_roles_by_sp,
        &ews_full_access_sps,
    ));

    // SP-only phase candidates: service principals whose appId has NO local
    // application object (foreign enterprise apps, managed identities, orphaned
    // SPs) and that hold at least one Graph application-permission grant — OR
    // are flagged risky by Identity Protection, so a risky grantless principal
    // is still scored.
    let local_app_ids: HashSet<String> = apps.iter().map(|a| a.app_id.clone()).collect();
    let sp_candidates = sp_audit_candidates(
        &sp_index,
        &local_app_ids,
        &graph_roles_by_sp,
        &ews_full_access_sps,
        &risky_by_sp,
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
            in_flight_cap: meter.limit(),
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
        admin_consented_scopes_by_client: consent_grants_read
            .then(|| delegated_scopes_by_client.clone()),
        orgwide_mail_by_sp,
        legacy_policies,
        exo_tripped,
        mail_scoping_unresolved: AtomicBool::new(false),
        sign_in_available,
        sign_in_map,
        risky_available,
        risky_by_sp,
    });
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
        || meter.limit(),
        |app| {
            if cancel.is_cancelled() || reauth_fatal_spawn.load(Ordering::Relaxed) {
                return None;
            }
            let ctx = ctx.clone();
            let app_handle = app_handle.clone();
            let ticker = meter.ticker();
            let cancel_for_task = cancel.clone();
            Some(tokio::spawn(async move {
                if cancel_for_task.is_cancelled() {
                    return Err(UiError::validation("cancelled", "audit cancelled"));
                }
                let last_sign_in = ctx.last_sign_in_for(&app.app_id);
                let result = score_one(&ctx, &app, last_sign_in).await;
                let (done, in_flight_cap) = ticker.tick();
                let progress = AuditProgress {
                    done,
                    total,
                    current_app: Some(app.display_name.clone()),
                    in_flight_cap,
                    cancelled: cancel_for_task.is_cancelled(),
                };
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

    // Same rule one level down: a resource whose permission index could not be
    // resolved makes every app declaring permissions against it score as though
    // it declared none — a quieter hole than a dropped app, because the app IS
    // in `items`, just with an empty permission set and therefore no findings.
    if ctx.resolver.had_unresolved() {
        degraded.push(AuditCoverageGap::PermissionResolution);
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
        let now = chrono::Utc::now();
        // `done` continues from the fan-out's completion count; each scored SP
        // is one more item done.
        for (done_count, sp) in (meter.done() + 1..).zip(sp_candidates) {
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
            emit_progress(
                &app_handle,
                "audit-progress",
                AuditProgress {
                    done: done_count,
                    total,
                    current_app: Some(item.application_name.clone()),
                    in_flight_cap: meter.limit(),
                    cancelled: false,
                },
            );
            items.push(item);
        }
    }

    let cancelled = cancelled_before_all_dispatched || cancel.is_cancelled();
    // Whether every mail permission was actually checked against Exchange
    // mailbox scoping. Not a `degraded` gap — the fallback is org-wide weight,
    // which over-reports — but the operator has to be told, because the
    // "Org-wide mailbox access" group then includes apps Exchange may already
    // confine, each offering a Scope fix that needs the same Exchange access.
    let mailbox_scoping_resolved = ctx.exo.is_some()
        && !legacy_read_failed
        && !ctx.mail_scoping_unresolved.load(Ordering::Acquire);
    items.sort_by_key(|i| std::cmp::Reverse(i.risk_score));
    // One summary line per run, like the site sweep's `site sweep complete`:
    // "it took 40 minutes / stopped at 60% / found less than yesterday" is
    // answerable from the log only if the run records its shape.
    tracing::info!(
        total,
        scored = items.len(),
        unscored,
        truncated,
        cancelled,
        degraded = ?degraded,
        mailbox_scoping_resolved,
        cached = run_is_cacheable(cancelled, truncated, &degraded),
        elapsed_secs = started.elapsed().as_secs(),
        "audit complete",
    );

    // One stamp for both, so the cached run and the one returned to the caller
    // carry the same completion time. The cache holds its own copy of the items:
    // one clone per completed, cacheable run is cheaper than the whole-tree
    // `serde_json::to_value` walk an untyped `put` did, and it makes every later
    // read (`get_cached_audit`, the Home summary, export) a refcount clone
    // instead of a full deserialize.
    let completed_at = Utc::now().to_rfc3339();
    if run_is_cacheable(cancelled, truncated, &degraded) {
        state.cache.put_typed(
            CacheKind::Audit,
            audit_cache_key(&tenant_id),
            Arc::new(CachedAuditRun {
                completed_at: completed_at.clone(),
                items: items.clone(),
                mailbox_scoping_resolved,
            }),
        );
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
        completed_at: Some(completed_at),
        mailbox_scoping_resolved,
    })
}

/// Signals an in-progress audit to stop at the next dispatch boundary.
/// Already in-flight per-app lookups are allowed to finish so their partial
/// results don't corrupt the cache.
#[tauri::command]
pub fn cancel_audit(state: State<'_, AppState>) {
    state.audit_cancel.cancel();
}
