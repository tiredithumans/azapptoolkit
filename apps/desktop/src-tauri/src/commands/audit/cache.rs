//! The audit-run cache: key, stored shape, cacheability guard, invalidation,
//! and the two read-only commands that serve the last completed run.

use tauri::State;

use azapptoolkit_core::audit::AuditItem;
use azapptoolkit_core::cache::CacheKind;

use crate::dto::UiError;
use crate::dto::audit::{AuditCoverageGap, AuditRunResult, CachedAuditSummary};
use crate::state::AppState;

/// Tenant-prefixed audit-run cache key — the same `{tenant_id}|` convention as
/// every other kind, so sign-out's prefix invalidation reaches it. (The
/// original `run:{tenant}` suffix shape was invisible to the prefix idiom.)
pub(crate) fn audit_cache_key(tenant_id: &str) -> String {
    format!("{tenant_id}|audit_run")
}

/// What the [`CacheKind::Audit`] run entry holds: the scored items **plus the
/// moment the run finished**.
///
/// The timestamp rides in the same entry rather than a second key so it can
/// never outlive, be evicted apart from, or disagree with the items it
/// describes. It is the only record of when a scan happened — the cache is
/// in-process with a 60-minute TTL, so "read time" and "run time" differ by up
/// to an hour, and a cache hit stamped on read would tell an operator a
/// 59-minute-old posture was current.
///
/// Stored with `put_typed` and read ONLY with `get_typed::<CachedAuditRun>`:
/// the entry is in-process, never serialized, and an untyped `cache.get` on it
/// reads `Null` and misses — which would surface as "no audit run".
pub(crate) struct CachedAuditRun {
    /// RFC3339 UTC.
    pub(crate) completed_at: String,
    pub(crate) items: Vec<AuditItem>,
    /// [`AuditRunResult::mailbox_scoping_resolved`] — stored with the items
    /// because an unresolved run is still cacheable (it over-reports, never
    /// under-reports), so a cache hit and its export must still carry the
    /// caveat.
    pub(crate) mailbox_scoping_resolved: bool,
    /// The run's app-management policy state, mirrored into [`CachedAuditSummary`]
    /// for the Home posture line. NOT reconstructable from the items (it is
    /// tenant-wide, not per-row), so it rides the entry — a cache hit that
    /// dropped it would silently answer "no cap known" an hour after a run
    /// that knew the cap.
    pub(crate) credential_policy_available: bool,
    pub(crate) credential_policy_max_days: Option<i64>,
}

/// Whether a finished run may be written to the audit cache.
///
/// **Only a complete, undegraded scan.** A cancelled or truncated run scored an
/// arbitrary subset of the tenant, and a degraded one scored every app but
/// under-reports because some input could not be resolved. On the next read a
/// cached run of any of those three kinds is indistinguishable from a clean
/// full scan — the operator sees an all-clear that was never established.
///
/// AGENTS.md states this ("a `cancelled`/`truncated`/`degraded` run is **never
/// cached** nor shown as an all-clear") and nothing enforced it; extracted from
/// [`run_audit`] purely so it can be, since that function needs a Tauri `State`
/// and cannot be unit-tested.
pub(crate) fn run_is_cacheable(
    cancelled: bool,
    truncated: bool,
    degraded: &[AuditCoverageGap],
) -> bool {
    !cancelled && !truncated && degraded.is_empty()
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
///
/// **Answers from cache alone** (as does [`get_cached_audit_summary`]), which
/// is why both check the session themselves. A read that reaches Graph goes
/// through `graph_for`, so a tenant with no session fails at the token and
/// never returns data. Here the `tenant_id` argument alone decided which
/// tenant's directory data came back — a stale or wrong id from the webview
/// (a tenant switch mid-flight is the realistic one) served the *other*
/// tenant's audit, which is the cross-tenant leak this codebase treats as its
/// first footgun. No session for that tenant ⇒ no cached answer (`Ok(None)`,
/// the same "no run cached" the view already handles).
///
/// `async` on purpose, like every other command (AGENTS.md's command shape): a
/// sync command runs on the main thread, and copying and serializing up to
/// 10 000 scored items there froze the window on every Security-tab hydrate.
/// Pinned by `repo_invariants::cache::cached_scan_reads_are_async_commands`.
#[tauri::command]
pub async fn get_cached_audit(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Option<AuditRunResult>, UiError> {
    let Some(_) = state.auth.tenant_context(&tenant_id) else {
        return Ok(None);
    };
    let key = audit_cache_key(&tenant_id);
    let Some(run) = state
        .cache
        .get_typed::<CachedAuditRun>(CacheKind::Audit, &key)
    else {
        return Ok(None);
    };
    Ok(Some(cached_run_result(tenant_id, &run)))
}

/// The [`AuditRunResult`] a cache hit answers with. The one deep copy left on
/// this path is `items`: [`AuditRunResult`] is a wire type the frontend
/// decodes, so it owns its items rather than sharing the cache's `Arc`.
fn cached_run_result(tenant_id: String, run: &CachedAuditRun) -> AuditRunResult {
    let items = run.items.clone();
    // Report availability is reconstructed from the cached items (every item
    // carries the run's `sign_in_report_available`); a cached run never re-prompts
    // for consent, so `sign_in_consent_required` is false on a cache hit.
    let sign_in_report_available = items.iter().any(|i| i.sign_in_report_available);
    AuditRunResult {
        tenant_id,
        total_apps: items.len(),
        items,
        cancelled: false,
        sign_in_report_available,
        sign_in_consent_required: false,
        credential_policy_available: run.credential_policy_available,
        credential_policy_max_days: run.credential_policy_max_days,
        // A truncated run is never cached (see `run_audit`), so anything read
        // back from here covered the whole tenant by construction.
        truncated: false,
        // Nor is a degraded one, for the same reason.
        degraded: Vec::new(),
        // The stamp the RUN wrote, not this read: a cache hit is what the
        // dashboard shows after a relaunch-free hour, and "scanned just now"
        // about an hour-old scan is the false claim this field exists to stop.
        completed_at: Some(run.completed_at.clone()),
        // Cached WITH the items: an unresolved run is cacheable, and its
        // caveat must survive the round trip.
        mailbox_scoping_resolved: run.mailbox_scoping_resolved,
    }
}

/// The Home dashboard's view of the cached audit: the posture counts and each
/// finding's worst severity, never the items (see [`CachedAuditSummary`]).
/// `None` when no run is cached — or when `tenant_id` has no session, exactly
/// like [`get_cached_audit`], since this too answers from the cache alone.
/// Borrows the cached run's items through the `Arc`, so nothing is copied.
///
/// `completed_at` is the stamp the run wrote, not this read's time: the card
/// says "Scanned 40 minutes ago" from it, and a cache hit re-stamped on read
/// would present an hour-old posture as current.
#[tauri::command]
pub async fn get_cached_audit_summary(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Option<CachedAuditSummary>, UiError> {
    let Some(_) = state.auth.tenant_context(&tenant_id) else {
        return Ok(None);
    };
    let Some(run) = state
        .cache
        .get_typed::<CachedAuditRun>(CacheKind::Audit, &audit_cache_key(&tenant_id))
    else {
        return Ok(None);
    };
    Ok(Some(CachedAuditSummary::from_items(
        &run.items,
        Some(run.completed_at.clone()),
        run.credential_policy_available,
        run.credential_policy_max_days,
    )))
}
