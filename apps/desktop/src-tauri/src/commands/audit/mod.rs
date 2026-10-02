//! Security audit: the run fan-out, its cache, and its exporter.
//!
//! Split by concern: `run` (the capped fan-out + Cancel), `cache` (the run
//! entry, its cacheability guard and the read-only serve commands), `export`
//! (the save-file dialog + JSON/HTML/CSV renderers), `prefetch` (tenant-wide
//! reads resolved before the fan-out), `score` (per-object scoring). The
//! failure classification, the shared `ScoreCtx` and the `ResourceResolver`
//! are used by several of those files, so they live here.

mod cache;
mod export;
mod prefetch;
mod run;
mod score;

// Glob re-exports keep every item reachable at `crate::commands::audit::*`
// (the pre-split path) — crucially including the hidden `__cmd__<name>` items
// that `#[tauri::command]` generates, which `generate_handler!` resolves at
// `commands::audit::<fn>` alongside the function itself.
pub use cache::*;
pub use export::*;
pub use run::*;

// `prefetch` and `score` expose no `pub` items (internal helpers), so they
// are not re-exported — callers in this subtree import them by path.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use azapptoolkit_core::audit::MailPermissionScope;
use azapptoolkit_core::cache::Cache;
use azapptoolkit_exchange::ExchangeClient;
use azapptoolkit_graph::GraphClient;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use crate::dto::UiError;

// ---------------- Shared plumbing ----------------

/// What the audit's per-app collector should do with one failed scoring task.
///
/// Extracted from the `dispatch_capped` collector so the rule "a dead session
/// stops the run" is unit-testable — the collector itself closes over `State`,
/// a Graph client and a tenant, and so is only reachable from a live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditFailure {
    /// The user cancelled; the run already accounts for this separately.
    Cancelled,
    /// The session is dead — every remaining app would fail identically, so the
    /// run must stop and must not cache what it managed to score.
    SessionDead,
    /// This one app failed. Warn, keep the rest of the run.
    Transient,
}

pub(crate) fn classify_audit_failure(err: &UiError) -> AuditFailure {
    if err.code == "cancelled" {
        AuditFailure::Cancelled
    } else if err.is_reauth_fatal() {
        AuditFailure::SessionDead
    } else {
        AuditFailure::Transient
    }
}

/// Shared, read-only scoring inputs, resolved tenant-wide before the fan-out and
/// cloned once (as an `Arc`) into every phase-1 scoring task — replacing the
/// ~dozen individual clones the dispatch closure used to make. Only the per-app
/// [`Application`] and its `last_sign_in` vary per task.
pub(crate) struct ScoreCtx {
    pub(crate) client: Arc<GraphClient>,
    pub(crate) cache: Arc<Cache>,
    pub(crate) tenant_id: String,
    pub(crate) resolver: Arc<ResourceResolver>,
    /// Best-effort Exchange client for mailbox-scope resolution; `None` degrades
    /// every mail permission to full org-wide weight.
    pub(crate) exo: Option<Arc<ExchangeClient>>,
    pub(crate) admin_consent_clients: Arc<HashSet<String>>,
    /// `spObjectId -> AllPrincipals delegated scope values`, the same map the
    /// SP-only phase scores from. Phase 1 copies an app's entry into
    /// `AppPermissions::admin_consented_scopes` so Rule 13 reports a broad
    /// delegated scope only when an admin consented to it for every user.
    /// `None` = the tenant-wide grants read failed: consent is unknown, and
    /// Rule 13 falls back to the declared scopes rather than hiding them.
    pub(crate) admin_consented_scopes_by_client: Option<Arc<HashMap<String, Vec<String>>>>,
    pub(crate) orgwide_mail_by_sp: Arc<HashMap<String, HashSet<String>>>,
    /// `appId -> Scoped { LegacyApplicationAccessPolicy }` for every app a
    /// `RestrictAccess` Application Access Policy confines, from the run's one
    /// tenant-wide policy read. Empty when Exchange is unavailable — every mail
    /// permission then scores at its full org-wide weight, exactly as before.
    pub(crate) legacy_policies: Arc<HashMap<String, MailPermissionScope>>,
    /// Exchange circuit breaker — flipped once an auth failure recurs, skipping
    /// the doomed cmdlet probes for the rest of the run.
    pub(crate) exo_tripped: Arc<AtomicBool>,
    /// Set when an app declaring a scopable mail permission was scored without
    /// a mailbox-scope answer (no Exchange client, an open breaker, or a failed
    /// probe) — it then scored at org-wide weight. Feeds
    /// `AuditRunResult::mailbox_scoping_resolved`.
    pub(crate) mail_scoping_unresolved: AtomicBool,
    pub(crate) sign_in_available: bool,
    pub(crate) sign_in_map: Arc<HashMap<String, Option<DateTime<Utc>>>>,
}

impl ScoreCtx {
    /// The principal's recorded last sign-in for the unused-app advisory. Outer
    /// `None` = report unavailable (skip). Otherwise the recorded time; absent
    /// from the report ⇒ `Some(None)` = no sign-in observed.
    pub(crate) fn last_sign_in_for(&self, app_id: &str) -> Option<Option<DateTime<Utc>>> {
        if self.sign_in_available {
            Some(self.sign_in_map.get(app_id).copied().flatten())
        } else {
            None
        }
    }
}

pub(crate) struct ResourceResolver {
    pub(crate) client: Arc<GraphClient>,
    /// Per-run memo. The value is a `OnceCell` rather than the index itself so
    /// N scoring tasks that all want the same resource share ONE round trip: on
    /// a cold cache every task raced to `resolve_resource_sp` for the same
    /// ~1500-permission Microsoft Graph index, because the map was only
    /// consulted before the fetch and written after it.
    pub(crate) cache: Mutex<HashMap<String, Arc<tokio::sync::OnceCell<Arc<ResourceIndex>>>>>,
    /// Set when a resource's permission index could not be resolved.
    ///
    /// A failed resolve yields an EMPTY index, and `resolve_permissions` skips
    /// every permission it cannot map — so the affected apps score as though
    /// they declared nothing at all. Without this flag the run finished with
    /// `degraded` empty and was cached as an authoritative clean scan, which is
    /// the one thing AGENTS.md says a degraded run must never be. The empty
    /// index is still memoized (a persistently unresolvable resource must not
    /// cost one failed round trip per app); the flag is what stops the result
    /// being mistaken for a complete one.
    unresolved: AtomicBool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResourceIndex {
    /// id → value for both roles and scopes, since ids are globally unique.
    pub(crate) by_id: HashMap<String, String>,
}

impl ResourceResolver {
    pub(crate) fn new(client: Arc<GraphClient>) -> Self {
        Self {
            client,
            cache: Mutex::new(HashMap::new()),
            unresolved: AtomicBool::new(false),
        }
    }

    /// True when at least one resource's permission index could not be
    /// resolved, so some declared permissions were skipped and the apps holding
    /// them scored below the truth.
    pub(crate) fn had_unresolved(&self) -> bool {
        self.unresolved.load(Ordering::Relaxed)
    }

    /// Returns a SHARED handle, not a copy. The Microsoft Graph resource index
    /// is ~1500 `(String, String)` pairs, and this is called once per distinct
    /// resource per app: handing out clones meant a 10 000-app run allocated
    /// tens of millions of strings for a read-only lookup table, inside the
    /// spawned scoring tasks (so it saturated every worker, not one).
    pub(crate) async fn index(&self, resource_app_id: &str) -> Arc<ResourceIndex> {
        // Take (or create) this resource's cell under the lock, then release it
        // before awaiting: holding it across the fetch would serialize resources
        // that are independent, and not holding a per-key cell at all let every
        // concurrent task issue the same request.
        let cell = {
            let mut cache = self.cache.lock().await;
            Arc::clone(
                cache
                    .entry(resource_app_id.to_string())
                    .or_insert_with(|| Arc::new(tokio::sync::OnceCell::new())),
            )
        };

        // Permission definitions are resolved live from Graph (cached under
        // `CacheKind::Permissions`, and again per-run in `self.cache`); the
        // bundled catalog is only a resource directory and carries no
        // per-permission data.
        Arc::clone(
            cell.get_or_init(|| async {
                let mut index = ResourceIndex::default();
                match self.client.resolve_resource_sp(resource_app_id).await {
                    Ok(Some(sp)) => {
                        for r in &sp.app_roles {
                            index.by_id.insert(r.id.clone(), r.value.clone());
                        }
                        for s in &sp.oauth2_permission_scopes {
                            index.by_id.insert(s.id.clone(), s.value.clone());
                        }
                    }
                    // BOTH arms are a coverage gap, not an empty resource. An
                    // `Err` is a failed read; `Ok(None)` is a resource whose
                    // service principal does not exist in this tenant, and in
                    // either case every permission declared against it is
                    // dropped by `resolve_permissions` and the app scores as
                    // though it held nothing. Recorded rather than swallowed:
                    // the run must not be cached or shown as an all-clear.
                    other => {
                        if let Err(err) = &other {
                            tracing::warn!(
                                ?err,
                                resource_app_id,
                                "audit could not resolve a resource's permission index"
                            );
                        } else {
                            tracing::warn!(
                                resource_app_id,
                                "audit found no service principal for a declared resource"
                            );
                        }
                        self.unresolved.store(true, Ordering::Relaxed);
                    }
                }
                Arc::new(index)
            })
            .await,
        )
    }
}

#[cfg(test)]
mod tests;
