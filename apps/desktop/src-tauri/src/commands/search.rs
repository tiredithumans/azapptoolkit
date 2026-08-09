//! Global-search command backing the top-bar search input.
//!
//! If the query parses as a GUID, runs exact lookups by object id and app id.
//! Otherwise it substring-matches ("contains anywhere") on display name, appId,
//! and object id across all three identity kinds. Microsoft Graph OData has no
//! `contains()` for directory objects (only `startswith` / token-based
//! `$search`), so true match-anywhere is done in memory over the tenant's
//! cached app-registration and service-principal indexes — the same cached
//! enumerations the App Registrations / Enterprise Apps lists populate, so a
//! warm tenant filters instantly.

use std::sync::Arc;

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::{Application, ServicePrincipal};
use azapptoolkit_graph::GraphClient;
use tauri::State;

use crate::commands::applications::search_corpus_key;
use crate::commands::guid::is_guid;
use crate::dto::UiError;
use crate::dto::search::{GlobalSearchResults, SearchHit};
use crate::state::AppState;

/// Per-kind cap on rows returned to the dropdown. Keeps the response small
/// and the UI predictable.
const SEARCH_TOP: u32 = 10;

/// Which result bucket a corpus row belongs to.
#[derive(Clone, Copy)]
enum SearchKind {
    AppReg,
    Enterprise,
    ManagedIdentity,
}

/// One pre-lowercased search-corpus row: the display fields plus their
/// lowercased forms (computed once at build time, not per query) and the
/// result bucket. Typed-cached as `Arc<Vec<SearchRow>>` so a debounced
/// keystroke reuses it via a refcount clone — no per-query deserialize of the
/// full SP/Application models and no per-query re-lowercasing.
struct SearchRow {
    id: String,
    app_id: String,
    display_name: String,
    name_lc: String,
    app_id_lc: String,
    id_lc: String,
    kind: SearchKind,
}

/// One half of the corpus, degrading a failed index read to no rows for that
/// half instead of failing the search. Named rather than a closure because the
/// two halves hold different element types.
///
/// Returns whether the half actually loaded. The caller **must** carry that
/// through: degrading the current query is the documented contract, but caching
/// the degraded result is not. An empty half is indistinguishable from a tenant
/// with no such objects once it is stored, so a single transient Graph error
/// used to hide every app registration (or every enterprise app) from search for
/// the whole `Lists` TTL — pinned, so LRU could not evict it either.
fn corpus_half<T>(
    index: Result<Arc<Vec<T>>, azapptoolkit_graph::GraphError>,
    which: &str,
) -> (Arc<Vec<T>>, bool) {
    match index {
        Ok(v) => (v, true),
        Err(err) => {
            tracing::warn!(
                ?err,
                index = which,
                "global search: corpus half unavailable — serving partial results, not caching"
            );
            (Arc::new(Vec::new()), false)
        }
    }
}

/// Returns the tenant's typed-cached search corpus, building it from the SP +
/// app-name indexes on a miss (and seeding those indexes if cold). Invalidated
/// alongside its source indexes by `invalidate_app_lists`.
async fn search_corpus(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> Arc<Vec<SearchRow>> {
    let corpus_key = search_corpus_key(tenant_id);
    if let Some(corpus) = state
        .cache
        .get_typed::<Vec<SearchRow>>(CacheKind::Lists, &corpus_key)
    {
        return corpus;
    }

    // Single-flight, like the two indexes below and the gallery corpus. A cold
    // corpus is the slow path (two directory scans), and it is reached from the
    // *keystroke* path: the debounce fires per burst, a resource re-run doesn't
    // cancel the command already in flight, and the focus prewarm races the
    // first query. Every one of those missed, so each rebuilt the corpus and
    // raced to overwrite the same pinned key.
    let gate = state.single_flight(&corpus_key);
    let _held = gate.lock().await;
    // Re-check: the build we queued behind has already populated the cache.
    if let Some(corpus) = state
        .cache
        .get_typed::<Vec<SearchRow>>(CacheKind::Lists, &corpus_key)
    {
        return corpus;
    }

    // Captured BEFORE the (possibly multi-second) index fetch below. The two
    // indexes each refuse to store a snapshot older than a mutation that landed
    // mid-flight; the corpus is derived from them and must refuse on the same
    // terms, or `invalidate_app_lists` would drop all three and this would
    // immediately re-pin a pre-mutation corpus for the full `Lists` TTL — where
    // LRU cannot reach it, so a deleted app stayed searchable for an hour.
    let watch = state.cache.generation_for(CacheKind::Lists, &corpus_key);

    // Both halves of the corpus are the shared tenant-wide indexes the App Reg /
    // Enterprise lists populate — app registrations without a paired SP appear
    // only in the application index, which is why both are needed.
    //
    // `join`, not `try_join` (and not the paired `indexes_cached` the lists
    // use): on a double-cold tenant these still fetch concurrently, but a
    // failure on ONE index must degrade only its own half of the corpus. A
    // short-circuiting join would let an unreadable `/applications` blank the
    // service-principal results too — search's contract is partial results, not
    // an error.
    let (sps, apps) = futures::future::join(
        crate::commands::applications::sp_index_cached(state, client, tenant_id),
        crate::commands::applications::app_name_index_cached(state, client, tenant_id),
    )
    .await;
    let (sps, sps_ok) = corpus_half(sps, "service_principals");
    let (apps, apps_ok) = corpus_half(apps, "applications");

    let mut rows: Vec<SearchRow> = Vec::with_capacity(sps.len() + apps.len());
    for a in apps.iter() {
        rows.push(SearchRow {
            name_lc: a.display_name.to_lowercase(),
            app_id_lc: a.app_id.to_lowercase(),
            id_lc: a.id.to_lowercase(),
            id: a.id.clone(),
            app_id: a.app_id.clone(),
            display_name: a.display_name.clone(),
            kind: SearchKind::AppReg,
        });
    }
    for sp in sps.iter() {
        let kind = if sp.service_principal_type.as_deref() == Some("ManagedIdentity") {
            SearchKind::ManagedIdentity
        } else {
            SearchKind::Enterprise
        };
        rows.push(SearchRow {
            name_lc: sp.display_name.to_lowercase(),
            app_id_lc: sp.app_id.to_lowercase(),
            id_lc: sp.id.to_lowercase(),
            id: sp.id.clone(),
            app_id: sp.app_id.clone(),
            display_name: sp.display_name.clone(),
            kind,
        });
    }
    let corpus = Arc::new(rows);
    // Pinned: rebuilding this corpus costs two full directory scans. Stored
    // only if this key was not invalidated since `watch` (see above) AND both
    // halves loaded — a partial corpus is served to this caller but never
    // cached, so the next keystroke retries the failed half instead of reading
    // a silent all-clear for the rest of the TTL.
    if sps_ok && apps_ok {
        state
            .cache
            .put_typed_index_if_current(watch, Arc::clone(&corpus));
    } else {
        tracing::warn!(
            tenant_id,
            "global search: corpus incomplete — serving it without caching"
        );
    }
    corpus
}

/// Warms the tenant's search corpus (and, transitively, the two tenant-wide
/// indexes it is built from) without running a query.
///
/// The corpus is `Lists`-TTL'd and dropped by every `invalidate_app_lists`, so
/// the first search after an idle hour — or after any app mutation — paid for
/// two full directory scans *on the keystroke path*, which is the multi-second
/// "search hung" the top bar showed. The front-end fires this when the search
/// box takes focus, so the rebuild overlaps the operator typing instead of
/// blocking the query. Best-effort by construction: a warm corpus returns
/// immediately, a cold one is built exactly once (single-flight), and an
/// unreadable index degrades to a partial corpus rather than an error — the
/// same contract `global_search` itself has.
#[tauri::command]
pub async fn prefetch_search_corpus(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    search_corpus(&state, &client, &tenant_id).await;
    Ok(())
}

#[tauri::command]
pub async fn global_search(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<GlobalSearchResults, UiError> {
    let trimmed = query.trim().to_string();
    if trimmed.is_empty() {
        return Ok(GlobalSearchResults {
            query: trimmed,
            ..Default::default()
        });
    }

    let client = state.graph_for(&tenant_id);

    if is_guid(&trimmed) {
        // GUID branch: probe ALL FOUR identities in parallel — a single GUID
        // can be an App Reg object id, an App Reg appId (shared with its
        // paired SP), or an SP object id / appId. The appId → SP probe is what
        // finds an enterprise app that has no local app registration at all
        // (gallery / third-party apps); each probe is best-effort, so a failed
        // lookup just contributes no hit.
        let (app_by_app_id, app_by_obj_id, sp_by_obj_id, sp_by_app_id) = futures::future::join4(
            client.find_application_by_app_id(&trimmed),
            client.get_application(&trimmed),
            client.get_service_principal_by_object_id(&trimmed),
            client.get_service_principal_by_app_id(&trimmed),
        )
        .await;

        let (app_registrations, enterprise_apps, managed_identities) = assemble_guid_hits(
            app_by_app_id.ok().flatten(),
            app_by_obj_id.ok(),
            sp_by_obj_id.ok().flatten(),
            sp_by_app_id.ok().flatten(),
        );

        return Ok(GlobalSearchResults {
            query: trimmed,
            looked_up_as_guid: true,
            app_registrations,
            enterprise_apps,
            managed_identities,
        });
    }

    // Substring ("contains anywhere") branch. Graph can't do this server-side,
    // so filter the tenant's pre-lowercased search corpus in memory on display
    // name / appId / object id (the latter two also give partial-GUID matching).
    // A warm corpus is a refcount clone — no per-query deserialize or lowercasing.
    let needle = trimmed.to_lowercase();
    let corpus = search_corpus(&state, &client, &tenant_id).await;

    // Rank each match (lower = better) and keep the best SEARCH_TOP per kind.
    let mut app_hits: Vec<(u8, &str, SearchHit)> = Vec::new();
    let mut ent_hits: Vec<(u8, &str, SearchHit)> = Vec::new();
    let mut mi_hits: Vec<(u8, &str, SearchHit)> = Vec::new();
    for row in corpus.iter() {
        let Some(r) = relevance(&needle, &row.name_lc, &row.app_id_lc, &row.id_lc) else {
            continue;
        };
        let hit = SearchHit {
            id: row.id.clone(),
            app_id: Some(row.app_id.clone()),
            display_name: row.display_name.clone(),
        };
        let bucket = match row.kind {
            SearchKind::AppReg => &mut app_hits,
            SearchKind::Enterprise => &mut ent_hits,
            SearchKind::ManagedIdentity => &mut mi_hits,
        };
        bucket.push((r, row.name_lc.as_str(), hit));
    }

    Ok(GlobalSearchResults {
        query: trimmed,
        looked_up_as_guid: false,
        app_registrations: finalize(&mut app_hits),
        enterprise_apps: finalize(&mut ent_hits),
        managed_identities: finalize(&mut mi_hits),
    })
}

/// Buckets the four GUID-probe results into (app registrations, enterprise
/// apps, managed identities) hits, deduping within a bucket by object id.
/// Pure and unit-tested — the original GUID branch probed only two of the four
/// identities, which made an enterprise app unfindable by its appId (the exact
/// lookup an admin pastes from the portal).
fn assemble_guid_hits(
    app_by_app_id: Option<Application>,
    app_by_obj_id: Option<Application>,
    sp_by_obj_id: Option<ServicePrincipal>,
    sp_by_app_id: Option<ServicePrincipal>,
) -> (Vec<SearchHit>, Vec<SearchHit>, Vec<SearchHit>) {
    let mut app_registrations: Vec<SearchHit> = Vec::new();
    for a in [app_by_app_id, app_by_obj_id].into_iter().flatten() {
        if app_registrations.iter().any(|h| h.id == a.id) {
            continue;
        }
        app_registrations.push(SearchHit {
            id: a.id,
            app_id: Some(a.app_id),
            display_name: a.display_name,
        });
    }

    let mut enterprise_apps: Vec<SearchHit> = Vec::new();
    let mut managed_identities: Vec<SearchHit> = Vec::new();
    for sp in [sp_by_obj_id, sp_by_app_id].into_iter().flatten() {
        if enterprise_apps
            .iter()
            .chain(managed_identities.iter())
            .any(|h| h.id == sp.id)
        {
            continue;
        }
        let hit = SearchHit {
            id: sp.id,
            app_id: Some(sp.app_id),
            display_name: sp.display_name,
        };
        if sp.service_principal_type.as_deref() == Some("ManagedIdentity") {
            managed_identities.push(hit);
        } else {
            enterprise_apps.push(hit);
        }
    }
    (app_registrations, enterprise_apps, managed_identities)
}

/// Relevance rank for a substring match (lower = better), or `None` when the
/// needle occurs in none of the fields. Tiers: exact name, name prefix, GUID
/// prefix (appId / object id), then a substring anywhere. All inputs are
/// already lowercased — `needle` by the caller, the field forms at corpus build
/// time — so this does only comparisons, no per-call allocation.
fn relevance(needle: &str, name_lc: &str, app_id_lc: &str, id_lc: &str) -> Option<u8> {
    if name_lc == needle {
        Some(0)
    } else if name_lc.starts_with(needle) {
        Some(1)
    } else if app_id_lc.starts_with(needle) || id_lc.starts_with(needle) {
        Some(2)
    } else if name_lc.contains(needle) || app_id_lc.contains(needle) || id_lc.contains(needle) {
        Some(3)
    } else {
        None
    }
}

/// Sorts ranked hits (rank, then lowercased display name) and keeps the best
/// [`SEARCH_TOP`].
fn finalize(hits: &mut [(u8, &str, SearchHit)]) -> Vec<SearchHit> {
    hits.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    hits.iter()
        .take(SEARCH_TOP as usize)
        .map(|(_, _, h)| h.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, app_id: &str, name: &str) -> Application {
        Application {
            id: id.into(),
            app_id: app_id.into(),
            display_name: name.into(),
            ..Default::default()
        }
    }

    fn sp(id: &str, app_id: &str, name: &str, sp_type: Option<&str>) -> ServicePrincipal {
        ServicePrincipal {
            id: id.into(),
            app_id: app_id.into(),
            display_name: name.into(),
            service_principal_type: sp_type.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn guid_hits_find_enterprise_app_by_app_id() {
        // The regression: an enterprise app with NO local app registration
        // (gallery / third-party) must be findable by its appId.
        let (apps, ents, mis) = assemble_guid_hits(
            None,
            None,
            None,
            Some(sp("sp-1", "guid-1", "Salesforce", Some("Application"))),
        );
        assert!(apps.is_empty());
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].id, "sp-1");
        assert!(mis.is_empty());
    }

    #[test]
    fn guid_hits_pair_app_reg_and_enterprise_app_for_one_app_id() {
        // A tenant-owned app's appId identifies both halves of the pairing.
        let (apps, ents, _) = assemble_guid_hits(
            Some(app("obj-1", "guid-1", "Contoso API")),
            None,
            None,
            Some(sp("sp-1", "guid-1", "Contoso API", Some("Application"))),
        );
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, "obj-1");
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].id, "sp-1");
    }

    #[test]
    fn guid_hits_find_app_reg_by_object_id_and_mi_by_type() {
        let (apps, ents, mis) = assemble_guid_hits(
            None,
            Some(app("obj-2", "app-2", "By Object Id")),
            Some(sp("sp-2", "app-3", "Build MI", Some("ManagedIdentity"))),
            None,
        );
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, "obj-2");
        assert!(ents.is_empty());
        assert_eq!(mis.len(), 1);
        assert_eq!(mis[0].id, "sp-2");
    }

    #[test]
    fn guid_hits_dedupe_within_buckets() {
        // The same object returned by two probes appears once.
        let (apps, ents, _) = assemble_guid_hits(
            Some(app("obj-1", "guid-1", "Contoso API")),
            Some(app("obj-1", "guid-1", "Contoso API")),
            Some(sp("sp-1", "guid-1", "Contoso API", Some("Application"))),
            Some(sp("sp-1", "guid-1", "Contoso API", Some("Application"))),
        );
        assert_eq!(apps.len(), 1);
        assert_eq!(ents.len(), 1);
    }

    #[test]
    fn relevance_matches_substring_anywhere_and_ranks() {
        // All fields are pre-lowercased (the corpus build lowercases them; the
        // caller lowercases the needle), so these are passed lowercased.
        let aid = "1234abcd-0000-0000-0000-000000000000";
        let oid = "99887766-0000-0000-0000-000000000000";
        // Mid-word substring (the win over startswith/$search): "duction" is
        // inside "production" but is neither a prefix nor a whole token.
        assert_eq!(relevance("duction", "production app", aid, oid), Some(3));
        // Tiering: exact < name-prefix < guid-prefix < substring.
        assert_eq!(
            relevance("production app", "production app", aid, oid),
            Some(0)
        );
        assert_eq!(relevance("prod", "production app", aid, oid), Some(1));
        assert_eq!(relevance("1234ab", "production app", aid, oid), Some(2)); // appId prefix
        assert_eq!(relevance("7766", "production app", aid, oid), Some(3)); // object-id substring
        assert_eq!(relevance("zzz", "production app", aid, oid), None);
    }
}
