//! Azure RBAC role-definition name resolution, shared by the managed-identity
//! Azure-roles view (`managed_identity`) and the Key Vault access sweep
//! (`keyvault_rbac`).
//!
//! ARM role assignments carry only a role-definition **id**. A built-in role
//! (`Owner`, `Key Vault Secrets Officer`, …) comes back under a different
//! subscription-prefixed path for every subscription, but it is one GUID — so
//! the fetch and the cache are keyed by the GUID, and each GUID is fetched once
//! per sweep through the first absolute path seen for it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use futures::stream::{self, StreamExt};

use azapptoolkit_arm::ArmClient;
use azapptoolkit_core::azure_roles::role_id_tail;
use azapptoolkit_core::cache::{Cache, CacheKind};

/// Maps each role GUID (lowercased, [`role_id_tail`]) to the path to fetch it
/// through. Empty ids and ids without a tail are dropped.
///
/// The ids are sorted first and the first path per GUID wins, so the fetch is
/// deterministic although both callers build their id sets in arbitrary order.
/// The path is always an id exactly as ARM returned it, never rewritten to the
/// tenant-level `/providers/Microsoft.Authorization/roleDefinitions/{guid}`:
/// that form resolves built-in roles only, and a custom role (defined at a
/// subscription or management-group scope) 404s there.
fn fetch_plan<'a>(ids: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, &'a str> {
    let sorted: BTreeSet<&'a str> = ids.into_iter().filter(|id| !id.is_empty()).collect();
    let mut plan = BTreeMap::new();
    for id in sorted {
        if let Some(guid) = role_id_tail(id) {
            plan.entry(guid).or_insert(id);
        }
    }
    plan
}

/// Tenant-prefixed cache key for one role GUID's resolved name.
fn role_name_cache_key(tenant_id: &str, guid: &str) -> String {
    format!("{tenant_id}|arm_roledef|{guid}")
}

/// Resolves role-definition ids to role names, keyed by lowercased role GUID
/// (look a row up with [`role_display_name`]). At most `concurrency` ARM reads
/// run at once; a GUID whose lookup fails is absent from the map.
///
/// Role definitions (Owner, Contributor, custom roles) are tenant-stable, so a
/// resolved name is cached — otherwise every Azure-roles view and vault sweep
/// re-fetches the same handful (and ARM throttles aggressively). Only a real
/// name is cached; a fetch failure falls back to the GUID tail without
/// poisoning the cache. Read-only until TTL / sign-out by design: a
/// role-definition rename is rare, so no mutation busts this — it is cleared by
/// the 60-min `Permissions` TTL and the sign-out tenant sweep.
///
/// Reads the cache on the caller's behalf, so a command calling it must prove
/// the session first (`repo_invariants/cache.rs` counts it as a cache read).
pub(crate) async fn resolve_role_names_cached<'a>(
    arm: &Arc<ArmClient>,
    cache: &Arc<Cache>,
    tenant_id: &str,
    ids: impl IntoIterator<Item = &'a str>,
    concurrency: usize,
) -> HashMap<String, String> {
    // Owned per-item futures (cloned `Arc`s, owned key and path): a future that
    // borrowed from this frame would not be `Send` for every lifetime, which the
    // `#[tauri::command]` wrappers of both callers require.
    let plan: Vec<(String, String)> = fetch_plan(ids)
        .into_iter()
        .map(|(guid, path)| (guid, path.to_string()))
        .collect();
    let resolved: Vec<Option<(String, String)>> = stream::iter(plan)
        .map(|(guid, path)| {
            let arm = Arc::clone(arm);
            let cache = Arc::clone(cache);
            let key = role_name_cache_key(tenant_id, &guid);
            async move {
                if let Some(name) = cache.get::<String>(CacheKind::Permissions, &key) {
                    return Some((guid, name));
                }
                let name = arm
                    .get_role_definition(&path)
                    .await
                    .ok()
                    .and_then(|d| d.properties.role_name)?;
                cache.put(CacheKind::Permissions, key, &name);
                Some((guid, name))
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    resolved.into_iter().flatten().collect()
}

/// The label for one assignment's role: its resolved name, else the id's
/// trailing segment (the GUID), or `(unknown role)` for an empty id.
pub(crate) fn role_display_name(names: &HashMap<String, String>, role_def_id: &str) -> String {
    if role_def_id.is_empty() {
        return "(unknown role)".to_string();
    }
    role_id_tail(role_def_id)
        .and_then(|guid| names.get(&guid).cloned())
        .unwrap_or_else(|| role_def_id.rsplit('/').next().unwrap_or("role").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";

    async fn requests(server: &MockServer) -> usize {
        server.received_requests().await.unwrap_or_default().len()
    }

    fn roledef(scope: &str, guid: &str) -> String {
        format!("{scope}/providers/Microsoft.Authorization/roleDefinitions/{guid}")
    }

    #[test]
    fn fetch_plan_collapses_one_builtin_across_subscriptions() {
        let a = roledef("/subscriptions/a", OWNER);
        let b = roledef("/subscriptions/b", &OWNER.to_uppercase());
        let plan = fetch_plan([b.as_str(), a.as_str()]);
        assert_eq!(plan.len(), 1, "{plan:?}");
        let path = plan[OWNER];
        // A path ARM returned, deterministically chosen — never tenant-level.
        assert!(path.starts_with("/subscriptions/"), "{path}");
        assert_eq!(path, fetch_plan([a.as_str(), b.as_str()])[OWNER]);
    }

    #[test]
    fn fetch_plan_keeps_a_custom_role_on_its_own_scope_path() {
        let custom = roledef("/subscriptions/c", "custom-guid");
        let plan = fetch_plan(["", custom.as_str()]);
        assert_eq!(plan.len(), 1, "the empty id is dropped: {plan:?}");
        assert_eq!(plan["custom-guid"], custom.as_str());
    }

    #[tokio::test]
    async fn resolves_each_role_guid_once_and_serves_repeats_from_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/subscriptions/a/providers/Microsoft.Authorization/roleDefinitions/g1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "properties": {"roleName": "Owner"}
            })))
            .mount(&server)
            .await;
        let arm = Arc::new(ArmClient::with_base_url(
            StaticTokenProvider::new("tok"),
            server.uri(),
        ));
        let cache = Cache::new();
        let in_a = roledef("/subscriptions/a", "g1");
        let in_b = roledef("/subscriptions/b", "G1");
        let ids = [in_a.as_str(), in_b.as_str()];

        let names = resolve_role_names_cached(&arm, &cache, "t1", ids, 4).await;
        assert_eq!(role_display_name(&names, &in_a), "Owner");
        assert_eq!(role_display_name(&names, &in_b), "Owner");
        assert_eq!(requests(&server).await, 1, "one GUID, one fetch");

        let names = resolve_role_names_cached(&arm, &cache, "t1", ids, 4).await;
        assert_eq!(role_display_name(&names, &in_b), "Owner");
        assert_eq!(requests(&server).await, 1, "a repeat is a cache hit");

        // The cache is tenant-scoped: another tenant fetches its own.
        let names = resolve_role_names_cached(&arm, &cache, "t2", ids, 4).await;
        assert_eq!(role_display_name(&names, &in_a), "Owner");
        assert_eq!(requests(&server).await, 2);
    }

    #[tokio::test]
    async fn a_failed_lookup_falls_back_to_the_guid_and_is_not_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let arm = Arc::new(ArmClient::with_base_url(
            StaticTokenProvider::new("tok"),
            server.uri(),
        ));
        let cache = Cache::new();
        let id = roledef("/subscriptions/a", "g2");

        let names = resolve_role_names_cached(&arm, &cache, "t1", [id.as_str()], 4).await;
        assert!(names.is_empty(), "{names:?}");
        assert_eq!(role_display_name(&names, &id), "g2");
        assert_eq!(
            cache.get::<String>(CacheKind::Permissions, "t1|arm_roledef|g2"),
            None
        );
    }

    #[test]
    fn role_display_name_marks_an_empty_id_unknown() {
        assert_eq!(role_display_name(&HashMap::new(), ""), "(unknown role)");
    }
}
