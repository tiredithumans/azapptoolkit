use super::super::*;
use super::common::*;

#[tokio::test]
async fn service_principal_lookup_caches_by_app_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "sp-1",
                "appId": "app-1",
                "displayName": "Demo App"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let sp1 = client
        .get_service_principal_by_app_id("app-1")
        .await
        .unwrap();
    assert_eq!(sp1.unwrap().id, "sp-1");
    // Second call must be served from cache (wiremock `.expect(1)` asserts).
    let sp2 = client
        .get_service_principal_by_app_id("app-1")
        .await
        .unwrap();
    assert_eq!(sp2.unwrap().id, "sp-1");
}

#[tokio::test]
async fn list_managed_identities_filters_by_sp_type() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$filter",
            "servicePrincipalType eq 'ManagedIdentity'",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "msi-sp-1",
                "appId": "msi-app-1",
                "displayName": "my-vm-identity",
                "accountEnabled": true,
                "servicePrincipalType": "ManagedIdentity"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let identities = client.list_managed_identities().await.unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].id, "msi-sp-1");
    assert_eq!(identities[0].display_name, "my-vm-identity");
}

#[tokio::test]
async fn list_tenant_app_role_resources_filters_by_owner_and_selects_app_roles() {
    // The picker's tenant-app source: owner-scoped to this tenant, projecting
    // appRoles, as an advanced query ($count + ConsistencyLevel: eventual). The
    // client returns the raw SPs (with appRoles); the command layer does the
    // app-role filtering.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        // `appOwnerOrganizationId` is an Edm.Guid → unquoted filter literal
        // (`eq <guid>`, not `eq '<guid>'`). A quoted value is a 400 against real
        // Graph; this asserts the Graph-correct, unquoted contract.
        .and(query_param(
            "$filter",
            "appOwnerOrganizationId eq tenant-test",
        ))
        .and(query_param("$select", "id,appId,displayName,appRoles"))
        .and(query_param("$count", "true"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "sp-orders",
                "appId": "app-orders",
                "displayName": "Contoso Orders API",
                "appRoles": [{
                    "id": "role-1",
                    "value": "Orders.Read.All",
                    "displayName": "Read orders",
                    "allowedMemberTypes": ["Application"],
                    "isEnabled": true
                }]
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let resources = client.list_tenant_app_role_resources().await.unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].app_id, "app-orders");
    assert_eq!(resources[0].app_roles.len(), 1);
    assert_eq!(resources[0].app_roles[0].value, "Orders.Read.All");
}

#[tokio::test]
async fn lean_sp_lookup_projects_lean_fields_and_caches() {
    // The audit's lean lookup must send $select=id,appId,accountEnabled (the
    // mock only matches that projection) and serve the second call from cache.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$select", "id,appId,accountEnabled"))
        .and(query_param("$top", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-lean", "appId": "app-1", "accountEnabled": true }]
        })))
        .expect(1) // second call is a cache hit, not a request
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let first = client
        .get_service_principal_by_app_id_lean("app-1")
        .await
        .unwrap();
    assert_eq!(first.as_ref().unwrap().id, "sp-lean");
    assert_eq!(first.unwrap().account_enabled, Some(true));
    let second = client
        .get_service_principal_by_app_id_lean("app-1")
        .await
        .unwrap();
    assert_eq!(second.unwrap().id, "sp-lean");
}

#[tokio::test]
async fn lean_and_full_sp_lookups_do_not_share_a_cache() {
    // The lean object must never satisfy the detail pane's full lookup (or
    // vice versa): they cache under distinct keys. One mock matches both
    // requests; `expect(2)` proves the second lookup re-fetched rather than
    // reading the other's cache entry.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$top", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-1", "appId": "app-1", "accountEnabled": true }]
        })))
        .expect(2)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    assert!(
        client
            .get_service_principal_by_app_id_lean("app-1")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .get_service_principal_by_app_id("app-1")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn seed_lean_sps_from_index_makes_the_lean_lookup_a_cache_hit() {
    // Seeding the lean cache from an already-fetched SP index must satisfy the
    // audit's lean lookup with NO Graph request — the whole point of reusing the
    // index scan instead of a second batched prewarm. The mock is mounted but
    // `.expect(1)` proves ONLY the app_id absent from the index reaches the
    // network; the seeded app_id is served from cache.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$select", "id,appId,accountEnabled"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-uncached", "appId": "app-missing", "accountEnabled": false }]
        })))
        .expect(1) // only the unmatched app_id resolves against the server
        .mount(&server)
        .await;
    let client = make_client(&server.uri());

    let sp_index: Vec<azapptoolkit_core::models::ServicePrincipal> =
        serde_json::from_value(serde_json::json!([
            { "id": "sp-seeded", "appId": "app-1", "accountEnabled": true }
        ]))
        .expect("sample SP index deserializes");
    client.seed_lean_sps_from_index(&["app-1".to_string(), "app-missing".to_string()], &sp_index);

    // Matched app_id: served from the seeded cache, zero requests.
    let hit = client
        .get_service_principal_by_app_id_lean("app-1")
        .await
        .unwrap();
    assert_eq!(hit.as_ref().unwrap().id, "sp-seeded");
    assert_eq!(hit.unwrap().account_enabled, Some(true));

    // Unmatched app_id: left cold on purpose, so it resolves against the server
    // (the single request `.expect(1)` accounts for).
    let miss = client
        .get_service_principal_by_app_id_lean("app-missing")
        .await
        .unwrap();
    assert_eq!(miss.unwrap().id, "sp-uncached");
}

#[tokio::test]
async fn seed_lean_sps_from_index_never_evicts_its_own_entries() {
    // Regression guard. Seeding one entry per app registration into a bucket
    // smaller than the pass would push every insert past the cap, evicting an
    // entry this same pass had just written — so the earliest-seeded apps would
    // fall back to an individual Graph GET, which is exactly the N+1 this
    // function exists to remove. The pass must be bounded by the bucket size.
    let server = MockServer::start().await;
    // Any request at all means a seeded entry was evicted and fell through.
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": []
        })))
        .expect(0)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());

    let cap = client
        .cache
        .capacity_for(azapptoolkit_core::cache::CacheKind::ServicePrincipal);
    let overflow = cap + 50;
    let sp_index: Vec<azapptoolkit_core::models::ServicePrincipal> = (0..overflow)
        .map(|i| {
            serde_json::from_value(serde_json::json!({
                "id": format!("sp-{i}"),
                "appId": format!("app-{i}"),
                "accountEnabled": true
            }))
            .expect("sample SP deserializes")
        })
        .collect();
    let app_ids: Vec<String> = (0..overflow).map(|i| format!("app-{i}")).collect();
    client.seed_lean_sps_from_index(&app_ids, &sp_index);

    // The FIRST app seeded must still be a cache hit: an uncapped pass would
    // have evicted it while writing the tail.
    let first = client
        .get_service_principal_by_app_id_lean("app-0")
        .await
        .unwrap();
    assert_eq!(
        first.as_ref().map(|sp| sp.id.as_str()),
        Some("sp-0"),
        "the earliest-seeded entry must survive the rest of the pass"
    );
}

#[tokio::test]
async fn list_service_principals_index_selects_superset_and_returns_all_sps() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$select",
            "id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,createdDateTime,alternativeNames",
        ))
        .and(query_param("$count", "true"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {
                    "id": "sp-1",
                    "appId": "app-1",
                    "displayName": "billing-api",
                    "servicePrincipalType": "Application",
                    "appOwnerOrganizationId": "tenant-github"
                },
                {
                    "id": "msi-1",
                    "appId": "msi-app-1",
                    "displayName": "my-vm-identity",
                    "servicePrincipalType": "ManagedIdentity",
                    "alternativeNames": [
                        "isExplicit=False",
                        "/subscriptions/s1/resourcegroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
                    ]
                }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    // The shared index is unfiltered: it includes managed identities, which
    // the Enterprise Applications list filters out client-side.
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(sps.len(), 2);
    // `alternativeNames` rides this projection so the managed-identity list can
    // derive its system-vs-user subtype from THIS index instead of running a
    // second `/servicePrincipals` scan of its own.
    assert_eq!(
        sps[1].alternative_names,
        vec![
            "isExplicit=False".to_string(),
            "/subscriptions/s1/resourcegroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
                .to_string()
        ]
    );
    assert_eq!(sps[0].app_id, "app-1");
    assert_eq!(
        sps[0].app_owner_organization_id.as_deref(),
        Some("tenant-github")
    );
    assert_eq!(
        sps[1].service_principal_type.as_deref(),
        Some("ManagedIdentity")
    );
}

#[tokio::test]
async fn resolve_resource_sp_caches_in_permissions_bucket() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "appId eq 'graph-id'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "sp-graph",
                "appId": "graph-id",
                "displayName": "Microsoft Graph",
                "appRoles": [{
                    "id": "role-1",
                    "allowedMemberTypes": ["Application"],
                    "displayName": "Read all users",
                    "value": "User.Read.All"
                }],
                "oauth2PermissionScopes": [{
                    "id": "scope-1",
                    "value": "email"
                }]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let first = client
        .resolve_resource_sp("graph-id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.app_roles.len(), 1);
    assert_eq!(first.oauth2_permission_scopes.len(), 1);
    // Second call served from cache.
    let _ = client.resolve_resource_sp("graph-id").await.unwrap();
}

#[tokio::test]
async fn prewarm_resource_sps_seeds_permissions_cache() {
    let server = MockServer::start().await;
    // Only the `$batch` POST is mocked — no GET /servicePrincipals mock exists,
    // so a resolve that misses the seeded cache would fail the test.
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                { "id": "0", "status": 200, "body": { "value": [{
                    "id": "sp-graph",
                    "appId": "graph-id",
                    "displayName": "Microsoft Graph",
                    "appRoles": [{
                        "id": "role-1",
                        "allowedMemberTypes": ["Application"],
                        "displayName": "Read all users",
                        "value": "User.Read.All"
                    }],
                    "oauth2PermissionScopes": []
                }] } },
                { "id": "1", "status": 200, "body": { "value": [] } }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let ids = vec!["graph-id".to_string(), "unknown-id".to_string()];
    client.prewarm_resource_sps(&ids).await;

    let graph_sp = client
        .resolve_resource_sp("graph-id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(graph_sp.id, "sp-graph");
    assert_eq!(graph_sp.app_roles.len(), 1);
    // An empty page seeds `None`, exactly like the single lookup caches it.
    assert!(
        client
            .resolve_resource_sp("unknown-id")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn prewarm_resource_sps_failure_degrades_to_per_resource_get() {
    let server = MockServer::start().await;
    // Whole-batch failure (400: not retried by the outer loop) is swallowed…
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": { "message": "bad batch" }
        })))
        .mount(&server)
        .await;
    // …and the per-resource GET still resolves.
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "appId eq 'graph-id'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-graph", "appId": "graph-id", "displayName": "Microsoft Graph" }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    client.prewarm_resource_sps(&["graph-id".to_string()]).await;
    let sp = client
        .resolve_resource_sp("graph-id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sp.id, "sp-graph");
}

#[tokio::test]
async fn sp_cache_is_tenant_scoped() {
    // Two clients for different tenants share one `Cache` (as `AppState`
    // does). A service principal's object `id` is tenant-specific, so a
    // cached entry for tenant A must NOT satisfy tenant B's lookup of the
    // same appId — otherwise runtime grants mis-join across tenants. Each
    // mock is `.expect(1)`, so a cache bleed (B reusing A's entry) fails the
    // test by leaving server B uncalled, and the id assertion fails too.
    // `Cache::new()` already returns an `Arc<Cache>`; clone it to share one
    // cache between the two per-tenant clients.
    let cache = Cache::new();

    let server_a = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "appId eq 'shared-app'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-in-tenant-a", "appId": "shared-app", "displayName": "Shared" }]
        })))
        .expect(1)
        .mount(&server_a)
        .await;

    let server_b = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "appId eq 'shared-app'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-in-tenant-b", "appId": "shared-app", "displayName": "Shared" }]
        })))
        .expect(1)
        .mount(&server_b)
        .await;

    let token = StaticTokenProvider::new("tok");
    let client_a = GraphClient::with_base_url(
        "tenant-a",
        token.clone(),
        token.clone(),
        cache.clone(),
        server_a.uri(),
    );
    let client_b = GraphClient::with_base_url(
        "tenant-b",
        token.clone(),
        token,
        cache.clone(),
        server_b.uri(),
    );

    let a = client_a
        .get_service_principal_by_app_id("shared-app")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.id, "sp-in-tenant-a");

    let b = client_b
        .get_service_principal_by_app_id("shared-app")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.id, "sp-in-tenant-b");
}

#[tokio::test]
async fn delete_service_principal_returns_ok_on_204() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/servicePrincipals/sp-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.delete_service_principal("sp-1").await.unwrap();
}

#[tokio::test]
async fn ensure_service_principal_skips_post_when_present() {
    let server = MockServer::start().await;
    // Lookup returns existing SP.
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "sp-1",
                "appId": "app-1",
                "displayName": "Existing"
            }]
        })))
        .mount(&server)
        .await;
    // POST mock is intentionally NOT registered; if we fall through to it
    // wiremock returns 404 and the test fails.
    let client = make_client(&server.uri());
    let (sp, created) = client.ensure_service_principal("app-1").await.unwrap();
    assert_eq!(sp.id, "sp-1");
    assert!(!created, "an existing SP must not report as newly created");
}

#[tokio::test]
async fn ensure_service_principal_creates_when_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/servicePrincipals"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "appId": "app-1" }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "sp-new",
            "appId": "app-1",
            "displayName": "Just created"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let (sp, created) = client.ensure_service_principal("app-1").await.unwrap();
    assert_eq!(sp.id, "sp-new");
    assert!(created, "a POSTed SP must report as newly created");
}

#[tokio::test]
async fn patch_service_principal_busts_the_sp_cache() {
    let server = MockServer::start().await;
    // The appId lookup is expected TWICE: once to prime the cache, once after
    // the patch busts it. A cache that survived the mutation would serve the
    // second read from cache and the GET would fire only once (failing
    // `.expect(2)` on drop) — that was the stale-SP bug this guards against.
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-1", "appId": "app-1", "displayName": "Demo App" }]
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/servicePrincipals/sp-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    // Prime the per-app SP cache.
    client
        .get_service_principal_by_app_id("app-1")
        .await
        .unwrap();
    // A patch (by SP object id) must sweep this tenant's SP cache — it's keyed
    // by appId, so the whole `{tenant}|` prefix falls.
    client
        .patch_service_principal("sp-1", &serde_json::json!({ "accountEnabled": false }))
        .await
        .unwrap();
    // The next lookup therefore re-fetches rather than returning the stale entry.
    client
        .get_service_principal_by_app_id("app-1")
        .await
        .unwrap();
}

#[tokio::test]
async fn patch_service_principal_sends_sso_mode() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/servicePrincipals/sp-1"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "preferredSingleSignOnMode": "saml" }),
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .patch_service_principal(
            "sp-1",
            &serde_json::json!({ "preferredSingleSignOnMode": "saml" }),
        )
        .await
        .unwrap();
}

/// Deleting a service principal must drop the tenant-wide **grant matrices**
/// too, not just the SP objects.
///
/// The two live under different `CacheKind`s, and no command compensated:
/// `invalidate_app_lists` touches `Lists` and the audit cache, never the
/// `grants:` prefix. So an operator deleted an over-privileged enterprise
/// application and the Security tab kept reporting its application permissions
/// as live — the worst direction for a least-privilege view to be wrong in.
#[tokio::test]
async fn deleting_a_service_principal_drops_the_grant_matrices() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/servicePrincipals/sp-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());

    // Seed both families the way the read-throughs do.
    client.cache.put(
        CacheKind::Permissions,
        "tenant-test|grants:oauth2_all".to_string(),
        &serde_json::json!([{ "clientId": "sp-1" }]),
    );
    client.cache.put(
        CacheKind::Permissions,
        "tenant-test|grants:assigned_to:sp-1".to_string(),
        &serde_json::json!([{ "appRoleId": "r" }]),
    );

    client.delete_service_principal("sp-1").await.unwrap();

    for key in [
        "tenant-test|grants:oauth2_all",
        "tenant-test|grants:assigned_to:sp-1",
    ] {
        assert!(
            client
                .cache
                .get::<serde_json::Value>(CacheKind::Permissions, key)
                .is_none(),
            "{key} still reports the deleted principal's access"
        );
    }
}

/// Publishing a new app role must drop the cached resource-SP definitions the
/// permission picker reads.
///
/// None of the three mutators reached that bucket, so an operator published a
/// role on their own API — which `list_tenant_app_role_resources` exists to
/// make grantable — opened the Grant-access wizard, and the role was not there.
#[tokio::test]
async fn publishing_app_roles_drops_the_cached_resource_definitions() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/servicePrincipals/sp-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());

    // What `resolve_resource_sp` caches, under its own `resource:` segment.
    client.cache.put(
        CacheKind::Permissions,
        "tenant-test|resource:api-app-id".to_string(),
        &serde_json::json!({ "appRoles": [] }),
    );
    // A grant matrix in the same bucket, which this mutation does NOT change.
    client.cache.put(
        CacheKind::Permissions,
        "tenant-test|grants:oauth2_all".to_string(),
        &serde_json::json!([]),
    );

    client
        .set_service_principal_app_roles("sp-1", &[serde_json::json!({ "value": "Orders.Read" })])
        .await
        .unwrap();

    assert!(
        client
            .cache
            .get::<serde_json::Value>(CacheKind::Permissions, "tenant-test|resource:api-app-id")
            .is_none(),
        "the stale role list would leave the new role out of the picker"
    );
    // The `resource:` segment is what makes this sweep precise — the grant
    // matrices are a different family in the same bucket and must survive.
    assert!(
        client
            .cache
            .get::<serde_json::Value>(CacheKind::Permissions, "tenant-test|grants:oauth2_all")
            .is_some(),
        "an unrelated family was swept; the key segmenting is not working"
    );
}
