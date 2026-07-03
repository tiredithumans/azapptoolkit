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
async fn list_service_principals_index_selects_superset_and_returns_all_sps() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$select",
            "id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,createdDateTime",
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
                    "servicePrincipalType": "ManagedIdentity"
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
