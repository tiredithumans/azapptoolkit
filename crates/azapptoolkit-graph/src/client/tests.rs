use super::*;
use azapptoolkit_core::cache::Cache;
use azapptoolkit_core::token::StaticTokenProvider;
use wiremock::matchers::{
    body_string_contains, header, method, path, query_param, query_param_is_missing,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_org_json() -> serde_json::Value {
    serde_json::json!({
        "value": [{
            "id": "tenant-1",
            "displayName": "Contoso",
            "verifiedDomains": [{"name": "contoso.onmicrosoft.com", "isDefault": true}]
        }]
    })
}

fn sample_apps_json() -> serde_json::Value {
    serde_json::json!({
        "@odata.count": 1,
        "value": [{
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo App",
            "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [],
            "keyCredentials": [],
            "requiredResourceAccess": []
        }]
    })
}

fn make_client(base: &str) -> GraphClient {
    let token = StaticTokenProvider::new("tok");
    GraphClient::with_base_url(
        "tenant-test",
        token.clone(),
        token,
        Cache::new(),
        base.to_string(),
    )
}

#[tokio::test]
async fn get_organization_returns_first_item() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organization"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_org_json()))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let org = client.get_organization().await.unwrap();
    assert_eq!(org.id, "tenant-1");
    assert_eq!(org.display_name, "Contoso");
}

#[tokio::test]
async fn me_active_directory_roles_extracts_display_names() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/transitiveMemberOf/microsoft.graph.directoryRole"))
        // `id` must stay in the $select: Graph returns only the selected
        // properties and DirectoryObject requires `id` to deserialize.
        .and(query_param("$select", "id,displayName"))
        // The OData cast is an advanced query: Graph 400s without both the
        // header and $count=true, so the mock pins them.
        .and(query_param("$count", "true"))
        .and(header("consistencylevel", "eventual"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {"id": "r1", "displayName": "Cloud Application Administrator"},
                {"id": "r2", "displayName": "Reports Reader"}
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let roles = client.me_active_directory_roles().await.unwrap();
    assert_eq!(
        roles,
        vec!["Cloud Application Administrator", "Reports Reader"]
    );
}

#[tokio::test]
async fn list_applications_uses_default_select_and_top() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$top", "50"))
        .and(query_param("$count", "true"))
        .and(query_param("$orderby", "displayName"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_apps_json()))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let page = client
        .list_applications(AppListQuery::default())
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].app_id, "app-1");
    assert_eq!(page.total_count, Some(1));
}

#[tokio::test]
async fn list_applications_with_expand_omits_orderby() {
    // Graph rejects `$orderby` + `$expand` on `/applications`, so an
    // expanding call (e.g. the security audit) must drop `$orderby`.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$expand", "owners($select=id)"))
        .and(query_param_is_missing("$orderby"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_apps_json()))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let page = client
        .list_applications(AppListQuery::default().with_expand("owners($select=id)"))
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
}

#[tokio::test]
async fn search_adds_consistency_level_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_apps_json()))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let _ = client
        .list_applications(AppListQuery::default().with_search("demo"))
        .await
        .unwrap();
}

#[tokio::test]
async fn retry_after_is_honored_on_429() {
    let server = MockServer::start().await;
    // First call returns 429, second returns 200.
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("throttled"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_org_json()))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let org = client.get_organization().await.unwrap();
    assert_eq!(org.id, "tenant-1");
}

#[tokio::test]
async fn unauthorized_returns_typed_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let err = client.get_organization().await.unwrap_err();
    assert!(matches!(err, GraphError::Unauthorized));
    assert_eq!(err.ui_code(), "unauthorized");
}

#[tokio::test]
async fn not_found_returns_typed_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let err = client.get_organization().await.unwrap_err();
    assert!(matches!(err, GraphError::NotFound(_)));
}

#[tokio::test]
async fn get_application_returns_single() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo App"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let app = client.get_application("obj-1").await.unwrap();
    assert_eq!(app.id, "obj-1");
    assert_eq!(app.app_id, "app-1");
}

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
async fn list_application_index_returns_appid_object_id_pairs_without_orderby() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$select", "id,appId"))
        .and(query_param_is_missing("$orderby"))
        .and(query_param_is_missing("$count"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {"id": "obj-a", "appId": "app-a", "displayName": "A"},
                {"id": "obj-b", "appId": "app-b", "displayName": "B"}
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let pairs = client.list_application_index(Some(5000)).await.unwrap();
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0], ("app-a".to_string(), "obj-a".to_string()));
}

#[tokio::test]
async fn list_owners_returns_value_array() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1/owners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@example.com"},
                {"id": "u2", "displayName": "Bob"}
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let owners = client.list_owners("obj-1").await.unwrap();
    assert_eq!(owners.len(), 2);
    assert_eq!(owners[0].display_name.as_deref(), Some("Alice"));
}

#[tokio::test]
async fn list_owners_follows_next_link() {
    let server = MockServer::start().await;
    let base = server.uri();
    let page2_link = format!("{base}/applications/obj-1/owners?page=2");

    Mock::given(method("GET"))
        .and(path("/applications/obj-1/owners"))
        .and(query_param_is_missing("page"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": page2_link,
            "value": [{"id": "u1", "displayName": "Alice"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1/owners"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "u2", "displayName": "Bob"}, {"id": "u3", "displayName": "Cara"}]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let owners = client.list_owners("obj-1").await.unwrap();
    assert_eq!(owners.len(), 3);
    assert_eq!(owners[2].display_name.as_deref(), Some("Cara"));
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
async fn list_oauth2_grants_filters_by_client_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2PermissionGrants"))
        .and(query_param("$filter", "clientId eq 'sp-1'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "grant-1",
                "clientId": "sp-1",
                "resourceId": "sp-graph",
                "consentType": "AllPrincipals",
                "scope": "email User.Read"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let grants = client.list_oauth2_grants("sp-1").await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].scope, "email User.Read");
}

// --------- M3 mutation tests ---------

#[tokio::test]
async fn create_application_posts_body_and_returns_app() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "displayName": "my-new-app",
            "signInAudience": "AzureADMyOrg"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "obj-99",
            "appId": "app-99",
            "displayName": "my-new-app",
            "signInAudience": "AzureADMyOrg"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let req = CreateApplicationRequest {
        display_name: "my-new-app".into(),
        sign_in_audience: Some("AzureADMyOrg".into()),
        description: None,
    };
    let app = client.create_application(&req).await.unwrap();
    assert_eq!(app.id, "obj-99");
    assert_eq!(app.display_name, "my-new-app");
}

#[tokio::test]
async fn update_application_patches_only_set_fields() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "displayName": "renamed" }),
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let patch = AppPatch {
        display_name: Some("renamed".into()),
        ..Default::default()
    };
    client.update_application("obj-1", &patch).await.unwrap();
}

#[tokio::test]
async fn delete_application_returns_ok_on_204() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.delete_application("obj-1").await.unwrap();
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
async fn add_password_posts_expected_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/addPassword"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keyId": "kid-1",
            "displayName": "CI secret",
            "hint": "abc",
            "secretText": "super-secret-value",
            "startDateTime": "2026-01-01T00:00:00Z",
            "endDateTime": "2026-07-01T00:00:00Z"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let cred = client
        .add_password("obj-1", "CI secret", Duration::from_secs(60 * 60 * 24 * 30))
        .await
        .unwrap();
    assert_eq!(cred.key_id, "kid-1");
    assert_eq!(cred.secret_text.as_deref(), Some("super-secret-value"));
}

#[tokio::test]
async fn add_password_window_sends_start_only_when_given() {
    let server = MockServer::start().await;
    let start = chrono::DateTime::parse_from_rfc3339("2026-07-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let end = chrono::DateTime::parse_from_rfc3339("2027-07-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let created = serde_json::json!({
        "keyId": "kid-2",
        "displayName": "scheduled secret",
        "endDateTime": "2027-07-01T00:00:00Z"
    });
    // Exact body match: with a start date the key must be present…
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/addPassword"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "passwordCredential": {
                "displayName": "scheduled secret",
                "startDateTime": "2026-07-01T00:00:00+00:00",
                "endDateTime": "2027-07-01T00:00:00+00:00",
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(created.clone()))
        .expect(1)
        .mount(&server)
        .await;
    // …and without one the key must be absent entirely (Graph defaults to now).
    Mock::given(method("POST"))
        .and(path("/applications/obj-2/addPassword"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "passwordCredential": {
                "displayName": "scheduled secret",
                "endDateTime": "2027-07-01T00:00:00+00:00",
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(created))
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let cred = client
        .add_password_window("obj-1", "scheduled secret", Some(start), end)
        .await
        .unwrap();
    assert_eq!(cred.key_id, "kid-2");
    client
        .add_password_window("obj-2", "scheduled secret", None, end)
        .await
        .unwrap();
}

#[tokio::test]
async fn remove_password_posts_key_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/removePassword"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "keyId": "kid-1" }),
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.remove_password("obj-1", "kid-1").await.unwrap();
}

#[tokio::test]
async fn add_owner_posts_full_odata_id() {
    let server = MockServer::start().await;
    let base = server.uri();
    let expected_odata_id = format!("{}/directoryObjects/u-1", base.trim_end_matches('/'));
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/owners/$ref"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "@odata.id": expected_odata_id,
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.add_owner("obj-1", "u-1").await.unwrap();
}

#[tokio::test]
async fn remove_owner_uses_nested_ref_path() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/applications/obj-1/owners/u-1/$ref"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.remove_owner("obj-1", "u-1").await.unwrap();
}

#[tokio::test]
async fn search_users_applies_startswith_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users"))
        .and(query_param(
            "$filter",
            "startswith(userPrincipalName,'ali') or startswith(displayName,'ali')",
        ))
        .and(query_param("$top", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "u-1",
                "displayName": "Alice",
                "userPrincipalName": "alice@contoso.com"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let users = client.search_users("ali").await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].display_name.as_deref(), Some("Alice"));
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

#[test]
fn escape_odata_doubles_single_quotes() {
    assert_eq!(escape_odata("O'Brien"), "O''Brien");
    assert_eq!(escape_odata("alice"), "alice");
}

// --------- M4 consent tests ---------

#[tokio::test]
async fn grant_app_role_posts_expected_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/servicePrincipals/sp-client/appRoleAssignments"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "principalId": "sp-client",
            "resourceId": "sp-resource",
            "appRoleId": "role-1",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "ara-1",
            "principalId": "sp-client",
            "resourceId": "sp-resource",
            "appRoleId": "role-1",
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let ara = client
        .grant_app_role("sp-client", "sp-resource", "role-1")
        .await
        .unwrap();
    assert_eq!(ara.id, "ara-1");
}

#[tokio::test]
async fn get_site_by_url_builds_host_relative_path() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sites/contoso.sharepoint.com:/sites/Marketing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "contoso.sharepoint.com,guid1,guid2",
            "displayName": "Marketing",
            "webUrl": "https://contoso.sharepoint.com/sites/Marketing"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let site = client
        .get_site_by_url("https://contoso.sharepoint.com/sites/Marketing/")
        .await
        .unwrap();
    assert_eq!(site.id, "contoso.sharepoint.com,guid1,guid2");
    assert_eq!(site.display_name.as_deref(), Some("Marketing"));
}

#[tokio::test]
async fn grant_site_permission_posts_application_identity() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sites/site-1/permissions"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "roles": ["write"],
            "grantedToIdentities": [
                { "application": { "id": "app-1", "displayName": "Demo" } }
            ]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "perm-1",
            "roles": ["write"],
            "grantedToIdentities": [
                { "application": { "id": "app-1", "displayName": "Demo" } }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perm = client
        .grant_site_permission("site-1", "app-1", "Demo", &["write".to_string()])
        .await
        .unwrap();
    assert_eq!(perm.id, "perm-1");
    assert_eq!(perm.roles, vec!["write".to_string()]);
    assert_eq!(
        perm.granted_to_identities[0]
            .application
            .as_ref()
            .and_then(|a| a.id.as_deref()),
        Some("app-1")
    );
}

#[tokio::test]
async fn list_site_permissions_uses_sharepoint_scope() {
    let server = MockServer::start().await;
    // The handler attaches the SharePoint bearer ("sp"), not the default
    // read token ("tok") — the site-permission endpoints need
    // Sites.FullControl.All, which the read scope lacks.
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "perm-1", "roles": ["read"],
                  "grantedToIdentities": [ { "application": { "id": "app-1" } } ] }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perms = client.list_site_permissions("site-1").await.unwrap();
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].id, "perm-1");
}

#[tokio::test]
async fn list_site_permissions_follows_next_link() {
    let server = MockServer::start().await;
    // A site whose grant list spans pages must return BOTH pages — the sweep's
    // "coverage is never overstated" invariant fails silently if page 2 drops.
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "perm-1", "roles": ["read"],
                  "grantedToIdentities": [ { "application": { "id": "app-1" } } ] }
            ],
            "@odata.nextLink": format!("{}/perm-page-2", server.uri()),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/perm-page-2"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "perm-2", "roles": ["write"],
                  "grantedToIdentities": [ { "application": { "id": "app-2" } } ] }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perms = client.list_site_permissions("site-1").await.unwrap();
    assert_eq!(
        perms.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        ["perm-1", "perm-2"],
        "the second page must not be silently dropped"
    );
}

#[tokio::test]
async fn site_permission_read_retries_a_429_honoring_retry_after() {
    let server = MockServer::start().await;
    // The sweep fans this read out across thousands of sites against the
    // throttle-happiest endpoint family — a transient 429 must be absorbed by
    // the retrying transport, not surface as a phantom per-site failure.
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("throttled"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "perm-1", "roles": ["read"],
                  "grantedToIdentities": [ { "application": { "id": "app-1" } } ] }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perms = client.list_site_permissions("site-1").await.unwrap();
    assert_eq!(perms.len(), 1, "the 429 must be retried, not propagated");
}

#[tokio::test]
async fn list_all_sites_follows_next_link_on_sharepoint_scope() {
    let server = MockServer::start().await;
    // Page 1 carries a nextLink back to this origin; page 2 ends the chain.
    // Both must attach the SharePoint bearer, like the permission endpoints.
    Mock::given(method("GET"))
        .and(path("/sites"))
        .and(query_param("search", "*"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [ { "id": "site-1", "displayName": "One", "webUrl": "https://x/sites/one" } ],
            "@odata.nextLink": format!("{}/sites-page-2", server.uri()),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites-page-2"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [ { "id": "site-2", "displayName": "Two", "webUrl": "https://x/sites/two" } ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let sites = client.list_all_sites(100).await.unwrap();
    assert_eq!(
        sites.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["site-1", "site-2"]
    );

    // The cap stops the walk without erroring (page 1 already satisfies it).
    let capped = client.list_all_sites(1).await.unwrap();
    assert_eq!(capped.len(), 1);
}

#[tokio::test]
async fn remove_site_permission_deletes_nested_path() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/sites/site-1/permissions/perm-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    client
        .remove_site_permission("site-1", "perm-1")
        .await
        .unwrap();
}

#[tokio::test]
async fn remove_app_role_assignment_deletes_nested_path() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(
            "/servicePrincipals/sp-client/appRoleAssignments/ara-1",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .remove_app_role_assignment("sp-client", "ara-1")
        .await
        .unwrap();
}

#[tokio::test]
async fn update_application_with_required_resource_access_serializes_fully() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "requiredResourceAccess": [{
                "resourceAppId": "00000003-0000-0000-c000-000000000000",
                "resourceAccess": [
                    {"id": "role-id", "type": "Role"},
                    {"id": "scope-id", "type": "Scope"},
                ]
            }]
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let patch = AppPatch {
        required_resource_access: Some(vec![RequiredResourceAccess {
            resource_app_id: "00000003-0000-0000-c000-000000000000".into(),
            resource_access: vec![
                azapptoolkit_core::models::ResourceAccess {
                    id: "role-id".into(),
                    r#type: "Role".into(),
                },
                azapptoolkit_core::models::ResourceAccess {
                    id: "scope-id".into(),
                    r#type: "Scope".into(),
                },
            ],
        }]),
        ..Default::default()
    };
    client.update_application("obj-1", &patch).await.unwrap();
}

#[tokio::test]
async fn upsert_admin_oauth2_grant_creates_when_absent() {
    let server = MockServer::start().await;
    // Lookup returns no existing grants.
    Mock::given(method("GET"))
        .and(path("/oauth2PermissionGrants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2PermissionGrants"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "clientId": "sp-client",
            "resourceId": "sp-graph",
            "consentType": "AllPrincipals",
            "scope": "User.Read email",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "grant-new",
            "clientId": "sp-client",
            "resourceId": "sp-graph",
            "consentType": "AllPrincipals",
            "scope": "User.Read email",
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let grant = client
        .upsert_admin_oauth2_grant("sp-client", "sp-graph", &["User.Read", "email"])
        .await
        .unwrap();
    assert_eq!(grant.id.as_deref(), Some("grant-new"));
}

#[tokio::test]
async fn upsert_admin_oauth2_grant_merges_scopes_when_existing_is_partial() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2PermissionGrants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "g-1",
                "clientId": "sp-client",
                "resourceId": "sp-graph",
                "consentType": "AllPrincipals",
                "scope": "User.Read"
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/oauth2PermissionGrants/g-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "scope": "User.Read email"
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let grant = client
        .upsert_admin_oauth2_grant("sp-client", "sp-graph", &["email", "User.Read"])
        .await
        .unwrap();
    assert!(grant.scope.split_whitespace().any(|s| s == "email"));
    assert!(grant.scope.split_whitespace().any(|s| s == "User.Read"));
}

#[tokio::test]
async fn add_key_credential_fetches_then_patches_with_appended_entry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo",
            "keyCredentials": [{
                "keyId": "existing",
                "displayName": "existing-cert",
                "type": "AsymmetricX509Cert",
                "usage": "Verify"
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "keyCredentials": [
                {
                    "keyId": "existing",
                    "displayName": "existing-cert",
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify"
                },
                {
                    "displayName": "new-cert",
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                    "key": "AAAA"
                }
            ]
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .add_key_credential(
            "obj-1",
            NewKeyCredential {
                display_name: Some("new-cert".into()),
                kind: Some("AsymmetricX509Cert".into()),
                usage: Some("Verify".into()),
                key: "AAAA".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn remove_key_credential_patches_filtered_array() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
            .and(path("/applications/obj-1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "obj-1",
                    "appId": "app-1",
                    "displayName": "Demo",
                    "keyCredentials": [
                        {"keyId": "keep", "displayName": "keep", "type": "AsymmetricX509Cert", "usage": "Verify"},
                        {"keyId": "drop", "displayName": "drop", "type": "AsymmetricX509Cert", "usage": "Verify"}
                    ]
                })),
            )
            .mount(&server)
            .await;
    Mock::given(method("PATCH"))
            .and(path("/applications/obj-1"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "keyCredentials": [
                    {"keyId": "keep", "displayName": "keep", "type": "AsymmetricX509Cert", "usage": "Verify"}
                ]
            })))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
    let client = make_client(&server.uri());
    client.remove_key_credential("obj-1", "drop").await.unwrap();
}

#[tokio::test]
async fn list_applications_all_follows_next_link() {
    let server = MockServer::start().await;
    let base = server.uri();
    let page2_link = format!("{base}/applications?page=2");

    // Page 1: matches the broad "list_applications" call (has $select etc).
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$top", "50"))
        .and(query_param("$count", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": page2_link,
            "value": [{
                "id": "a1","appId":"app-1","displayName":"one"
            }]
        })))
        .mount(&server)
        .await;

    // Page 2: matched by the `page=2` query string from the nextLink.
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id":"a2","appId":"app-2","displayName":"two"
            }, {
                "id":"a3","appId":"app-3","displayName":"three"
            }]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let apps = client
        .list_applications_all(AppListQuery::default(), None)
        .await
        .unwrap();
    assert_eq!(apps.len(), 3);
    assert_eq!(apps[0].app_id, "app-1");
    assert_eq!(apps[2].app_id, "app-3");
}

#[tokio::test]
async fn collect_all_pages_capped_truncates_instead_of_erroring() {
    // The tenant-wide index scans must degrade to a truncated list rather than
    // fail outright past the cap (review P-M8 / T-M1). Page 1 + page 2 already
    // overshoot a cap of 3; the third page is never fetched and the result is
    // truncated with `truncated == true`.
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/sp"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": format!("{base}/sp?page=3"),
            "value": [2, 3]
        })))
        .mount(&server)
        .await;
    // Guard: page 3 must never be requested once the cap is reached.
    Mock::given(method("GET"))
        .and(path("/sp"))
        .and(query_param("page", "3"))
        .respond_with(ResponseTemplate::new(500).set_body_string("should not be fetched"))
        .expect(0)
        .mount(&server)
        .await;

    let client = make_client(&base);
    let page1 = Paged::<serde_json::Value> {
        items: vec![serde_json::json!(0), serde_json::json!(1)],
        next_link: Some(format!("{base}/sp?page=2")),
        total_count: None,
    };
    let (items, truncated) = client.collect_all_pages_capped(page1, 3).await.unwrap();
    assert_eq!(items.len(), 3);
    assert!(truncated, "rows existed beyond the cap");
}

#[tokio::test]
async fn collect_all_pages_capped_returns_full_set_under_the_cap() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("GET"))
        .and(path("/sp"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [2]
        })))
        .mount(&server)
        .await;

    let client = make_client(&base);
    let page1 = Paged::<serde_json::Value> {
        items: vec![serde_json::json!(0), serde_json::json!(1)],
        next_link: Some(format!("{base}/sp?page=2")),
        total_count: None,
    };
    let (items, truncated) = client.collect_all_pages_capped(page1, 100).await.unwrap();
    assert_eq!(items.len(), 3);
    assert!(!truncated, "everything fit under the cap");
}

#[tokio::test]
async fn collect_all_pages_capped_stops_a_cyclic_next_link() {
    // A self-referential nextLink must terminate at the cap, not loop forever
    // or error — the cap is its own cyclic guard.
    let server = MockServer::start().await;
    let base = server.uri();
    let cycle = format!("{base}/sp?cycle=1");
    Mock::given(method("GET"))
        .and(path("/sp"))
        .and(query_param("cycle", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": cycle,
            "value": [9]
        })))
        .mount(&server)
        .await;

    let client = make_client(&base);
    let page1 = Paged::<serde_json::Value> {
        items: vec![serde_json::json!(0)],
        next_link: Some(cycle.clone()),
        total_count: None,
    };
    let (items, truncated) = client.collect_all_pages_capped(page1, 5).await.unwrap();
    assert_eq!(items.len(), 5);
    assert!(truncated);
}

#[tokio::test]
async fn get_json_absolute_rejects_foreign_origin() {
    let server = MockServer::start().await;
    let client = make_client(&server.uri());
    let err = client
        .get_json_absolute::<serde_json::Value>("https://evil.example.com/v1.0/applications")
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Protocol(_)));
}

#[tokio::test]
async fn throttle_observer_fires_on_429() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let server = MockServer::start().await;
    // Two 429s then a success to make sure the observer fires every time
    // even though the retry machinery ultimately recovers.
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("throttled"),
        )
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_org_json()))
        .mount(&server)
        .await;

    struct Counter(AtomicUsize);
    impl ThrottleObserver for Counter {
        fn on_throttle(&self, _retry_after_secs: Option<u64>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let client = make_client(&server.uri());
    client.set_throttle_observer(counter.clone());
    client.get_organization().await.unwrap();
    assert_eq!(counter.0.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn upsert_admin_oauth2_grant_noops_when_scopes_are_subset() {
    let server = MockServer::start().await;
    // Only the GET is mocked; any PATCH/POST would fail the test because
    // wiremock returns 404 for unmatched requests.
    Mock::given(method("GET"))
        .and(path("/oauth2PermissionGrants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "g-1",
                "clientId": "sp-client",
                "resourceId": "sp-graph",
                "consentType": "AllPrincipals",
                "scope": "User.Read email profile"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let grant = client
        .upsert_admin_oauth2_grant("sp-client", "sp-graph", &["email"])
        .await
        .unwrap();
    assert_eq!(grant.id.as_deref(), Some("g-1"));
}

#[tokio::test]
async fn directory_audits_for_app_filters_by_target_resources() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auditLogs/directoryAudits"))
        .and(query_param(
            "$filter",
            "targetResources/any(t:t/id eq 'obj-1') or targetResources/any(t:t/id eq 'sp-1')",
        ))
        .and(query_param("$top", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "audit-1",
                "activityDisplayName": "Update application",
                "activityDateTime": "2026-05-20T10:00:00Z",
                "result": "success",
                "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}},
                "targetResources": [{"id": "obj-1", "displayName": "My App", "type": "Application"}]
            }]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_audit_log_token(StaticTokenProvider::new("a"));
    let logs = client
        .list_directory_audits_for_app(&["obj-1".into(), "sp-1".into()], 50)
        .await
        .unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(
        logs[0].activity_display_name.as_deref(),
        Some("Update application")
    );
    assert_eq!(
        logs[0].target_resources[0].resource_type.as_deref(),
        Some("Application")
    );
}

#[tokio::test]
async fn directory_audits_without_token_is_forbidden() {
    // No mock needed: the missing-token guard returns before any request.
    let client = make_client("http://127.0.0.1:0");
    let err = client
        .list_directory_audits_for_app(&["obj-1".into()], 50)
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)), "got {err:?}");
}

#[tokio::test]
async fn sign_in_activities_are_cached_per_tenant() {
    let server = MockServer::start().await;
    // The slow beta report is expected exactly ONCE: the second call must be
    // served from the per-tenant Permissions cache, not re-paginated. `.expect(1)`
    // is verified on server drop, so a regression that dropped caching fails here.
    Mock::given(method("GET"))
        .and(path("/reports/servicePrincipalSignInActivities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "appId": "app-1",
                "lastSignInActivity": { "lastSignInDateTime": "2026-05-01T00:00:00Z" }
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_audit_log_token(StaticTokenProvider::new("a"));
    let first = client
        .list_service_principal_sign_in_activities()
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    // Second call is a cache hit — no second request reaches the mock.
    let second = client
        .list_service_principal_sign_in_activities()
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].app_id.as_deref(), Some("app-1"));
}

#[tokio::test]
async fn conditional_access_policies_parse_and_follow_paging() {
    let server = MockServer::start().await;
    let uri = server.uri();
    Mock::given(method("GET"))
            .and(path("/identity/conditionalAccess/policies"))
            .and(query_param_is_missing("page"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "ca-1",
                    "displayName": "Require MFA",
                    "state": "enabled",
                    "conditions": {"applications": {"includeApplications": ["All"], "excludeApplications": null}},
                    "grantControls": {"builtInControls": ["mfa"], "operator": "OR"}
                }],
                "@odata.nextLink": format!("{uri}/identity/conditionalAccess/policies?page=2")
            })))
            .mount(&server)
            .await;
    Mock::given(method("GET"))
        .and(path("/identity/conditionalAccess/policies"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "ca-2", "displayName": "Block legacy", "state": "disabled"}]
        })))
        .mount(&server)
        .await;

    let client = make_client(&uri).with_policy_token(StaticTokenProvider::new("p"));
    let policies = client.list_conditional_access_policies().await.unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].id.as_deref(), Some("ca-1"));
    let apps = policies[0]
        .conditions
        .as_ref()
        .and_then(|c| c.applications.as_ref())
        .unwrap();
    assert_eq!(apps.include_applications, vec!["All".to_string()]);
    assert!(apps.exclude_applications.is_empty());
}

#[tokio::test]
async fn conditional_access_without_token_is_forbidden() {
    let client = make_client("http://127.0.0.1:0");
    let err = client.list_conditional_access_policies().await.unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)), "got {err:?}");
}

#[tokio::test]
async fn conditional_access_first_page_404_is_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/identity/conditionalAccess/policies"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "error": {"code": "Request_ResourceNotFound"}
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_policy_token(StaticTokenProvider::new("p"));
    let policies = client.list_conditional_access_policies().await.unwrap();
    assert!(policies.is_empty());
}

#[tokio::test]
async fn conditional_access_refuses_foreign_origin_next_link() {
    let server = MockServer::start().await;
    // First (and only legitimate) page hands back a nextLink to a foreign
    // origin; the scoped follower must refuse to attach the bearer to it.
    Mock::given(method("GET"))
        .and(path("/identity/conditionalAccess/policies"))
        .and(query_param_is_missing("page"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "ca-1", "displayName": "Require MFA", "state": "enabled"}],
            "@odata.nextLink": "https://evil.example.com/identity/conditionalAccess/policies?page=2"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_policy_token(StaticTokenProvider::new("p"));
    let err = client.list_conditional_access_policies().await.unwrap_err();
    assert!(matches!(err, GraphError::Protocol(_)), "got {err:?}");
}

#[test]
fn same_origin_rejects_embedded_credentials() {
    let base = "https://graph.microsoft.com";
    assert!(same_origin(base, "https://graph.microsoft.com/v1.0/foo"));
    // userinfo is ignored by Url::origin(); we must reject it explicitly.
    assert!(!same_origin(
        base,
        "https://user:pass@graph.microsoft.com/v1.0/foo"
    ));
    assert!(!same_origin(base, "https://evil.example.com/v1.0/foo"));
}

#[test]
fn site_lookup_path_handles_clean_root_and_subsite_urls() {
    // Clean site collection URL.
    assert_eq!(
        site_lookup_path("https://contoso.sharepoint.com/sites/Marketing"),
        "/sites/contoso.sharepoint.com:/sites/Marketing"
    );
    // Trailing slash is tolerated.
    assert_eq!(
        site_lookup_path("https://contoso.sharepoint.com/sites/Marketing/"),
        "/sites/contoso.sharepoint.com:/sites/Marketing"
    );
    // Bare tenant root has no relative path.
    assert_eq!(
        site_lookup_path("https://contoso.sharepoint.com"),
        "/sites/contoso.sharepoint.com"
    );
    // Subsite paths (no app token) are preserved verbatim.
    assert_eq!(
        site_lookup_path("https://contoso.sharepoint.com/sites/Marketing/Team"),
        "/sites/contoso.sharepoint.com:/sites/Marketing/Team"
    );
}

#[test]
fn site_lookup_path_strips_document_copy_link_decoration() {
    // The "Copy link" form that produced `Resource not found for the
    // segment ':x:'`: app token + redirect + library + file + query string.
    assert_eq!(
        site_lookup_path(
            "https://contoso.sharepoint.com/:x:/r/sites/Marketing/Shared%20Documents/Book.xlsx?d=w123&csf=1&web=1&e=abc"
        ),
        "/sites/contoso.sharepoint.com:/sites/Marketing"
    );
    // Word doc on a Teams-provisioned site.
    assert_eq!(
        site_lookup_path("https://contoso.sharepoint.com/:w:/r/teams/Sales/Docs/Plan.docx?web=1"),
        "/sites/contoso.sharepoint.com:/teams/Sales"
    );
    // OneDrive (personal) sharing link.
    assert_eq!(
        site_lookup_path(
            "https://contoso-my.sharepoint.com/:b:/r/personal/user_contoso_com/Documents/Report.pdf?csf=1"
        ),
        "/sites/contoso-my.sharepoint.com:/personal/user_contoso_com"
    );
}

#[tokio::test]
async fn directory_audits_tenant_wide_sends_only_top() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auditLogs/directoryAudits"))
        .and(query_param_is_missing("$filter"))
        .and(query_param("$top", "200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "audit-2", "activityDisplayName": "Add owner"}]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_audit_log_token(StaticTokenProvider::new("a"));
    let logs = client.list_directory_audits(200).await.unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].id.as_deref(), Some("audit-2"));
}

#[tokio::test]
async fn instantiate_template_returns_app_and_sp() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate",
        ))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "displayName": "My SAML App" }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "application": {"id": "app-obj-1", "appId": "client-1", "displayName": "My SAML App"},
            "servicePrincipal": {"id": "sp-1", "appId": "client-1", "displayName": "My SAML App"}
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let pair = client
        .instantiate_application_template("8adf8e6e-67b2-4cf2-a259-e3dc5476c621", "My SAML App")
        .await
        .unwrap();
    assert_eq!(pair.application.id, "app-obj-1");
    assert_eq!(pair.service_principal.id, "sp-1");
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

#[tokio::test]
async fn patch_application_web_sends_identifier_and_reply_urls() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/applications/app-obj-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "identifierUris": ["https://app/saml"],
            "web": { "redirectUris": ["https://app/acs"], "logoutUrl": "https://app/logout" }
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .patch_application_web(
            "app-obj-1",
            &serde_json::json!({
                "identifierUris": ["https://app/saml"],
                "web": { "redirectUris": ["https://app/acs"], "logoutUrl": "https://app/logout" }
            }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn add_token_signing_certificate_returns_thumbprint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/servicePrincipals/sp-1/addTokenSigningCertificate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "thumbprint": "C2DDD8044C956ACD0269A75A64B7862DB9DDAC3E",
            "key": "MIICqjCCAZKg",
            "keyId": "4c266507-3e74-4b91-aeba-18a25b450f6e",
            "usage": "Verify",
            "type": "AsymmetricX509Cert"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let end = chrono::Utc::now() + chrono::Duration::days(365);
    let cert = client
        .add_token_signing_certificate("sp-1", "CN=Demo", end)
        .await
        .unwrap();
    assert_eq!(cert.thumbprint, "C2DDD8044C956ACD0269A75A64B7862DB9DDAC3E");
}

#[tokio::test]
async fn create_and_assign_claims_policy_use_policy_write_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/policies/claimsMappingPolicies"))
        .and(header("authorization", "Bearer pw"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "definition": ["{\"x\":1}"],
            "displayName": "Demo Claims",
            "isOrganizationDefault": false
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "pol-1",
            "displayName": "Demo Claims",
            "definition": ["{\"x\":1}"]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/servicePrincipals/sp-1/claimsMappingPolicies/$ref"))
        .and(header("authorization", "Bearer pw"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_policy_write_token(StaticTokenProvider::new("pw"));
    let policy = client
        .create_claims_mapping_policy("{\"x\":1}", "Demo Claims")
        .await
        .unwrap();
    assert_eq!(policy.id, "pol-1");
    client
        .assign_claims_mapping_policy("sp-1", &policy.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn claims_policy_write_without_token_is_forbidden() {
    // No policy_write_token attached → typed Forbidden, not a panic.
    let client = make_client("http://localhost:0");
    let err = client
        .create_claims_mapping_policy("{}", "x")
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)));
}

#[test]
fn parse_claims_challenge_extracts_only_insufficient_claims() {
    // Quoted form on an insufficient_claims challenge.
    assert_eq!(
        parse_claims_challenge(
            r#"Bearer realm="", error="insufficient_claims", claims="eyJhIjoxfQ""#
        ),
        Some("eyJhIjoxfQ".to_string())
    );
    // Bare value ending at a comma.
    assert_eq!(
        parse_claims_challenge("Bearer error=insufficient_claims, claims=abc123, foo=bar"),
        Some("abc123".to_string())
    );
    // An ordinary 401 (expired token) is NOT a CAE challenge.
    assert_eq!(
        parse_claims_challenge(r#"Bearer realm="", error="invalid_token""#),
        None
    );
    // insufficient_claims with no claims directive → None (nothing to forward).
    assert_eq!(
        parse_claims_challenge(r#"Bearer error="insufficient_claims""#),
        None
    );
}

#[tokio::test]
async fn cae_claims_challenge_triggers_one_remint_and_retry() {
    use async_trait::async_trait;
    use azapptoolkit_core::token::BearerProvider;
    use std::sync::Arc;

    // Returns the base token normally, a distinct token when re-minted for a
    // claims challenge — so the mock can assert which one was used.
    struct CaeProvider;
    #[async_trait]
    impl BearerProvider for CaeProvider {
        // `Result` is shadowed by the crate's alias in this module; qualify it.
        async fn bearer(&self) -> std::result::Result<String, String> {
            Ok("tok".into())
        }
        async fn bearer_with_claims(&self, _claims: &str) -> std::result::Result<String, String> {
            Ok("tok-cae".into())
        }
    }

    let server = MockServer::start().await;
    // First attempt (Bearer tok) is challenged for insufficient_claims.
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "WWW-Authenticate",
            r#"Bearer realm="", error="insufficient_claims", claims="eyJhIjoxfQ""#,
        ))
        .mount(&server)
        .await;
    // The re-minted token (Bearer tok-cae) succeeds.
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .and(header("authorization", "Bearer tok-cae"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "obj-1", "appId": "app-1", "displayName": "Demo"
        })))
        .mount(&server)
        .await;

    let provider: Arc<dyn BearerProvider> = Arc::new(CaeProvider);
    let client = GraphClient::with_base_url(
        "tenant-test",
        provider.clone(),
        provider,
        Cache::new(),
        server.uri(),
    );
    let app = client.get_application("obj-1").await.unwrap();
    assert_eq!(app.id, "obj-1");
}

#[tokio::test]
async fn batch_get_json_maps_inner_statuses_in_order() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                // Deliberately reversed to prove results are matched by `id`,
                // not response position.
                { "id": "1", "status": 404, "body": { "error": { "message": "nope" } } },
                { "id": "0", "status": 200, "body": { "id": "sp-0" } }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let urls = vec![
        "/servicePrincipals/a".to_string(),
        "/servicePrincipals/b".to_string(),
    ];
    let out: Vec<Result<serde_json::Value>> = client.batch_get_json(&urls).await.unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].as_ref().unwrap()["id"], "sp-0");
    assert!(matches!(out[1], Err(GraphError::NotFound(_))));
}

#[tokio::test]
async fn batch_get_json_retries_inner_429_then_surfaces_throttled() {
    let server = MockServer::start().await;
    // Always throttle the sub-request with `Retry-After: 0` so the retry loop
    // doesn't actually sleep; after MAX_RETRIES it surfaces as Throttled (and,
    // crucially, terminates rather than spinning).
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                { "id": "0", "status": 429, "headers": { "Retry-After": "0" }, "body": {} }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let urls = vec!["/servicePrincipals/a".to_string()];
    let out: Vec<Result<serde_json::Value>> = client.batch_get_json(&urls).await.unwrap();
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0], Err(GraphError::Throttled { .. })));
}

#[tokio::test]
async fn batch_get_service_principals_maps_404_to_none_in_order() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                { "id": "1", "status": 404, "body": { "error": { "message": "gone" } } },
                { "id": "0", "status": 200, "body": { "id": "sp-0", "appId": "app-0" } }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let ids = vec!["sp-0".to_string(), "sp-1".to_string()];
    let out = client.batch_get_service_principals(&ids).await.unwrap();
    assert_eq!(out.len(), 2);
    // Matched by `id`, so a vanished principal (404) is `Ok(None)`, not an error.
    assert_eq!(out[0].as_ref().unwrap().as_ref().unwrap().id, "sp-0");
    assert!(matches!(out[1], Ok(None)));
}

#[tokio::test]
async fn batch_list_app_role_assigned_to_follows_nextlink_overflow() {
    let server = MockServer::start().await;
    // First (batched) page carries an `@odata.nextLink` (same-origin, so
    // `get_json_absolute` will follow it) — proving the overflow fallback runs.
    let next = format!(
        "{}/servicePrincipals/sp-0/appRoleAssignedTo?page=2",
        server.uri()
    );
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [{ "id": "0", "status": 200, "body": {
                "value": [{ "id": "a1", "principalId": "p1", "resourceId": "res1", "appRoleId": "r1" }],
                "@odata.nextLink": next,
            }}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/sp-0/appRoleAssignedTo"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "a2", "principalId": "p2", "resourceId": "res2", "appRoleId": "r2" }]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let out = client
        .batch_list_app_role_assigned_to(&["sp-0".to_string()])
        .await
        .unwrap();
    let assigns = out[0].as_ref().unwrap();
    assert_eq!(assigns.len(), 2, "first page + overflow page concatenated");
    assert_eq!(assigns[0].id, "a1");
    assert_eq!(assigns[1].id, "a2");
}

#[tokio::test]
async fn batch_list_service_principal_groups_sends_consistencylevel_per_subrequest() {
    let server = MockServer::start().await;
    // The mock only answers when the POST body carries the advanced-query
    // header, so a missing per-sub-request header makes the call fail.
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .and(body_string_contains("ConsistencyLevel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [{ "id": "0", "status": 200, "body": {
                "value": [{ "id": "g1", "displayName": "Group One" }]
            }}]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let out = client
        .batch_list_service_principal_groups(&["sp-0".to_string()])
        .await
        .unwrap();
    let groups = out[0].as_ref().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, "g1");
}

// --- Request-struct serialization: guards the hand-typed-camelCase hazard.
// These typed bodies replaced inline `serde_json::json!` blocks; the rename_all
// + skip_serializing_if behavior must match the exact keys Graph expects, so we
// assert the serialized JSON rather than trusting the derive.

#[test]
fn federated_credential_request_serializes_to_graph_shape() {
    let req = FederatedCredentialRequest {
        name: "gh-actions".into(),
        issuer: "https://token.actions.githubusercontent.com".into(),
        subject: "repo:org/app:ref:refs/heads/main".into(),
        audiences: vec!["api://AzureADTokenExchange".into()],
        description: None,
    };
    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        serde_json::json!({
            "name": "gh-actions",
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": "repo:org/app:ref:refs/heads/main",
            "audiences": ["api://AzureADTokenExchange"],
            // description is sent as null when absent (not omitted), matching the
            // body the command originally hand-built.
            "description": null,
        })
    );
}

#[test]
fn federated_credential_patch_serializes_without_name() {
    let patch = FederatedCredentialPatch {
        issuer: "https://token.actions.githubusercontent.com".into(),
        subject: "repo:org/app:pull_request".into(),
        audiences: vec!["api://AzureADTokenExchange".into()],
        description: None,
    };
    assert_eq!(
        serde_json::to_value(&patch).unwrap(),
        serde_json::json!({
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": "repo:org/app:pull_request",
            "audiences": ["api://AzureADTokenExchange"],
            // null clears a previously-set description; `name` must never
            // appear — Graph rejects patches that touch it.
            "description": null,
        })
    );
}

#[tokio::test]
async fn update_federated_credential_patches_credential_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(
            "/applications/obj-1/federatedIdentityCredentials/fic-1",
        ))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "issuer": "https://accounts.google.com",
            "subject": "112633961854638529490",
            "audiences": ["api://AzureADTokenExchange"],
            "description": "gcp workload",
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let patch = FederatedCredentialPatch {
        issuer: "https://accounts.google.com".into(),
        subject: "112633961854638529490".into(),
        audiences: vec!["api://AzureADTokenExchange".into()],
        description: Some("gcp workload".into()),
    };
    client
        .update_federated_credential("obj-1", "fic-1", &patch)
        .await
        .unwrap();
}

#[test]
fn service_principal_patches_use_camel_case() {
    assert_eq!(
        serde_json::to_value(ServicePrincipalSsoModePatch {
            preferred_single_sign_on_mode: "saml".into(),
        })
        .unwrap(),
        serde_json::json!({ "preferredSingleSignOnMode": "saml" })
    );
    assert_eq!(
        serde_json::to_value(ServicePrincipalSigningKeyPatch {
            preferred_token_signing_key_thumbprint: "ABC123".into(),
        })
        .unwrap(),
        serde_json::json!({ "preferredTokenSigningKeyThumbprint": "ABC123" })
    );
}

#[test]
fn application_sso_patch_matches_saml_body_and_skips_unset() {
    // SAML: identifierUris + web (with logoutUrl), no spa.
    let saml = ApplicationSsoPatch {
        identifier_uris: Some(vec!["https://app/saml".into()]),
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(vec!["https://app/acs".into()]),
            logout_url: Some("https://app/logout".into()),
            implicit_grant_settings: None,
        }),
        spa: None,
    };
    assert_eq!(
        serde_json::to_value(&saml).unwrap(),
        serde_json::json!({
            "identifierUris": ["https://app/saml"],
            "web": { "redirectUris": ["https://app/acs"], "logoutUrl": "https://app/logout" },
        })
    );

    // OIDC web+spa replacement: no identifierUris, no logoutUrl.
    let oidc = ApplicationSsoPatch {
        identifier_uris: None,
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(vec!["https://app/cb".into()]),
            logout_url: None,
            implicit_grant_settings: None,
        }),
        spa: Some(ApplicationSpaPatch {
            redirect_uris: Some(vec!["https://app/spa".into()]),
        }),
    };
    assert_eq!(
        serde_json::to_value(&oidc).unwrap(),
        serde_json::json!({
            "web": { "redirectUris": ["https://app/cb"] },
            "spa": { "redirectUris": ["https://app/spa"] },
        })
    );
}

#[test]
fn application_authentication_patch_nests_implicit_grant_and_skips_unset() {
    // A full save: web (reply URLs + logout + implicit grant), spa, public
    // client, and the fallback-public-client flag. implicitGrantSettings must
    // nest under `web`, not appear at the top level.
    let full = ApplicationAuthenticationPatch {
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(vec!["https://app/cb".into()]),
            logout_url: Some("https://app/logout".into()),
            implicit_grant_settings: Some(ImplicitGrantSettingsPatch {
                enable_access_token_issuance: Some(false),
                enable_id_token_issuance: Some(true),
            }),
        }),
        spa: Some(ApplicationSpaPatch {
            redirect_uris: Some(vec!["https://app/spa".into()]),
        }),
        public_client: Some(ApplicationPublicClientPatch {
            redirect_uris: Some(vec!["http://localhost".into()]),
        }),
        is_fallback_public_client: Some(true),
    };
    assert_eq!(
        serde_json::to_value(&full).unwrap(),
        serde_json::json!({
            "web": {
                "redirectUris": ["https://app/cb"],
                "logoutUrl": "https://app/logout",
                "implicitGrantSettings": {
                    "enableAccessTokenIssuance": false,
                    "enableIdTokenIssuance": true,
                },
            },
            "spa": { "redirectUris": ["https://app/spa"] },
            "publicClient": { "redirectUris": ["http://localhost"] },
            "isFallbackPublicClient": true,
        })
    );

    // An all-default patch serializes to an empty object: every field is
    // skip_serializing_if = Option::is_none, so a no-op save sends nothing.
    assert_eq!(
        serde_json::to_value(ApplicationAuthenticationPatch::default()).unwrap(),
        serde_json::json!({})
    );
}

#[test]
fn expose_api_patch_uses_camel_case_and_skips_unset() {
    // A scopes-only patch must not touch identifierUris or the pre-authorized
    // list (Graph full-replaces every array it receives).
    let scopes_only = ApplicationExposeApiPatch {
        identifier_uris: None,
        api: Some(ApiApplicationPatch {
            oauth2_permission_scopes: Some(vec![OAuth2PermissionScope {
                id: "11111111-1111-1111-1111-111111111111".into(),
                value: "Files.Read".into(),
                admin_consent_display_name: Some("Read files".into()),
                admin_consent_description: Some("Allows reading files.".into()),
                user_consent_display_name: None,
                user_consent_description: None,
                r#type: Some("User".into()),
                is_enabled: Some(true),
            }]),
            pre_authorized_applications: None,
        }),
    };
    assert_eq!(
        serde_json::to_value(&scopes_only).unwrap(),
        serde_json::json!({
            "api": {
                "oauth2PermissionScopes": [{
                    "id": "11111111-1111-1111-1111-111111111111",
                    "value": "Files.Read",
                    "adminConsentDisplayName": "Read files",
                    "adminConsentDescription": "Allows reading files.",
                    "userConsentDisplayName": null,
                    "userConsentDescription": null,
                    "type": "User",
                    "isEnabled": true,
                }],
            },
        })
    );

    // URIs-only patch leaves the whole api block untouched.
    let uris_only = ApplicationExposeApiPatch {
        identifier_uris: Some(vec!["api://app-1".into()]),
        api: None,
    };
    assert_eq!(
        serde_json::to_value(&uris_only).unwrap(),
        serde_json::json!({ "identifierUris": ["api://app-1"] })
    );

    // Pre-authorized clients serialize with camelCase delegatedPermissionIds.
    let pre_only = ApplicationExposeApiPatch {
        identifier_uris: None,
        api: Some(ApiApplicationPatch {
            oauth2_permission_scopes: None,
            pre_authorized_applications: Some(vec![PreAuthorizedApplication {
                app_id: "22222222-2222-2222-2222-222222222222".into(),
                delegated_permission_ids: vec!["11111111-1111-1111-1111-111111111111".into()],
            }]),
        }),
    };
    assert_eq!(
        serde_json::to_value(&pre_only).unwrap(),
        serde_json::json!({
            "api": {
                "preAuthorizedApplications": [{
                    "appId": "22222222-2222-2222-2222-222222222222",
                    "delegatedPermissionIds": ["11111111-1111-1111-1111-111111111111"],
                }],
            },
        })
    );
}

#[test]
fn application_expose_api_deserializes_tolerantly() {
    // Graph can return a null api block / null arrays on older objects; the
    // projection must default them rather than fail the whole tab.
    let v: ApplicationExposeApi = serde_json::from_value(serde_json::json!({
        "id": "obj-1",
        "appId": "app-1",
        "identifierUris": null,
        "api": null,
    }))
    .unwrap();
    assert!(v.identifier_uris.is_empty());
    assert!(v.api.oauth2_permission_scopes.is_empty());

    let v: ApplicationExposeApi = serde_json::from_value(serde_json::json!({
        "id": "obj-1",
        "appId": "app-1",
        "identifierUris": ["api://app-1"],
        "api": {
            "oauth2PermissionScopes": [{
                "id": "s-1",
                "value": "Files.Read",
                "type": "Admin",
                "isEnabled": true,
            }],
            "preAuthorizedApplications": [{
                "appId": "client-1",
                "delegatedPermissionIds": ["s-1"],
            }],
        },
    }))
    .unwrap();
    assert_eq!(v.identifier_uris, vec!["api://app-1".to_string()]);
    assert_eq!(
        v.api.oauth2_permission_scopes[0].r#type.as_deref(),
        Some("Admin")
    );
    assert_eq!(
        v.api.pre_authorized_applications[0].delegated_permission_ids,
        vec!["s-1".to_string()]
    );
}

// ---------------- group membership ----------------

#[tokio::test]
async fn list_service_principal_groups_sends_cast_query_and_parses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/sp-1/memberOf/microsoft.graph.group"))
        // The OData cast is an advanced query: both ConsistencyLevel and
        // $count are mandatory or Graph rejects it with Request_UnsupportedQuery.
        .and(header("consistencylevel", "eventual"))
        .and(query_param("$count", "true"))
        .and(query_param(
            "$select",
            "id,displayName,securityEnabled,groupTypes",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {"id": "g-1", "displayName": "PowerBI-SPs", "securityEnabled": true, "groupTypes": []},
                {"id": "g-2", "displayName": "All Staff", "securityEnabled": false,
                 "groupTypes": ["Unified", "DynamicMembership"]},
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let groups = client.list_service_principal_groups("sp-1").await.unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].display_name.as_deref(), Some("PowerBI-SPs"));
    assert_eq!(groups[0].security_enabled, Some(true));
    assert!(groups[0].group_types.is_empty());
    assert!(
        groups[1]
            .group_types
            .iter()
            .any(|t| t == "DynamicMembership")
    );
}

#[tokio::test]
async fn add_group_member_posts_ref_built_from_base_url() {
    let server = MockServer::start().await;
    // The @odata.id must be derived from the configured base URL (sovereign
    // clouds), never a hardcoded graph.microsoft.com.
    let expected_ref = format!("{}/directoryObjects/sp-1", server.uri());
    Mock::given(method("POST"))
        .and(path("/groups/g-1/members/$ref"))
        .and(header("authorization", "Bearer gm-tok"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({"@odata.id": expected_ref}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client =
        make_client(&server.uri()).with_group_member_token(StaticTokenProvider::new("gm-tok"));
    client.add_group_member("g-1", "sp-1").await.unwrap();
}

#[tokio::test]
async fn remove_group_member_deletes_ref() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/groups/g-1/members/sp-1/$ref"))
        .and(header("authorization", "Bearer gm-tok"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client =
        make_client(&server.uri()).with_group_member_token(StaticTokenProvider::new("gm-tok"));
    client.remove_group_member("g-1", "sp-1").await.unwrap();
}

#[tokio::test]
async fn group_member_write_without_token_degrades_to_forbidden() {
    // No with_group_member_token → the optional scope isn't wired; the call
    // must surface Forbidden (graceful degradation), not panic.
    let server = MockServer::start().await;
    let client = make_client(&server.uri());
    let err = client.add_group_member("g-1", "sp-1").await.unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)));
}
