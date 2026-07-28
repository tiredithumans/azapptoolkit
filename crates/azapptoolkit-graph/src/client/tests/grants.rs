// Grant/assignment tests reach the client only through `common::make_client`;
// nothing from the client module itself is referenced by name.
use super::common::*;

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

/// The pre-read variant must make NO grant-collection read of its own — that is
/// the entire reason it exists. The admin-consent path upserts once per declared
/// resource, so a read inside the call is an N+1 in the resource count. Only the
/// PATCH is mocked here: any GET would fall through to wiremock's 404 and fail
/// the upsert, so a reintroduced read cannot pass silently.
#[tokio::test]
async fn upsert_admin_oauth2_grant_in_reads_no_grants_of_its_own() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/oauth2PermissionGrants/g-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "scope": "User.Read email"
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let existing = vec![
        // A grant on a DIFFERENT resource must not be matched…
        azapptoolkit_core::models::OAuth2PermissionGrant {
            id: Some("g-other".into()),
            client_id: "sp-client".into(),
            resource_id: "sp-exchange".into(),
            consent_type: "AllPrincipals".into(),
            principal_id: None,
            scope: "Mail.Read".into(),
        },
        // …nor a user-consent grant on the right one.
        azapptoolkit_core::models::OAuth2PermissionGrant {
            id: Some("g-user".into()),
            client_id: "sp-client".into(),
            resource_id: "sp-graph".into(),
            consent_type: "Principal".into(),
            principal_id: Some("u-1".into()),
            scope: "openid".into(),
        },
        azapptoolkit_core::models::OAuth2PermissionGrant {
            id: Some("g-1".into()),
            client_id: "sp-client".into(),
            resource_id: "sp-graph".into(),
            consent_type: "AllPrincipals".into(),
            principal_id: None,
            scope: "User.Read".into(),
        },
    ];
    let client = make_client(&server.uri());
    let grant = client
        .upsert_admin_oauth2_grant_in("sp-client", "sp-graph", &["email"], &existing)
        .await
        .unwrap();
    assert_eq!(grant.id.as_deref(), Some("g-1"));
    assert!(grant.scope.split_whitespace().any(|s| s == "email"));
}

/// With no matching grant in the pre-read list, the variant creates one — and
/// still makes no read.
#[tokio::test]
async fn upsert_admin_oauth2_grant_in_creates_when_the_pre_read_list_has_no_match() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2PermissionGrants"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "grant-new",
            "clientId": "sp-client",
            "resourceId": "sp-graph",
            "consentType": "AllPrincipals",
            "scope": "User.Read"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let grant = client
        .upsert_admin_oauth2_grant_in("sp-client", "sp-graph", &["User.Read"], &[])
        .await
        .unwrap();
    assert_eq!(grant.id.as_deref(), Some("grant-new"));
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

/// The tenant-wide grant matrices are cached, so a second read must not hit
/// Graph. `expect(1)` on the mock is the assertion.
#[tokio::test]
async fn tenant_wide_grant_reads_are_cached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2PermissionGrants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "grant-1",
                "clientId": "sp-1",
                "resourceId": "sp-graph",
                "consentType": "AllPrincipals",
                "scope": "User.Read"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    assert_eq!(client.list_all_oauth2_grants().await.unwrap().len(), 1);
    assert_eq!(client.list_all_oauth2_grants().await.unwrap().len(), 1);
}

/// The invariant that makes caching a security-posture read safe: any grant
/// WRITE drops the cached matrices, so a revoked grant can never keep rendering
/// as present. Pinned here rather than trusted to seven command call sites —
/// this is why the invalidation lives in the client (see `invalidate_grant_cache`).
#[tokio::test]
async fn a_grant_write_invalidates_the_cached_matrices() {
    let server = MockServer::start().await;
    // Two reads are expected: the cold one, then the re-read after the write.
    Mock::given(method("GET"))
        .and(path("/oauth2PermissionGrants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "grant-1",
                "clientId": "sp-1",
                "resourceId": "sp-graph",
                "consentType": "AllPrincipals",
                "scope": "User.Read"
            }]
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/oauth2PermissionGrants/grant-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    client.list_all_oauth2_grants().await.unwrap();
    client.delete_oauth2_grant("grant-1").await.unwrap();
    // Cache was swept by the delete, so this re-reads rather than serving stale.
    client.list_all_oauth2_grants().await.unwrap();
}

/// The sweep is scoped to the `grants:` segment, so it must NOT evict the
/// sign-in-activity report that shares `CacheKind::Permissions` — that is a slow
/// beta endpoint and dumping it on every grant write would be a bad trade.
#[tokio::test]
async fn the_grant_sweep_spares_the_sign_in_activity_cache() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/reports/servicePrincipalSignInActivities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "appId": "app-1", "lastSignInActivity": null }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/oauth2PermissionGrants/grant-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_audit_log_token(StaticTokenProvider::new("a"));
    client
        .list_service_principal_sign_in_activities()
        .await
        .unwrap();
    client.delete_oauth2_grant("grant-1").await.unwrap();
    // Still cached — the `expect(1)` above fails if the sweep was over-broad.
    client
        .list_service_principal_sign_in_activities()
        .await
        .unwrap();
}
