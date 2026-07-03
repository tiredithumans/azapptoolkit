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
