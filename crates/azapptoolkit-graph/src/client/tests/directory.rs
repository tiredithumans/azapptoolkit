use super::super::*;
use super::common::*;

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
async fn me_active_directory_roles_extracts_names_and_template_ids() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me/transitiveMemberOf/microsoft.graph.directoryRole"))
        // `id` must stay in the $select: Graph returns only the selected
        // properties and ActiveDirectoryRole requires `id` to deserialize.
        // `roleTemplateId` is what consumers match on — directoryRole objects
        // can carry legacy display names ("SharePoint Service Administrator").
        .and(query_param("$select", "id,displayName,roleTemplateId"))
        // The OData cast is an advanced query: Graph 400s without both the
        // header and $count=true, so the mock pins them.
        .and(query_param("$count", "true"))
        .and(header("consistencylevel", "eventual"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {
                    "id": "r1",
                    "displayName": "Cloud Application Administrator",
                    "roleTemplateId": "158c047a-c907-4556-b7ef-446551a6b5f7"
                },
                {
                    "id": "r2",
                    "displayName": "SharePoint Service Administrator",
                    "roleTemplateId": "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let roles = client.me_active_directory_roles().await.unwrap();
    assert_eq!(roles.len(), 2);
    assert_eq!(
        roles[0].display_name.as_deref(),
        Some("Cloud Application Administrator")
    );
    assert_eq!(
        roles[0].role_template_id.as_deref(),
        Some("158c047a-c907-4556-b7ef-446551a6b5f7")
    );
    // The legacy-named row still carries the immutable template id.
    assert_eq!(
        roles[1].display_name.as_deref(),
        Some("SharePoint Service Administrator")
    );
    assert_eq!(
        roles[1].role_template_id.as_deref(),
        Some("f28a1f50-f6e7-4571-818b-6a12f2af6b6c")
    );
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
