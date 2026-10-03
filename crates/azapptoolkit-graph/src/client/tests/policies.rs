use super::super::*;
use super::common::*;

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

#[tokio::test]
async fn update_claims_policy_patches_only_the_definition() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/policies/claimsMappingPolicies/pol-1"))
        .and(header("authorization", "Bearer pw"))
        // Only `definition`: Graph keeps every property not sent (displayName).
        .and(wiremock::matchers::body_json(serde_json::json!({
            "definition": ["{\"x\":1}"]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_policy_write_token(StaticTokenProvider::new("pw"));
    client
        .update_claims_mapping_policy("pol-1", "{\"x\":1}")
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_claims_policy_deletes_the_object_not_the_ref() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/policies/claimsMappingPolicies/pol-1"))
        .and(header("authorization", "Bearer pw"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_policy_write_token(StaticTokenProvider::new("pw"));
    client.delete_claims_mapping_policy("pol-1").await.unwrap();
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests.iter().all(|r| !r.url.path().ends_with("$ref")),
        "a policy delete is not an unassign"
    );
}

#[tokio::test]
async fn policy_subjects_send_top_and_follow_next_link() {
    let server = MockServer::start().await;
    let next = format!(
        "{}/policies/claimsMappingPolicies/pol-1/appliesTo?$skiptoken=2",
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/policies/claimsMappingPolicies/pol-1/appliesTo"))
        .and(wiremock::matchers::query_param("$skiptoken", "2"))
        .and(header("authorization", "Bearer pw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "app-obj-1"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/policies/claimsMappingPolicies/pol-1/appliesTo"))
        .and(wiremock::matchers::query_param("$top", "999"))
        .and(wiremock::matchers::query_param("$select", "id"))
        .and(header("authorization", "Bearer pw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "sp-1"}],
            "@odata.nextLink": next,
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_policy_write_token(StaticTokenProvider::new("pw"));
    let subjects = client
        .list_claims_mapping_policy_subjects("pol-1")
        .await
        .unwrap();
    assert_eq!(subjects, vec!["sp-1".to_string(), "app-obj-1".to_string()]);
}

#[tokio::test]
async fn default_app_management_policy_parses_and_caches() {
    let server = MockServer::start().await;
    // Payload mirrors a real tenantAppManagementPolicy, unknown members
    // included (`@odata.type`, `servicePrincipalRestrictions`) — the model must
    // tolerate them. `restrictForAppsCreatedAfterDateTime: null` = retroactive.
    Mock::given(method("GET"))
        .and(path("/policies/defaultAppManagementPolicy"))
        .and(header("authorization", "Bearer policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "default-policy",
            "displayName": null,
            "isEnabled": true,
            "applicationRestrictions": {
                "@odata.type": "#microsoft.graph.appManagementApplicationConfiguration",
                "keyCredentials": [],
                "passwordCredentials": [
                    {"restrictionType": "passwordAddition", "state": "disabled"},
                    {
                        "restrictionType": "passwordLifetime",
                        "state": "enabled",
                        "maxLifetime": "P90D",
                        "restrictForAppsCreatedAfterDateTime": null
                    }
                ]
            },
            "servicePrincipalRestrictions": {
                "@odata.type": "#microsoft.graph.appManagementServicePrincipalConfiguration",
                "keyCredentials": [],
                "passwordCredentials": []
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_policy_token(StaticTokenProvider::new("policy"));
    let first = client.get_default_app_management_policy().await.unwrap();
    let policy = first.expect("policy present");
    assert!(policy.is_enabled);
    let secrets = &policy
        .application_restrictions
        .unwrap()
        .password_credentials;
    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[1].max_lifetime.as_deref(), Some("P90D"));
    assert!(
        secrets[1]
            .restrict_for_apps_created_after_date_time
            .is_none()
    );
    // Read-through cache: the second call never touches the mock.
    let second = client.get_default_app_management_policy().await.unwrap();
    assert_eq!(second.unwrap().id, "default-policy");
}

#[tokio::test]
async fn absent_default_app_management_policy_reads_as_none() {
    let server = MockServer::start().await;
    // A tenant that never touched the feature answers 404 — an ordinary empty
    // answer, not a failure (CA-collection precedent).
    Mock::given(method("GET"))
        .and(path("/policies/defaultAppManagementPolicy"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_policy_token(StaticTokenProvider::new("policy"));
    assert!(
        client
            .get_default_app_management_policy()
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn app_management_policy_reads_without_token_are_forbidden() {
    let client = make_client("http://127.0.0.1:0");
    let err = client
        .get_default_app_management_policy()
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)), "got {err:?}");
    let err = client.list_app_management_policies().await.unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)), "got {err:?}");
    let err = client
        .list_app_management_policies_for_app("obj-1")
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)), "got {err:?}");
}

#[tokio::test]
async fn custom_app_management_policies_expand_targets_and_degrade() {
    let server = MockServer::start().await;
    // Collection read carries the `appliesTo` targets…
    Mock::given(method("GET"))
        .and(path("/policies/appManagementPolicies"))
        .and(wiremock::matchers::query_param("$expand", "appliesTo"))
        .and(wiremock::matchers::query_param("$top", "999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "custom-1",
                "displayName": "Strict secrets",
                "isEnabled": true,
                "restrictions": {
                    "@odata.type": "#microsoft.graph.customAppManagementConfiguration",
                    "passwordCredentials": [{
                        "restrictionType": "passwordLifetime",
                        "state": "enabled",
                        "maxLifetime": "P30D"
                    }]
                },
                "appliesTo": [{
                    "id": "app-obj-1",
                    "@odata.type": "#microsoft.graph.application"
                }]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    // …the per-app nav read does not.
    Mock::given(method("GET"))
        .and(path("/applications/app-obj-1/appManagementPolicies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "custom-1",
                "displayName": "Strict secrets",
                "isEnabled": true,
                "restrictions": {
                    "applicationRestrictions": {
                        "passwordCredentials": [{
                            "restrictionType": "passwordLifetime",
                            "state": "enabled",
                            "maxLifetime": "P30D"
                        }]
                    }
                }
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_policy_token(StaticTokenProvider::new("policy"));
    let policies = client.list_app_management_policies().await.unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].applies_to[0].id, "app-obj-1");
    // Second call served from cache (mock .expect(1)).
    assert_eq!(
        client.list_app_management_policies().await.unwrap().len(),
        1
    );

    let for_app = client
        .list_app_management_policies_for_app("app-obj-1")
        .await
        .unwrap();
    assert_eq!(for_app.len(), 1);
    let restrictions = for_app[0].restrictions.as_ref().unwrap();
    assert_eq!(restrictions.password_entries().count(), 1);
}

#[tokio::test]
async fn missing_app_management_policy_collection_reads_as_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/policies/appManagementPolicies"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-x/appManagementPolicies"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_policy_token(StaticTokenProvider::new("policy"));
    assert!(
        client
            .list_app_management_policies()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        client
            .list_app_management_policies_for_app("obj-x")
            .await
            .unwrap()
            .is_empty()
    );
}
