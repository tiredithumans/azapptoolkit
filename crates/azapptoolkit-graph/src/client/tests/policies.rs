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
