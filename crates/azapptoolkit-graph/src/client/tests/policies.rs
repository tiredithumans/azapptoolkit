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
