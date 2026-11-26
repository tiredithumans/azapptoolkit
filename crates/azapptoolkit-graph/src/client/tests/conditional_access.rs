use super::super::*;
use super::common::*;

fn ca_client(uri: &str) -> GraphClient {
    make_client(uri)
        .with_conditional_access_write_token(StaticTokenProvider::new("caw"))
        .with_policy_token(StaticTokenProvider::new("pol"))
        .with_audit_log_token(StaticTokenProvider::new("aud"))
}

#[tokio::test]
async fn create_ca_policy_posts_the_body_with_the_ca_write_token() {
    let server = MockServer::start().await;
    let body =
        serde_json::json!({ "displayName": "x", "state": "enabledForReportingButNotEnforced" });
    Mock::given(method("POST"))
        .and(path("/identity/conditionalAccess/policies"))
        .and(header("authorization", "Bearer caw"))
        .and(wiremock::matchers::body_json(body.clone()))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "pol-1", "displayName": "x", "state": "enabledForReportingButNotEnforced"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let created = ca_client(&server.uri())
        .create_ca_policy(&body)
        .await
        .unwrap();
    assert_eq!(created.id.as_deref(), Some("pol-1"));
}

#[tokio::test]
async fn set_ca_policy_state_patches_state_only() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/identity/conditionalAccess/policies/pol-1"))
        .and(header("authorization", "Bearer caw"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "state": "enabled" }),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    ca_client(&server.uri())
        .set_ca_policy_state("pol-1", "enabled")
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_ca_policy_uses_the_write_token() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/identity/conditionalAccess/policies/pol-1"))
        .and(header("authorization", "Bearer caw"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let client = ca_client(&server.uri());
    client.delete_ca_policy("pol-1").await.unwrap();
}

#[tokio::test]
async fn policy_id_is_shape_checked() {
    let client = ca_client("http://127.0.0.1:9");
    for result in [
        client.set_ca_policy_state("a/b", "enabled").await,
        client.delete_ca_policy("../x").await,
    ] {
        assert!(matches!(result, Err(GraphError::Protocol(_))), "{result:?}");
    }
}

#[tokio::test]
async fn create_ip_named_location_is_untrusted_with_typed_ranges() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/conditionalAccess/namedLocations"))
        .and(header("authorization", "Bearer caw"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "displayName": "Payroll egress",
            "isTrusted": false,
            "ipRanges": [
                { "@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "10.0.0.0/8" },
                { "@odata.type": "#microsoft.graph.iPv6CidrRange", "cidrAddress": "2001:db8::/32" }
            ]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "id": "loc-1", "displayName": "Payroll egress", "isTrusted": false,
            "ipRanges": [{ "cidrAddress": "10.0.0.0/8" }, { "cidrAddress": "2001:db8::/32" }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let loc = ca_client(&server.uri())
        .create_ip_named_location(
            "Payroll egress",
            &[
                (false, "10.0.0.0/8".to_string()),
                (true, "2001:db8::/32".to_string()),
            ],
        )
        .await
        .unwrap();
    assert_eq!(loc.id.as_deref(), Some("loc-1"));
    assert_eq!(loc.ip_ranges.len(), 2);
    assert_eq!(loc.is_trusted, Some(false));
}

#[tokio::test]
async fn list_named_locations_pages_with_top() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/identity/conditionalAccess/namedLocations"))
        .and(query_param("$top", "999"))
        .and(header("authorization", "Bearer pol"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "@odata.type": "#microsoft.graph.ipNamedLocation", "id": "loc-1", "displayName": "Office", "isTrusted": true, "ipRanges": [{ "cidrAddress": "10.0.0.0/8" }] },
                { "@odata.type": "#microsoft.graph.countryNamedLocation", "id": "loc-2", "displayName": "NL", "ipRanges": null }
            ]
        })))
        .mount(&server)
        .await;
    let locs = ca_client(&server.uri())
        .list_named_locations()
        .await
        .unwrap();
    assert_eq!(locs.len(), 2);
    assert_eq!(locs[1].ip_ranges.len(), 0, "null ranges tolerated");
    assert!(locs[0].is_ip());
    assert!(!locs[1].is_ip());
}

#[tokio::test]
async fn sp_sign_ins_filter_and_prefer_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/beta/auditLogs/signIns"))
        .and(header("authorization", "Bearer aud"))
        .and(header("prefer", "include-unknown-enum-members"))
        .and(wiremock::matchers::query_param_contains(
            "$filter",
            "signInEventTypes/any",
        ))
        .and(wiremock::matchers::query_param_contains(
            "$filter",
            "appId eq '11111111-1111-1111-1111-111111111111'",
        ))
        .and(wiremock::matchers::query_param_contains(
            "$filter",
            "createdDateTime ge 2026-11-18T00:00:00Z ",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "createdDateTime": "2026-11-24T10:00:00Z",
                "ipAddress": "203.0.113.7",
                "appliedConditionalAccessPolicies": [
                    { "id": "pol-1", "displayName": "lock", "result": "reportOnlyFailure" }
                ]
            }]
        })))
        .mount(&server)
        .await;
    let uri = format!("{}/v1.0", server.uri());
    let client = ca_client(&uri);
    // Sub-second precision is dropped: Graph's documented filters use whole seconds.
    let since: jiff::Timestamp = "2026-11-18T00:00:00.123456789Z".parse().unwrap();
    let (rows, truncated) = client
        .list_service_principal_sign_ins("11111111-1111-1111-1111-111111111111", since)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!truncated);
    assert_eq!(rows[0].ip_address.as_deref(), Some("203.0.113.7"));
    assert_eq!(
        rows[0].applied_conditional_access_policies[0]
            .result
            .as_deref(),
        Some("reportOnlyFailure")
    );
}
