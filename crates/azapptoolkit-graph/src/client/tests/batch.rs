use super::super::*;
use super::common::*;

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
