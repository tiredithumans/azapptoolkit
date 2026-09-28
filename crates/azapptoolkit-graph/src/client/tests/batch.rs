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
async fn batch_get_applications_credentials_projects_secrets_and_keeps_input_order() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        // The sweep reads `passwordCredentials`; a projection that drops it
        // would make every app look secret-free and the sweep a silent no-op.
        .and(body_string_contains("passwordCredentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                // Reversed on purpose: results are matched by `id`, not position.
                { "id": "1", "status": 404, "body": { "error": { "message": "gone" } } },
                { "id": "0", "status": 200, "body": {
                    "id": "obj-0", "appId": "app-0", "displayName": "Zero",
                    "passwordCredentials": [{ "keyId": "k1", "endDateTime": "2020-01-01T00:00:00Z" }]
                } }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let ids = vec!["obj-0".to_string(), "obj-1".to_string()];
    let out = client
        .batch_get_applications_credentials(&ids)
        .await
        .unwrap();
    assert_eq!(out.len(), 2);
    let first = out[0].as_ref().unwrap();
    assert_eq!(first.id, "obj-0");
    assert_eq!(first.password_credentials.len(), 1);
    assert_eq!(first.password_credentials[0].key_id, "k1");
    // A vanished selected app is that id's own `Err`, not a hole in the vec.
    assert!(matches!(out[1], Err(GraphError::NotFound(_))));
}

#[tokio::test]
async fn batch_list_app_role_assigned_to_follows_nextlink_overflow() {
    let server = MockServer::start().await;
    // First (batched) page carries an `@odata.nextLink` (same-origin, so
    // `get_json_absolute_with` will follow it) — proving the overflow fallback runs.
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
        // Page 1 was a plain read, so the continuation must be one too — not
        // an advanced query served by the eventually-consistent index.
        .and(header_is_missing("consistencylevel"))
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

/// The overflow continuation of an advanced-query batch stays an advanced
/// query: Graph does not carry `ConsistencyLevel` into the `nextLink` request,
/// so page 2 must restate it or it is served by a different store than page 1.
#[tokio::test]
async fn batch_list_service_principal_groups_overflow_stays_an_advanced_query() {
    let server = MockServer::start().await;
    let next = format!(
        "{}/servicePrincipals/sp-0/memberOf/microsoft.graph.group?page=2",
        server.uri()
    );
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [{ "id": "0", "status": 200, "body": {
                "value": [{ "id": "g1", "displayName": "Group One" }],
                "@odata.nextLink": next,
            }}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/servicePrincipals/sp-0/memberOf/microsoft.graph.group",
        ))
        .and(query_param("page", "2"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "g2", "displayName": "Group Two" }]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let out = client
        .batch_list_service_principal_groups(&["sp-0".to_string()])
        .await
        .unwrap();
    let groups = out[0].as_ref().unwrap();
    assert_eq!(groups.len(), 2, "page 1 + the advanced-query page 2");
    assert_eq!(groups[1].id, "g2");
}

/// An inner 5xx is re-batched like an inner 429 — the same GET sent alone
/// would be retried, so a batched one must not fail where it would not.
#[tokio::test]
async fn batch_get_json_rebatches_an_inner_503_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                { "id": "0", "status": 200, "body": { "id": "sp-0" } },
                { "id": "1", "status": 503, "headers": { "Retry-After": "0" }, "body": {} }
            ]
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Only the failed sub-request is re-sent.
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [{ "id": "1", "status": 200, "body": { "id": "sp-1" } }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let counter = ThrottleCounter::new();
    let client = make_client(&server.uri());
    client.set_throttle_observer(counter.clone());
    let urls = vec![
        "/servicePrincipals/a".to_string(),
        "/servicePrincipals/b".to_string(),
    ];
    let out: Vec<Result<serde_json::Value>> = client.batch_get_json(&urls).await.unwrap();
    assert_eq!(out[0].as_ref().unwrap()["id"], "sp-0");
    assert_eq!(out[1].as_ref().unwrap()["id"], "sp-1");
    assert_eq!(
        counter.count(),
        0,
        "a 5xx is a failed request, not service pressure — the throttle stays put"
    );
}

/// A 5xx that outlasts the retry budget still surfaces as `Server`, and the
/// re-batch loop terminates rather than spinning.
#[tokio::test]
async fn batch_get_json_surfaces_an_exhausted_inner_503_as_server() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                { "id": "0", "status": 503, "headers": { "Retry-After": "0" }, "body": {} }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let out: Vec<Result<serde_json::Value>> = client
        .batch_get_json(&["/servicePrincipals/a".to_string()])
        .await
        .unwrap();
    assert!(
        matches!(out[0], Err(GraphError::Server { status: 503, .. })),
        "got {:?}",
        out[0]
    );
}

/// A sub-request the envelope never answered is that id's own `Protocol`
/// error, not a silently missing result or a shifted vec.
#[tokio::test]
async fn batch_get_json_reports_an_unanswered_sub_request_as_protocol() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [{ "id": "0", "status": 200, "body": { "id": "sp-0" } }]
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
    assert!(
        matches!(out[1], Err(GraphError::Protocol(_))),
        "got {:?}",
        out[1]
    );
}

/// A throttle observer that only counts how often it was notified.
struct ThrottleCounter(std::sync::atomic::AtomicUsize);
impl ThrottleCounter {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(std::sync::atomic::AtomicUsize::new(0)))
    }
    fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl ThrottleObserver for ThrottleCounter {
    fn on_throttle(&self, _retry_after_secs: Option<u64>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
