use super::super::transport::parse_claims_challenge;
use super::super::*;
use super::common::*;

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

#[test]
fn search_phrase_neutralizes_embedded_quotes() {
    // `$search` has no quote escape — an embedded `"` would end the phrase
    // early and make Graph reject the request, so it becomes a space.
    assert_eq!(
        search_phrase("displayName", "Contoso"),
        "\"displayName:Contoso\""
    );
    assert_eq!(
        search_phrase("displayName", "Cont\"oso"),
        "\"displayName:Cont oso\""
    );
}

#[test]
fn escape_odata_doubles_single_quotes() {
    assert_eq!(escape_odata("O'Brien"), "O''Brien");
    assert_eq!(escape_odata("alice"), "alice");
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

// `same_origin` (incl. the embedded-credentials rejection) is unit-tested at
// its single-sourced home, `azapptoolkit_core::net`; the origin-guard
// *behavior* stays pinned here by the nextLink tests above.
#[tokio::test]
async fn scoped_one_shot_maps_429_to_throttled_without_retry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/sp-1/synchronization/jobs"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "7")
                .set_body_string("busy"),
        )
        // One-shot contract: the scoped transport degrades fast, no retry —
        // but the *error* must still be the typed `Throttled` (ui code
        // `throttled`, retryable) the retrying transport returns, not a
        // generic `Api { status: 429 }`.
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sync_token(StaticTokenProvider::new("sync"));
    let err = client.list_synchronization_jobs("sp-1").await.unwrap_err();
    assert!(
        matches!(
            err,
            GraphError::Throttled {
                retry_after_secs: Some(7)
            }
        ),
        "got {err:?}"
    );
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
