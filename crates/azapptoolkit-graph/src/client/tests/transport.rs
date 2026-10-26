use super::super::transport::{map_error_status, parse_claims_challenge};
use super::super::*;
use super::common::*;

/// The request body is serialized ONCE, outside the retry loop, and replayed on
/// each attempt as `Bytes`. This pins the two things that refactor could break:
/// a retried write must send the byte-identical body again (not an empty one),
/// and it must still carry `Content-Type: application/json` — which now comes
/// from the header map rather than from `RequestBuilder::json`.
#[tokio::test]
async fn a_retried_write_replays_the_same_body_and_content_type() {
    let server = MockServer::start().await;
    let body = serde_json::json!({ "displayName": "Renamed App" });
    // Both mocks match on the body + header, so an attempt that dropped either
    // falls through to wiremock's 404 and fails the call.
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(body.clone()))
        .and(header("content-type", "application/json"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("throttled"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(body.clone()))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    client
        .patch_application_web("obj-1", &body)
        .await
        .expect("the retried PATCH resends the same body");
}

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
    let (items, truncated) = client
        .collect_all_pages_capped(page1, 3, false)
        .await
        .unwrap();
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
    let (items, truncated) = client
        .collect_all_pages_capped(page1, 100, false)
        .await
        .unwrap();
    assert_eq!(items.len(), 3);
    assert!(!truncated, "everything fit under the cap");
}

#[tokio::test]
async fn collect_all_pages_capped_stops_a_cyclic_next_link() {
    // A self-referential nextLink returning ROWS terminates at the cap. This is
    // the case the cap does cover — see the empty-page sibling below for the one
    // it does not.
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
    let (items, truncated) = client
        .collect_all_pages_capped(page1, 5, false)
        .await
        .unwrap();
    assert_eq!(items.len(), 5);
    assert!(truncated);
}

/// The item cap is **not** a cycle guard, which the old doc comment claimed.
/// Only a non-empty page advances toward it, so an empty page carrying a
/// `nextLink` spun without bound — and Graph legitimately returns exactly that
/// on filtered directory collections, which is what both callers of this helper
/// page through.
#[tokio::test]
async fn collect_all_pages_capped_stops_an_empty_page_cycle() {
    let server = MockServer::start().await;
    let base = server.uri();
    let cycle = format!("{base}/sp?cycle=1");
    Mock::given(method("GET"))
        .and(path("/sp"))
        .and(query_param("cycle", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": cycle,
            // Empty — so `out.len()` never grows and the cap is never reached.
            "value": []
        })))
        .mount(&server)
        .await;

    let client = make_client(&base);
    let page1 = Paged::<serde_json::Value> {
        items: vec![serde_json::json!(0)],
        next_link: Some(cycle.clone()),
        total_count: None,
    };
    // Terminates via MAX_PAGES. Degrades rather than erroring, matching this
    // helper's contract — before the page guard this call never returned.
    let (items, truncated) = client
        .collect_all_pages_capped(page1, 5, false)
        .await
        .unwrap();
    assert_eq!(items.len(), 1, "only the caller's first page had rows");
    assert!(
        truncated,
        "a run cut short by the page guard is not full coverage"
    );
}

#[tokio::test]
async fn get_json_absolute_rejects_foreign_origin() {
    let server = MockServer::start().await;
    let client = make_client(&server.uri());
    let err = client
        .get_json_absolute_with::<serde_json::Value>(
            "https://evil.example.com/v1.0/applications",
            false,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Protocol(_)));
}

#[tokio::test]
async fn collect_pages_from_capped_refuses_a_foreign_next_link() {
    // The scoped follower checks the origin BEFORE handing the link to the
    // closure, which is what attaches the scoped bearer — so the closure must
    // never run for a foreign link.
    let client = make_client("https://graph.microsoft.com/v1.0");
    let first = Paged {
        items: vec![1],
        next_link: Some("https://evil.example.com/x".into()),
        total_count: None,
    };
    let err = client
        .collect_pages_from_capped(first, 10, |_url: String| async move {
            panic!("a foreign nextLink must never reach the fetch closure")
        })
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Protocol(_)), "got {err:?}");
}

#[tokio::test]
async fn get_json_optional_maps_only_404_to_none() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/things/gone"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/things/here"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "x"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/things/denied"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());

    let gone = client
        .get_json_optional::<serde_json::Value>("/things/gone", &[])
        .await
        .expect("a 404 is the object having vanished, not an error");
    assert!(gone.is_none());

    let here = client
        .get_json_optional::<serde_json::Value>("/things/here", &[])
        .await
        .unwrap();
    assert_eq!(here.unwrap()["id"], "x");

    let denied = client
        .get_json_optional::<serde_json::Value>("/things/denied", &[])
        .await
        .expect_err("a 403 must stay an error, never read as a vanished object");
    assert!(matches!(denied, GraphError::Forbidden(_)), "got {denied:?}");
}

/// A throttle observer that only counts how often it was notified.
struct Counter(std::sync::atomic::AtomicUsize);
impl Counter {
    fn new() -> Arc<Self> {
        Arc::new(Self(std::sync::atomic::AtomicUsize::new(0)))
    }
    fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl ThrottleObserver for Counter {
    fn on_throttle(&self, _retry_after_secs: Option<u64>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn throttle_observer_fires_on_429() {
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

    let counter = Counter::new();
    let client = make_client(&server.uri());
    client.set_throttle_observer(counter.clone());
    client.get_organization().await.unwrap();
    assert_eq!(counter.count(), 2);
}

/// Mounts one 429 (`Retry-After: 0`) followed by a 200 on `/organization`,
/// replacing whatever the server held so an exhausted 429 mock can't shadow
/// the re-mount.
async fn mount_one_429_then_ok(server: &MockServer) {
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("throttled"),
        )
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_org_json()))
        .mount(server)
        .await;
}

/// The observer slot is single, so a second fan-out attaching on the same
/// per-tenant client displaces the first — but a finishing run must detach
/// only its OWN tracker. Before, `clear_throttle_observer` wiped whichever
/// observer was installed, leaving the surviving run with a fixed cap and no
/// back-off for the rest of its life.
#[tokio::test]
async fn clear_throttle_observer_detaches_only_its_own_observer() {
    let server = MockServer::start().await;
    let client = make_client(&server.uri());
    let a = Counter::new();
    let b = Counter::new();
    let a_obs: Arc<dyn ThrottleObserver> = a.clone();
    let b_obs: Arc<dyn ThrottleObserver> = b.clone();

    // Phase 1: b displaces a; only the installed observer is notified.
    client.set_throttle_observer(a_obs.clone());
    client.set_throttle_observer(b_obs.clone());
    mount_one_429_then_ok(&server).await;
    client.get_organization().await.unwrap();
    assert_eq!(a.count(), 0, "displaced observer is not notified");
    assert_eq!(b.count(), 1);

    // Phase 2: a's detach is a no-op because a is no longer installed — b
    // stays attached and keeps seeing 429s.
    assert!(!client.clear_throttle_observer(&a_obs));
    mount_one_429_then_ok(&server).await;
    client.get_organization().await.unwrap();
    assert_eq!(b.count(), 2, "a's detach must not remove b");

    // Phase 3: b's own detach works, after which nothing is notified.
    assert!(client.clear_throttle_observer(&b_obs));
    mount_one_429_then_ok(&server).await;
    client.get_organization().await.unwrap();
    assert_eq!(b.count(), 2, "detached observer is no longer notified");
    assert_eq!(a.count(), 0);
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

/// The retrying core keeps its own inline status match (it also decides retry
/// vs done and catches the CAE challenge), while the one-shot scoped read and
/// every `$batch` sub-response go through `map_error_status`. Both must give
/// the same answer for every error status, or one Graph failure would type
/// differently depending on the path that fetched it. A retried status runs
/// out the budget (`Retry-After: 0` keeps that instant) and must then surface
/// as the same variant `map_error_status` names.
#[tokio::test]
async fn the_retrying_core_and_map_error_status_agree_on_every_error_status() {
    let server = MockServer::start().await;
    let body = r#"{"error":{"code":"x","message":"nope"}}"#;
    let statuses: [u16; 14] = [
        400, 401, 403, 404, 405, 409, 412, 422, 429, 500, 501, 502, 503, 504,
    ];
    for status in statuses {
        Mock::given(method("GET"))
            .and(path(format!("/applications/s{status}")))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Retry-After", "0")
                    .set_body_string(body),
            )
            .mount(&server)
            .await;
    }
    let client = make_client(&server.uri());
    for status in statuses {
        let retried = client
            .get_application(&format!("s{status}"))
            .await
            .unwrap_err();
        let table = map_error_status(status, body.to_string(), Some(0));
        assert_eq!(format!("{retried:?}"), format!("{table:?}"), "{status}");
    }
}

/// Returns the base token normally, a distinct token when re-minted for a
/// claims challenge — so a mock can assert which one was used.
struct CaeProvider;
#[async_trait::async_trait]
impl azapptoolkit_core::token::BearerProvider for CaeProvider {
    // `Result` is shadowed by the crate's alias in this module; qualify it.
    async fn bearer(&self) -> std::result::Result<String, azapptoolkit_core::token::TokenError> {
        Ok("tok".into())
    }
    async fn bearer_with_claims(
        &self,
        _claims: &str,
    ) -> std::result::Result<String, azapptoolkit_core::token::TokenError> {
        Ok("tok-cae".into())
    }
}

/// A [`GraphClient`] whose read and write tokens are both [`CaeProvider`].
fn cae_client(base: String) -> GraphClient {
    let provider: Arc<dyn azapptoolkit_core::token::BearerProvider> = Arc::new(CaeProvider);
    GraphClient::with_base_url(
        "tenant-test",
        provider.clone(),
        provider,
        Cache::new(),
        base,
    )
}

#[tokio::test]
async fn cae_claims_challenge_triggers_one_remint_and_retry() {
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

    let client = cae_client(server.uri());
    let app = client.get_application("obj-1").await.unwrap();
    assert_eq!(app.id, "obj-1");
}

/// The CAE re-mint happens at most once per request. A resource that still
/// challenges the re-minted token must surface `Unauthorized` after exactly
/// two requests — the once-only guard is what stops a persistent 401 from
/// looping through `bearer_with_claims` forever.
#[tokio::test]
async fn cae_remints_only_once() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "WWW-Authenticate",
            r#"Bearer realm="", error="insufficient_claims", claims="eyJhIjoxfQ""#,
        ))
        .expect(2)
        .mount(&server)
        .await;

    let client = cae_client(server.uri());
    let err = client.get_application("obj-1").await.unwrap_err();
    assert!(matches!(err, GraphError::Unauthorized), "got {err:?}");
}

/// Mints the base token, then fails the claims re-mint with `code` — the
/// shape a dead session, a step-up or an unreachable token endpoint takes
/// at the CAE re-mint.
struct FailingRemintProvider(&'static str);
#[async_trait::async_trait]
impl azapptoolkit_core::token::BearerProvider for FailingRemintProvider {
    async fn bearer(&self) -> std::result::Result<String, azapptoolkit_core::token::TokenError> {
        Ok("tok".into())
    }
    async fn bearer_with_claims(
        &self,
        _claims: &str,
    ) -> std::result::Result<String, azapptoolkit_core::token::TokenError> {
        Err(azapptoolkit_core::token::TokenError::new(
            self.0,
            "re-mint failed",
        ))
    }
}

/// A failed CAE re-mint keeps the classification the token layer gave it, so
/// the operator gets that failure's lever (Re-authenticate, Verify identity,
/// a transient Retry) instead of a "Refresh token" that cannot fix it. Only an
/// unclassified failure is the bare rejected-token 401.
#[tokio::test]
async fn a_failed_cae_remint_keeps_the_classified_token_error() {
    for (code, want) in [
        ("refresh_missing", "refresh_missing"),
        ("not_signed_in", "not_signed_in"),
        ("interaction_required", "interaction_required"),
        ("consent_required", "consent_required"),
        ("network_error", "network_error"),
        ("token_error", "unauthorized"),
        ("something_new", "unauthorized"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-1"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "WWW-Authenticate",
                r#"Bearer realm="", error="insufficient_claims", claims="eyJhIjoxfQ""#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let provider: Arc<dyn azapptoolkit_core::token::BearerProvider> =
            Arc::new(FailingRemintProvider(code));
        let client = GraphClient::with_base_url(
            "tenant-test",
            provider.clone(),
            provider,
            Cache::new(),
            server.uri(),
        );
        let err = client.get_application("obj-1").await.unwrap_err();
        assert_eq!(err.ui_code(), want, "{code}: {err:?}");
        // The fatal ones are what stop a long-running fan-out.
        assert_eq!(
            matches!(&err, GraphError::Token(t) if t.is_reauth_fatal()),
            azapptoolkit_core::reauth::is_reauth_fatal(code),
            "{code}"
        );
    }
}

// ── Retry class, end to end ────────────────────────────────────────────────
// `retry_class_for` decides whether a request whose outcome is unknown may be
// replayed. The policy itself is unit-tested in `core::http_retry`; these pin
// the graph-side mapping, so a POST routed as idempotent (or a `retry_class_for`
// edit) fails here rather than minting duplicate credentials in production.

/// The `addPassword` double-mint that commit 8fb1ac7 fixed: a 502 on a POST
/// may have committed server-side, and replaying it mints a second secret the
/// operator never sees the plaintext of. The POST is sent exactly once.
#[tokio::test]
async fn add_password_is_not_replayed_after_a_502() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/addPassword"))
        .respond_with(
            ResponseTemplate::new(502)
                .insert_header("Retry-After", "0")
                .set_body_string("bad gateway"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let err = client
        .add_password("obj-1", "x", std::time::Duration::from_secs(86400))
        .await
        .unwrap_err();
    assert!(
        matches!(err, GraphError::Server { status: 502, .. }),
        "got {err:?}"
    );
}

/// A GET is idempotent, so a transient 5xx is ridden out.
#[tokio::test]
async fn an_idempotent_get_is_replayed_after_a_502() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organization"))
        .respond_with(
            ResponseTemplate::new(502)
                .insert_header("Retry-After", "0")
                .set_body_string("bad gateway"),
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

/// The `$batch` POST wraps only GETs, so it states `RetryClass::Idempotent`
/// explicitly instead of taking the class from its verb — a 502 on the outer
/// POST is replayed like the reads it carries.
#[tokio::test]
async fn the_batch_post_is_replayed_after_a_502() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(
            ResponseTemplate::new(502)
                .insert_header("Retry-After", "0")
                .set_body_string("bad gateway"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [{ "id": "0", "status": 200, "body": { "id": "sp-0" } }]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let out: Vec<Result<serde_json::Value>> = client
        .batch_get_json(&["/servicePrincipals/sp-0".to_string()])
        .await
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].as_ref().unwrap()["id"], "sp-0");
}

// ── Scoped writes ride the retry loop ──────────────────────────────────────
// Group membership, SharePoint grants and claims policies need their own
// tokens, but they are no longer one-shot: the DR restore re-adds group
// memberships in a loop and a multi-target SharePoint grant loops over sites
// and lists, so a 429 must be waited out, not recorded as a failure.

#[tokio::test]
async fn a_scoped_write_rides_out_a_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/groups/g-1/members/$ref"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("throttled"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/groups/g-1/members/$ref"))
        .and(header("authorization", "Bearer gm-tok"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let counter = Counter::new();
    let client =
        make_client(&server.uri()).with_group_member_token(StaticTokenProvider::new("gm-tok"));
    client.set_throttle_observer(counter.clone());
    client
        .add_group_member("g-1", "sp-1")
        .await
        .expect("the scoped POST is replayed after a 429");
    assert_eq!(
        counter.count(),
        1,
        "a scoped 429 reaches the throttle observer"
    );
}

/// A scoped POST that creates something is still never replayed after a 5xx —
/// a second site grant is not a harmless duplicate.
#[tokio::test]
async fn a_scoped_post_is_not_replayed_after_a_502() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sites/site-1/permissions"))
        .respond_with(
            ResponseTemplate::new(502)
                .insert_header("Retry-After", "0")
                .set_body_string("bad gateway"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let err = client
        .grant_site_permission("site-1", "app-1", "Demo", &["read".to_string()])
        .await
        .unwrap_err();
    assert!(
        matches!(err, GraphError::Server { status: 502, .. }),
        "got {err:?}"
    );
}

/// The class comes from the verb, not a hardcoded `NonIdempotent`: a scoped
/// DELETE is idempotent, so it is replayed after a 5xx like an unscoped one.
#[tokio::test]
async fn a_scoped_delete_is_replayed_after_a_503() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/sites/site-1/permissions/perm-1"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "0")
                .set_body_string("unavailable"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/sites/site-1/permissions/perm-1"))
        .and(header("authorization", "Bearer sp"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    client
        .remove_site_permission("site-1", "perm-1")
        .await
        .expect("the scoped DELETE is replayed after a 503");
}

/// `{"value":[{"id":"sp-1","appId":"app-1","displayName":"one"}]}`, gzipped
/// (`mtime = 0`, so the bytes are stable).
const GZIPPED_ONE_SP_PAGE: [u8; 73] = [
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xab, 0x56, 0x2a, 0x4b, 0xcc, 0x29,
    0x4d, 0x55, 0xb2, 0x8a, 0xae, 0x56, 0xca, 0x4c, 0x51, 0xb2, 0x52, 0x2a, 0x2e, 0xd0, 0x35, 0x54,
    0xd2, 0x51, 0x4a, 0x2c, 0x28, 0xf0, 0x04, 0x71, 0x81, 0x34, 0x98, 0x9f, 0x92, 0x59, 0x5c, 0x90,
    0x93, 0x58, 0xe9, 0x97, 0x98, 0x0b, 0x54, 0xab, 0x94, 0x9f, 0x97, 0xaa, 0x54, 0x1b, 0x5b, 0x0b,
    0x00, 0xd0, 0x88, 0x1a, 0x9f, 0x3d, 0x00, 0x00, 0x00,
];

/// Graph reads ask for a compressed body and inflate it transparently. A cold
/// launch pages the whole tenant, and a 999-row `/applications` page selecting
/// the credential arrays is megabytes of raw JSON; without the workspace
/// `gzip` feature every byte of it crossed the wire uncompressed.
#[tokio::test]
async fn graph_reads_ask_for_and_inflate_a_gzipped_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(|req: &wiremock::Request| {
            req.headers
                .get("accept-encoding")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(',').any(|enc| enc.trim() == "gzip"))
        })
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .insert_header("content-type", "application/json")
                .set_body_bytes(GZIPPED_ONE_SP_PAGE.to_vec()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(sps.len(), 1, "the gzipped page did not decode");
    assert_eq!(sps[0].app_id, "app-1");
}

/// `{"value":"aaaa…"}` with 4096 `a`s, gzipped (`mtime = 0`): 54 bytes on the
/// wire, 4108 decoded.
const GZIPPED_4108_DECODED: [u8; 54] = [
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xed, 0xc1, 0x31, 0x11, 0x00, 0x20,
    0x0c, 0x04, 0x30, 0x2f, 0x2f, 0x03, 0x37, 0x1d, 0xd8, 0x58, 0x61, 0xe9, 0xe1, 0x1d, 0x1f, 0x5c,
    0x92, 0xce, 0xa9, 0xb5, 0x67, 0x46, 0x0a, 0x00, 0x00, 0x00, 0xf8, 0x5e, 0xee, 0x03, 0x7f, 0x5a,
    0x15, 0x48, 0x0c, 0x10, 0x00, 0x00,
];

/// A success body is capped by its DECODED size. reqwest inflates a gzip reply
/// and drops its `Content-Length`, so a body that fits the cap on the wire can
/// decode far past it; only the running total of decoded chunks catches that.
/// Past the cap is a `Protocol` error, sent once and never retried.
#[tokio::test]
async fn a_success_body_is_capped_by_its_decoded_size_not_its_wire_size() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .insert_header("content-type", "application/json")
                .set_body_bytes(GZIPPED_4108_DECODED.to_vec()),
        )
        // One capped read (never replayed) and one under the default cap.
        .expect(2)
        .mount(&server)
        .await;

    let capped = make_client(&server.uri()).with_max_body_bytes(1024);
    let err = capped
        .get_json::<serde_json::Value>("/applications/obj-1", &[], false)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, GraphError::Protocol(m) if m == "response body exceeds the 1 KiB limit"),
        "got {err:?}"
    );
    assert_eq!(err.ui_code(), "protocol_error");
    assert!(!err.is_retryable());

    // The same reply inflates and decodes under the default cap, so the
    // refusal above is the cap and not a broken fixture.
    let body: serde_json::Value = make_client(&server.uri())
        .get_json("/applications/obj-1", &[], false)
        .await
        .unwrap();
    assert_eq!(body["value"].as_str().map(str::len), Some(4096));
}
