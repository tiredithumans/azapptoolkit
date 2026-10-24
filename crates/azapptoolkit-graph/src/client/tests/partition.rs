//! Partitioned tenant-wide scans (`partition.rs`) against a mock Graph: when a
//! collection is sliced, that every slice is read once and merged in prefix
//! order, and that every way slicing can go wrong ends in the serial read
//! rather than a short list.

use super::super::*;
use super::common::*;

const PREFIXES: &str = "0123456789abcdef";

/// `n` service principals in the `prefix` slice: ids `sp-{prefix}{i}`, appIds
/// GUID-shaped and starting with `prefix`.
fn slice_rows(prefix: char, n: usize) -> Vec<serde_json::Value> {
    (0..n)
        .map(|i| {
            serde_json::json!({
                "id": format!("sp-{prefix}{i}"),
                "appId": format!("{prefix}{i:07}-0000-0000-0000-000000000000"),
                "displayName": format!("{prefix}{i}"),
            })
        })
        .collect()
}

/// Page one of the unfiltered read: the first two rows of slice `0`, and a
/// `nextLink` (so the tenant spans more than one page).
async fn mount_probe(server: &MockServer) {
    let next = format!("{}/servicePrincipals?page=2", server.uri());
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$top", MAX_PAGE_SIZE))
        .and(query_param_is_missing("$filter"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": next,
            "value": slice_rows('0', 2),
        })))
        .mount(server)
        .await;
}

/// The rest of the 48-row tenant after the probe page: what the serial
/// path's continuation holds.
fn serial_rest_rows() -> Vec<serde_json::Value> {
    PREFIXES
        .chars()
        .flat_map(|p| slice_rows(p, 3))
        .skip(2)
        .collect()
}

/// Page two of the unfiltered read: the serial path's continuation, holding
/// the rest of the 48-row tenant.
async fn mount_serial_rest(server: &MockServer, hits: u64) {
    mount_serial_rest_rows(server, hits, serial_rest_rows()).await;
}

/// Page two of the unfiltered read with the given rows.
async fn mount_serial_rest_rows(server: &MockServer, hits: u64, rest: Vec<serde_json::Value>) {
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("page", "2"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": rest })),
        )
        .expect(hits)
        .mount(server)
        .await;
}

async fn mount_count(server: &MockServer, count: u64) {
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/$count"))
        .and(header("consistencylevel", "eventual"))
        // Graph's `$count` is text/plain, sometimes behind a byte-order mark.
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("\u{feff}{count}")))
        .mount(server)
        .await;
}

/// Each plain slice answers with three rows of its own prefix, and must be
/// asked for exactly `hits` times.
async fn mount_plain_slices(server: &MockServer, hits: u64) {
    mount_plain_slice_rows(server, Some(hits)).await;
}

/// Each plain slice answers with three rows of its own prefix. With no hit
/// count: a wave one slice fails cancels the rest, so how many of the others
/// were asked for is timing.
async fn mount_plain_slice_rows(server: &MockServer, hits: Option<u64>) {
    for p in PREFIXES.chars() {
        let mock = Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param("$filter", format!("startswith(appId,'{p}')")))
            .and(header_is_missing("consistencylevel"))
            .and(query_param_is_missing("$count"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": slice_rows(p, 3) })),
            );
        match hits {
            Some(hits) => mock.expect(hits).mount(server).await,
            None => mock.mount(server).await,
        }
    }
}

fn row_ids(rows: &[ServicePrincipal]) -> Vec<String> {
    rows.iter().map(|r| r.id.clone()).collect()
}

/// How many slice requests (any `$filter`) the server has seen, and how many
/// of those were advanced queries.
async fn slice_requests(server: &MockServer) -> (usize, usize) {
    let requests = server.received_requests().await.unwrap_or_default();
    let slices: Vec<_> = requests
        .iter()
        .filter(|r| r.url.query_pairs().any(|(k, _)| k == "$filter"))
        .collect();
    let advanced = slices
        .iter()
        .filter(|r| r.headers.contains_key("consistencylevel"))
        .count();
    (slices.len(), advanced)
}

fn all_ids() -> Vec<String> {
    PREFIXES
        .chars()
        .flat_map(|p| (0..3).map(move |i| format!("sp-{p}{i}")))
        .collect()
}

#[tokio::test]
async fn a_single_page_tenant_is_never_sliced() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param_is_missing("$filter"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": slice_rows('a', 2) })),
        )
        .expect(1)
        .mount(&server)
        .await;
    mount_count(&server, 2).await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(wiremock::matchers::query_param_contains(
            "$filter",
            "startswith",
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(sps.len(), 2);
    server.verify().await;
}

#[tokio::test]
async fn a_large_tenant_is_read_as_sixteen_slices_in_prefix_order() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    mount_plain_slices(&server, 1).await;
    // The probe's own nextLink is never followed once the slices are trusted.
    mount_serial_rest(&server, 0).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    server.verify().await;
}

#[tokio::test]
async fn a_slice_continuation_is_followed_as_a_plain_read() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 49).await;
    for p in PREFIXES.chars().filter(|p| *p != 'c') {
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param("$filter", format!("startswith(appId,'{p}')")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": slice_rows(p, 3) })),
            )
            .mount(&server)
            .await;
    }
    // Slice `c` spans two pages: its continuation is a plain read like its
    // page one, never an advanced query.
    let next = format!("{}/servicePrincipals?slice=c2", server.uri());
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "startswith(appId,'c')"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": next,
            "value": slice_rows('c', 3),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("slice", "c2"))
        .and(header_is_missing("consistencylevel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-c9", "appId": "c9000000-0000-0000-0000-000000000000" }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(sps.len(), 49);
    assert!(sps.iter().any(|s| s.id == "sp-c9"));
    server.verify().await;
}

/// Plain slices rejected with a 400 retry once as an advanced query; the mode
/// that worked is remembered, so the next scan goes straight to it.
#[tokio::test]
async fn rejected_plain_slices_retry_as_an_advanced_query_and_remember_it() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(wiremock::matchers::query_param_contains(
            "$filter",
            "startswith",
        ))
        .and(header_is_missing("consistencylevel"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Unsupported query."))
        .mount(&server)
        .await;
    for p in PREFIXES.chars() {
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param("$filter", format!("startswith(appId,'{p}')")))
            .and(query_param("$count", "true"))
            .and(header("consistencylevel", "eventual"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": slice_rows(p, 3) })),
            )
            .expect(2)
            .mount(&server)
            .await;
    }
    mount_serial_rest(&server, 0).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    let (first_total, first_advanced) = slice_requests(&server).await;
    assert_eq!(first_advanced, 16);
    // The first 400 cancels the rest of the plain wave.
    assert!(first_total > 16, "no plain slice was tried first");

    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    let (total, advanced) = slice_requests(&server).await;
    assert_eq!(
        (total - first_total, advanced - first_advanced),
        (16, 16),
        "the second scan must go straight to the advanced slices"
    );
    server.verify().await;
}

/// Slices rejected in both modes fall back to the serial read, and the
/// collection stays serial: the second scan sends neither slices nor `$count`.
#[tokio::test]
async fn slices_rejected_in_both_modes_read_serially_from_then_on() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/$count"))
        .respond_with(ResponseTemplate::new(200).set_body_string("48"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(wiremock::matchers::query_param_contains(
            "$filter",
            "startswith",
        ))
        .respond_with(ResponseTemplate::new(400).set_body_string("Unsupported query."))
        .mount(&server)
        .await;
    mount_serial_rest(&server, 2).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    let (first_total, first_advanced) = slice_requests(&server).await;
    assert!(
        first_advanced >= 1 && first_total > first_advanced,
        "both modes must be tried before falling back"
    );

    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    assert_eq!(
        slice_requests(&server).await.0,
        first_total,
        "a collection that rejected slicing must stay serial"
    );
    server.verify().await;
}

/// The slices returned fewer rows than `/$count`: they are not trusted, and
/// the serial read supplies the tenant. Here the serial read returns exactly
/// the slices' union, so the count was stale (the index lags a delete) and
/// the slices were complete: nothing is held against the collection, and
/// every later scan slices again.
#[tokio::test]
async fn a_stale_count_falls_back_to_the_serial_read_without_a_strike() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 60).await;
    mount_plain_slices(&server, 3).await;
    mount_serial_rest(&server, 3).await;

    let client = make_client(&server.uri());
    for _ in 0..3 {
        let sps = client.list_service_principals_index().await.unwrap();
        assert_eq!(row_ids(&sps), all_ids());
    }
    assert_eq!(slice_requests(&server).await, (48, 0));
    server.verify().await;
}

/// Slice `c` answers with two of its three rows. The union is short of the
/// count, and the serial read returns a row the slices missed, so the refusal
/// counts; a second one in a row pins the collection serial, and the third
/// scan sends no slices.
async fn mount_short_slice_c(server: &MockServer, times: u64) {
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "startswith(appId,'c')"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": slice_rows('c', 2) })),
        )
        .up_to_n_times(times)
        .with_priority(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn slices_that_really_missed_a_row_count_toward_the_serial_pin() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    mount_short_slice_c(&server, 2).await;
    mount_plain_slice_rows(&server, None).await;
    mount_serial_rest(&server, 3).await;

    let client = make_client(&server.uri());
    for _ in 0..3 {
        let sps = client.list_service_principals_index().await.unwrap();
        assert_eq!(row_ids(&sps), all_ids());
    }
    assert_eq!(slice_requests(&server).await, (32, 0));
    server.verify().await;
}

/// A merge that validates clears the strike: short, then whole, then short
/// again leaves the collection one refusal from the pin, so the fourth scan
/// still slices.
#[tokio::test]
async fn a_validated_merge_clears_the_strike() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    mount_short_slice_c(&server, 1).await;
    mount_plain_slice_rows(&server, None).await;
    mount_serial_rest(&server, 2).await;

    let client = make_client(&server.uri());
    for _ in 0..2 {
        let sps = client.list_service_principals_index().await.unwrap();
        assert_eq!(row_ids(&sps), all_ids());
    }
    mount_short_slice_c(&server, 1).await;
    for _ in 0..2 {
        let sps = client.list_service_principals_index().await.unwrap();
        assert_eq!(row_ids(&sps), all_ids());
    }
    assert_eq!(
        slice_requests(&server).await,
        (64, 0),
        "the fourth scan must still slice: the validated second scan cleared the first strike"
    );
    server.verify().await;
}

/// One row short of `/$count` is one principal dropped, so there is no
/// tolerance: a principal with no `appId` past the probe page is in no slice,
/// and the serial read is the only one that returns it. Its presence pins the
/// collection serial, so the next scan sends no slices.
#[tokio::test]
async fn a_principal_without_an_app_id_beyond_page_one_is_never_dropped() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 49).await;
    mount_plain_slices(&server, 1).await;
    let mut rest = serial_rest_rows();
    rest.push(serde_json::json!({ "id": "agent-1", "appId": null, "displayName": "Agent" }));
    mount_serial_rest_rows(&server, 2, rest).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(sps.len(), 49);
    assert!(sps.iter().any(|s| s.id == "agent-1" && s.app_id.is_empty()));
    let sliced = slice_requests(&server).await;
    assert_eq!(sliced.0, 16);

    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(sps.len(), 49);
    assert_eq!(
        slice_requests(&server).await,
        sliced,
        "the second scan must not slice"
    );
    server.verify().await;
}

/// A principal with no `appId` on the probe page is proof the tenant cannot
/// be sliced: no slice is asked for, and the collection stays serial.
#[tokio::test]
async fn a_probe_row_without_an_app_id_reads_serially_at_once() {
    let server = MockServer::start().await;
    let next = format!("{}/servicePrincipals?page=2", server.uri());
    let mut page_one = slice_rows('0', 2);
    page_one.push(serde_json::json!({ "id": "agent-1", "appId": null, "displayName": "Agent" }));
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param_is_missing("$filter"))
        .and(query_param_is_missing("page"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": next,
            "value": page_one,
        })))
        .mount(&server)
        .await;
    mount_count(&server, 49).await;
    mount_plain_slices(&server, 0).await;
    mount_serial_rest(&server, 2).await;

    let client = make_client(&server.uri());
    for _ in 0..2 {
        let sps = client.list_service_principals_index().await.unwrap();
        assert_eq!(sps.len(), 49);
    }
    assert_eq!(slice_requests(&server).await, (0, 0));
    server.verify().await;
}

/// A 400 on a slice's continuation says nothing about the filter: the scan
/// reads serially, and the next scan tries the same plain slices again rather
/// than retrying as an advanced query or pinning serial. Two such refusals in
/// a row pin the collection serial.
#[tokio::test]
async fn a_continuation_400_reads_serially_without_rejecting_the_mode() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    for p in PREFIXES.chars().filter(|p| *p != 'c') {
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param("$filter", format!("startswith(appId,'{p}')")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": slice_rows(p, 3) })),
            )
            .mount(&server)
            .await;
    }
    let next = format!("{}/servicePrincipals?slice=c2", server.uri());
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "startswith(appId,'c')"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": next,
            "value": slice_rows('c', 2),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("slice", "c2"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad continuation."))
        .mount(&server)
        .await;
    mount_serial_rest(&server, 3).await;

    let client = make_client(&server.uri());
    for _ in 0..3 {
        let sps = client.list_service_principals_index().await.unwrap();
        assert_eq!(row_ids(&sps), all_ids());
    }
    let (total, advanced) = slice_requests(&server).await;
    assert_eq!(
        advanced, 0,
        "a continuation 400 must not retry as an advanced query"
    );
    assert_eq!(
        total, 32,
        "the first two scans slice; the third is pinned serial"
    );
    server.verify().await;
}

/// Slice `7`'s responder: `status` (with `Retry-After: 0`, so the retries are
/// instant) while `failing` is set, its three rows once it is cleared.
struct SwitchableSlice7 {
    status: u16,
    failing: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl wiremock::Respond for SwitchableSlice7 {
    fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            ResponseTemplate::new(self.status).insert_header("retry-after", "0")
        } else {
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": slice_rows('7', 3) }))
        }
    }
}

/// Mounts slice `7` failing with `status`; clearing the returned flag lets it
/// answer again.
async fn mount_failing_slice_7(
    server: &MockServer,
    status: u16,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let failing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "startswith(appId,'7')"))
        .respond_with(SwitchableSlice7 {
            status,
            failing: failing.clone(),
        })
        .with_priority(1)
        .mount(server)
        .await;
    failing
}

/// Runs one scan, asserts it returned the whole tenant, and reports whether it
/// sent any slice request.
async fn scan_sliced(client: &GraphClient, server: &MockServer) -> bool {
    let before = slice_requests(server).await.0;
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    slice_requests(server).await.0 > before
}

/// A slice whose throttling outlasts the retry budget does not fail the scan:
/// the serial read supplies it. A 429 says nothing about the filter or the
/// index, so it is no lag strike — the second throttled scan still slices,
/// where two such waves used to pin the collection serial for the client's
/// lifetime — but it has its own bound: the third throttled wave in a row
/// pins it, since sixteen chains that each fail and then pay the serial read
/// anyway only add to the load.
#[tokio::test]
async fn a_slice_out_of_retries_reads_serially() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    let _throttled = mount_failing_slice_7(&server, 429).await;
    mount_plain_slice_rows(&server, None).await;
    mount_serial_rest(&server, 4).await;

    let client = make_client(&server.uri());
    for scan in 1..=3 {
        assert!(
            scan_sliced(&client, &server).await,
            "throttled scan {scan} must still slice"
        );
    }
    assert!(
        !scan_sliced(&client, &server).await,
        "three throttled waves in a row pin the collection serial"
    );
    assert_eq!(
        slice_requests(&server).await.1,
        0,
        "a throttle must not retry as an advanced query"
    );
    server.verify().await;
}

/// The throttle bound counts waves in a row: a merge that validates between
/// them clears it, like the lag strikes, so a tenant throttled now and then
/// is never pinned by throttles spread across the session.
#[tokio::test]
async fn a_validated_merge_clears_the_throttle_count() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    mount_plain_slice_rows(&server, None).await;
    // Five throttled scans fall back to the serial read; the clean one does not.
    mount_serial_rest(&server, 5).await;

    let client = make_client(&server.uri());
    let throttled = mount_failing_slice_7(&server, 429).await;
    for _ in 0..2 {
        assert!(scan_sliced(&client, &server).await);
    }
    throttled.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(
        scan_sliced(&client, &server).await,
        "the clean scan validates"
    );
    throttled.store(true, std::sync::atomic::Ordering::SeqCst);
    for scan in 4..=6 {
        assert!(
            scan_sliced(&client, &server).await,
            "scan {scan} must still slice: the validated merge cleared the earlier throttles"
        );
    }
    server.verify().await;
}

/// Only a throttle is transient. A slice out of retries on a server error is
/// judged like any failed wave — a strike, since its empty union can never
/// prove the slices complete — so two in a row pin the collection serial, as
/// before.
#[tokio::test]
async fn a_slice_out_of_retries_on_a_server_error_is_a_strike() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    let _failing = mount_failing_slice_7(&server, 503).await;
    mount_plain_slice_rows(&server, None).await;
    mount_serial_rest(&server, 3).await;

    let client = make_client(&server.uri());
    for scan in 1..=2 {
        assert!(
            scan_sliced(&client, &server).await,
            "scan {scan} slices; the strikes are only being counted"
        );
    }
    assert!(
        !scan_sliced(&client, &server).await,
        "two server-error waves in a row pin the collection serial"
    );
    server.verify().await;
}

/// A mode that validated before and then answers 400 on one slice's page one
/// is not pinned serial outright: the scan reads serially and the next scan
/// tries the same plain slices again.
#[tokio::test]
async fn a_known_mode_rejected_once_is_not_pinned_outright() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    mount_plain_slice_rows(&server, None).await;
    mount_serial_rest(&server, 1).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(wiremock::matchers::query_param_contains(
            "$filter",
            "startswith",
        ))
        .respond_with(ResponseTemplate::new(400).set_body_string("Unsupported query."))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    let (after_rejection, advanced) = slice_requests(&server).await;
    assert_eq!(
        advanced, 0,
        "a known plain mode must not fall through to advanced slices"
    );
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    assert!(
        slice_requests(&server).await.0 > after_rejection,
        "the third scan must slice again"
    );
    server.verify().await;
}

/// A slice whose page one holds a row outside its prefix means Graph misread
/// the filter: the slice stops there (its continuation is never requested),
/// the serial read supplies the tenant, and the collection is pinned serial.
#[tokio::test]
async fn a_foreign_prefix_row_stops_the_slice_at_page_one() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    let next = format!("{}/servicePrincipals?slice=1b", server.uri());
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "startswith(appId,'1')"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": next,
            "value": [{ "id": "sp-x", "appId": "2abc0000-0000-0000-0000-000000000000" }],
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("slice", "1b"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    mount_plain_slice_rows(&server, None).await;
    mount_serial_rest(&server, 2).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    let sliced = slice_requests(&server).await;
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
    assert_eq!(
        slice_requests(&server).await,
        sliced,
        "the second scan must not slice"
    );
    server.verify().await;
}

/// A tenant whose `/$count` cannot be read is never sliced.
#[tokio::test]
async fn no_count_means_a_serial_read() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/$count"))
        .respond_with(ResponseTemplate::new(403).set_body_string("denied"))
        .mount(&server)
        .await;
    mount_plain_slices(&server, 0).await;
    mount_serial_rest(&server, 1).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(sps.len(), 48);
    server.verify().await;
}

/// A slice that cannot be read for a reason other than an unsupported filter
/// fails the scan, exactly as the serial read would.
#[tokio::test]
async fn a_forbidden_slice_fails_the_scan() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(wiremock::matchers::query_param_contains(
            "$filter",
            "startswith",
        ))
        .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let err = client.list_service_principals_index().await.unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)), "{err:?}");
}

/// A throttled slice rides the shared retry policy instead of failing the scan.
#[tokio::test]
async fn a_throttled_slice_is_retried() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 48).await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "startswith(appId,'7')"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    mount_plain_slices(&server, 1).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
}

/// The audit's `$expand=owners` scan is never sliced (a slice can fall back to
/// an advanced query, and Graph answers an expanding advanced query with the
/// expansion silently missing), nor asked for a count.
#[tokio::test]
async fn an_expanding_application_scan_is_never_sliced() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$expand", "owners($select=id)"))
        .and(query_param_is_missing("$filter"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "obj-1", "appId": "a1", "displayName": "One" }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/applications/$count"))
        .respond_with(ResponseTemplate::new(200).set_body_string("1"))
        .expect(0)
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let (apps, truncated) = client
        .list_applications_all(
            crate::client::AppListQuery::default().with_expand("owners($select=id)"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(apps.len(), 1);
    assert!(!truncated);
    server.verify().await;
}

/// The list scan of `/applications` slices with its own projection and page
/// size on every slice.
#[tokio::test]
async fn a_large_application_scan_slices_with_its_projection() {
    let server = MockServer::start().await;
    let app = |p: char, i: usize| {
        serde_json::json!({
            "id": format!("obj-{p}{i}"),
            "appId": format!("{p}{i:07}-0000-0000-0000-000000000000"),
            "displayName": format!("{p}{i}"),
        })
    };
    let next = format!("{}/applications?page=2", server.uri());
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param_is_missing("$filter"))
        .and(query_param_is_missing("page"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": next,
            "value": [app('0', 0)],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/applications/$count"))
        .respond_with(ResponseTemplate::new(200).set_body_string("16"))
        .mount(&server)
        .await;
    for p in PREFIXES.chars() {
        Mock::given(method("GET"))
            .and(path("/applications"))
            .and(query_param("$filter", format!("startswith(appId,'{p}')")))
            .and(query_param("$select", "id,appId,displayName"))
            .and(query_param("$top", "999"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": [app(p, 0)] })),
            )
            .expect(1)
            .mount(&server)
            .await;
    }

    let client = make_client(&server.uri());
    let (apps, truncated) = client
        .list_applications_all(
            crate::client::AppListQuery::default()
                .with_select(vec!["id", "appId", "displayName"])
                .with_top(999),
            Some(10_000),
        )
        .await
        .unwrap();
    assert_eq!(apps.len(), 16);
    assert_eq!(apps[15].id, "obj-f0");
    assert!(!truncated);
    server.verify().await;
}

/// A service principal Graph returns without an `appId` no longer fails the
/// whole index.
#[tokio::test]
async fn a_service_principal_without_an_app_id_reads_as_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "sp-1", "appId": "a1", "displayName": "One" },
                { "id": "agent-1", "appId": null, "displayName": "Agent" }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(sps.len(), 2);
    assert_eq!(sps[1].app_id, "");
}
