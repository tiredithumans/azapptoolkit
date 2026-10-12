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

/// Page two of the unfiltered read: the serial path's continuation, holding
/// the rest of the 48-row tenant.
async fn mount_serial_rest(server: &MockServer, hits: u64) {
    let rest: Vec<serde_json::Value> = PREFIXES
        .chars()
        .flat_map(|p| slice_rows(p, 3))
        .skip(2)
        .collect();
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

/// Each plain slice answers with three rows of its own prefix.
async fn mount_plain_slices(server: &MockServer, hits: u64) {
    for p in PREFIXES.chars() {
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param("$filter", format!("startswith(appId,'{p}')")))
            .and(header_is_missing("consistencylevel"))
            .and(query_param_is_missing("$count"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": slice_rows(p, 3) })),
            )
            .expect(hits)
            .mount(server)
            .await;
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

/// The slices returned fewer rows than `/$count` (beyond its tolerance): they
/// are not trusted, and the serial read supplies the tenant.
#[tokio::test]
async fn a_count_shortfall_falls_back_to_the_serial_read() {
    let server = MockServer::start().await;
    mount_probe(&server).await;
    mount_count(&server, 60).await;
    mount_plain_slices(&server, 1).await;
    mount_serial_rest(&server, 1).await;

    let client = make_client(&server.uri());
    let sps = client.list_service_principals_index().await.unwrap();
    assert_eq!(row_ids(&sps), all_ids());
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
