use super::super::*;
use super::common::*;

#[tokio::test]
async fn get_site_by_url_builds_host_relative_path() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sites/contoso.sharepoint.com:/sites/Marketing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "contoso.sharepoint.com,guid1,guid2",
            "displayName": "Marketing",
            "webUrl": "https://contoso.sharepoint.com/sites/Marketing"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let site = client
        .get_site_by_url("https://contoso.sharepoint.com/sites/Marketing/")
        .await
        .unwrap();
    assert_eq!(site.id, "contoso.sharepoint.com,guid1,guid2");
    assert_eq!(site.display_name.as_deref(), Some("Marketing"));
}

#[tokio::test]
async fn grant_site_permission_posts_application_identity() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sites/site-1/permissions"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "roles": ["write"],
            "grantedToIdentities": [
                { "application": { "id": "app-1", "displayName": "Demo" } }
            ]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "perm-1",
            "roles": ["write"],
            "grantedToIdentities": [
                { "application": { "id": "app-1", "displayName": "Demo" } }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perm = client
        .grant_site_permission("site-1", "app-1", "Demo", &["write".to_string()])
        .await
        .unwrap();
    assert_eq!(perm.id, "perm-1");
    assert_eq!(perm.roles, vec!["write".to_string()]);
    assert_eq!(
        perm.granted_to_identities[0]
            .application
            .as_ref()
            .and_then(|a| a.id.as_deref()),
        Some("app-1")
    );
}

#[tokio::test]
async fn list_site_permissions_uses_sharepoint_scope() {
    let server = MockServer::start().await;
    // The handler attaches the SharePoint bearer ("sp"), not the default
    // read token ("tok") — the site-permission endpoints need
    // Sites.FullControl.All, which the read scope lacks.
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "perm-1", "roles": ["read"],
                  "grantedToIdentities": [ { "application": { "id": "app-1" } } ] }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perms = client.list_site_permissions("site-1").await.unwrap();
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].id, "perm-1");
}

#[tokio::test]
async fn list_site_permissions_follows_next_link() {
    let server = MockServer::start().await;
    // A site whose grant list spans pages must return BOTH pages — the sweep's
    // "coverage is never overstated" invariant fails silently if page 2 drops.
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "perm-1", "roles": ["read"],
                  "grantedToIdentities": [ { "application": { "id": "app-1" } } ] }
            ],
            "@odata.nextLink": format!("{}/perm-page-2", server.uri()),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/perm-page-2"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "perm-2", "roles": ["write"],
                  "grantedToIdentities": [ { "application": { "id": "app-2" } } ] }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perms = client.list_site_permissions("site-1").await.unwrap();
    assert_eq!(
        perms.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        ["perm-1", "perm-2"],
        "the second page must not be silently dropped"
    );
}

#[tokio::test]
async fn site_permission_read_retries_a_429_honoring_retry_after() {
    let server = MockServer::start().await;
    // The sweep fans this read out across thousands of sites against the
    // throttle-happiest endpoint family — a transient 429 must be absorbed by
    // the retrying transport, not surface as a phantom per-site failure.
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("throttled"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "perm-1", "roles": ["read"],
                  "grantedToIdentities": [ { "application": { "id": "app-1" } } ] }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perms = client.list_site_permissions("site-1").await.unwrap();
    assert_eq!(perms.len(), 1, "the 429 must be retried, not propagated");
}

#[tokio::test]
async fn list_all_sites_follows_next_link_on_sharepoint_scope() {
    let server = MockServer::start().await;
    // Page 1 carries a nextLink back to this origin; page 2 ends the chain.
    // Both must attach the SharePoint bearer, like the permission endpoints.
    Mock::given(method("GET"))
        .and(path("/sites"))
        .and(query_param("search", "*"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [ { "id": "site-1", "displayName": "One", "webUrl": "https://x/sites/one" } ],
            "@odata.nextLink": format!("{}/sites-page-2", server.uri()),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites-page-2"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [ { "id": "site-2", "displayName": "Two", "webUrl": "https://x/sites/two" } ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let (sites, truncated) = client.list_all_sites(100).await.unwrap();
    assert_eq!(
        sites.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["site-1", "site-2"]
    );
    assert!(!truncated, "exhausted within the cap is full coverage");

    // The cap stops the walk without erroring — and says so: page 1 satisfies
    // it but still carries a nextLink, so sites exist beyond the prefix.
    let (capped, truncated) = client.list_all_sites(1).await.unwrap();
    assert_eq!(capped.len(), 1);
    assert!(
        truncated,
        "a pending nextLink at the cap means the tenant has more sites"
    );
}

/// The cap signal when the FIRST page already overshoots it — the case the
/// sweep meets on a large tenant (`$top=200` against a 5000 cap is 25 pages,
/// but the last one usually overshoots). Until this the client silently
/// `truncate(max)`-ed and the sweep reported the prefix as the whole tenant,
/// so a `Sites.Selected` grant on site 5001 read as "no per-site grants".
///
/// The exact-fit sibling is the one a naive `len() >= max` check gets wrong:
/// three sites under a cap of three is full coverage, not truncation.
#[tokio::test]
async fn list_all_sites_reports_truncation_when_page_one_overshoots_the_cap() {
    let site = |n: u8| {
        serde_json::json!({
            "id": format!("site-{n}"),
            "displayName": format!("Site {n}"),
            "webUrl": format!("https://x/sites/{n}")
        })
    };

    let overshoot = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sites"))
        .and(query_param("search", "*"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [site(1), site(2), site(3)]
        })))
        .mount(&overshoot)
        .await;
    let client =
        make_client(&overshoot.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let (sites, truncated) = client.list_all_sites(2).await.unwrap();
    assert_eq!(
        sites.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["site-1", "site-2"],
        "the prefix is cut to the cap"
    );
    assert!(truncated, "a third site existed beyond the cap");

    let exact = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sites"))
        .and(query_param("search", "*"))
        .and(header(AUTHORIZATION.as_str(), "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [site(1), site(2)]
        })))
        .mount(&exact)
        .await;
    let client = make_client(&exact.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let (sites, truncated) = client.list_all_sites(2).await.unwrap();
    assert_eq!(sites.len(), 2);
    assert!(
        !truncated,
        "exactly filling the cap with no nextLink is full coverage"
    );
}

#[tokio::test]
async fn remove_site_permission_deletes_nested_path() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/sites/site-1/permissions/perm-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    client
        .remove_site_permission("site-1", "perm-1")
        .await
        .unwrap();
}

/// The full folder walk over a real HTTP server: site collection → drives →
/// path-addressed driveItem, ending at the listItem ids the grant endpoint needs.
///
/// Two things only an end-to-end test catches. The pasted URL is deep, so the
/// site lookup must be truncated to `/sites/Finance` (passing it through 404s),
/// and the driveItem address needs the **trailing colon** before the query
/// string or Graph reads `?$select=` as part of the path.
#[tokio::test]
async fn resolve_sharepoint_resource_walks_a_deep_folder_url_to_list_item_ids() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sites/contoso.sharepoint.com:/sites/Finance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "site-1",
            "displayName": "Finance",
            "webUrl": "https://contoso.sharepoint.com/sites/Finance"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites/site-1/drives"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {
                    "id": "drive-1",
                    "name": "Documents",
                    "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents"
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drives/drive-1/root:/Invoices/2026:"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "item-1",
            "name": "2026",
            "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/Invoices/2026",
            "folder": { "childCount": 3 },
            "sharepointIds": { "listId": "list-1", "listItemId": "17" }
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    // Literal spaces, as a hand-typed URL would have them.
    let resolved = client
        .resolve_sharepoint_resource(
            "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices/2026",
        )
        .await
        .unwrap();

    // A folder in a document library resolves at the File level — the reach
    // `Files.SelectedOperations.Selected` describes ("file or library folder").
    assert_eq!(resolved.level, SelectedScopeLevel::File);
    assert!(resolved.is_folder);
    assert_eq!(resolved.site_id, "site-1");
    assert_eq!(resolved.list_id.as_deref(), Some("list-1"));
    assert_eq!(resolved.item_id.as_deref(), Some("17"));
    assert_eq!(resolved.drive_id.as_deref(), Some("drive-1"));
    assert_eq!(
        resolved.display_path,
        "Finance / Documents / Invoices / 2026"
    );
}

/// A bare site URL resolves at the site level and stops there — one read, no
/// drive listing. This is the target a `Files.*` scope has to be refused
/// against, so the level it reports is load-bearing.
#[tokio::test]
async fn resolve_sharepoint_resource_stops_at_a_site_url() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sites/contoso.sharepoint.com:/sites/Finance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "site-1",
            "displayName": "Finance",
            "webUrl": "https://contoso.sharepoint.com/sites/Finance"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let resolved = client
        .resolve_sharepoint_resource("https://contoso.sharepoint.com/sites/Finance")
        .await
        .unwrap();
    assert_eq!(resolved.level, SelectedScopeLevel::Site);
    assert_eq!(resolved.list_id, None);
    assert_eq!(resolved.item_id, None);
}

/// The library root resolves at the List level via `/drives/{id}/list` — the
/// exact join, rather than matching `webUrl`s between `/drives` and `/lists`.
#[tokio::test]
async fn resolve_sharepoint_resource_maps_a_library_root_to_its_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sites/contoso.sharepoint.com:/sites/Finance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "site-1",
            "displayName": "Finance",
            "webUrl": "https://contoso.sharepoint.com/sites/Finance"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites/site-1/drives"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "drive-1",
                "name": "Documents",
                "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents"
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drives/drive-1/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "list-1",
            "name": "Shared Documents",
            "displayName": "Documents",
            "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let resolved = client
        .resolve_sharepoint_resource(
            "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents",
        )
        .await
        .unwrap();
    assert_eq!(resolved.level, SelectedScopeLevel::List);
    assert_eq!(resolved.list_id.as_deref(), Some("list-1"));
    assert_eq!(resolved.item_id, None);
}

/// A subsite probe that the caller lacks rights on. The parent site holds no
/// library or list matching the URL, so the resolver descends one segment and
/// asks SharePoint for `/sites/Finance/Reports` — which answers 403. That is a
/// fact about the caller, not the URL, and it must reach the command typed as
/// `Forbidden` so `map_sharepoint_err` can splice the Full-Control remediation.
/// Until this every probe error collapsed into "did not resolve to a list,
/// library or item", steering the operator to fix a URL that was fine.
///
/// 403 is outside the retry budget (`http_retry` retries 5xx/429/network only),
/// so this resolves in one round trip.
#[tokio::test]
async fn resolve_sharepoint_resource_propagates_a_forbidden_subsite_probe() {
    let server = MockServer::start().await;
    mount_empty_finance_site(&server).await;
    Mock::given(method("GET"))
        .and(path("/sites/contoso.sharepoint.com:/sites/Finance/Reports"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": { "code": "accessDenied", "message": "Access denied" }
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let err = client
        .resolve_sharepoint_resource(
            "https://contoso.sharepoint.com/sites/Finance/Reports/Shared Documents",
        )
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Forbidden(_)), "got {err:?}");
}

/// The intended 404 path still yields the operator-facing sentence: a probe
/// that finds no subsite means the URL names nothing this toolkit can grant
/// against, and that is what the message should say.
#[tokio::test]
async fn resolve_sharepoint_resource_reports_a_missing_subsite_as_unresolved() {
    let server = MockServer::start().await;
    mount_empty_finance_site(&server).await;
    Mock::given(method("GET"))
        .and(path("/sites/contoso.sharepoint.com:/sites/Finance/Reports"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "error": { "code": "itemNotFound", "message": "Requested site could not be found" }
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let err = client
        .resolve_sharepoint_resource(
            "https://contoso.sharepoint.com/sites/Finance/Reports/Shared Documents",
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&err, GraphError::Protocol(m) if m.contains("did not resolve")),
        "got {err:?}"
    );
}

/// `/sites/Finance` with no drives and no lists, so a deeper URL forces the
/// resolver to descend into a subsite probe (`path()` ignores the `$select` /
/// `$top` query on the two collection reads).
async fn mount_empty_finance_site(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/sites/contoso.sharepoint.com:/sites/Finance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "site-1",
            "displayName": "Finance",
            "webUrl": "https://contoso.sharepoint.com/sites/Finance"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites/site-1/drives"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites/site-1/lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .mount(server)
        .await;
}

/// The sub-site grant posts `grantedToV2` — the singular form these endpoints
/// require. The site endpoint's `grantedToIdentities` array is rejected here,
/// so wiremock's exact body match is the guard against reusing the wrong builder.
#[tokio::test]
async fn grant_list_item_permission_posts_granted_to_v2() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sites/site-1/lists/list-1/items/17/permissions"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "roles": ["read"],
            "grantedToV2": {
                "application": { "id": "app-1", "displayName": "Demo" }
            }
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "perm-9",
            "roles": ["read"],
            "grantedToV2": {
                "application": { "id": "app-1", "displayName": "Demo" }
            }
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perm = client
        .grant_list_item_permission(
            "site-1",
            "list-1",
            "17",
            "app-1",
            "Demo",
            &["read".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(perm.id, "perm-9");
    // The principal is read back out of `grantedToV2`, not the site shape.
    assert_eq!(perm.app_id(), Some("app-1"));
    assert_eq!(perm.app_display_name(), Some("Demo"));
}

/// A permission granted to a *user* or a SharePoint group is an ordinary
/// sharing entry, not a Selected-scope app grant — reporting it as one would
/// overstate what an application can reach.
#[tokio::test]
async fn a_non_application_permission_reports_no_app_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sites/site-1/lists/list-1/permissions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "p1", "roles": ["read"],
                  "grantedToV2": { "siteGroup": { "id": "10", "displayName": "Members" } } },
                { "id": "p2", "roles": ["write"],
                  "grantedToV2": { "application": { "id": "app-1", "displayName": "Demo" } } }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let perms = client
        .list_list_permissions("site-1", "list-1")
        .await
        .unwrap();
    assert_eq!(perms.len(), 2);
    assert_eq!(perms[0].app_id(), None, "a site group is not an app grant");
    assert_eq!(perms[1].app_id(), Some("app-1"));
}

/// A batched site read whose grant list overflows continues page 2 on the
/// SharePoint token, not the verb-selected read token (`tok`), which lacks
/// `Sites.FullControl.All` — that fallback made page 2 a 403 while page 1
/// succeeded.
#[tokio::test]
async fn batch_list_site_permissions_continues_page_two_on_the_sharepoint_token() {
    let server = MockServer::start().await;
    let next = format!("{}/sites/site-1/permissions?page=2", server.uri());
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .and(header("authorization", "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [{ "id": "0", "status": 200, "body": {
                "value": [{ "id": "perm-1", "roles": ["read"] }],
                "@odata.nextLink": next,
            }}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sites/site-1/permissions"))
        .and(query_param("page", "2"))
        .and(header("authorization", "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "perm-2", "roles": ["write"] }]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let out = client
        .batch_list_site_permissions(&["site-1".to_string()])
        .await
        .unwrap();
    let perms = out[0].as_ref().expect("page 2 rides the SharePoint bearer");
    assert_eq!(perms.len(), 2);
    assert_eq!(perms[0].id, "perm-1");
    assert_eq!(perms[1].id, "perm-2");
}

/// The two id-addressed reads behind the per-app item-access list: each target
/// becomes one sub-request, a list item is named through its `driveItem`, and
/// a missing target is its own `NotFound`, not a failure of the batch.
#[tokio::test]
async fn selected_targets_are_read_by_id_in_one_scoped_batch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .and(header("authorization", "Bearer sp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                { "id": "0", "status": 200, "body": {
                    "id": "list-1", "name": "Shared Documents", "displayName": "Documents",
                    "webUrl": "https://contoso.sharepoint.com/sites/Fin/Shared%20Documents" } },
                { "id": "1", "status": 200, "body": {
                    "id": "di-1", "name": "2026", "webUrl": "https://x/2026",
                    "folder": { "childCount": 3 } } },
                { "id": "2", "status": 404, "body": { "error": { "code": "itemNotFound" } } }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let targets = [
        SelectedTarget {
            site_id: "s,1,2",
            list_id: "list-1",
            item_id: None,
        },
        SelectedTarget {
            site_id: "s,1,2",
            list_id: "list-1",
            item_id: Some("17"),
        },
        SelectedTarget {
            site_id: "s,1,2",
            list_id: "list-1",
            item_id: Some("99"),
        },
    ];
    let names = client
        .batch_get_selected_target_names(&targets)
        .await
        .unwrap();

    assert_eq!(
        names[0].as_ref().unwrap().display_name.as_deref(),
        Some("Documents")
    );
    let folder = names[1].as_ref().unwrap();
    assert_eq!(folder.name.as_deref(), Some("2026"));
    assert!(folder.folder.is_some());
    assert!(matches!(names[2], Err(GraphError::NotFound(_))));

    let body: serde_json::Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    let urls: Vec<&str> = body["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["url"].as_str().unwrap())
        .collect();
    assert_eq!(
        urls,
        [
            "/sites/s,1,2/lists/list-1?$select=id,name,displayName,webUrl",
            "/sites/s,1,2/lists/list-1/items/17/driveItem?$select=id,name,webUrl,folder",
            "/sites/s,1,2/lists/list-1/items/99/driveItem?$select=id,name,webUrl,folder",
        ]
    );
}

#[tokio::test]
async fn selected_permissions_are_read_by_id_with_a_page_size() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                { "id": "0", "status": 200, "body": { "value": [
                    { "id": "p1", "roles": ["read"],
                      "grantedToV2": { "application": { "id": "app-1" } } } ] } }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_sharepoint_token(StaticTokenProvider::new("sp"));
    let out = client
        .batch_list_selected_permissions(&[SelectedTarget {
            site_id: "s,1,2",
            list_id: "list-1",
            item_id: Some("17"),
        }])
        .await
        .unwrap();
    assert_eq!(out[0].as_ref().unwrap()[0].app_id(), Some("app-1"));

    let body: serde_json::Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    assert_eq!(
        body["requests"][0]["url"].as_str().unwrap(),
        format!("/sites/s,1,2/lists/list-1/items/17/permissions?$top={MAX_PAGE_SIZE}")
    );
}
