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
    let sites = client.list_all_sites(100).await.unwrap();
    assert_eq!(
        sites.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["site-1", "site-2"]
    );

    // The cap stops the walk without erroring (page 1 already satisfies it).
    let capped = client.list_all_sites(1).await.unwrap();
    assert_eq!(capped.len(), 1);
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
