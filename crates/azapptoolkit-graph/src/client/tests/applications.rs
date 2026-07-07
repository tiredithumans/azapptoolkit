use super::super::*;
use super::common::*;

#[tokio::test]
async fn list_applications_uses_default_select_and_top() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$top", "50"))
        .and(query_param("$count", "true"))
        .and(query_param("$orderby", "displayName"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_apps_json()))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let page = client
        .list_applications(AppListQuery::default())
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].app_id, "app-1");
    assert_eq!(page.total_count, Some(1));
}

#[tokio::test]
async fn list_applications_with_expand_omits_orderby() {
    // Graph rejects `$orderby` + `$expand` on `/applications`, so an
    // expanding call (e.g. the security audit) must drop `$orderby`.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$expand", "owners($select=id)"))
        .and(query_param_is_missing("$orderby"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_apps_json()))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let page = client
        .list_applications(AppListQuery::default().with_expand("owners($select=id)"))
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
}

#[tokio::test]
async fn search_adds_consistency_level_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(header("consistencylevel", "eventual"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_apps_json()))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let _ = client
        .list_applications(AppListQuery::default().with_search("demo"))
        .await
        .unwrap();
}

#[tokio::test]
async fn get_application_returns_single() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo App"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let app = client.get_application("obj-1").await.unwrap();
    assert_eq!(app.id, "obj-1");
    assert_eq!(app.app_id, "app-1");
}

#[tokio::test]
async fn list_application_index_returns_appid_object_id_pairs_without_orderby() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$select", "id,appId"))
        .and(query_param_is_missing("$orderby"))
        .and(query_param_is_missing("$count"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {"id": "obj-a", "appId": "app-a", "displayName": "A"},
                {"id": "obj-b", "appId": "app-b", "displayName": "B"}
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let pairs = client.list_application_index(Some(5000)).await.unwrap();
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0], ("app-a".to_string(), "obj-a".to_string()));
}

#[tokio::test]
async fn list_owners_returns_value_array() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1/owners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@example.com"},
                {"id": "u2", "displayName": "Bob"}
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let owners = client.list_owners("obj-1").await.unwrap();
    assert_eq!(owners.len(), 2);
    assert_eq!(owners[0].display_name.as_deref(), Some("Alice"));
}

#[tokio::test]
async fn list_owners_follows_next_link() {
    let server = MockServer::start().await;
    let base = server.uri();
    let page2_link = format!("{base}/applications/obj-1/owners?page=2");

    Mock::given(method("GET"))
        .and(path("/applications/obj-1/owners"))
        .and(query_param_is_missing("page"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": page2_link,
            "value": [{"id": "u1", "displayName": "Alice"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1/owners"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "u2", "displayName": "Bob"}, {"id": "u3", "displayName": "Cara"}]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let owners = client.list_owners("obj-1").await.unwrap();
    assert_eq!(owners.len(), 3);
    assert_eq!(owners[2].display_name.as_deref(), Some("Cara"));
}

#[tokio::test]
async fn create_application_posts_body_and_returns_app() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "displayName": "my-new-app",
            "signInAudience": "AzureADMyOrg"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "obj-99",
            "appId": "app-99",
            "displayName": "my-new-app",
            "signInAudience": "AzureADMyOrg"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let req = CreateApplicationRequest {
        display_name: "my-new-app".into(),
        sign_in_audience: Some("AzureADMyOrg".into()),
        description: None,
    };
    let app = client.create_application(&req).await.unwrap();
    assert_eq!(app.id, "obj-99");
    assert_eq!(app.display_name, "my-new-app");
}

#[tokio::test]
async fn update_application_patches_only_set_fields() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "displayName": "renamed" }),
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let patch = AppPatch {
        display_name: Some("renamed".into()),
        ..Default::default()
    };
    client.update_application("obj-1", &patch).await.unwrap();
}

#[tokio::test]
async fn update_application_sets_and_clears_notes() {
    // Setting notes sends the text; clearing sends an empty string (the typed
    // `AppPatch` can't emit an explicit JSON `null`, so `Some("")` is the clear).
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-set"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "notes": "Rotate secrets quarterly." }),
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-clear"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "notes": "" }),
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .update_application(
            "obj-set",
            &AppPatch {
                notes: Some("Rotate secrets quarterly.".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    client
        .update_application(
            "obj-clear",
            &AppPatch {
                notes: Some(String::new()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_application_returns_ok_on_204() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.delete_application("obj-1").await.unwrap();
}

#[tokio::test]
async fn add_owner_posts_full_odata_id() {
    let server = MockServer::start().await;
    let base = server.uri();
    let expected_odata_id = format!("{}/directoryObjects/u-1", base.trim_end_matches('/'));
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/owners/$ref"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "@odata.id": expected_odata_id,
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.add_owner("obj-1", "u-1").await.unwrap();
}

#[tokio::test]
async fn remove_owner_uses_nested_ref_path() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/applications/obj-1/owners/u-1/$ref"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.remove_owner("obj-1", "u-1").await.unwrap();
}

#[tokio::test]
async fn update_application_with_required_resource_access_serializes_fully() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "requiredResourceAccess": [{
                "resourceAppId": "00000003-0000-0000-c000-000000000000",
                "resourceAccess": [
                    {"id": "role-id", "type": "Role"},
                    {"id": "scope-id", "type": "Scope"},
                ]
            }]
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let patch = AppPatch {
        required_resource_access: Some(vec![RequiredResourceAccess {
            resource_app_id: "00000003-0000-0000-c000-000000000000".into(),
            resource_access: vec![
                azapptoolkit_core::models::ResourceAccess {
                    id: "role-id".into(),
                    r#type: "Role".into(),
                },
                azapptoolkit_core::models::ResourceAccess {
                    id: "scope-id".into(),
                    r#type: "Scope".into(),
                },
            ],
        }]),
        ..Default::default()
    };
    client.update_application("obj-1", &patch).await.unwrap();
}

#[tokio::test]
async fn list_applications_all_follows_next_link() {
    let server = MockServer::start().await;
    let base = server.uri();
    let page2_link = format!("{base}/applications?page=2");

    // Page 1: matches the broad "list_applications" call (has $select etc).
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("$top", "50"))
        .and(query_param("$count", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.nextLink": page2_link,
            "value": [{
                "id": "a1","appId":"app-1","displayName":"one"
            }]
        })))
        .mount(&server)
        .await;

    // Page 2: matched by the `page=2` query string from the nextLink.
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id":"a2","appId":"app-2","displayName":"two"
            }, {
                "id":"a3","appId":"app-3","displayName":"three"
            }]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let apps = client
        .list_applications_all(AppListQuery::default(), None)
        .await
        .unwrap();
    assert_eq!(apps.len(), 3);
    assert_eq!(apps[0].app_id, "app-1");
    assert_eq!(apps[2].app_id, "app-3");
}

#[tokio::test]
async fn instantiate_template_returns_app_and_sp() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate",
        ))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "displayName": "My SAML App" }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "application": {"id": "app-obj-1", "appId": "client-1", "displayName": "My SAML App"},
            "servicePrincipal": {"id": "sp-1", "appId": "client-1", "displayName": "My SAML App"}
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let pair = client
        .instantiate_application_template("8adf8e6e-67b2-4cf2-a259-e3dc5476c621", "My SAML App")
        .await
        .unwrap();
    assert_eq!(pair.application.id, "app-obj-1");
    assert_eq!(pair.service_principal.id, "sp-1");
}

#[tokio::test]
async fn patch_application_web_sends_identifier_and_reply_urls() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/applications/app-obj-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "identifierUris": ["https://app/saml"],
            "web": { "redirectUris": ["https://app/acs"], "logoutUrl": "https://app/logout" }
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .patch_application_web(
            "app-obj-1",
            &serde_json::json!({
                "identifierUris": ["https://app/saml"],
                "web": { "redirectUris": ["https://app/acs"], "logoutUrl": "https://app/logout" }
            }),
        )
        .await
        .unwrap();
}
