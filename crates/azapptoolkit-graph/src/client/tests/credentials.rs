use super::super::*;
use super::common::*;

#[tokio::test]
async fn add_password_posts_expected_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/addPassword"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keyId": "kid-1",
            "displayName": "CI secret",
            "hint": "abc",
            "secretText": "super-secret-value",
            "startDateTime": "2026-01-01T00:00:00Z",
            "endDateTime": "2026-07-01T00:00:00Z"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let cred = client
        .add_password("obj-1", "CI secret", Duration::from_secs(60 * 60 * 24 * 30))
        .await
        .unwrap();
    assert_eq!(cred.key_id, "kid-1");
    assert_eq!(cred.secret_text.as_deref(), Some("super-secret-value"));
}

#[tokio::test]
async fn add_password_window_sends_start_only_when_given() {
    let server = MockServer::start().await;
    let start = chrono::DateTime::parse_from_rfc3339("2026-07-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let end = chrono::DateTime::parse_from_rfc3339("2027-07-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let created = serde_json::json!({
        "keyId": "kid-2",
        "displayName": "scheduled secret",
        "endDateTime": "2027-07-01T00:00:00Z"
    });
    // Exact body match: with a start date the key must be present…
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/addPassword"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "passwordCredential": {
                "displayName": "scheduled secret",
                "startDateTime": "2026-07-01T00:00:00+00:00",
                "endDateTime": "2027-07-01T00:00:00+00:00",
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(created.clone()))
        .expect(1)
        .mount(&server)
        .await;
    // …and without one the key must be absent entirely (Graph defaults to now).
    Mock::given(method("POST"))
        .and(path("/applications/obj-2/addPassword"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "passwordCredential": {
                "displayName": "scheduled secret",
                "endDateTime": "2027-07-01T00:00:00+00:00",
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(created))
        .expect(1)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let cred = client
        .add_password_window("obj-1", "scheduled secret", Some(start), end)
        .await
        .unwrap();
    assert_eq!(cred.key_id, "kid-2");
    client
        .add_password_window("obj-2", "scheduled secret", None, end)
        .await
        .unwrap();
}

#[tokio::test]
async fn remove_password_posts_key_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications/obj-1/removePassword"))
        .and(wiremock::matchers::body_json(
            serde_json::json!({ "keyId": "kid-1" }),
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.remove_password("obj-1", "kid-1").await.unwrap();
}

#[tokio::test]
async fn add_key_credential_fetches_then_patches_with_appended_entry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo",
            "keyCredentials": [{
                "keyId": "existing",
                "displayName": "existing-cert",
                "type": "AsymmetricX509Cert",
                "usage": "Verify"
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "keyCredentials": [
                {
                    "keyId": "existing",
                    "displayName": "existing-cert",
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify"
                },
                {
                    "displayName": "new-cert",
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                    "key": "AAAA"
                }
            ]
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .add_key_credential(
            "obj-1",
            NewKeyCredential {
                display_name: Some("new-cert".into()),
                kind: Some("AsymmetricX509Cert".into()),
                usage: Some("Verify".into()),
                key: "AAAA".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn remove_key_credential_patches_filtered_array() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
            .and(path("/applications/obj-1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "obj-1",
                    "appId": "app-1",
                    "displayName": "Demo",
                    "keyCredentials": [
                        {"keyId": "keep", "displayName": "keep", "type": "AsymmetricX509Cert", "usage": "Verify"},
                        {"keyId": "drop", "displayName": "drop", "type": "AsymmetricX509Cert", "usage": "Verify"}
                    ]
                })),
            )
            .mount(&server)
            .await;
    Mock::given(method("PATCH"))
            .and(path("/applications/obj-1"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "keyCredentials": [
                    {"keyId": "keep", "displayName": "keep", "type": "AsymmetricX509Cert", "usage": "Verify"}
                ]
            })))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
    let client = make_client(&server.uri());
    client.remove_key_credential("obj-1", "drop").await.unwrap();
}

#[tokio::test]
async fn add_token_signing_certificate_returns_thumbprint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/servicePrincipals/sp-1/addTokenSigningCertificate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "thumbprint": "C2DDD8044C956ACD0269A75A64B7862DB9DDAC3E",
            "key": "MIICqjCCAZKg",
            "keyId": "4c266507-3e74-4b91-aeba-18a25b450f6e",
            "usage": "Verify",
            "type": "AsymmetricX509Cert"
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let end = chrono::Utc::now() + chrono::Duration::days(365);
    let cert = client
        .add_token_signing_certificate("sp-1", "CN=Demo", end)
        .await
        .unwrap();
    assert_eq!(cert.thumbprint, "C2DDD8044C956ACD0269A75A64B7862DB9DDAC3E");
}

#[tokio::test]
async fn update_federated_credential_patches_credential_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(
            "/applications/obj-1/federatedIdentityCredentials/fic-1",
        ))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "issuer": "https://accounts.google.com",
            "subject": "112633961854638529490",
            "audiences": ["api://AzureADTokenExchange"],
            "description": "gcp workload",
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let patch = FederatedCredentialPatch {
        issuer: "https://accounts.google.com".into(),
        subject: "112633961854638529490".into(),
        audiences: vec!["api://AzureADTokenExchange".into()],
        description: Some("gcp workload".into()),
    };
    client
        .update_federated_credential("obj-1", "fic-1", &patch)
        .await
        .unwrap();
}
