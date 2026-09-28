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
async fn add_key_credential_preserves_the_surviving_certificate_blob() {
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
                "usage": "Verify",
                // The certificate blob itself. `KeyCredential` does not model
                // it, so a typed round-trip here wrote the survivor back
                // keyless — silently destroying a live credential. Graph
                // returns it on exactly this `$select=keyCredentials` read.
                //
                // Deliberately not base64-DER-shaped: the assertion is that the
                // value survives byte-for-byte, and an `MII…` placeholder reads
                // as a real certificate to the secrets scanner.
                "key": "cert-blob-existing-must-survive"
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
                    "usage": "Verify",
                    "key": "cert-blob-existing-must-survive"
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
async fn remove_key_credential_preserves_the_surviving_certificate_blob() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo",
            "keyCredentials": [
                {"keyId": "keep", "displayName": "keep", "type": "AsymmetricX509Cert",
                 "usage": "Verify", "key": "cert-blob-keep-must-survive"},
                {"keyId": "drop", "displayName": "drop", "type": "AsymmetricX509Cert",
                 "usage": "Verify", "key": "cert-blob-drop"}
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "keyCredentials": [
                {"keyId": "keep", "displayName": "keep", "type": "AsymmetricX509Cert",
                 "usage": "Verify", "key": "cert-blob-keep-must-survive"}
            ]
        })))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client.remove_key_credential("obj-1", "drop").await.unwrap();
}

/// A key id that is already gone (another admin, a stale finding) is
/// `NotFound`, and the unchanged array is NOT written back: a PATCH would
/// report a removal that never happened.
#[tokio::test]
async fn remove_key_credential_refuses_an_absent_key_without_patching() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keyCredentials": [
                {"keyId": "keep", "type": "AsymmetricX509Cert", "usage": "Verify",
                 "key": "cert-blob-keep"}
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let err = client
        .remove_key_credential("obj-1", "gone")
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::NotFound(_)), "got {err:?}");
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

/// `addTokenSigningCertificate` writes three objects per certificate sharing
/// one `customKeyIdentifier`: a `Sign` key, a `Verify` key and the PFX
/// password in `passwordCredentials`. Retiring the certificate drops all
/// three (the thumbprint compared case-insensitively) and keeps every
/// unrelated entry byte-for-byte — removing only the key halves stranded the
/// password credential forever.
#[tokio::test]
async fn removing_a_sp_signing_cert_drops_both_key_halves_and_its_pfx_password() {
    let server = MockServer::start().await;
    let other_key = serde_json::json!({
        "keyId": "k-other", "customKeyIdentifier": "BBB", "usage": "Verify", "type": "AsymmetricX509Cert"
    });
    let other_password = serde_json::json!({ "keyId": "p-bbb", "customKeyIdentifier": "BBB" });
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/sp-1"))
        .and(query_param("$select", "keyCredentials,passwordCredentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keyCredentials": [
                { "keyId": "k-sign", "customKeyIdentifier": "AAA", "usage": "Sign", "type": "X509CertAndPassword" },
                // Same certificate, different case: the match is case-insensitive.
                { "keyId": "k-verify", "customKeyIdentifier": "aaa", "usage": "Verify", "type": "AsymmetricX509Cert" },
                other_key.clone()
            ],
            "passwordCredentials": [
                { "keyId": "p-aaa", "customKeyIdentifier": "AAA" },
                other_password.clone()
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/servicePrincipals/sp-1"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "keyCredentials": [other_key],
            "passwordCredentials": [other_password]
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    client
        .remove_service_principal_key_credential("sp-1", "k-sign")
        .await
        .expect("the PATCH carries exactly the surviving entries");
}

/// The SP-side twin: an absent key is `NotFound` with no PATCH — which also
/// retires the old no-op PATCH an unresolvable key used to send.
#[tokio::test]
async fn removing_an_absent_sp_key_sends_no_patch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/sp-1"))
        .and(query_param("$select", "keyCredentials,passwordCredentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keyCredentials": [
                { "keyId": "k-other", "customKeyIdentifier": "BBB", "usage": "Verify", "type": "AsymmetricX509Cert" }
            ],
            "passwordCredentials": [
                { "keyId": "p-bbb", "customKeyIdentifier": "BBB" }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/servicePrincipals/sp-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let err = client
        .remove_service_principal_key_credential("sp-1", "k-gone")
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::NotFound(_)), "got {err:?}");
}
