//! End-to-end handler tests against a mock Graph — the shape
//! `applications::credentials::handler_tests` established. Kept apart from
//! `tests` (pure helpers) so the mock-server fixtures don't grow into it.

use crate::state::AppState;

use super::config::{
    get_sso_config_core, set_claims_mapping_core, set_oidc_redirect_uris_core, set_saml_urls_core,
};
use super::create::{
    configure_oidc, configure_saml, create_oidc_sso_application_core,
    create_saml_sso_application_core,
};

use crate::dto::sso::{
    ClaimsPolicyDto, OidcSsoConfigInput, SamlSsoConfigInput, SamlSsoSummary, SsoSummary,
};

use super::*;

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::{Application, ServicePrincipal};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::commands::applications::{
    app_detail_key, app_name_index_hit, app_name_index_store, sp_index_hit, sp_index_store,
};

const TENANT: &str = "t1";
const OBJECT: &str = "obj-1";

/// Seeds what an in-place PATCH must NOT drop (the two pinned tenant-wide
/// indexes) alongside what it must drop (the app's detail row).
fn seed(state: &AppState) {
    sp_index_store(&state.cache, TENANT, vec![ServicePrincipal::default()]);
    app_name_index_store(&state.cache, TENANT, vec![Application::default()]);
    state.cache.put(
        CacheKind::Lists,
        app_detail_key(TENANT, OBJECT),
        &serde_json::json!({"id": OBJECT}),
    );
}

fn detail_cached(state: &AppState) -> bool {
    state
        .cache
        .get::<serde_json::Value>(CacheKind::Lists, &app_detail_key(TENANT, OBJECT))
        .is_some()
}

/// Opening the SSO tab reads the service principal ONCE: the owner summary
/// and the rollover panel's initial state ride on `get_sso_config` instead
/// of re-running the SP→app chain (`get_sso_summary`) and re-reading the SP
/// (`get_signing_cert_rollover`). The mock's `expect(1)` is the pin.
#[tokio::test]
async fn an_sso_tab_open_reads_the_service_principal_once() {
    // Real encoding pair (base64 customKeyIdentifier / hex nomination) —
    // see the rollover fixtures in `tests`.
    const A_B64: &str = "ATKoPe8CbYUF5PKRSLDOvhutu7A=";
    const A_HEX: &str = "0132A83DEF026D8505E4F29148B0CEBE1BADBBB0";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/servicePrincipals/sp-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sp-1",
            "appId": "app-1",
            "preferredSingleSignOnMode": "saml",
            "preferredTokenSigningKeyThumbprint": A_HEX.to_ascii_lowercase(),
            "keyCredentials": [
                { "keyId": "k1", "customKeyIdentifier": A_B64, "usage": "Sign",
                  "endDateTime": "2099-01-01T00:00:00Z" },
                { "keyId": "k2", "customKeyIdentifier": A_B64, "usage": "Verify",
                  "endDateTime": "2099-01-01T00:00:00Z" }
            ],
            "notificationEmailAddresses": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .mount(&server)
        .await;
    // The claims list is left unmocked: it 404s and degrades to
    // `claims_read_failed`, which is what a missing consent looks like.

    let state = AppState::for_test(TENANT, &server.uri());
    let cfg = get_sso_config_core(&state, TENANT, "sp-1".into())
        .await
        .expect("the SSO config reads");

    assert!(cfg.claims_read_failed);
    assert_eq!(cfg.signing_cert_thumbprint.as_deref(), Some(A_HEX));
    match cfg.summary {
        Some(SsoSummary::Saml(ref s)) => {
            assert!(
                s.federation_metadata_url.ends_with("appid=app-1"),
                "{}",
                s.federation_metadata_url
            );
            assert!(s.login_url.ends_with(&format!("/{TENANT}/saml2")));
        }
        ref other => panic!("a SAML app must carry a SAML summary, got {other:?}"),
    }
    let roll = cfg.rollover.expect("a SAML app carries its rollover state");
    assert_eq!(roll.phase, azapptoolkit_dto::sso::RolloverPhase::Steady);
    assert_eq!(
        roll.certs.len(),
        1,
        "the Sign/Verify pair is one certificate"
    );
    assert_eq!(roll.active_thumbprint.as_deref(), Some(A_HEX));
    // Dropping the server verifies `expect(1)`.
}

#[tokio::test]
async fn a_redirect_uri_patch_busts_the_detail_tier_and_keeps_the_indexes() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(format!("/v1.0/applications/{OBJECT}")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);

    set_oidc_redirect_uris_core(
        &state,
        TENANT,
        OBJECT,
        vec!["https://app.example/cb".into()],
        Vec::new(),
    )
    .await
    .expect("the mocked PATCH succeeds");

    assert!(
        !detail_cached(&state),
        "the app's detail row must be busted — the Authentication tab reads it"
    );
    // The point of the detail tier: a redirect-URI edit adds, removes or
    // renames no app or SP, so the two indexes (a full directory scan each
    // to rebuild) must survive it.
    assert!(
        sp_index_hit(&state.cache, TENANT).is_some(),
        "the SP index must survive an in-place app PATCH"
    );
    assert!(
        app_name_index_hit(&state.cache, TENANT).is_some(),
        "the app-registration index must survive an in-place app PATCH"
    );
}

#[tokio::test]
async fn a_failed_redirect_uri_patch_invalidates_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(format!("/v1.0/applications/{OBJECT}")))
        .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
        .mount(&server)
        .await;

    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);

    let err = set_oidc_redirect_uris_core(
        &state,
        TENANT,
        OBJECT,
        vec!["https://app.example/cb".into()],
        Vec::new(),
    )
    .await
    .expect_err("a 403 must surface as an error");
    assert_eq!(err.code, "forbidden");

    // "Invalidate caches only on `Ok`".
    assert!(
        detail_cached(&state),
        "a failed mutation must leave the cached detail row alone"
    );
    assert!(sp_index_hit(&state.cache, TENANT).is_some());
    assert!(app_name_index_hit(&state.cache, TENANT).is_some());
}

#[tokio::test]
async fn an_invalid_redirect_uri_never_reaches_graph() {
    // No mock mounted: any request would 404 and fail the test differently.
    let server = MockServer::start().await;
    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);

    let err = set_oidc_redirect_uris_core(
        &state,
        TENANT,
        OBJECT,
        vec!["http://insecure.example/cb".into()],
        Vec::new(),
    )
    .await
    .expect_err("an insecure redirect URI is rejected locally");
    assert_eq!(err.code, "invalid_redirect_uri");
    assert!(
        detail_cached(&state),
        "a rejected input invalidates nothing"
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
}

/// The SAML URL editor validated its reply URLs and then wrote the logout URL
/// as typed. A plaintext or custom-scheme logout URL is refused before any
/// request, by the logout rules rather than the reply-URL ones.
#[tokio::test]
async fn an_invalid_saml_logout_url_never_reaches_graph() {
    // No mock mounted: any request would be recorded (and 404).
    let server = MockServer::start().await;
    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);

    for logout in ["http://evil.example/logout", "myapp://logout"] {
        let err = set_saml_urls_core(
            &state,
            TENANT,
            OBJECT,
            vec!["https://sp.example".into()],
            vec!["https://sp.example/acs".into()],
            Some(format!("  {logout}  ")),
        )
        .await
        .expect_err("an unsafe logout URL is rejected locally");
        assert_eq!(err.code, "invalid_redirect_uri", "{logout}");
        // The editor re-sends the stored logout URL on every save, so the
        // error names the field.
        assert!(err.message.starts_with("Logout URL: "), "{}", err.message);
    }
    assert!(
        detail_cached(&state),
        "a rejected input invalidates nothing"
    );
    let requests = server
        .received_requests()
        .await
        .expect("request recording is on");
    assert!(
        requests.is_empty(),
        "{} request(s) reached Graph",
        requests.len()
    );
}

/// A valid logout URL is written trimmed — the value that was checked.
#[tokio::test]
async fn a_saml_logout_url_is_written_trimmed() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(format!("/v1.0/applications/{OBJECT}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let state = AppState::for_test(TENANT, &server.uri());

    set_saml_urls_core(
        &state,
        TENANT,
        OBJECT,
        vec!["https://sp.example".into()],
        vec!["https://sp.example/acs".into()],
        Some(" https://sp.example/logout ".into()),
    )
    .await
    .expect("a valid logout URL is saved");
    let requests = server.received_requests().await.expect("recording is on");
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).expect("JSON body");
    assert_eq!(body["web"]["logoutUrl"], "https://sp.example/logout");
}

/// The SAML create wizard: same gate, before instantiate, so no app or service
/// principal is left half-configured.
#[tokio::test]
async fn an_invalid_saml_create_logout_url_never_reaches_graph() {
    let server = MockServer::start().await;
    let state = AppState::for_test(TENANT, &server.uri());

    for logout in ["http://evil.example/logout", "myapp://logout"] {
        let input = SamlSsoConfigInput {
            logout_url: Some(logout.into()),
            ..saml_input()
        };
        let err = create_saml_sso_application_core(&state, TENANT, input)
            .await
            .expect_err("an unsafe logout URL is rejected before instantiate");
        assert_eq!(err.code, "invalid_redirect_uri", "{logout}");
        assert!(err.message.starts_with("Logout URL: "), "{}", err.message);
    }
    let requests = server
        .received_requests()
        .await
        .expect("request recording is on");
    assert!(
        requests.is_empty(),
        "{} request(s) reached Graph",
        requests.len()
    );
}

/// The create wizard writes the logout URL it checked: trimmed.
#[tokio::test]
async fn a_saml_create_logout_url_is_written_trimmed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1.0/applicationTemplates/{}/instantiate",
            CloudEnvironment::Commercial.custom_app_template_id()
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "application": { "id": OBJECT, "appId": "app-1" },
            "servicePrincipal": { "id": SP, "appId": "app-1" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_saml_create(&server).await;
    let state = AppState::for_test(TENANT, &server.uri());

    // No claims or notification steps: only the URL write matters here.
    let input = SamlSsoConfigInput {
        logout_url: Some(" https://sp.example/logout ".into()),
        claims_policy: None,
        notification_emails: Vec::new(),
        ..saml_input()
    };
    create_saml_sso_application_core(&state, TENANT, input)
        .await
        .expect("a valid logout URL is saved");
    let requests = server.received_requests().await.expect("recording is on");
    let app_patch = requests
        .iter()
        .find(|r| {
            r.method.as_str() == "PATCH" && r.url.path() == format!("/v1.0/applications/{OBJECT}")
        })
        .expect("the app's SSO URLs are written");
    let body: serde_json::Value = serde_json::from_slice(&app_patch.body).expect("JSON body");
    assert_eq!(body["web"]["logoutUrl"], "https://sp.example/logout");
}

// ---- claims-mapping policy saves ----

const SP: &str = "sp-1";

fn claims_policy() -> ClaimsPolicyDto {
    ClaimsPolicyDto {
        schema: vec![crate::dto::sso::ClaimSchemaEntryDto {
            source: Some("user".into()),
            id: Some("mail".into()),
            jwt_claim_type: Some("email".into()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

async fn mount_assigned(server: &MockServer, ids: &[&str]) {
    let value: Vec<serde_json::Value> = ids
        .iter()
        .map(|id| serde_json::json!({"id": id, "definition": ["{}"]}))
        .collect();
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1.0/servicePrincipals/{SP}/claimsMappingPolicies"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": value })),
        )
        .mount(server)
        .await;
}

async fn mount_subjects(server: &MockServer, policy: &str, subjects: &[&str]) {
    let value: Vec<serde_json::Value> = subjects
        .iter()
        .map(|id| serde_json::json!({ "id": id }))
        .collect();
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1.0/policies/claimsMappingPolicies/{policy}/appliesTo"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": value })),
        )
        .mount(server)
        .await;
}

/// Mounts every claims write with the expected call count.
async fn mount_writes(
    server: &MockServer,
    patch: u64,
    create: u64,
    unassign: u64,
    assign: u64,
    delete: u64,
) {
    Mock::given(method("PATCH"))
        .and(path("/v1.0/policies/claimsMappingPolicies/pol-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(patch)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1.0/policies/claimsMappingPolicies"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "pol-new", "displayName": "Custom claims", "definition": ["{}"]
        })))
        .expect(create)
        .mount(server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "/v1.0/servicePrincipals/{SP}/claimsMappingPolicies/pol-1/$ref"
        )))
        .respond_with(ResponseTemplate::new(204))
        .expect(unassign)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1.0/servicePrincipals/{SP}/claimsMappingPolicies/$ref"
        )))
        .respond_with(ResponseTemplate::new(204))
        .expect(assign)
        .mount(server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1.0/policies/claimsMappingPolicies/pol-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(delete)
        .mount(server)
        .await;
}

fn assert_detail_tier_only(state: &AppState) {
    assert!(!detail_cached(state), "a claims save busts the detail tier");
    assert!(
        sp_index_hit(&state.cache, TENANT).is_some(),
        "the SP index must survive a claims save"
    );
    assert!(
        app_name_index_hit(&state.cache, TENANT).is_some(),
        "the app-registration index must survive a claims save"
    );
}

#[tokio::test]
async fn a_claims_save_patches_a_policy_this_app_owns_in_place() {
    let server = MockServer::start().await;
    mount_assigned(&server, &["pol-1"]).await;
    mount_subjects(&server, "pol-1", &[SP]).await;
    mount_writes(&server, 1, 0, 0, 0, 0).await;

    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);
    let id = set_claims_mapping_core(&state, TENANT, SP, "Custom claims", &claims_policy())
        .await
        .expect("the mocked PATCH succeeds");
    assert_eq!(id.as_deref(), Some("pol-1"), "same policy, edited in place");
    assert_detail_tier_only(&state);
}

#[tokio::test]
async fn a_claims_save_on_a_shared_policy_forks_a_private_copy() {
    let server = MockServer::start().await;
    mount_assigned(&server, &["pol-1"]).await;
    mount_subjects(&server, "pol-1", &[SP, "other-sp"]).await;
    // Never PATCH (it would change the other app's claims), never delete.
    mount_writes(&server, 0, 1, 1, 1, 0).await;

    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);
    let id = set_claims_mapping_core(&state, TENANT, SP, "Custom claims", &claims_policy())
        .await
        .expect("the mocked fork succeeds");
    assert_eq!(id.as_deref(), Some("pol-new"));
    assert_detail_tier_only(&state);
}

#[tokio::test]
async fn a_failed_claims_listing_writes_nothing_and_invalidates_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1.0/servicePrincipals/{SP}/claimsMappingPolicies"
        )))
        .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
        .mount(&server)
        .await;
    mount_writes(&server, 0, 0, 0, 0, 0).await;

    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);
    let err = set_claims_mapping_core(&state, TENANT, SP, "Custom claims", &claims_policy())
        .await
        .expect_err("a failed listing surfaces instead of being guessed around");
    assert_eq!(err.code, "forbidden");
    assert!(detail_cached(&state), "a failed save invalidates nothing");
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests.iter().all(|r| r.method.as_str() == "GET"),
        "no write may follow a failed listing: {requests:?}"
    );
}

#[tokio::test]
async fn clearing_claims_unassigns_and_deletes_an_orphaned_policy() {
    let server = MockServer::start().await;
    mount_assigned(&server, &["pol-1"]).await;
    mount_subjects(&server, "pol-1", &[SP]).await;
    mount_writes(&server, 0, 0, 1, 0, 1).await;

    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);
    let id = set_claims_mapping_core(
        &state,
        TENANT,
        SP,
        "Custom claims",
        &ClaimsPolicyDto::default(),
    )
    .await
    .expect("the mocked detach succeeds");
    assert_eq!(id, None);
    assert_detail_tier_only(&state);
}

#[tokio::test]
async fn clearing_claims_never_deletes_a_shared_policy() {
    let server = MockServer::start().await;
    mount_assigned(&server, &["pol-1"]).await;
    mount_subjects(&server, "pol-1", &[SP, "other-sp"]).await;
    mount_writes(&server, 0, 0, 1, 0, 0).await;

    let state = AppState::for_test(TENANT, &server.uri());
    seed(&state);
    let id = set_claims_mapping_core(
        &state,
        TENANT,
        SP,
        "Custom claims",
        &ClaimsPolicyDto::default(),
    )
    .await
    .expect("the mocked unassign succeeds");
    assert_eq!(id, None);
}

// ---- SAML create orchestration (`configure_saml`, steps 2–6) ----

const CERT_PATH: &str = "/v1.0/servicePrincipals/sp-1/addTokenSigningCertificate";

/// Mounts the always-succeeding writes of a SAML create: both PATCHes and
/// the certificate mint. Individual tests layer higher-priority failures on
/// top.
async fn mount_saml_create(server: &MockServer) {
    Mock::given(method("PATCH"))
        .and(path(format!("/v1.0/servicePrincipals/{SP}")))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("/v1.0/applications/{OBJECT}")))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(CERT_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "thumbprint": "C2DDD8044C956ACD0269A75A64B7862DB9DDAC3E",
            "key": "MIIC-test",
            "endDateTime": "2027-01-01T00:00:00Z"
        })))
        .mount(server)
        .await;
}

/// Mounts a claims-policy create + assign that succeed.
async fn mount_claims_create_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1.0/policies/claimsMappingPolicies"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "pol-new", "displayName": "Contoso claims", "definition": ["{}"]
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1.0/servicePrincipals/{SP}/claimsMappingPolicies/$ref"
        )))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

fn saml_input() -> SamlSsoConfigInput {
    SamlSsoConfigInput {
        display_name: "Contoso".into(),
        entity_id: "https://sp.example".into(),
        reply_url: "https://sp.example/acs".into(),
        claims_policy: Some(claims_policy()),
        notification_emails: vec!["ops@example.com".into()],
        ..Default::default()
    }
}

async fn run_saml_create(server: &MockServer) -> Result<SamlSsoSummary, UiError> {
    let state = AppState::for_test(TENANT, &server.uri());
    let client = state.graph_for(TENANT);
    configure_saml(
        &client,
        CloudEnvironment::Commercial,
        OBJECT,
        SP,
        TENANT,
        "app-1",
        &saml_input(),
    )
    .await
}

#[tokio::test]
async fn a_clean_saml_create_has_no_warnings() {
    let server = MockServer::start().await;
    mount_saml_create(&server).await;
    mount_claims_create_ok(&server).await;

    let summary = run_saml_create(&server).await.expect("every step succeeds");
    assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
    assert_eq!(summary.claims_policy_id.as_deref(), Some("pol-new"));
    assert_eq!(summary.signing_cert_base64.as_deref(), Some("MIIC-test"));
}

#[tokio::test]
async fn a_saml_create_reports_a_failed_claims_step_as_a_warning() {
    let server = MockServer::start().await;
    mount_saml_create(&server).await;
    // 403, not 5xx: `http_retry` would retry a 5xx.
    Mock::given(method("POST"))
        .and(path("/v1.0/policies/claimsMappingPolicies"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
        .mount(&server)
        .await;

    let summary = run_saml_create(&server)
        .await
        .expect("the claims step is best-effort; the create still succeeds");
    assert_eq!(summary.claims_policy_id, None);
    assert_eq!(summary.warnings.len(), 1, "{:?}", summary.warnings);
    let w = &summary.warnings[0];
    assert!(w.starts_with("Custom claims were not applied"), "{w}");
    // The 403 carries the role remediation, like the SSO tab's save.
    assert!(w.contains("Application Administrator"), "{w}");
    assert!(w.contains("Save claims"), "{w}");
}

#[tokio::test]
async fn a_saml_create_reports_failed_notification_emails_as_a_warning() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(format!("/v1.0/servicePrincipals/{SP}")))
        .and(wiremock::matchers::body_string_contains(
            "notificationEmailAddresses",
        ))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid address"))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_saml_create(&server).await;
    mount_claims_create_ok(&server).await;

    let summary = run_saml_create(&server)
        .await
        .expect("the email step is best-effort; the create still succeeds");
    assert_eq!(summary.warnings.len(), 1, "{:?}", summary.warnings);
    assert!(
        summary.warnings[0].starts_with("Certificate-expiry notification emails were not saved"),
        "{}",
        summary.warnings[0]
    );
    assert_eq!(summary.claims_policy_id.as_deref(), Some("pol-new"));
}

#[tokio::test]
async fn a_lagging_replica_at_certificate_mint_is_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(CERT_PATH))
        .respond_with(ResponseTemplate::new(404))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    mount_saml_create(&server).await;
    mount_claims_create_ok(&server).await;

    let summary = run_saml_create(&server)
        .await
        .expect("a NotFound right after instantiate is replication lag");
    assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
    let mints = server
        .received_requests()
        .await
        .expect("request recording is on")
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == CERT_PATH)
        .count();
    assert_eq!(mints, 2, "one 404, then the retry that landed");
}

#[tokio::test]
async fn a_lagging_replica_at_certificate_activation_is_retried() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(format!("/v1.0/servicePrincipals/{SP}")))
        .and(wiremock::matchers::body_string_contains(
            "preferredTokenSigningKeyThumbprint",
        ))
        .respond_with(ResponseTemplate::new(404))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    mount_saml_create(&server).await;
    mount_claims_create_ok(&server).await;

    run_saml_create(&server)
        .await
        .expect("the activation PATCH waits out replication lag");
    let activations = server
        .received_requests()
        .await
        .expect("request recording is on")
        .iter()
        .filter(|r| {
            r.method.as_str() == "PATCH"
                && String::from_utf8_lossy(&r.body).contains("preferredTokenSigningKeyThumbprint")
        })
        .count();
    assert_eq!(activations, 2, "one 404, then the retry that landed");
}

fn oidc_input(secret_lifetime_days: Option<u32>) -> OidcSsoConfigInput {
    OidcSsoConfigInput {
        display_name: "x".into(),
        secret_display_name: Some("oidc".into()),
        secret_lifetime_days,
        ..Default::default()
    }
}

#[tokio::test]
async fn an_oidc_secret_is_minted_inside_the_two_year_cap() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v1.0/applications/{OBJECT}/addPassword")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keyId": "k1",
            "displayName": "oidc",
            "secretText": "s3cret"
        })))
        .mount(&server)
        .await;
    let state = AppState::for_test(TENANT, &server.uri());
    let client = state.graph_for(TENANT);

    let (summary, minted) = configure_oidc(
        &client,
        CloudEnvironment::Commercial,
        OBJECT,
        "app-1",
        SP,
        TENANT,
        &oidc_input(Some(730)),
    )
    .await
    .expect("the secret is minted");
    assert!(summary.client_secret.is_some());
    // The metadata handed to the cache patch never carries the value.
    assert!(minted.expect("the secret's metadata").secret_text.is_none());

    let requests = server
        .received_requests()
        .await
        .expect("request recording is on");
    assert_eq!(requests.len(), 1, "only addPassword — no redirect PATCH");
    let body: serde_json::Value = requests[0].body_json().expect("JSON body");
    let end = body["passwordCredential"]["endDateTime"]
        .as_str()
        .expect("endDateTime is sent");
    let end = chrono::DateTime::parse_from_rfc3339(end).expect("RFC 3339 endDateTime");
    let want = chrono::Utc::now() + chrono::Duration::days(730);
    let drift = (end.with_timezone(&chrono::Utc) - want).num_seconds().abs();
    assert!(drift <= 300, "endDateTime {end} is not now + 730 days");
}

#[tokio::test]
async fn an_out_of_range_secret_lifetime_never_reaches_graph() {
    // No mocks: any request would be recorded (and 404).
    let server = MockServer::start().await;
    let state = AppState::for_test(TENANT, &server.uri());
    let client = state.graph_for(TENANT);

    for days in [Some(0), Some(731), Some(u32::MAX)] {
        // The create gate: rejected before instantiate, so no app or
        // service principal is left half-configured.
        let err = create_oidc_sso_application_core(&state, TENANT, oidc_input(days))
            .await
            .unwrap_err();
        assert_eq!(err.code, "invalid_secret_lifetime", "{days:?}");
        // And `configure_oidc` resolves through the same gate.
        let err = configure_oidc(
            &client,
            CloudEnvironment::Commercial,
            OBJECT,
            "app-1",
            SP,
            TENANT,
            &oidc_input(days),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "invalid_secret_lifetime", "{days:?}");
    }
    let requests = server
        .received_requests()
        .await
        .expect("request recording is on");
    assert!(
        requests.is_empty(),
        "{} request(s) reached Graph",
        requests.len()
    );
}
