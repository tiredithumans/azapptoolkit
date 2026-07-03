use super::*;
use azapptoolkit_core::token::StaticTokenProvider;
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::error::ExchangeError;

fn make_client(base: &str) -> ExchangeClient {
    let token = StaticTokenProvider::new("tok");
    ExchangeClient::with_base_url(token, "tenant-1", "admin@contoso.com", base.to_string())
}

fn invoke_path() -> String {
    format!("/adminapi/{ADMIN_API_VERSION}/tenant-1/{INVOKE_ENDPOINT}")
}

#[tokio::test]
async fn new_service_principal_posts_cmdlet_envelope_with_anchor() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(header("authorization", "Bearer tok"))
        .and(header("x-anchormailbox", "UPN:admin@contoso.com"))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "New-ServicePrincipal",
                "Parameters": {
                    "AppId": "app-1",
                    "ObjectId": "obj-1",
                    "DisplayName": "Demo"
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "AppId": "app-1", "ObjectId": "obj-1", "DisplayName": "Demo" }]
        })))
        .mount(&server)
        .await;

    // get-first lookup returns nothing so we fall through to New-.
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-ServicePrincipal",
                "Parameters": { "Identity": "app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let sp = client
        .ensure_service_principal("app-1", "obj-1", "Demo")
        .await
        .unwrap();
    assert_eq!(sp.app_id.as_deref(), Some("app-1"));
    assert_eq!(sp.object_id.as_deref(), Some("obj-1"));
}

#[tokio::test]
async fn ensure_service_principal_skips_new_when_present() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-ServicePrincipal",
                "Parameters": { "Identity": "app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "AppId": "app-1", "ObjectId": "obj-existing", "DisplayName": "Existing" }]
        })))
        .mount(&server)
        .await;
    // No New-ServicePrincipal mock registered: any such call 404s and fails.
    let client = make_client(&server.uri());
    let sp = client
        .ensure_service_principal("app-1", "obj-1", "Demo")
        .await
        .unwrap();
    assert_eq!(sp.object_id.as_deref(), Some("obj-existing"));
}

#[tokio::test]
async fn new_role_assignment_includes_scope_when_present() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "New-ManagementRoleAssignment",
                "Parameters": {
                    "App": "app-1",
                    "Role": "Application Mail.Read",
                    "CustomResourceScope": "azapptoolkit_app-1"
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "Name": "ra-1",
                "Role": "Application Mail.Read",
                "RoleAssigneeName": "app-1",
                "CustomResourceScope": "azapptoolkit_app-1",
                "Identity": "ra-1"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let ra = client
        .new_role_assignment("app-1", "Application Mail.Read", Some("azapptoolkit_app-1"))
        .await
        .unwrap();
    assert_eq!(ra.role.as_deref(), Some("Application Mail.Read"));
}

#[tokio::test]
async fn list_service_principals_posts_empty_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-ServicePrincipal",
                "Parameters": {}
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "AppId": "app-1", "ObjectId": "obj-1", "DisplayName": "Demo" },
                { "AppId": "app-2", "ObjectId": "obj-2", "DisplayName": "Other" }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let sps = client.list_service_principals().await.unwrap();
    assert_eq!(sps.len(), 2);
    assert_eq!(sps[1].object_id.as_deref(), Some("obj-2"));
}

#[tokio::test]
async fn test_application_access_policy_posts_app_and_identity() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Test-ApplicationAccessPolicy",
                "Parameters": { "AppId": "app-1", "Identity": "user@contoso.com" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "AppId": "app-1",
                "Mailbox": "user",
                "AccessCheckResult": "Denied"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let result = client
        .test_application_access_policy("app-1", "user@contoso.com")
        .await
        .unwrap();
    assert_eq!(result.granted, Some(false));
}

#[tokio::test]
async fn get_group_returns_none_on_not_found_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            "The operation couldn't be performed because object 'x' couldn't be found.",
        ))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let group = client.get_group("missing").await.unwrap();
    assert!(group.is_none());
}

#[tokio::test]
async fn ensure_security_group_creates_when_missing() {
    let server = MockServer::start().await;
    // Get-first lookup returns nothing → fall through to New-.
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-DistributionGroup",
                "Parameters": { "Identity": "azapptoolkit_app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "New-DistributionGroup",
                "Parameters": {
                    "Name": "azapptoolkit_app-1",
                    "Alias": "azapptoolkit_app-1",
                    "Type": "Security",
                    "IgnoreNamingPolicy": true
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "DistinguishedName": "CN=azapptoolkit_app-1,OU=contoso,DC=prod",
                "PrimarySmtpAddress": "azapptoolkit_app-1@contoso.com",
                "Name": "azapptoolkit_app-1"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let g = client
        .ensure_security_group("azapptoolkit_app-1", "azapptoolkit_app-1")
        .await
        .unwrap();
    assert_eq!(
        g.distinguished_name.as_deref(),
        Some("CN=azapptoolkit_app-1,OU=contoso,DC=prod")
    );
}

#[tokio::test]
async fn ensure_security_group_reuses_existing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-DistributionGroup",
                "Parameters": { "Identity": "azapptoolkit_app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "DistinguishedName": "CN=existing,DC=prod",
                "Name": "azapptoolkit_app-1"
            }]
        })))
        .mount(&server)
        .await;
    // No New-DistributionGroup mock: creating again would 404 and fail.
    let client = make_client(&server.uri());
    let g = client
        .ensure_security_group("azapptoolkit_app-1", "azapptoolkit_app-1")
        .await
        .unwrap();
    assert_eq!(g.distinguished_name.as_deref(), Some("CN=existing,DC=prod"));
}

#[tokio::test]
async fn add_group_member_swallows_already_member() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            "The recipient \"user@contoso.com\" is already a member of the group.",
        ))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    // A 400 "already a member" must resolve to Ok (idempotent re-add).
    client
        .add_group_member("azapptoolkit_app-1", "user@contoso.com")
        .await
        .unwrap();
}

#[tokio::test]
async fn remove_group_member_swallows_not_a_member() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("The recipient \"user@contoso.com\" isn't a member of the group."),
        )
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .remove_group_member("azapptoolkit_app-1", "user@contoso.com")
        .await
        .unwrap();
}

#[tokio::test]
async fn list_group_members_projects_recipients() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-DistributionGroupMember",
                "Parameters": { "Identity": "azapptoolkit_app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "DisplayName": "Ada", "PrimarySmtpAddress": "ada@contoso.com", "RecipientType": "UserMailbox" },
                { "DisplayName": "Bo", "PrimarySmtpAddress": "bo@contoso.com", "RecipientType": "UserMailbox" }
            ]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let members = client
        .list_group_members("azapptoolkit_app-1")
        .await
        .unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(
        members[0].primary_smtp_address.as_deref(),
        Some("ada@contoso.com")
    );
}

#[tokio::test]
async fn unauthorized_maps_to_typed_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let err = client.get_application_access_policies().await.unwrap_err();
    assert!(matches!(err, ExchangeError::Unauthorized));
}

#[tokio::test]
async fn retry_after_is_honored_on_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let policies = client.get_application_access_policies().await.unwrap();
    assert!(policies.is_empty());
}

// The free-fn unit tests (member_of_group_filter, escape_opath,
// sanitize_error_body, compose_error_detail) live beside their subjects in
// `client/groups.rs` and `client/transport.rs`.

#[tokio::test]
async fn forbidden_surfaces_diagnostics_header_reason() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ms-diagnostics", "2000003;reason=\"role required\"")
                .insert_header("request-id", "req-9")
                .set_body_string("\0\0\0"),
        )
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let err = client.get_application_access_policies().await.unwrap_err();
    match err {
        ExchangeError::Forbidden {
            detail,
            had_diagnostics,
        } => {
            assert!(detail.contains("Get-ApplicationAccessPolicy"));
            assert!(detail.contains("role required"));
            assert!(detail.contains("req-9"));
            // x-ms-diagnostics was present → the confident RBAC hint applies.
            assert!(had_diagnostics);
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[tokio::test]
async fn forbidden_without_diagnostics_is_flagged_reasonless() {
    // A 403 with neither an x-ms-diagnostics reason nor a body (only a
    // request-id) — the shape a stale role token produces. It must be flagged
    // `had_diagnostics: false` so the UI hint avoids asserting a definite
    // Exchange RBAC gap (see `ExchangeError::ui_hint`).
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("request-id", "req-7")
                .set_body_string("\0\0\0"),
        )
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let err = client.get_application_access_policies().await.unwrap_err();
    match err {
        ExchangeError::Forbidden {
            detail,
            had_diagnostics,
        } => {
            assert!(!had_diagnostics);
            assert!(detail.contains("<no body>"));
            assert!(detail.contains("req-7"));
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
}
