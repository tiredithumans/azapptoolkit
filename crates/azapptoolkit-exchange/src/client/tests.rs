use super::*;
use azapptoolkit_core::token::StaticTokenProvider;
use serde_json::json;
use wiremock::matchers::{body_json, body_string_contains, header, method, path};
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
async fn set_management_scope_filter_rereads_when_the_cmdlet_returns_nothing() {
    // `Set-ManagementScope` emits no object on success, so the client re-reads
    // the scope — that read is what proves the new filter actually landed.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Set-ManagementScope",
                "Parameters": {
                    "Identity": "app_scope_app-1",
                    "RecipientRestrictionFilter": "MemberOfGroup -eq 'CN=Managed,DC=prod'",
                    "Confirm": false
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-ManagementScope",
                "Parameters": { "Identity": "app_scope_app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "Name": "app_scope_app-1",
                "RecipientFilter": "MemberOfGroup -eq 'CN=Managed,DC=prod'"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let scope = client
        .set_management_scope_filter("app_scope_app-1", "MemberOfGroup -eq 'CN=Managed,DC=prod'")
        .await
        .unwrap();
    assert_eq!(
        scope.recipient_filter.as_deref(),
        Some("MemberOfGroup -eq 'CN=Managed,DC=prod'")
    );
}

#[tokio::test]
async fn set_management_scope_filter_rejects_a_filter_that_did_not_land() {
    // The re-read proves a scope by that name EXISTS — which was already true
    // before the call. It must also prove the filter took: this scope governs
    // every role assignment using it, so reporting success on an unapplied
    // filter leaves them all pointed at the previous group set.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Set-ManagementScope",
                "Parameters": {
                    "Identity": "app_scope_app-1",
                    "RecipientRestrictionFilter": "MemberOfGroup -eq 'CN=Managed,DC=prod'",
                    "Confirm": false
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .mount(&server)
        .await;
    // Exchange still reports the OLD group — the repoint silently did not apply.
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-ManagementScope",
                "Parameters": { "Identity": "app_scope_app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "Name": "app_scope_app-1",
                "RecipientFilter": "MemberOfGroup -eq 'CN=Stale,DC=prod'"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    let err = client
        .set_management_scope_filter("app_scope_app-1", "MemberOfGroup -eq 'CN=Managed,DC=prod'")
        .await
        .expect_err("a filter that did not land must not report success");
    assert!(
        err.to_string().contains("did not take the filter"),
        "error must name the unapplied filter, got: {err}"
    );
}

#[tokio::test]
async fn set_management_scope_filter_accepts_exchange_reformatting_the_same_groups() {
    // The comparison is on the group DN *set*, not the raw string: Exchange
    // normalizes OPATH whitespace, parens and quoting, and a byte comparison
    // would reject filters that applied perfectly.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Set-ManagementScope",
                "Parameters": {
                    "Identity": "app_scope_app-1",
                    "RecipientRestrictionFilter": "MemberOfGroup -eq 'CN=A,DC=prod' -or MemberOfGroup -eq 'CN=B,DC=prod'",
                    "Confirm": false
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-ManagementScope",
                "Parameters": { "Identity": "app_scope_app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "Name": "app_scope_app-1",
                // Same two groups, Exchange's own formatting.
                "RecipientFilter": "((MemberOfGroup -eq 'CN=B,DC=prod') -or (MemberOfGroup -eq 'CN=A,DC=prod'))"
            }]
        })))
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    client
        .set_management_scope_filter(
            "app_scope_app-1",
            "MemberOfGroup -eq 'CN=A,DC=prod' -or MemberOfGroup -eq 'CN=B,DC=prod'",
        )
        .await
        .expect("reformatting that preserves the group set must be accepted");
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

#[tokio::test]
async fn a_paged_collection_is_followed_to_the_end() {
    // The admin API caps a response at 1000 entries and signals more with
    // `@odata.nextLink`; continuation is a POST to that URL with the SAME body
    // (not a GET, unlike Graph). Dropping the link returned a first page
    // indistinguishable from a complete collection — and every caller of a
    // collection read here feeds a scoping decision that is only sound on a
    // complete set (`plan_consolidation`'s "unverified == 0", the reverse
    // "which scopes reference this group" lookup).
    let server = MockServer::start().await;
    let page2 = format!("{}/page2", server.uri());

    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "Name": "scope-a", "RecipientFilter": "MemberOfGroup -eq 'CN=a'" }],
            "@odata.nextLink": page2,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/page2"))
        // Same body as the first request, per the pagination contract.
        .and(body_json(json!({
            "CmdletInput": { "CmdletName": "Get-ManagementScope", "Parameters": {} }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "Name": "scope-b", "RecipientFilter": "MemberOfGroup -eq 'CN=b'" }]
        })))
        .mount(&server)
        .await;

    let scopes = make_client(&server.uri())
        .list_management_scopes()
        .await
        .expect("paged read");
    let names: Vec<_> = scopes.iter().filter_map(|s| s.name.as_deref()).collect();
    assert_eq!(
        names,
        vec!["scope-a", "scope-b"],
        "the second page must be followed, not dropped"
    );
}

/// A `nextLink` naming a foreign host must not receive the Exchange admin
/// bearer. `core::net` states the rule in its own module doc and Graph, ARM and
/// Key Vault all enforce it; this client followed the link verbatim, so a
/// response body could redirect an admin-scoped token to any host.
#[tokio::test]
async fn a_next_link_on_a_foreign_origin_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "Name": "scope-a", "RecipientFilter": "MemberOfGroup -eq 'CN=a'" }],
            "@odata.nextLink": "https://evil.example/page2",
        })))
        .mount(&server)
        .await;

    let err = make_client(&server.uri())
        .list_management_scopes()
        .await
        .expect_err("an off-origin continuation must not be followed");
    let msg = err.to_string();
    assert!(
        msg.contains("different origin"),
        "the refusal must say why: {msg}"
    );
    // The offending host is named, but the full attacker-controlled URL is not
    // echoed into logs or error UI.
    assert!(msg.contains("evil.example"), "{msg}");
    assert!(
        !msg.contains("/page2"),
        "the full link must not be echoed: {msg}"
    );
}

#[tokio::test]
async fn a_single_page_response_makes_exactly_one_request() {
    // The paging loop must not cost an extra round trip on the common case: no
    // `@odata.nextLink` means done.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "Name": "only", "RecipientFilter": "MemberOfGroup -eq 'CN=x'" }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let scopes = make_client(&server.uri())
        .list_management_scopes()
        .await
        .expect("single page");
    assert_eq!(scopes.len(), 1);
    // `expect(1)` is asserted when the server drops at end of scope.
}

#[tokio::test]
async fn an_empty_body_mid_pagination_fails_instead_of_truncating() {
    // The previous page promised a continuation, so an empty body here is a
    // broken response — not the end of the collection. Returning the pages read
    // so far as `Ok` handed the consolidation planner a short list, and a short
    // list is what its "unverified == 0" check reads as "nothing left to
    // verify". A truncated collection widens access, so it has to fail.
    let server = MockServer::start().await;
    let page2 = format!("{}/page2", server.uri());
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "Name": "scope-a", "RecipientFilter": "MemberOfGroup -eq 'CN=a'" }],
            "@odata.nextLink": page2,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/page2"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(Vec::new()))
        .mount(&server)
        .await;

    match make_client(&server.uri()).list_management_scopes().await {
        Err(ExchangeError::Protocol(msg)) => {
            assert!(
                msg.contains("truncated"),
                "the error must say why it refused: {msg}"
            );
        }
        other => panic!("expected a Protocol refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_not_found_mid_pagination_is_not_reported_as_an_absent_object() {
    // `invoke_optional` maps `NotFound` to an empty collection so a missing
    // `-Identity` reads as `None`. That is only sound on the FIRST page: a 404
    // while following an `@odata.nextLink` means the continuation expired or
    // broke, and mapping it to empty turned "I read half of this object's
    // scopes" into "this object has none".
    let server = MockServer::start().await;
    let page2 = format!("{}/page2", server.uri());
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "Name": "scope-a", "RecipientFilter": "MemberOfGroup -eq 'CN=a'" }],
            "@odata.nextLink": page2,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/page2"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": "ResourceNotFound", "message": "not found" }
        })))
        .mount(&server)
        .await;

    match make_client(&server.uri()).list_management_scopes().await {
        Err(ExchangeError::Protocol(msg)) => {
            assert!(
                msg.contains("page 2"),
                "should name the failing page: {msg}"
            );
            assert!(msg.contains("truncated"), "and why it refused: {msg}");
        }
        other => panic!("a mid-pagination 404 must not become an empty collection: {other:?}"),
    }
}

#[tokio::test]
async fn an_empty_next_link_terminates_rather_than_looping() {
    // A present-but-blank link is treated as "no more pages", not as a URL to
    // POST to — otherwise one malformed response spins until MAX_PAGES.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "Name": "only" }],
            "@odata.nextLink": "   ",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let scopes = make_client(&server.uri())
        .list_management_scopes()
        .await
        .expect("blank link terminates");
    assert_eq!(scopes.len(), 1);
}

// ── Retry class: a write is not replayed after an unknown outcome ──────────

#[tokio::test]
async fn a_write_is_not_replayed_after_a_server_error() {
    // A 502 on a POST leaves the outcome unknown: the write may already have
    // committed. Replaying `New-ManagementRoleAssignment` then fails as a
    // duplicate ("failed to assign", org-wide grant kept) and replaying
    // `Remove-ApplicationAccessPolicy` fails as not-found (migration reported
    // "partial") — false failures after a write that landed. `expect(1)` is
    // verified when the server drops; nothing sleeps because nothing retries.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway"))
        .expect(1)
        .mount(&server)
        .await;
    let err = make_client(&server.uri())
        .new_role_assignment("app-1", "Application Mail.Read", Some("scope"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ExchangeError::Server { status: 502, .. }),
        "got {err:?}"
    );

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway"))
        .expect(1)
        .mount(&server)
        .await;
    let err = make_client(&server.uri())
        .remove_application_access_policy("id")
        .await
        .unwrap_err();
    assert!(
        matches!(err, ExchangeError::Server { status: 502, .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_read_is_retried_after_a_server_error() {
    // A `Get-` cmdlet is replay-safe, so the transient budget still applies.
    // `Retry-After: 0` keeps the test from spending the real 1 s backoff.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(502).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .mount(&server)
        .await;
    let policies = make_client(&server.uri())
        .get_application_access_policies()
        .await
        .expect("a read recovers from one 502");
    assert!(policies.is_empty());
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_write_is_still_retried_when_throttled() {
    // A 429 is a refusal before any work was done, so even a write replays.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "Name": "ra-1",
                "Role": "Application Mail.Read",
                "RoleAssigneeName": "app-1",
                "CustomResourceScope": "scope",
                "Identity": "ra-1"
            }]
        })))
        .mount(&server)
        .await;
    let ra = make_client(&server.uri())
        .new_role_assignment("app-1", "Application Mail.Read", Some("scope"))
        .await
        .expect("a throttled write is replayed");
    assert_eq!(ra.role.as_deref(), Some("Application Mail.Read"));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

// ── Mid-pagination errors keep their classification ────────────────────────

/// Mounts a first page that promises a continuation at `{server}/page2`.
async fn mount_first_page_with_next_link(server: &MockServer) {
    let page2 = format!("{}/page2", server.uri());
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "Name": "scope-a", "RecipientFilter": "MemberOfGroup -eq 'CN=a'" }],
            "@odata.nextLink": page2,
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn an_auth_failure_mid_pagination_keeps_its_classification() {
    // Only a not-found is reclassified mid-pagination (so `invoke_optional`
    // cannot read it as "absent"). A 401/403 on page 2 must stay itself: the
    // audit's Exchange breaker and the sign-in / role guidance key off it.
    let server = MockServer::start().await;
    mount_first_page_with_next_link(&server).await;
    Mock::given(method("POST"))
        .and(path("/page2"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let err = make_client(&server.uri())
        .list_management_scopes()
        .await
        .unwrap_err();
    assert!(matches!(err, ExchangeError::Unauthorized), "got {err:?}");

    let server = MockServer::start().await;
    mount_first_page_with_next_link(&server).await;
    Mock::given(method("POST"))
        .and(path("/page2"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ms-diagnostics", "2000003;reason=\"denied\""),
        )
        .mount(&server)
        .await;
    let err = make_client(&server.uri())
        .list_management_scopes()
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ExchangeError::Forbidden {
                had_diagnostics: true,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_dead_session_mid_pagination_stays_reauth_fatal() {
    use azapptoolkit_core::token::{BearerProvider, TokenError};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Mints a token for page 1, then reports the session gone — the bearer is
    // fetched per page, so this is exactly what a mid-read sign-out looks like.
    struct DiesAfterFirstPage(AtomicUsize);
    // The `#[async_trait]` expansion, written out: this crate has no
    // async-trait dependency and one test does not justify adding it.
    impl BearerProvider for DiesAfterFirstPage {
        fn bearer<'life0, 'async_trait>(
            &'life0 self,
        ) -> Pin<
            Box<dyn Future<Output = std::result::Result<String, TokenError>> + Send + 'async_trait>,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok("tok".to_string())
                } else {
                    Err(TokenError::new("refresh_missing", "gone"))
                }
            })
        }
    }

    let server = MockServer::start().await;
    mount_first_page_with_next_link(&server).await;
    let client = ExchangeClient::with_base_url(
        Arc::new(DiesAfterFirstPage(AtomicUsize::new(0))),
        "tenant-1",
        "admin@contoso.com",
        server.uri(),
    );
    let err = client.list_management_scopes().await.unwrap_err();
    assert!(matches!(err, ExchangeError::Token(_)), "got {err:?}");
    assert_eq!(err.ui_code(), "refresh_missing");
    assert!(
        azapptoolkit_core::reauth::is_reauth_fatal(err.ui_code()),
        "a dead session on page 2 must still stop a fan-out"
    );
}

// ── Identity-less list reads never read a rejection as "empty" ─────────────

const NOT_FOUND_BODY: &str =
    "The operation couldn't be performed because object 'x' couldn't be found.";

/// Mounts one answer for `cmdlet` called with no parameters (a list-all).
async fn mount_list_all(server: &MockServer, cmdlet: &str, status: u16) {
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": { "CmdletName": cmdlet, "Parameters": {} }
        })))
        .respond_with(ResponseTemplate::new(status).set_body_string(NOT_FOUND_BODY))
        .mount(server)
        .await;
}

#[tokio::test]
async fn list_management_scopes_does_not_read_a_not_found_rejection_as_empty() {
    // A list-all has no `-Identity` to be missing: an empty tenant answers 200
    // with `value: []`. Read as "no scopes", a rejection that happens to say
    // "not found" let the reverse-reference check clear a group for the
    // irreversible delete while scopes still referenced it.
    let server = MockServer::start().await;
    mount_list_all(&server, "Get-ManagementScope", 400).await;
    let err = make_client(&server.uri())
        .list_management_scopes()
        .await
        .expect_err("a rejected list-all is an error, never an empty tenant");
    assert!(
        matches!(err, ExchangeError::Api { status: 400, .. }),
        "got {err:?}"
    );

    let server = MockServer::start().await;
    mount_list_all(&server, "Get-ManagementScope", 404).await;
    let err = make_client(&server.uri())
        .list_management_scopes()
        .await
        .expect_err("a 404 on a list-all is not an empty list");
    assert!(matches!(err, ExchangeError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn application_access_policies_do_not_read_a_not_found_rejection_as_empty() {
    let server = MockServer::start().await;
    mount_list_all(&server, "Get-ApplicationAccessPolicy", 400).await;
    let err = make_client(&server.uri())
        .get_application_access_policies()
        .await
        .expect_err("a rejected list-all is an error, never an empty tenant");
    assert!(
        matches!(err, ExchangeError::Api { status: 400, .. }),
        "got {err:?}"
    );

    let server = MockServer::start().await;
    mount_list_all(&server, "Get-ApplicationAccessPolicy", 404).await;
    let err = make_client(&server.uri())
        .get_application_access_policies()
        .await
        .expect_err("a 404 on a list-all is not an empty list");
    assert!(matches!(err, ExchangeError::NotFound(_)), "got {err:?}");
}

// ── set_management_scope_filter refuses BEFORE the cmdlet runs ─────────────

/// Mounts a catch-all that must never be hit: `expect(0)` is verified when the
/// server drops, on top of the explicit "no request received" assertions.
async fn mount_no_request_expected(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
        .expect(0)
        .mount(server)
        .await;
}

#[tokio::test]
async fn set_management_scope_filter_refuses_a_filter_that_confines_nothing_before_writing() {
    // Exchange applies the filter to every role assignment on the scope, so an
    // unrestricting one widens them all to the whole organization. The refusal
    // is only worth anything if it happens before `Set-ManagementScope` runs.
    let server = MockServer::start().await;
    mount_no_request_expected(&server).await;
    let client = make_client(&server.uri());
    for filter in ["", "   ", "RecipientTypeDetails -eq 'UserMailbox'"] {
        match client
            .set_management_scope_filter("app_scope_app-1", filter)
            .await
        {
            Err(ExchangeError::Protocol(m)) => {
                assert!(m.contains("confines nothing"), "{filter:?}: {m}");
            }
            other => panic!("{filter:?} must be refused, got {other:?}"),
        }
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no cmdlet may run for a filter that confines nothing"
    );
}

#[tokio::test]
async fn set_management_scope_filter_refuses_an_unreadable_filter_before_writing() {
    // Names a group (so it passes the first refusal) but holds a MemberOfGroup
    // token that is not a plain `-eq`, so its reach cannot be stated.
    let server = MockServer::start().await;
    mount_no_request_expected(&server).await;
    let filter = "MemberOfGroup -eq 'CN=A,DC=x' -or MemberOfGroup -like 'CN=B*'";
    match make_client(&server.uri())
        .set_management_scope_filter("app_scope_app-1", filter)
        .await
    {
        Err(ExchangeError::Protocol(m)) => {
            assert!(m.contains("cannot fully"), "{m}");
            assert!(m.contains("Nothing was changed"), "{m}");
        }
        other => panic!("an unreadable filter must be refused, got {other:?}"),
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ── ensure_management_scope is create-only ──────────────────────────────────

#[tokio::test]
async fn ensure_management_scope_creates_when_missing() {
    let server = MockServer::start().await;
    // The realistic EXO shape for an `-Identity` that does not resolve: a 400
    // carrying "couldn't be found", read by `invoke_optional` as "no scope".
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-ManagementScope",
                "Parameters": { "Identity": "app_scope_app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(400).set_body_string(NOT_FOUND_BODY))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "New-ManagementScope",
                "Parameters": {
                    "Name": "app_scope_app-1",
                    "RecipientRestrictionFilter": "MemberOfGroup -eq 'CN=Managed,DC=prod'"
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "Name": "app_scope_app-1",
                "RecipientFilter": "MemberOfGroup -eq 'CN=Managed,DC=prod'"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let scope = make_client(&server.uri())
        .ensure_management_scope("app_scope_app-1", "MemberOfGroup -eq 'CN=Managed,DC=prod'")
        .await
        .expect("a missing scope is created");
    assert_eq!(scope.name.as_deref(), Some("app_scope_app-1"));
    assert_eq!(
        scope.recipient_filter.as_deref(),
        Some("MemberOfGroup -eq 'CN=Managed,DC=prod'")
    );
}

#[tokio::test]
async fn ensure_management_scope_never_touches_an_existing_scope() {
    // Create-only: repointing a scope changes what every role assignment on it
    // reaches, so that is `set_management_scope_filter`'s job alone. An
    // existing scope comes back as it is, stale filter and all.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .and(body_json(json!({
            "CmdletInput": {
                "CmdletName": "Get-ManagementScope",
                "Parameters": { "Identity": "app_scope_app-1" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{
                "Name": "app_scope_app-1",
                "RecipientFilter": "MemberOfGroup -eq 'CN=Stale,DC=prod'"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    for cmdlet in ["New-ManagementScope", "Set-ManagementScope"] {
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_string_contains(cmdlet))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .expect(0)
            .mount(&server)
            .await;
    }
    let scope = make_client(&server.uri())
        .ensure_management_scope("app_scope_app-1", "MemberOfGroup -eq 'CN=Managed,DC=prod'")
        .await
        .expect("the existing scope is returned");
    assert_eq!(
        scope.recipient_filter.as_deref(),
        Some("MemberOfGroup -eq 'CN=Stale,DC=prod'"),
        "the existing scope wins, unchanged"
    );
}

// ── Terminal transport mappings ─────────────────────────────────────────────

/// Total attempts one request gets under the shared retry budget, read off
/// `RetryBudget` itself rather than restating its constant here (the
/// `repo_invariants` raw-primitive rule keeps that name inside `http_retry`).
async fn attempts_under_the_retry_budget() -> u64 {
    let mut budget = azapptoolkit_core::http_retry::RetryBudget::new();
    let mut attempts = 1;
    while budget.may_retry() {
        budget.wait(Some(0)).await;
        attempts += 1;
    }
    attempts
}

#[tokio::test]
async fn a_persistent_5xx_on_a_read_surfaces_as_server_after_the_retry_budget() {
    // `Retry-After: 0` is honored exactly, so the budget is spent without the
    // real jittered backoff.
    let attempts = attempts_under_the_retry_budget().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "0")
                .set_body_string("unavailable"),
        )
        .expect(attempts)
        .mount(&server)
        .await;
    let err = make_client(&server.uri())
        .list_service_principals()
        .await
        .expect_err("a persistent 503 fails once the budget is spent");
    assert!(
        matches!(err, ExchangeError::Server { status: 503, .. }),
        "got {err:?}"
    );
    assert!(err.is_retryable(), "a 5xx stays classed transient");
    assert_eq!(
        server.received_requests().await.unwrap().len() as u64,
        attempts
    );
}

#[tokio::test]
async fn a_persistent_429_surfaces_as_throttled() {
    let attempts = attempts_under_the_retry_budget().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(invoke_path()))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .expect(attempts)
        .mount(&server)
        .await;
    let err = make_client(&server.uri())
        .list_service_principals()
        .await
        .expect_err("a persistent 429 fails once the budget is spent");
    assert!(
        matches!(
            err,
            ExchangeError::Throttled {
                retry_after_secs: Some(0)
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len() as u64,
        attempts
    );
}

#[tokio::test]
async fn a_connection_failure_surfaces_as_network() {
    // Bind then drop a listener so the port refuses connections. A write
    // (non-idempotent) is not replayed after a network error, so this fails on
    // the first attempt without any backoff.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let err = make_client(&format!("http://127.0.0.1:{port}"))
        .remove_role_assignment("ra-1")
        .await
        .expect_err("nothing is listening");
    assert!(matches!(err, ExchangeError::Network(_)), "got {err:?}");
}
