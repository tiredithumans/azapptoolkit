use super::super::*;
use super::common::*;
use azapptoolkit_core::scoping::admin_unit::AdminUnitMemberKind;

const AU: &str = "6c3e1f0a-1b2c-4d3e-8f4a-5b6c7d8e9f01";
const SP: &str = "5f8b2c1a-0d3e-4b6f-9a7c-1e2d3f4a5b6c";
const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";

fn au_client(uri: &str) -> GraphClient {
    make_client(uri).with_admin_unit_roles_token(StaticTokenProvider::new("aur"))
}

#[tokio::test]
async fn list_admin_units_selects_and_pages() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/directory/administrativeUnits"))
        .and(query_param(
            "$select",
            "id,displayName,membershipType,membershipRule,membershipRuleProcessingState,isMemberManagementRestricted",
        ))
        .and(query_param("$top", MAX_PAGE_SIZE))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": AU, "displayName": "Finance", "membershipType": "Dynamic",
                "membershipRule": "(user.department -eq \"Finance\")",
                "membershipRuleProcessingState": "On", "isMemberManagementRestricted": false
            }]
        })))
        .mount(&server)
        .await;
    let units = make_client(&server.uri()).list_admin_units().await.unwrap();
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].display_name.as_deref(), Some("Finance"));
    assert_eq!(units[0].membership_type.as_deref(), Some("Dynamic"));
    assert_eq!(
        units[0].membership_rule_processing_state.as_deref(),
        Some("On")
    );
}

#[tokio::test]
async fn create_dynamic_admin_unit_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/directory/administrativeUnits"))
        .and(header("authorization", "Bearer aur"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "displayName": "Finance",
            "membershipType": "Dynamic",
            "membershipRule": "(user.department -eq \"Finance\")",
            "membershipRuleProcessingState": "On"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": AU, "displayName": "Finance", "membershipType": "Dynamic"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let unit = au_client(&server.uri())
        .create_dynamic_admin_unit("Finance", "(user.department -eq \"Finance\")")
        .await
        .unwrap();
    assert_eq!(unit.id, AU);
}

#[tokio::test]
async fn admin_unit_has_members_casts_to_the_kind() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/directory/administrativeUnits/{AU}/members/microsoft.graph.group"
        )))
        .and(query_param_is_missing("$top"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/directory/administrativeUnits/{AU}/members/microsoft.graph.user"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": [{ "id": "u-1" }] })),
        )
        .mount(&server)
        .await;
    let client = make_client(&server.uri());
    assert!(
        client
            .admin_unit_has_members(AU, AdminUnitMemberKind::User)
            .await
            .unwrap()
    );
    assert!(
        !client
            .admin_unit_has_members(AU, AdminUnitMemberKind::Group)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn role_assignments_for_a_principal_filter_and_expand() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/roleManagement/directory/roleAssignments"))
        .and(query_param("$filter", format!("principalId eq '{SP}'")))
        .and(query_param("$expand", "roleDefinition($select=id,displayName,templateId)"))
        .and(query_param_is_missing("$top"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "ra-1", "principalId": SP, "roleDefinitionId": USER_ADMIN,
                "directoryScopeId": format!("/administrativeUnits/{AU}"),
                "roleDefinition": { "id": USER_ADMIN, "displayName": "User Administrator", "templateId": USER_ADMIN }
            }]
        })))
        .mount(&server)
        .await;
    let roles = make_client(&server.uri())
        .list_role_assignments_for_principal(SP)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(
        roles[0].directory_scope_id,
        format!("/administrativeUnits/{AU}")
    );
    assert_eq!(
        roles[0]
            .role_definition
            .as_ref()
            .and_then(|d| d.template_id.as_deref()),
        Some(USER_ADMIN)
    );
}

#[tokio::test]
async fn unit_scoped_role_assignments_keep_only_unit_scopes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/roleManagement/directory/roleAssignments"))
        .and(query_param_is_missing("$top"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "ra-1", "principalId": SP, "roleDefinitionId": USER_ADMIN, "directoryScopeId": format!("/administrativeUnits/{AU}") },
                { "id": "ra-2", "principalId": SP, "roleDefinitionId": USER_ADMIN, "directoryScopeId": "/" }
            ]
        })))
        .mount(&server)
        .await;
    let all = make_client(&server.uri())
        .list_directory_role_assignments()
        .await
        .unwrap();
    assert_eq!(
        all.len(),
        2,
        "every direct assignment, tenant and unit scope"
    );
}

#[tokio::test]
async fn assign_role_at_admin_unit_scopes_to_the_unit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/roleManagement/directory/roleAssignments"))
        .and(header("authorization", "Bearer aur"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "principalId": SP,
            "roleDefinitionId": USER_ADMIN,
            "directoryScopeId": format!("/administrativeUnits/{AU}")
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "ra-new", "principalId": SP, "roleDefinitionId": USER_ADMIN,
            "directoryScopeId": format!("/administrativeUnits/{AU}")
        })))
        .expect(1)
        .mount(&server)
        .await;
    let created = au_client(&server.uri())
        .assign_role_at_admin_unit(SP, USER_ADMIN, AU)
        .await
        .unwrap();
    assert_eq!(created.id, "ra-new");
}

#[tokio::test]
async fn delete_role_assignment_uses_the_write_token() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/roleManagement/directory/roleAssignments/ra-1"))
        .and(header("authorization", "Bearer aur"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    au_client(&server.uri())
        .delete_role_assignment("ra-1")
        .await
        .unwrap();
}

#[tokio::test]
async fn ids_are_shape_checked_and_writes_need_the_token() {
    let client = au_client("http://127.0.0.1:9");
    assert!(matches!(
        client.get_admin_unit("a/b").await,
        Err(GraphError::Protocol(_))
    ));
    assert!(matches!(
        client
            .admin_unit_has_members("../x", AdminUnitMemberKind::User)
            .await,
        Err(GraphError::Protocol(_))
    ));
    assert!(matches!(
        client.delete_role_assignment("a?b").await,
        Err(GraphError::Protocol(_))
    ));
    assert!(matches!(
        client
            .assign_role_at_admin_unit(SP, USER_ADMIN, "a/b")
            .await,
        Err(GraphError::Protocol(_))
    ));
    assert!(matches!(
        client
            .list_role_assignments_for_principal("x' or 1 eq 1")
            .await,
        Err(GraphError::Protocol(_))
    ));
    let no_token = make_client("http://127.0.0.1:9");
    assert!(matches!(
        no_token.assign_role_at_admin_unit(SP, USER_ADMIN, AU).await,
        Err(GraphError::Forbidden(_))
    ));
    assert!(matches!(
        no_token
            .create_dynamic_admin_unit("x", "(user.department -eq \"x\")")
            .await,
        Err(GraphError::Forbidden(_))
    ));
}
