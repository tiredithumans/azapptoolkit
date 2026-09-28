use std::collections::{HashMap, HashSet};

use azapptoolkit_core::models::ServicePrincipal;

use crate::dto::permissions::{PermissionKind, ResolvedPermission};

/// Resolves one declared permission to a [`ResolvedPermission`] through the
/// fixed fallback ladder — live resource SP (`appRoles` then
/// `oauth2PermissionScopes`) → raw GUID with the declared Role/Scope kind —
/// joining the matching runtime grant via the caller's per-resource closures.
/// There is no bundled rung: the resource directory carries names only.
/// Extracted so the ladder reads once instead of near-identical struct builds
/// inside the loop.
fn resolve_one_permission(
    resource_app_id: &str,
    resource_display_name: &Option<String>,
    live_sp: Option<&ServicePrincipal>,
    access: &azapptoolkit_core::models::ResourceAccess,
    runtime_assignment_for: &impl Fn(&str) -> Option<String>,
    runtime_grant_for: &impl Fn(&str) -> Option<String>,
) -> ResolvedPermission {
    // 1. Live SP (appRoles, then oauth2PermissionScopes).
    if let Some(sp) = live_sp {
        if let Some(role) = sp.app_roles.iter().find(|r| r.id == access.id) {
            return ResolvedPermission {
                resource_app_id: resource_app_id.to_string(),
                resource_display_name: resource_display_name.clone(),
                permission_id: access.id.clone(),
                permission_value: Some(role.value.clone()),
                permission_display_name: Some(role.display_name.clone()),
                permission_kind: PermissionKind::Application,
                runtime_assignment_id: runtime_assignment_for(&access.id),
                runtime_grant_id: None,
            };
        }
        if let Some(scope) = sp
            .oauth2_permission_scopes
            .iter()
            .find(|s| s.id == access.id)
        {
            let display = scope
                .admin_consent_display_name
                .clone()
                .unwrap_or_else(|| scope.value.clone());
            return ResolvedPermission {
                resource_app_id: resource_app_id.to_string(),
                resource_display_name: resource_display_name.clone(),
                permission_id: access.id.clone(),
                permission_value: Some(scope.value.clone()),
                permission_display_name: Some(display),
                permission_kind: PermissionKind::Delegated,
                runtime_assignment_id: None,
                runtime_grant_id: runtime_grant_for(&scope.value),
            };
        }
    }

    // 2. Total miss: surface raw GUIDs with the declared Role/Scope kind.
    let permission_kind = PermissionKind::from_access_type(&access.r#type);
    let runtime_assignment_id = matches!(permission_kind, PermissionKind::Application)
        .then(|| runtime_assignment_for(&access.id))
        .flatten();
    ResolvedPermission {
        resource_app_id: resource_app_id.to_string(),
        resource_display_name: resource_display_name.clone(),
        permission_id: access.id.clone(),
        permission_value: None,
        permission_display_name: None,
        permission_kind,
        runtime_assignment_id,
        runtime_grant_id: None,
    }
}

/// Resolves every declared permission (see [`resolve_one_permission`]) and
/// reports whether the resolution is **degraded**: `true` when a declared
/// resource's service principal couldn't be read. That resource's rows still
/// come back (the ladder falls through to the raw GUID), but without
/// the resource SP id they can't be joined to their runtime grants, so they read
/// as "Not granted" whether or not they are — the caller must not cache or
/// present such a result as authoritative.
pub(super) async fn resolve_required_resource_access(
    client: &azapptoolkit_graph::GraphClient,
    declared: &[azapptoolkit_core::models::RequiredResourceAccess],
    app_role_assignments: &[azapptoolkit_core::models::AppRoleAssignment],
    oauth2_permission_grants: &[azapptoolkit_core::models::OAuth2PermissionGrant],
) -> (Vec<ResolvedPermission>, bool) {
    let directory = azapptoolkit_permissions::ResourceDirectory::bundled();

    // Resolve every distinct declared resource's SP up front and concurrently
    // (each is an independent, Permissions-cached Graph lookup) so the per-row
    // formatting below reads `live_sps` without awaiting, instead of paying one
    // serial round trip per resource on a cold cache. We need each SP's id to
    // join runtime assignments/grants to the declared rows.
    let unique_resource_ids: Vec<String> = {
        let mut seen = HashSet::new();
        declared
            .iter()
            .map(|r| r.resource_app_id.clone())
            .filter(|id| seen.insert(id.clone()))
            .collect()
    };
    let lookups = futures::future::join_all(unique_resource_ids.into_iter().map(|id| async move {
        let sp = client.resolve_resource_sp(&id).await;
        (id, sp)
    }))
    .await;
    // `Ok(None)` — the resource SP is genuinely absent from the tenant — is an
    // answer, not a degradation: nothing can be granted on a resource with no
    // SP. Only an `Err` (throttling past the retry budget, a transient Graph
    // failure) leaves the grant state unknown. The graph layer already caches
    // only `Ok` (`resolve_resource_sp`); collapsing the two here is what let a
    // throttled lookup be cached as "Not granted".
    let mut degraded = false;
    let live_sps: HashMap<String, Option<ServicePrincipal>> = lookups
        .into_iter()
        .map(|(id, sp)| match sp {
            Ok(sp) => (id, sp),
            Err(e) => {
                tracing::warn!(
                    resource_app_id = %id,
                    error = %e,
                    "resource service principal unreadable; its permission rows can't be joined to grants"
                );
                degraded = true;
                (id, None)
            }
        })
        .collect();

    let mut out = Vec::new();

    for resource in declared {
        let resource_display_from_directory = directory
            .resource(&resource.resource_app_id)
            .map(|r| r.display_name.clone());

        let live_sp = live_sps
            .get(&resource.resource_app_id)
            .and_then(|o| o.as_ref());
        let resource_sp_id = live_sp.map(|sp| sp.id.as_str());

        let resource_display_name =
            resource_display_from_directory.or_else(|| live_sp.map(|sp| sp.display_name.clone()));

        // Runtime-grant joins. Application: assignment.resource_id ==
        // resource_sp.id && assignment.app_role_id == permission_id.
        // Delegated: grant.resource_id == resource_sp.id and the scope
        // string contains the scope value (split_whitespace handles weird
        // whitespace exactly like the revoke command does).
        let runtime_assignment_for = |permission_id: &str| -> Option<String> {
            let sp_id = resource_sp_id?;
            app_role_assignments
                .iter()
                .find(|a| a.resource_id == sp_id && a.app_role_id == permission_id)
                .map(|a| a.id.clone())
        };
        let runtime_grant_for = |scope_value: &str| -> Option<String> {
            let sp_id = resource_sp_id?;
            oauth2_permission_grants
                .iter()
                .find(|g| {
                    g.resource_id == sp_id && g.scope.split_whitespace().any(|s| s == scope_value)
                })
                .and_then(|g| g.id.clone())
        };

        for access in &resource.resource_access {
            out.push(resolve_one_permission(
                &resource.resource_app_id,
                &resource_display_name,
                live_sp,
                access,
                &runtime_assignment_for,
                &runtime_grant_for,
            ));
        }
    }

    (out, degraded)
}

#[cfg(test)]
mod tests {
    use azapptoolkit_core::cache::Cache;
    use azapptoolkit_core::models::{
        AppRole, AppRoleAssignment, OAuth2PermissionScope, RequiredResourceAccess, ResourceAccess,
    };
    use azapptoolkit_core::token::StaticTokenProvider;
    use azapptoolkit_graph::GraphClient;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    // Resource appIds outside the bundled directory, so the resource name
    // comes from the live SP (and the join depends on it).
    const RES_A: &str = "11111111-aaaa-4aaa-8aaa-000000000001";
    const RES_B: &str = "22222222-bbbb-4bbb-8bbb-000000000002";

    fn client(server: &MockServer) -> GraphClient {
        GraphClient::with_base_url(
            "tenant-1".to_string(),
            StaticTokenProvider::new("t"),
            StaticTokenProvider::new("t"),
            Cache::new(),
            format!("{}/v1.0", server.uri()),
        )
    }

    fn declared() -> Vec<RequiredResourceAccess> {
        [(RES_A, "r1"), (RES_B, "r2")]
            .into_iter()
            .map(|(res, role)| RequiredResourceAccess {
                resource_app_id: res.into(),
                resource_access: vec![ResourceAccess {
                    id: role.into(),
                    r#type: "Role".into(),
                }],
            })
            .collect()
    }

    fn assignment() -> Vec<AppRoleAssignment> {
        vec![AppRoleAssignment {
            id: "assign-1".into(),
            principal_id: "sp-app".into(),
            resource_id: "sp-a".into(),
            app_role_id: "r1".into(),
            ..Default::default()
        }]
    }

    async fn mount_resource_a(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", format!("appId eq '{RES_A}'")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "sp-a",
                    "appId": RES_A,
                    "displayName": "Resource A",
                    "appRoles": [{
                        "id": "r1",
                        "allowedMemberTypes": ["Application"],
                        "displayName": "Role one",
                        "value": "A.Read.All"
                    }]
                }]
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn one_unreadable_resource_flags_the_resolution_but_keeps_its_rows() {
        let server = MockServer::start().await;
        mount_resource_a(&server).await;
        // 403 is non-retryable, so the test doesn't wait out a backoff.
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", format!("appId eq '{RES_B}'")))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let (rows, degraded) =
            resolve_required_resource_access(&client(&server), &declared(), &assignment(), &[])
                .await;

        assert!(
            degraded,
            "an unreadable resource SP degrades the resolution"
        );
        let a = rows
            .iter()
            .find(|r| r.resource_app_id == RES_A)
            .expect("A's row");
        assert_eq!(a.runtime_assignment_id.as_deref(), Some("assign-1"));
        let b = rows
            .iter()
            .find(|r| r.resource_app_id == RES_B)
            .expect("B's row is kept");
        assert!(b.runtime_assignment_id.is_none());
    }

    #[tokio::test]
    async fn an_absent_resource_sp_is_not_degraded() {
        let server = MockServer::start().await;
        mount_resource_a(&server).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", format!("appId eq '{RES_B}'")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
            )
            .mount(&server)
            .await;

        let (rows, degraded) =
            resolve_required_resource_access(&client(&server), &declared(), &assignment(), &[])
                .await;

        assert!(
            !degraded,
            "a resource with no SP in the tenant is an answer"
        );
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn a_directory_resource_resolves_from_the_live_sp() {
        const GRAPH: &str = "00000003-0000-0000-c000-000000000000";
        let name = Some("Microsoft Graph".to_string());
        let sp = ServicePrincipal {
            id: "sp-graph".into(),
            app_id: GRAPH.into(),
            app_roles: vec![AppRole {
                id: "r1".into(),
                value: "User.Read.All".into(),
                display_name: "Read all users' full profiles".into(),
                ..Default::default()
            }],
            oauth2_permission_scopes: vec![OAuth2PermissionScope {
                id: "s1".into(),
                value: "User.Read".into(),
                admin_consent_display_name: Some("Sign in and read user profile".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let assignment_for = |id: &str| Some(format!("assign-{id}"));
        let grant_for = |value: &str| Some(format!("grant-{value}"));
        let resolve = |id: &str, kind: &str| {
            let access = ResourceAccess {
                id: id.into(),
                r#type: kind.into(),
            };
            resolve_one_permission(
                GRAPH,
                &name,
                Some(&sp),
                &access,
                &assignment_for,
                &grant_for,
            )
        };

        let role = resolve("r1", "Role");
        assert_eq!(role.permission_kind, PermissionKind::Application);
        assert_eq!(role.permission_value.as_deref(), Some("User.Read.All"));
        assert_eq!(
            role.resource_display_name.as_deref(),
            Some("Microsoft Graph")
        );
        assert_eq!(role.runtime_assignment_id.as_deref(), Some("assign-r1"));
        assert!(role.runtime_grant_id.is_none());

        let scope = resolve("s1", "Scope");
        assert_eq!(scope.permission_kind, PermissionKind::Delegated);
        assert_eq!(
            scope.permission_display_name.as_deref(),
            Some("Sign in and read user profile")
        );
        // The delegated join keys off the scope value, not its id.
        assert_eq!(scope.runtime_grant_id.as_deref(), Some("grant-User.Read"));
        assert!(scope.runtime_assignment_id.is_none());

        let role_miss = resolve("zz", "Role");
        assert_eq!(role_miss.permission_kind, PermissionKind::Application);
        assert!(role_miss.permission_value.is_none());
        assert!(role_miss.permission_display_name.is_none());
        assert_eq!(
            resolve("zz", "Scope").permission_kind,
            PermissionKind::Delegated
        );
        assert_eq!(
            resolve("zz", "Other").permission_kind,
            PermissionKind::Unknown
        );
    }
}
