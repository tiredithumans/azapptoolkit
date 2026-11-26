//! Admin-unit scoping (C1): limit an app's tenant-wide directory writes to an
//! administrative unit, and the reads and writes around it.
//!
//! The apply core assigns the mapped role at the unit's scope, makes sure the
//! app can read tenant-wide (the role is unusable otherwise), and only then
//! removes the tenant-wide write permission — and only when the unit can
//! actually reach someone. Every step that landed is reported.

use std::collections::HashMap;

use tauri::State;

use azapptoolkit_core::cache::Cache;
use azapptoolkit_core::guid::is_guid;
use azapptoolkit_core::models::{AdministrativeUnit, DirectoryRoleAssignment};
use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
use azapptoolkit_core::scoping::admin_unit::{
    AdminUnitMemberKind, DirectoryWriteMapping, covering_permission, covering_role_name,
    directory_write_mapping, satisfies_tenant_read,
};
use azapptoolkit_graph::{GraphClient, GraphError};

use crate::commands::applications::invalidate_app_detail_state;
use crate::commands::graph_err::forbidden_remediation;
use crate::commands::graph_roles::{graph_resource_roles, strip_app_role_grants};
use crate::commands::permissions::remove_declared_access;
use crate::commands::sharepoint::{
    GraphRolePrincipal, declare_and_grant_graph_role, require_same_app,
};
use crate::dto::UiError;
use crate::dto::admin_units::{
    AdminUnitDto, DirectoryRoleDto, DirectoryRoleScopeDto, DirectoryWriteScopeResult,
};
use crate::state::{AppState, ConsentFeature};

/// The capability whose remediation a 403 here carries.
const CAPABILITY: &str = "admin_unit_roles";

fn invalid_id(what: &str) -> UiError {
    UiError::validation("invalid_id", format!("The {what} isn't a valid id."))
}

/// A Graph error through the capability's 403 remediation, and the few
/// refusals Graph words recognisably mapped to their own codes.
fn admin_unit_err(err: GraphError) -> UiError {
    let api_body = match &err {
        GraphError::Api { body, .. } => Some(body.to_ascii_lowercase()),
        _ => None,
    };
    let ui = UiError::from(err);
    if let Some(body) = api_body {
        if body.contains("membershiprule") || body.contains("membership rule") {
            return UiError::validation("invalid_membership_rule", ui.message);
        }
        if body.contains("licen") {
            return UiError::validation("admin_unit_licence_required", ui.message);
        }
        if body.contains("restricted") {
            return UiError::validation("admin_unit_restricted", ui.message);
        }
    }
    match forbidden_remediation(&ui, CAPABILITY) {
        Some(remediation) => UiError {
            message: format!("{} {remediation}", ui.message),
            ..ui
        },
        None => ui,
    }
}

fn to_dto(unit: AdministrativeUnit) -> AdminUnitDto {
    let dynamic = unit
        .membership_type
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case("Dynamic"));
    let rule_processing_on = !dynamic
        || unit
            .membership_rule_processing_state
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("On"));
    AdminUnitDto {
        display_name: unit.display_name.clone().unwrap_or_else(|| unit.id.clone()),
        id: unit.id,
        dynamic,
        membership_rule: unit.membership_rule,
        rule_processing_on,
        restricted: unit.is_member_management_restricted.unwrap_or(false),
    }
}

/// A new unit's name (1–256 characters, trimmed) and rule (1–3072).
pub(crate) fn validate_new_unit(display_name: &str, membership_rule: &str) -> Result<(), UiError> {
    let name = display_name.trim();
    if name.is_empty() || name.chars().count() > 256 {
        return Err(UiError::validation(
            "invalid_name",
            "Give the admin unit a name of up to 256 characters.",
        ));
    }
    let rule = membership_rule.trim();
    if rule.is_empty() || rule.chars().count() > 3072 {
        return Err(UiError::validation(
            "invalid_membership_rule",
            "Enter a membership rule of up to 3072 characters.",
        ));
    }
    Ok(())
}

/// The assignment `assignment_id` among a principal's own, if it is scoped to
/// an admin unit (a tenant-scope role is listed, never removed here).
pub(crate) fn removable_unit_assignment<'a>(
    assignments: &'a [DirectoryRoleAssignment],
    assignment_id: &str,
) -> Result<&'a DirectoryRoleAssignment, UiError> {
    let found = assignments
        .iter()
        .find(|a| a.id == assignment_id)
        .ok_or_else(|| {
            UiError::not_found(
                "role_assignment",
                "That role assignment isn't one this app holds.",
            )
        })?;
    if found.admin_unit_id().is_none() {
        return Err(UiError::validation(
            "not_admin_unit_scoped",
            "Only a role limited to an admin unit can be removed here.",
        ));
    }
    Ok(found)
}

/// What still lets the app write everywhere despite a unit limit: a
/// tenant-scope role among `roles` that covers `mapping`, or a held
/// `Directory.ReadWrite.All` (among `held_values`).
fn covering_role(
    mapping: &DirectoryWriteMapping,
    roles: &[DirectoryRoleAssignment],
    held_values: &[&String],
) -> Option<String> {
    roles
        .iter()
        .filter(|r| r.is_tenant_scope())
        .find_map(|r| covering_role_name(mapping, r.role_template_id()))
        .map(str::to_string)
        .or_else(|| {
            held_values
                .iter()
                .any(|v| covering_permission(Some(MICROSOFT_GRAPH_APP_ID), v))
                .then(|| "Directory.ReadWrite.All".to_string())
        })
}

/// Why the tenant-wide write must stay, if it must.
fn kept_reason(
    mapping: &DirectoryWriteMapping,
    unit: &AdminUnitDto,
    has_members: bool,
    created_now: bool,
) -> Option<String> {
    let what = match mapping.member_kind {
        AdminUnitMemberKind::User => "users",
        AdminUnitMemberKind::Group => "groups",
        AdminUnitMemberKind::Device => "devices",
    };
    if created_now {
        Some(format!(
            "The admin unit was just created and Microsoft is still working out its members, so \
             {} stays for now. Use Scope… again once the unit lists its {what}.",
            mapping.permission
        ))
    } else if unit.dynamic && !unit.rule_processing_on {
        Some(format!(
            "The admin unit's membership rule is paused, so {} stays. Turn the rule on in the \
             Entra portal, then use Scope… again.",
            mapping.permission
        ))
    } else if !has_members {
        Some(match mapping.member_kind {
            AdminUnitMemberKind::Group => format!(
                "The admin unit holds no groups, so {} stays. Add groups to the unit in the Entra \
                 portal, then use Scope… again.",
                mapping.permission
            ),
            _ => format!(
                "The admin unit has no {what} yet, so {} stays. Use Scope… again once it does.",
                mapping.permission
            ),
        })
    } else {
        None
    }
}

/// [`scope_directory_write`]'s core, over a client and a cache so the
/// orchestration is testable against a mock Graph.
pub(crate) async fn scope_directory_write_core(
    client: &GraphClient,
    cache: &Cache,
    principal: &GraphRolePrincipal<'_>,
    mapping: &'static DirectoryWriteMapping,
    admin_unit_id: &str,
    created_now: bool,
    require_held: bool,
) -> Result<DirectoryWriteScopeResult, UiError> {
    // 1. Every read the decision rests on, before any write.
    let sp = client
        .get_service_principal_by_object_id(principal.sp_object_id)
        .await
        .map_err(admin_unit_err)?
        .ok_or_else(|| UiError::not_found("service_principal", "Service principal not found"))?;
    require_same_app(&sp.app_id, principal.app_id, "service principal")?;
    // The app registration too, before any write (the ids arrive separately
    // from the webview).
    if let Some(object_id) = principal.object_id {
        let app = client
            .get_application(object_id)
            .await
            .map_err(admin_unit_err)?;
        require_same_app(&app.app_id, principal.app_id, "app registration")?;
    }
    let graph = graph_resource_roles(client).await?;
    let existing = client
        .list_app_role_assignments(principal.sp_object_id)
        .await
        .map_err(admin_unit_err)?;
    let roles = client
        .list_role_assignments_for_principal(principal.sp_object_id)
        .await
        .map_err(admin_unit_err)?;
    let unit = to_dto(
        client
            .get_admin_unit(admin_unit_id)
            .await
            .map_err(admin_unit_err)?,
    );
    let has_members = client
        .admin_unit_has_members(admin_unit_id, mapping.member_kind)
        .await
        .map_err(admin_unit_err)?;

    let write_role_id: String = graph
        .role_value_by_id
        .iter()
        .find(|(_, v)| v.as_str() == mapping.permission)
        .map(|(id, _)| id.clone())
        .ok_or_else(|| {
            UiError::not_found(
                "role",
                format!("Microsoft Graph doesn't expose {}", mapping.permission),
            )
        })?;
    let is_write_grant = |a: &azapptoolkit_core::models::AppRoleAssignment| {
        a.resource_id.eq_ignore_ascii_case(&graph.sp_object_id)
            && a.app_role_id.eq_ignore_ascii_case(&write_role_id)
    };
    let held_writes = existing.iter().filter(|a| is_write_grant(a)).count();
    let held_values: Vec<&String> = existing
        .iter()
        .filter(|a| a.resource_id.eq_ignore_ascii_case(&graph.sp_object_id))
        .filter_map(|a| graph.role_value_by_id.get(&a.app_role_id))
        .collect();
    // The audit's Fix limits a write the app holds; it never gives a role to
    // an app whose write was only declared.
    if require_held && held_writes == 0 {
        return Err(UiError::validation(
            "write_not_held",
            format!(
                "This app doesn't hold {} tenant-wide (it may only be declared), so there's \
                 nothing to limit. To give it limited write access, use Grant access.",
                mapping.permission
            ),
        ));
    }

    let mut result = DirectoryWriteScopeResult {
        write_held: held_writes > 0,
        covering_role: covering_role(mapping, &roles, &held_values),
        ..Default::default()
    };

    // 2. The role at the unit's scope (idempotent).
    result.role_already_held = roles.iter().any(|r| {
        r.admin_unit_id()
            .is_some_and(|id| id.eq_ignore_ascii_case(admin_unit_id))
            && r.role_template_id()
                .eq_ignore_ascii_case(mapping.role_template_id)
    });
    if !result.role_already_held {
        client
            .assign_role_at_admin_unit(
                principal.sp_object_id,
                mapping.role_template_id,
                admin_unit_id,
            )
            .await
            .map_err(admin_unit_err)?;
        result.role_assigned = true;
        invalidate_app_detail_state(cache, principal.tenant_id);
    }

    // 3. Tenant-wide read: without it the role does nothing.
    result.read_already_held = held_values
        .iter()
        .any(|v| satisfies_tenant_read(mapping, Some(MICROSOFT_GRAPH_APP_ID), v));
    if !result.read_already_held {
        match declare_and_grant_graph_role(
            client,
            cache,
            principal,
            &graph.sp_object_id,
            &graph.role_value_by_id,
            &existing,
            mapping.read_permission,
        )
        .await
        {
            Ok(_) => {
                result.read_granted = true;
                invalidate_app_detail_state(cache, principal.tenant_id);
            }
            // A dead session or a missing consent keeps its code, so the UI
            // raises the right lever (the role, if newly assigned, stays: a
            // rerun finds it held).
            Err(e) if e.is_reauth_fatal() || e.is_consent_required() => {
                return Err(UiError {
                    message: format!(
                        "{} Couldn't give the app tenant-wide read ({}): {}",
                        if result.role_assigned {
                            "The admin role was assigned, but the run stopped."
                        } else {
                            "The run stopped."
                        },
                        mapping.read_permission,
                        e.message
                    ),
                    ..e
                });
            }
            Err(e) => {
                result.warnings.push(format!(
                    "Couldn't give the app tenant-wide read ({}): {}",
                    mapping.read_permission, e.message
                ));
                result.kept_reason = Some(format!(
                    "The app couldn't be given {}, which the role needs, so {} stays. Fix the \
                     error and use Scope… again.",
                    mapping.read_permission, mapping.permission
                ));
                return Ok(result);
            }
        }
    }

    // 4. Strip the tenant-wide write, only when the unit reaches someone.
    result.kept_reason = kept_reason(mapping, &unit, has_members, created_now);
    if result.kept_reason.is_some() {
        return Ok(result);
    }
    let removed = strip_app_role_grants(
        client,
        principal.sp_object_id,
        &existing,
        |a| is_write_grant(a).then(|| mapping.permission.to_string()),
        &mut result.warnings,
    )
    .await;
    result.orgwide_removed = !removed.is_empty();
    if result.orgwide_removed {
        invalidate_app_detail_state(cache, principal.tenant_id);
        // An expiry set on the write ends with it: a role assignment can't be
        // dated, nor is the read given the date. Say so (the command prunes
        // the stale tag).
        if let Some(e) = azapptoolkit_core::audit::expiries_in(&sp.tags)
            .iter()
            .find(|e| {
                e.resource_app_id
                    .eq_ignore_ascii_case(MICROSOFT_GRAPH_APP_ID)
                    && e.app_role_id.eq_ignore_ascii_case(&write_role_id)
            })
        {
            let (outlives, also_remove) = if result.read_granted {
                (
                    format!(
                        "The admin role and the {} granted now don't carry",
                        mapping.read_permission
                    ),
                    " and the read from its permissions",
                )
            } else {
                ("The admin role doesn't carry".to_string(), "")
            };
            result.warnings.push(format!(
                "{} was set to expire on {}. {outlives} that date: if the app's access should end \
                 then, remove the role from its Directory roles{also_remove}.",
                mapping.permission, e.expires_on
            ));
        }
    }
    // On an app registration the declaration goes too, so "Grant admin
    // consent" can't restore the tenant-wide grant — but only once every held
    // grant of it is gone: a live grant must never be left undeclared.
    let every_grant_removed = removed.len() == held_writes;
    if let Some(object_id) = principal.object_id.filter(|_| every_grant_removed) {
        match client.get_application(object_id).await {
            Ok(mut app) => {
                require_same_app(&app.app_id, principal.app_id, "app registration")?;
                if remove_declared_access(
                    &mut app.required_resource_access,
                    MICROSOFT_GRAPH_APP_ID,
                    &write_role_id,
                    Some("Role"),
                ) {
                    let patch = azapptoolkit_graph::client::AppPatch {
                        required_resource_access: Some(app.required_resource_access),
                        ..Default::default()
                    };
                    match client.update_application(object_id, &patch).await {
                        Ok(_) => invalidate_app_detail_state(cache, principal.tenant_id),
                        Err(e) => result.warnings.push(format!(
                            "Removed the grant, but not {} from the app's API permissions ({}). \
                             Remove it on the Permissions tab so \"Grant admin consent\" can't \
                             restore it.",
                            mapping.permission,
                            UiError::from(e).message
                        )),
                    }
                }
            }
            Err(e) => result.warnings.push(format!(
                "Removed the grant, but couldn't read the app registration to remove {} from its \
                 API permissions ({}).",
                mapping.permission,
                UiError::from(e).message
            )),
        }
    }
    Ok(result)
}

/// The principal's service principal: `sp_object_id` when the caller has it,
/// else the one paired with `app_id` (an audit row for an app registration
/// carries no SP id).
pub(crate) async fn resolve_sp_object_id(
    client: &GraphClient,
    sp_object_id: Option<&str>,
    app_id: &str,
) -> Result<String, UiError> {
    if let Some(id) = sp_object_id {
        return Ok(id.to_string());
    }
    client
        .get_service_principal_by_app_id(app_id)
        .await
        .map_err(admin_unit_err)?
        .map(|sp| sp.id)
        .ok_or_else(|| UiError::not_found("service_principal", "This app has no service principal"))
}

/// Limits `permission_value` (Microsoft Graph) held by the principal to the
/// admin unit `admin_unit_id`. `created_now` says the unit was created in this
/// same wizard run (its membership is still being calculated).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn scope_directory_write(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: Option<String>,
    object_id: Option<String>,
    app_id: String,
    permission_value: String,
    admin_unit_id: String,
    created_now: bool,
    require_held: bool,
) -> Result<DirectoryWriteScopeResult, UiError> {
    crate::commands::guid::require_app_id(&app_id)?;
    if !is_guid(&admin_unit_id) {
        return Err(invalid_id("admin unit id"));
    }
    if object_id.as_deref().is_some_and(|o| !is_guid(o)) {
        return Err(invalid_id("app registration id"));
    }
    if sp_object_id.as_deref().is_some_and(|o| !is_guid(o)) {
        return Err(invalid_id("service principal id"));
    }
    let mapping = directory_write_mapping(Some(MICROSOFT_GRAPH_APP_ID), &permission_value)
        .ok_or_else(|| {
            UiError::validation(
                "not_directory_write",
                format!("{permission_value} can't be limited to an admin unit."),
            )
        })?;
    // Both tokens before the first write: the role rides `admin_unit_roles`
    // (whose consent covers the write scopes too), the read grant and the
    // strip ride `write`. A consent surfaced mid-run would strand the role.
    for feature in [ConsentFeature::AdminUnitRoles, ConsentFeature::Write] {
        state
            .ensure_feature_token(&tenant_id, feature)
            .await
            .map_err(UiError::from)?;
    }
    let client = state.graph_for(&tenant_id);
    let sp_object_id = resolve_sp_object_id(&client, sp_object_id.as_deref(), &app_id).await?;
    let result = scope_directory_write_core(
        &client,
        &state.cache,
        &GraphRolePrincipal {
            tenant_id: &tenant_id,
            object_id: object_id.as_deref(),
            sp_object_id: &sp_object_id,
            app_id: &app_id,
        },
        mapping,
        &admin_unit_id,
        created_now,
        require_held,
    )
    .await?;
    // The stripped write's expiry tag names a grant no longer held.
    if result.orgwide_removed {
        crate::commands::grant_expiry::prune_unheld_expiries(&state, &tenant_id, &sp_object_id)
            .await;
    }
    Ok(result)
}

/// The tenant's administrative units.
#[tauri::command]
pub async fn list_admin_units(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<AdminUnitDto>, UiError> {
    let units = state
        .graph_for(&tenant_id)
        .list_admin_units()
        .await
        .map_err(admin_unit_err)?;
    let mut out: Vec<AdminUnitDto> = units.into_iter().map(to_dto).collect();
    out.sort_by_key(|u| u.display_name.to_lowercase());
    Ok(out)
}

/// Creates an admin unit whose members come from `membership_rule`.
#[tauri::command]
pub async fn create_admin_unit_by_rule(
    state: State<'_, AppState>,
    tenant_id: String,
    display_name: String,
    membership_rule: String,
) -> Result<AdminUnitDto, UiError> {
    validate_new_unit(&display_name, &membership_rule)?;
    let unit = state
        .graph_for(&tenant_id)
        .create_dynamic_admin_unit(display_name.trim(), membership_rule.trim())
        .await
        .map_err(admin_unit_err)?;
    Ok(to_dto(unit))
}

/// The principal's direct, active directory role assignments, with each
/// admin unit named (an unreadable name falls back to its id).
#[tauri::command]
pub async fn list_directory_roles(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: String,
) -> Result<Vec<DirectoryRoleDto>, UiError> {
    if !is_guid(&sp_object_id) {
        return Err(invalid_id("service principal id"));
    }
    let client = state.graph_for(&tenant_id);
    let assignments = client
        .list_role_assignments_for_principal(&sp_object_id)
        .await
        .map_err(admin_unit_err)?;
    let mut unit_names: HashMap<String, String> = HashMap::new();
    for id in assignments.iter().filter_map(|a| a.admin_unit_id()) {
        if unit_names.contains_key(id) {
            continue;
        }
        let name = match client.get_admin_unit(id).await {
            Ok(u) => u.display_name.unwrap_or_else(|| id.to_string()),
            Err(_) => id.to_string(),
        };
        unit_names.insert(id.to_string(), name);
    }
    Ok(assignments
        .iter()
        .map(|a| DirectoryRoleDto {
            assignment_id: a.id.clone(),
            role_template_id: a.role_template_id().to_string(),
            role_name: a
                .role_definition
                .as_ref()
                .and_then(|d| d.display_name.clone())
                .unwrap_or_else(|| a.role_template_id().to_string()),
            scope: match a.admin_unit_id() {
                Some(id) => DirectoryRoleScopeDto::AdminUnit {
                    id: id.to_string(),
                    name: unit_names
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| id.to_string()),
                },
                None if a.is_tenant_scope() => DirectoryRoleScopeDto::Tenant,
                None => DirectoryRoleScopeDto::Object {
                    id: a.directory_scope_id.trim_start_matches('/').to_string(),
                },
            },
        })
        .collect())
}

/// Removes one admin-unit-scoped role assignment the principal holds,
/// re-read live first; a tenant-scope assignment is refused.
#[tauri::command]
pub async fn remove_admin_unit_role(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: String,
    assignment_id: String,
) -> Result<(), UiError> {
    if !is_guid(&sp_object_id) {
        return Err(invalid_id("service principal id"));
    }
    let client = state.graph_for(&tenant_id);
    let assignments = client
        .list_role_assignments_for_principal(&sp_object_id)
        .await
        .map_err(admin_unit_err)?;
    let target = removable_unit_assignment(&assignments, &assignment_id)?;
    client
        .delete_role_assignment(&target.id)
        .await
        .map_err(admin_unit_err)?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
    use azapptoolkit_core::scoping::admin_unit::directory_write_mapping;
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use crate::commands::test_support::mock_graph;

    const T: &str = "tenant-test";
    const SP: &str = "5f8b2c1a-0d3e-4b6f-9a7c-1e2d3f4a5b6c";
    const OBJ: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    const APP: &str = "11111111-2222-4333-8444-555555555555";
    const AU: &str = "6c3e1f0a-1b2c-4d3e-8f4a-5b6c7d8e9f01";
    const GRAPH_SP: &str = "99999999-8888-4777-8666-555555555555";
    const USER_RW: &str = "741f803b-c850-494e-b5df-cde7c675a1ca";
    const USER_R: &str = "df021288-bdef-4463-88db-98f22de89214";
    const DIR_R: &str = "7ab1d382-f21e-4acd-a863-ba3e13f7da61";
    const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
    const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";

    fn client(server: &MockServer) -> GraphClient {
        mock_graph(server).with_admin_unit_roles_token(StaticTokenProvider::new("aur"))
    }

    fn user_mapping() -> &'static DirectoryWriteMapping {
        directory_write_mapping(Some(MICROSOFT_GRAPH_APP_ID), "User.ReadWrite.All").unwrap()
    }

    fn principal(object_id: Option<&'static str>) -> GraphRolePrincipal<'static> {
        GraphRolePrincipal {
            tenant_id: T,
            object_id,
            sp_object_id: SP,
            app_id: APP,
        }
    }

    /// The app's SP, Graph's roles, the app's grants (`held` role ids), its
    /// direct role assignments, and the unit (dynamic or not, processing, and
    /// whether it has a user member).
    struct World<'a> {
        held: &'a [&'a str],
        roles: serde_json::Value,
        unit_dynamic: bool,
        processing: &'a str,
        has_users: bool,
        /// The SP's tags (grant expiries).
        tags: &'a [&'a str],
    }

    impl Default for World<'_> {
        fn default() -> Self {
            World {
                held: &[USER_RW],
                roles: serde_json::json!([]),
                unit_dynamic: false,
                processing: "On",
                has_users: true,
                tags: &[],
            }
        }
    }

    async fn mount(server: &MockServer, w: &World<'_>) {
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/servicePrincipals/{SP}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": SP, "appId": APP, "displayName": "Directory Sync", "tags": w.tags
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", format!("appId eq '{MICROSOFT_GRAPH_APP_ID}'")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": GRAPH_SP, "appId": MICROSOFT_GRAPH_APP_ID, "displayName": "Microsoft Graph",
                    "appRoles": [
                        { "id": USER_RW, "value": "User.ReadWrite.All", "allowedMemberTypes": ["Application"] },
                        { "id": USER_R, "value": "User.Read.All", "allowedMemberTypes": ["Application"] },
                        { "id": DIR_R, "value": "Directory.Read.All", "allowedMemberTypes": ["Application"] },
                        { "id": "19dbc75e-c2e2-444c-a770-ec69d8559fc7", "value": "Directory.ReadWrite.All", "allowedMemberTypes": ["Application"] }
                    ]
                }]
            })))
            .mount(server)
            .await;
        let grants: Vec<serde_json::Value> = w
            .held
            .iter()
            .map(|role| {
                serde_json::json!({
                    "id": format!("ga-{role}"), "principalId": SP,
                    "resourceId": GRAPH_SP, "appRoleId": role
                })
            })
            .collect();
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1.0/servicePrincipals/{SP}/appRoleAssignments"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": grants })),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/roleManagement/directory/roleAssignments"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": w.roles.clone() })),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/directory/administrativeUnits/{AU}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": AU, "displayName": "Finance",
                "membershipType": if w.unit_dynamic { "Dynamic" } else { "Assigned" },
                "membershipRuleProcessingState": w.processing
            })))
            .mount(server)
            .await;
        let members = if w.has_users {
            serde_json::json!([{ "id": "u-1" }])
        } else {
            serde_json::json!([])
        };
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1.0/directory/administrativeUnits/{AU}/members/microsoft.graph.user"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": members })),
            )
            .mount(server)
            .await;
    }

    async fn expect_role_post(server: &MockServer, status: u16, times: u64) {
        Mock::given(method("POST"))
            .and(path("/v1.0/roleManagement/directory/roleAssignments"))
            .and(body_json(serde_json::json!({
                "principalId": SP, "roleDefinitionId": USER_ADMIN,
                "directoryScopeId": format!("/administrativeUnits/{AU}")
            })))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "id": "ra-new", "principalId": SP, "roleDefinitionId": USER_ADMIN,
                    "directoryScopeId": format!("/administrativeUnits/{AU}"),
                    "error": { "code": "Authorization_RequestDenied", "message": "denied" }
                })),
            )
            .expect(times)
            .mount(server)
            .await;
    }

    async fn expect_read_grant(server: &MockServer, status: u16, times: u64) {
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1.0/servicePrincipals/{SP}/appRoleAssignments"
            )))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "id": "ga-read", "principalId": SP, "resourceId": GRAPH_SP, "appRoleId": USER_R,
                    "error": { "code": "Request_BadRequest", "message": "bad" }
                })),
            )
            .expect(times)
            .mount(server)
            .await;
    }

    async fn expect_strip(server: &MockServer, times: u64) {
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/v1.0/servicePrincipals/{SP}/appRoleAssignments/ga-{USER_RW}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(times)
            .mount(server)
            .await;
    }

    async fn run(
        server: &MockServer,
        object_id: Option<&'static str>,
        created_now: bool,
    ) -> DirectoryWriteScopeResult {
        try_run(server, object_id, created_now, false)
            .await
            .unwrap()
    }

    async fn try_run(
        server: &MockServer,
        object_id: Option<&'static str>,
        created_now: bool,
        require_held: bool,
    ) -> Result<DirectoryWriteScopeResult, UiError> {
        let cache = azapptoolkit_core::cache::Cache::new();
        scope_directory_write_core(
            &client(server),
            &cache,
            &principal(object_id),
            user_mapping(),
            AU,
            created_now,
            require_held,
        )
        .await
    }

    fn method_and_path(r: &Request) -> String {
        format!("{} {}", r.method, r.url.path())
    }

    #[tokio::test]
    async fn grant_then_read_then_strip_in_order() {
        let server = MockServer::start().await;
        mount(&server, &World::default()).await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 1).await;
        expect_strip(&server, 1).await;
        let r = run(&server, None, false).await;
        assert!(
            r.role_assigned && r.read_granted && r.orgwide_removed,
            "{r:?}"
        );
        let writes: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() != "GET")
            .map(method_and_path)
            .collect();
        assert_eq!(
            writes,
            vec![
                "POST /v1.0/roleManagement/directory/roleAssignments".to_string(),
                format!("POST /v1.0/servicePrincipals/{SP}/appRoleAssignments"),
                format!("DELETE /v1.0/servicePrincipals/{SP}/appRoleAssignments/ga-{USER_RW}"),
            ]
        );
    }

    /// An expiry on the stripped write doesn't carry to the admin role (a
    /// role assignment can't be dated): the result says so (C1g).
    #[tokio::test]
    async fn an_expiring_write_warns_that_its_date_does_not_carry() {
        let server = MockServer::start().await;
        let tag =
            format!("azapptoolkit:grantExpiry:v1|{MICROSOFT_GRAPH_APP_ID}|{USER_RW}|2026-12-31");
        mount(
            &server,
            &World {
                tags: &[tag.as_str()],
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 1).await;
        expect_strip(&server, 1).await;
        let r = run(&server, None, false).await;
        assert!(r.orgwide_removed, "{r:?}");
        assert!(
            r.warnings.iter().any(|w| w.contains("2026-12-31")
                && w.contains("User.ReadWrite.All")
                && w.contains("User.Read.All")),
            "the read granted now outlives the date too: {r:?}"
        );
        // Without a date there is nothing to say.
        let server = MockServer::start().await;
        mount(&server, &World::default()).await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 1).await;
        expect_strip(&server, 1).await;
        let r = run(&server, None, false).await;
        assert!(r.warnings.iter().all(|w| !w.contains("expire")), "{r:?}");
    }

    #[tokio::test]
    async fn a_failed_role_assignment_strips_nothing() {
        let server = MockServer::start().await;
        mount(&server, &World::default()).await;
        expect_role_post(&server, 403, 1).await;
        expect_read_grant(&server, 201, 0).await;
        expect_strip(&server, 0).await;
        let err = try_run(&server, None, false, false).await.unwrap_err();
        assert_eq!(err.code, "forbidden");
    }

    #[tokio::test]
    async fn a_failed_read_grant_strips_nothing() {
        let server = MockServer::start().await;
        mount(&server, &World::default()).await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 400, 1).await;
        expect_strip(&server, 0).await;
        let r = run(&server, None, false).await;
        assert!(
            r.role_assigned && !r.read_granted && !r.orgwide_removed,
            "{r:?}"
        );
        assert!(r.kept_reason.is_some(), "{r:?}");
    }

    #[tokio::test]
    async fn an_existing_assignment_is_idempotent() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                held: &[USER_RW, USER_R],
                roles: serde_json::json!([{
                    "id": "ra-1", "principalId": SP, "roleDefinitionId": USER_ADMIN,
                    "directoryScopeId": format!("/administrativeUnits/{AU}")
                }]),
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 0).await;
        expect_read_grant(&server, 201, 0).await;
        expect_strip(&server, 1).await;
        let r = run(&server, None, false).await;
        assert!(
            r.role_already_held && r.read_already_held && r.orgwide_removed,
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn a_held_directory_read_satisfies_the_read() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                held: &[USER_RW, DIR_R],
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 0).await;
        expect_strip(&server, 1).await;
        let r = run(&server, None, false).await;
        assert!(r.read_already_held, "{r:?}");
    }

    #[tokio::test]
    async fn a_just_created_unit_keeps_tenant_wide() {
        let server = MockServer::start().await;
        mount(&server, &World::default()).await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 1).await;
        expect_strip(&server, 0).await;
        let r = run(&server, None, true).await;
        assert!(!r.orgwide_removed && r.kept_reason.is_some(), "{r:?}");
    }

    #[tokio::test]
    async fn a_unit_without_members_of_the_type_keeps_tenant_wide() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                has_users: false,
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 1).await;
        expect_strip(&server, 0).await;
        let r = run(&server, None, false).await;
        assert!(!r.orgwide_removed && r.kept_reason.is_some(), "{r:?}");
    }

    #[tokio::test]
    async fn a_paused_rule_keeps_tenant_wide() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                unit_dynamic: true,
                processing: "Paused",
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 1).await;
        expect_strip(&server, 0).await;
        let r = run(&server, None, false).await;
        assert!(!r.orgwide_removed && r.kept_reason.is_some(), "{r:?}");
    }

    #[tokio::test]
    async fn a_covering_tenant_role_is_reported() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                roles: serde_json::json!([{
                    "id": "ra-ga", "principalId": SP, "roleDefinitionId": GLOBAL_ADMIN,
                    "directoryScopeId": "/"
                }]),
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 1).await;
        expect_strip(&server, 1).await;
        let r = run(&server, None, false).await;
        assert_eq!(r.covering_role.as_deref(), Some("Global Administrator"));
        assert!(r.orgwide_removed, "the strip still removes a real grant");
    }

    #[tokio::test]
    async fn an_sp_only_principal_never_touches_a_manifest() {
        let server = MockServer::start().await;
        mount(&server, &World::default()).await;
        expect_role_post(&server, 201, 1).await;
        expect_read_grant(&server, 201, 1).await;
        expect_strip(&server, 1).await;
        run(&server, None, false).await;
        let touched_apps = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.path().starts_with("/v1.0/applications"));
        assert!(!touched_apps);
    }

    #[tokio::test]
    async fn an_app_registration_also_loses_its_declaration() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                held: &[USER_RW, USER_R],
                ..World::default()
            },
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/applications/{OBJ}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": OBJ, "appId": APP, "displayName": "Directory Sync",
                "requiredResourceAccess": [{
                    "resourceAppId": MICROSOFT_GRAPH_APP_ID,
                    "resourceAccess": [
                        { "id": USER_RW, "type": "Role" },
                        { "id": USER_R, "type": "Role" }
                    ]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("/v1.0/applications/{OBJ}")))
            .and(body_json(serde_json::json!({
                "requiredResourceAccess": [{
                    "resourceAppId": MICROSOFT_GRAPH_APP_ID,
                    "resourceAccess": [{ "id": USER_R, "type": "Role" }]
                }]
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        expect_role_post(&server, 201, 1).await;
        expect_strip(&server, 1).await;
        let r = run(&server, Some(OBJ), false).await;
        assert!(r.orgwide_removed, "{r:?}");
    }

    #[test]
    fn remove_refuses_a_tenant_scope_assignment() {
        let assignments = vec![
            DirectoryRoleAssignment {
                id: "ra-tenant".into(),
                principal_id: SP.into(),
                role_definition_id: USER_ADMIN.into(),
                directory_scope_id: "/".into(),
                role_definition: None,
            },
            DirectoryRoleAssignment {
                id: "ra-unit".into(),
                principal_id: SP.into(),
                role_definition_id: USER_ADMIN.into(),
                directory_scope_id: format!("/administrativeUnits/{AU}"),
                role_definition: None,
            },
        ];
        assert_eq!(
            removable_unit_assignment(&assignments, "ra-tenant")
                .unwrap_err()
                .code,
            "not_admin_unit_scoped"
        );
        assert_eq!(
            removable_unit_assignment(&assignments, "ra-other")
                .unwrap_err()
                .code,
            "role_assignment_not_found",
            "another principal's assignment isn't in this principal's list"
        );
        assert!(removable_unit_assignment(&assignments, "ra-unit").is_ok());
    }

    #[test]
    fn create_admin_unit_validates_name_and_rule() {
        let code = |n: &str, r: &str| validate_new_unit(n, r).err().map(|e| e.code);
        assert_eq!(code("Finance", r#"(user.department -eq "Finance")"#), None);
        assert_eq!(
            code("  ", "(user.department -eq \"x\")"),
            Some("invalid_name".into())
        );
        assert_eq!(
            code(&"x".repeat(257), "(user.department -eq \"x\")"),
            Some("invalid_name".into())
        );
        assert_eq!(code("Finance", " "), Some("invalid_membership_rule".into()));
        assert_eq!(
            code("Finance", &"x".repeat(3073)),
            Some("invalid_membership_rule".into())
        );
    }

    #[tokio::test]
    async fn a_missing_sp_id_resolves_from_the_app_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", format!("appId eq '{APP}'")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": SP, "appId": APP, "displayName": "Directory Sync" }]
            })))
            .mount(&server)
            .await;
        let c = client(&server);
        assert_eq!(resolve_sp_object_id(&c, None, APP).await.unwrap(), SP);
        assert_eq!(resolve_sp_object_id(&c, Some(SP), APP).await.unwrap(), SP);
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param(
                "$filter",
                "appId eq '22222222-3333-4444-8555-666666666666'",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .mount(&server)
            .await;
        assert_eq!(
            resolve_sp_object_id(&c, None, "22222222-3333-4444-8555-666666666666")
                .await
                .unwrap_err()
                .code,
            "service_principal_not_found"
        );
    }

    const DIR_RW: &str = "19dbc75e-c2e2-444c-a770-ec69d8559fc7";

    /// I1: the audit's Fix never assigns a role to an app that doesn't hold
    /// the tenant-wide write it claims to limit.
    #[tokio::test]
    async fn the_fix_refuses_a_write_the_app_does_not_hold() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                held: &[USER_R],
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 0).await;
        expect_read_grant(&server, 201, 0).await;
        let err = try_run(&server, None, false, true).await.unwrap_err();
        assert_eq!(err.code, "write_not_held");
    }

    /// The wizard may give an app limited write access from scratch.
    #[tokio::test]
    async fn the_wizard_may_grant_a_limited_write_from_scratch() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                held: &[USER_R],
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 1).await;
        expect_strip(&server, 0).await;
        let r = run(&server, None, false).await;
        assert!(
            r.role_assigned && !r.write_held && !r.orgwide_removed,
            "{r:?}"
        );
    }

    /// I2: a drifted app registration is refused before anything is written.
    #[tokio::test]
    async fn a_drifted_app_registration_is_refused_before_any_write() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                held: &[USER_RW, USER_R],
                ..World::default()
            },
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/applications/{OBJ}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": OBJ, "appId": "22222222-3333-4444-8555-666666666666",
                "displayName": "Someone else"
            })))
            .mount(&server)
            .await;
        expect_role_post(&server, 201, 0).await;
        expect_strip(&server, 0).await;
        let err = try_run(&server, Some(OBJ), false, false).await.unwrap_err();
        assert_eq!(err.code, "principal_mismatch");
    }

    /// I3: a failed strip keeps the declaration, so a live grant is never
    /// left undeclared.
    #[tokio::test]
    async fn a_failed_strip_keeps_the_declaration() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                held: &[USER_RW, USER_R],
                ..World::default()
            },
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/applications/{OBJ}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": OBJ, "appId": APP, "displayName": "Directory Sync",
                "requiredResourceAccess": [{
                    "resourceAppId": MICROSOFT_GRAPH_APP_ID,
                    "resourceAccess": [
                        { "id": USER_RW, "type": "Role" },
                        { "id": USER_R, "type": "Role" }
                    ]
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/v1.0/servicePrincipals/{SP}/appRoleAssignments/ga-{USER_RW}"
            )))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": { "code": "Authorization_RequestDenied", "message": "denied" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("/v1.0/applications/{OBJ}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        expect_role_post(&server, 201, 1).await;
        let r = run(&server, Some(OBJ), false).await;
        assert!(!r.orgwide_removed && !r.warnings.is_empty(), "{r:?}");
    }

    /// I4: a dead session on the read grant returns its code (so the UI can
    /// prompt re-auth) instead of a warning string.
    #[tokio::test]
    async fn a_dead_session_on_the_read_grant_returns_its_code() {
        let server = MockServer::start().await;
        mount(&server, &World::default()).await;
        expect_role_post(&server, 201, 1).await;
        let dead: Arc<dyn azapptoolkit_core::token::BearerProvider> =
            crate::commands::test_support::dead_token();
        let client = GraphClient::with_base_url(
            "tenant-test",
            StaticTokenProvider::new("tok"),
            dead,
            azapptoolkit_core::cache::Cache::new(),
            format!("{}/v1.0", server.uri()),
        )
        .with_admin_unit_roles_token(StaticTokenProvider::new("aur"));
        let cache = azapptoolkit_core::cache::Cache::new();
        let err = scope_directory_write_core(
            &client,
            &cache,
            &principal(None),
            user_mapping(),
            AU,
            false,
            false,
        )
        .await
        .unwrap_err();
        assert!(err.is_reauth_fatal(), "{err:?}");
    }

    /// I5: a tenant-wide Directory.ReadWrite.All still writes everyone.
    #[tokio::test]
    async fn a_covering_directory_readwrite_grant_is_reported() {
        let server = MockServer::start().await;
        mount(
            &server,
            &World {
                held: &[USER_RW, USER_R, DIR_RW],
                ..World::default()
            },
        )
        .await;
        expect_role_post(&server, 201, 1).await;
        expect_strip(&server, 1).await;
        let r = run(&server, None, false).await;
        assert_eq!(r.covering_role.as_deref(), Some("Directory.ReadWrite.All"));
    }
}
