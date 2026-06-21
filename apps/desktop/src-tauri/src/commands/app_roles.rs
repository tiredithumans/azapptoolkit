//! Exposed app-role commands — the Entra "App roles" blade for an enterprise
//! application: the role *definitions* the app publishes (`appRoles`), not the
//! role *assignments* in `enterprise_application::list_enterprise_app_assignments`.
//!
//! Graph treats `appRoles` as a **full replacement** on PATCH, so every mutation
//! re-reads live state, applies the change to the fetched collection, and writes
//! the whole array back. Roles are kept as raw JSON between read and write so a
//! role the caller isn't editing — notably the SAML default `msiam_access`, which
//! carries `value: null` and a read-only `origin` — round-trips byte-faithfully
//! (a typed shape would rewrite its `null` value to `""`). Deleting an enabled
//! role follows the portal's two-step contract: Graph rejects removing an enabled
//! role, so it's disabled in its own PATCH first, then removed in a second.
//!
//! When a local app registration backs the service principal, the roles are
//! defined on the **application** (their canonical home — Entra mirrors them onto
//! the paired SP); otherwise (gallery / foreign-tenant apps) they live directly on
//! the **service principal**.

use serde_json::Value;
use tauri::State;

use azapptoolkit_core::models::AppRole;

use crate::dto::enterprise_application::{AppRoleInput, AppRolesView};
use crate::dto::UiError;
use crate::state::AppState;

use super::applications::invalidate_app_details;

/// A random v4 GUID for a new app-role id. Generated here (like the portal) so
/// the upsert PATCH is self-contained.
fn new_app_role_guid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1 (RFC 4122)
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Where an enterprise app's exposed roles live. Resolved per request from the
/// SP's `appId`: the paired application when one exists locally, else the SP.
enum RoleTarget {
    Application(String),
    ServicePrincipal(String),
}

impl RoleTarget {
    fn kind_str(&self) -> &'static str {
        match self {
            Self::Application(_) => "application",
            Self::ServicePrincipal(_) => "servicePrincipal",
        }
    }
}

async fn resolve_target(
    client: &azapptoolkit_graph::GraphClient,
    service_principal_id: &str,
    app_id: &str,
) -> Result<RoleTarget, UiError> {
    match client.find_application_by_app_id(app_id).await? {
        Some(app) => Ok(RoleTarget::Application(app.id)),
        None => Ok(RoleTarget::ServicePrincipal(
            service_principal_id.to_string(),
        )),
    }
}

async fn read_roles(
    client: &azapptoolkit_graph::GraphClient,
    target: &RoleTarget,
) -> Result<Vec<Value>, UiError> {
    match target {
        RoleTarget::Application(id) => Ok(client.get_application_app_roles_raw(id).await?),
        RoleTarget::ServicePrincipal(id) => {
            Ok(client.get_service_principal_app_roles_raw(id).await?)
        }
    }
}

async fn write_roles(
    client: &azapptoolkit_graph::GraphClient,
    target: &RoleTarget,
    roles: &[Value],
) -> Result<(), UiError> {
    match target {
        RoleTarget::Application(id) => Ok(client.set_application_app_roles(id, roles).await?),
        RoleTarget::ServicePrincipal(id) => {
            Ok(client.set_service_principal_app_roles(id, roles).await?)
        }
    }
}

fn role_id(role: &Value) -> Option<&str> {
    role.get("id").and_then(Value::as_str)
}

fn role_value(role: &Value) -> &str {
    role.get("value").and_then(Value::as_str).unwrap_or("")
}

/// A role with no `value` is a built-in default Entra publishes (the SAML
/// `msiam_access` role) — custom roles always carry one. Editing or deleting it
/// can break sign-in, and it's not something an admin creates here, so it's
/// surfaced read-only.
fn is_builtin(role: &Value) -> bool {
    role_value(role).trim().is_empty()
}

fn validate_role_input(input: &AppRoleInput) -> Result<(), UiError> {
    let display_name = input.display_name.trim();
    if display_name.is_empty() {
        return Err(UiError::validation(
            "invalid_app_role",
            "Display name is required.",
        ));
    }
    if display_name.chars().count() > 100 {
        return Err(UiError::validation(
            "invalid_app_role",
            "Display name can be at most 100 characters.",
        ));
    }
    let value = input.value.trim();
    if value.is_empty() {
        return Err(UiError::validation(
            "invalid_app_role",
            "Value is required.",
        ));
    }
    if value.chars().count() > 250 {
        return Err(UiError::validation(
            "invalid_app_role",
            "Value can be at most 250 characters.",
        ));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(UiError::validation(
            "invalid_app_role",
            "Value cannot contain spaces.",
        ));
    }
    // Entra rejects a value beginning with '.'; catch it here for a clearer
    // message than the raw Graph error. (Deeper character rules are left to
    // Graph, whose rejection names the actual rule.)
    if value.starts_with('.') {
        return Err(UiError::validation(
            "invalid_app_role",
            "Value cannot start with a period.",
        ));
    }
    if input.allowed_member_types.is_empty() {
        return Err(UiError::validation(
            "invalid_app_role",
            "Select at least one allowed member type.",
        ));
    }
    if input
        .allowed_member_types
        .iter()
        .any(|t| !matches!(t.as_str(), "User" | "Application"))
    {
        return Err(UiError::validation(
            "invalid_app_role",
            "Allowed member types must be 'User' and/or 'Application'.",
        ));
    }
    Ok(())
}

/// Writes the validated input's mutable fields onto a role object, preserving
/// `id`, `origin`, and any other keys Graph round-trips.
fn apply_input(obj: &mut serde_json::Map<String, Value>, input: &AppRoleInput) {
    obj.insert(
        "displayName".into(),
        Value::String(input.display_name.trim().to_string()),
    );
    let desc = input
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    obj.insert(
        "description".into(),
        desc.map_or(Value::Null, |d| Value::String(d.to_string())),
    );
    obj.insert(
        "value".into(),
        Value::String(input.value.trim().to_string()),
    );
    obj.insert(
        "allowedMemberTypes".into(),
        Value::Array(
            input
                .allowed_member_types
                .iter()
                .map(|t| Value::String(t.clone()))
                .collect(),
        ),
    );
    obj.insert("isEnabled".into(), Value::Bool(input.is_enabled));
}

/// Applies an upsert to the live role list: replace by id (edit) or append a new
/// role (create). Rejects a duplicate value (case-insensitive — two roles
/// differing only by case are indistinguishable in the `roles` claim), an edit
/// targeting an id Graph no longer has, and an edit of a built-in default role.
fn merge_role(
    mut roles: Vec<Value>,
    input: &AppRoleInput,
    id: Option<String>,
) -> Result<Vec<Value>, UiError> {
    let value = input.value.trim();
    if roles
        .iter()
        .any(|r| role_id(r) != id.as_deref() && role_value(r).eq_ignore_ascii_case(value))
    {
        return Err(UiError::validation(
            "duplicate_app_role_value",
            format!("An app role with value '{value}' already exists on this app."),
        ));
    }
    match id {
        Some(id) => {
            let Some(target) = roles.iter_mut().find(|r| role_id(r) == Some(id.as_str())) else {
                return Err(UiError::not_found(
                    "app_role",
                    "App role no longer exists on the app; refresh and retry.",
                ));
            };
            if is_builtin(target) {
                return Err(UiError::validation(
                    "builtin_app_role",
                    "The built-in default app role can't be modified.",
                ));
            }
            let Some(obj) = target.as_object_mut() else {
                return Err(UiError::validation(
                    "invalid_app_role",
                    "App role has an unexpected shape; refresh and retry.",
                ));
            };
            apply_input(obj, input);
        }
        None => {
            let mut obj = serde_json::Map::new();
            obj.insert("id".into(), Value::String(new_app_role_guid()));
            apply_input(&mut obj, input);
            roles.push(Value::Object(obj));
        }
    }
    Ok(roles)
}

/// The PATCH bodies a role deletion may need.
struct RoleRemoval {
    /// Role list with the target disabled — sent first when the role is still
    /// enabled (Graph rejects removing an enabled role outright).
    disable_first: Option<Vec<Value>>,
    /// Role list without the target.
    roles: Vec<Value>,
}

/// Plans the removal of `role_id` from the live collection. `Ok(None)` when the
/// role is already gone (the deletion's goal state — treated as success).
fn plan_role_removal(roles: &[Value], target_id: &str) -> Result<Option<RoleRemoval>, UiError> {
    let Some(target) = roles.iter().find(|r| role_id(r) == Some(target_id)) else {
        return Ok(None);
    };
    if is_builtin(target) {
        return Err(UiError::validation(
            "builtin_app_role",
            "The built-in default app role can't be deleted.",
        ));
    }
    // Graph's default for a missing isEnabled is true, so only an explicit false
    // skips the disable round-trip.
    let enabled = target
        .get("isEnabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let disable_first = enabled.then(|| {
        roles
            .iter()
            .cloned()
            .map(|mut r| {
                if role_id(&r) == Some(target_id) {
                    if let Some(obj) = r.as_object_mut() {
                        obj.insert("isEnabled".into(), Value::Bool(false));
                    }
                }
                r
            })
            .collect()
    });
    let remaining = roles
        .iter()
        .filter(|r| role_id(r) != Some(target_id))
        .cloned()
        .collect();
    Ok(Some(RoleRemoval {
        disable_first,
        roles: remaining,
    }))
}

// ---------------- Commands ----------------

/// Reads the enterprise app's exposed app roles plus where they're defined
/// (`application` vs `servicePrincipal`). A live read against the canonical
/// target, so the App roles tab is authoritative immediately after a write
/// (no app → SP replication lag).
#[tauri::command]
pub async fn list_enterprise_app_roles(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    app_id: String,
) -> Result<AppRolesView, UiError> {
    let client = state.graph_for(&tenant_id);
    let target = resolve_target(&client, &service_principal_id, &app_id).await?;
    let raw = read_roles(&client, &target).await?;
    let roles: Vec<AppRole> = serde_json::from_value(Value::Array(raw)).unwrap_or_default();
    Ok(AppRolesView {
        target_kind: target.kind_str().to_string(),
        roles,
    })
}

/// Creates (`input.id = None`, GUID generated here) or updates one exposed app
/// role, then writes the full collection back.
#[tauri::command]
pub async fn upsert_enterprise_app_role(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    app_id: String,
    input: AppRoleInput,
) -> Result<(), UiError> {
    validate_role_input(&input)?;
    let client = state.graph_for(&tenant_id);
    let target = resolve_target(&client, &service_principal_id, &app_id).await?;
    let live = read_roles(&client, &target).await?;
    let merged = merge_role(live, &input, input.id.clone())?;
    write_roles(&client, &target, &merged).await?;
    // Entra mirrors the app's roles onto the paired SP's appRoles, which the
    // cached detail payloads embed (the Access tab's role picker reads them).
    invalidate_app_details(&state.cache, &tenant_id);
    Ok(())
}

/// Deletes one exposed app role, disabling it first when needed (Graph rejects
/// removing an enabled role). Idempotent: a role that's already gone is success.
/// If the second PATCH fails after the disable, the role is left disabled —
/// harmless; a retry completes the removal.
#[tauri::command]
pub async fn delete_enterprise_app_role(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    app_id: String,
    role_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let target = resolve_target(&client, &service_principal_id, &app_id).await?;
    let live = read_roles(&client, &target).await?;
    let Some(plan) = plan_role_removal(&live, &role_id)? else {
        return Ok(());
    };
    if let Some(disabled) = plan.disable_first {
        write_roles(&client, &target, &disabled).await?;
    }
    write_roles(&client, &target, &plan.roles).await?;
    invalidate_app_details(&state.cache, &tenant_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn role(id: &str, value: &str, enabled: Option<bool>) -> Value {
        let mut obj = json!({
            "id": id,
            "displayName": value,
            "allowedMemberTypes": ["User"],
            "origin": "Application",
        });
        obj["value"] = match value {
            "" => Value::Null, // model the SAML default (msiam_access) role
            v => Value::String(v.to_string()),
        };
        if let Some(e) = enabled {
            obj["isEnabled"] = Value::Bool(e);
        }
        obj
    }

    fn input(id: Option<&str>, value: &str) -> AppRoleInput {
        AppRoleInput {
            id: id.map(str::to_string),
            display_name: "Task Writer".into(),
            value: value.into(),
            description: Some("Can write tasks.".into()),
            allowed_member_types: vec!["User".into()],
            is_enabled: true,
        }
    }

    #[test]
    fn new_app_role_guid_is_v4_format() {
        let g = new_app_role_guid();
        assert_eq!(g.len(), 36);
        assert_eq!(g.as_bytes()[14], b'4'); // version nibble
    }

    #[test]
    fn validate_rejects_bad_fields() {
        assert!(validate_role_input(&input(None, "task.write")).is_ok());
        assert!(validate_role_input(&input(None, "")).is_err());
        assert!(validate_role_input(&input(None, "has space")).is_err());
        assert!(validate_role_input(&input(None, ".leading")).is_err());

        let mut no_member = input(None, "ok");
        no_member.allowed_member_types = vec![];
        assert!(validate_role_input(&no_member).is_err());

        let mut bad_member = input(None, "ok");
        bad_member.allowed_member_types = vec!["Device".into()];
        assert!(validate_role_input(&bad_member).is_err());

        let mut long_name = input(None, "ok");
        long_name.display_name = "x".repeat(101);
        assert!(validate_role_input(&long_name).is_err());
    }

    #[test]
    fn merge_appends_replaces_and_rejects_duplicates() {
        let existing = vec![role("a", "admin", Some(true))];

        // Append a new role.
        let merged = merge_role(existing.clone(), &input(None, "writer"), None).unwrap();
        assert_eq!(merged.len(), 2);
        assert!(role_id(&merged[1]).is_some());
        assert_eq!(role_value(&merged[1]), "writer");

        // Replace by id keeps the list length and applies the new value.
        let merged = merge_role(
            existing.clone(),
            &input(Some("a"), "admin2"),
            Some("a".into()),
        )
        .unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(role_value(&merged[0]), "admin2");

        // Duplicate value (other id, case-insensitive) is rejected.
        assert!(merge_role(existing.clone(), &input(None, "ADMIN"), None).is_err());

        // Editing an id Graph no longer has is a not-found, not a silent append.
        assert!(merge_role(existing, &input(Some("gone"), "x"), Some("gone".into())).is_err());
    }

    #[test]
    fn merge_edit_preserves_unknown_keys_and_blocks_builtin() {
        // Editing a role keeps its `origin` (a read-only key we don't manage).
        let existing = vec![role("a", "admin", Some(true))];
        let merged = merge_role(existing, &input(Some("a"), "admin"), Some("a".into())).unwrap();
        assert_eq!(
            merged[0].get("origin").and_then(Value::as_str),
            Some("Application")
        );

        // The built-in default (value-less) role can't be edited.
        let builtin = vec![role("def", "", Some(true))];
        assert!(merge_role(builtin, &input(Some("def"), "x"), Some("def".into())).is_err());
    }

    #[test]
    fn plan_removal_disables_enabled_role_first() {
        let roles = vec![
            role("a", "admin", Some(true)),
            role("b", "writer", Some(true)),
        ];
        let plan = plan_role_removal(&roles, "a").unwrap().unwrap();
        let disabled = plan
            .disable_first
            .expect("enabled role needs a disable pass");
        assert_eq!(
            disabled.iter().find(|r| role_id(r) == Some("a")).unwrap()["isEnabled"],
            Value::Bool(false)
        );
        assert_eq!(plan.roles.len(), 1);
        assert_eq!(role_id(&plan.roles[0]), Some("b"));

        // A missing isEnabled means enabled (Graph default) — still two-step.
        let roles = vec![role("a", "admin", None)];
        assert!(plan_role_removal(&roles, "a")
            .unwrap()
            .unwrap()
            .disable_first
            .is_some());

        // An already-disabled role removes in one PATCH.
        let roles = vec![role("a", "admin", Some(false))];
        assert!(plan_role_removal(&roles, "a")
            .unwrap()
            .unwrap()
            .disable_first
            .is_none());

        // Already gone ⇒ nothing to do.
        assert!(plan_role_removal(&[role("a", "admin", Some(false))], "zz")
            .unwrap()
            .is_none());

        // The built-in default role can't be deleted.
        assert!(plan_role_removal(&[role("def", "", Some(true))], "def").is_err());
    }
}
