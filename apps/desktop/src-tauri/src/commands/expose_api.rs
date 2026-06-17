//! "Expose an API" commands — the portal blade for an app registration:
//! Application ID URI(s), the delegated scopes the API defines
//! (`api.oauth2PermissionScopes`), and pre-authorized client applications
//! (`api.preAuthorizedApplications`).
//!
//! Graph treats both `api` arrays as **full replacements** on PATCH, so every
//! mutation here re-reads live state, applies the change to the fetched list,
//! and writes the whole array back — the cached detail payload is never used
//! as the merge base. Deleting a scope follows the portal's two-step contract:
//! Graph rejects removing a scope that is still enabled, so an enabled scope
//! is disabled in its own PATCH first, then removed (and stripped from any
//! pre-authorized clients) in a second.

use tauri::State;

use azapptoolkit_core::models::{
    ApiApplication, ApplicationExposeApi, OAuth2PermissionScope, PreAuthorizedApplication,
};
use azapptoolkit_graph::client::{ApiApplicationPatch, ApplicationExposeApiPatch};

use crate::dto::expose_api::{ExposeApiDto, SetPreAuthorizedAppInput, UpsertApiScopeInput};
use crate::dto::UiError;
use crate::state::AppState;

use super::applications::invalidate_app_details;
use super::search::is_guid;

/// A random v4 GUID for a new scope id. Generated client-side (like the
/// portal) so the upsert PATCH is self-contained.
fn new_scope_guid() -> String {
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

/// Live read of the app's `identifierUris` + `api` block — the merge base for
/// every mutation below.
async fn fetch_expose_api(
    client: &azapptoolkit_graph::GraphClient,
    object_id: &str,
) -> Result<ApplicationExposeApi, UiError> {
    client
        .get_application_expose_api(object_id)
        .await?
        .ok_or_else(|| UiError::not_found("application", "application not found"))
}

/// Validates one Application ID URI: non-empty, no whitespace, and carrying a
/// scheme. Entra's deeper rules (verified domains for https URIs, allowed
/// schemes) are left to Graph — its rejection message names the actual rule.
fn validate_identifier_uri(uri: &str) -> Result<(), UiError> {
    if uri.is_empty() {
        return Err(UiError::validation(
            "invalid_identifier_uri",
            "Application ID URI cannot be empty.",
        ));
    }
    if uri.chars().any(char::is_whitespace) {
        return Err(UiError::validation(
            "invalid_identifier_uri",
            format!("Application ID URI '{uri}' cannot contain whitespace."),
        ));
    }
    if !uri.contains(':') {
        return Err(UiError::validation(
            "invalid_identifier_uri",
            format!(
                "Application ID URI '{uri}' must include a scheme (e.g. api://… or https://…)."
            ),
        ));
    }
    Ok(())
}

fn validate_scope_input(input: &UpsertApiScopeInput) -> Result<(), UiError> {
    let value = input.value.trim();
    if value.is_empty() {
        return Err(UiError::validation(
            "invalid_scope",
            "Scope name is required.",
        ));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(UiError::validation(
            "invalid_scope",
            "Scope name cannot contain spaces.",
        ));
    }
    if !matches!(input.scope_type.as_str(), "Admin" | "User") {
        return Err(UiError::validation(
            "invalid_scope",
            "Who can consent must be 'Admin' (admins only) or 'User' (admins and users).",
        ));
    }
    // Graph requires both admin-consent strings on an enabled scope; requiring
    // them always (like the portal) keeps a later re-enable from failing.
    if input.admin_consent_display_name.trim().is_empty()
        || input.admin_consent_description.trim().is_empty()
    {
        return Err(UiError::validation(
            "invalid_scope",
            "Admin consent display name and description are required.",
        ));
    }
    Ok(())
}

/// Builds the Graph `permissionScope` from the validated input.
fn build_scope(input: &UpsertApiScopeInput, id: String) -> OAuth2PermissionScope {
    let opt = |s: &Option<String>| {
        s.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    OAuth2PermissionScope {
        id,
        value: input.value.trim().to_string(),
        admin_consent_display_name: Some(input.admin_consent_display_name.trim().to_string()),
        admin_consent_description: Some(input.admin_consent_description.trim().to_string()),
        user_consent_display_name: opt(&input.user_consent_display_name),
        user_consent_description: opt(&input.user_consent_description),
        r#type: Some(input.scope_type.clone()),
        is_enabled: Some(input.is_enabled),
    }
}

/// Applies an upsert to the live scope list: replace by id, or append a new
/// scope. Rejects a duplicate scope name (case-insensitive — two values
/// differing only by case are indistinguishable to consent UX) and an edit
/// targeting an id Graph no longer has.
fn merge_scope(
    mut scopes: Vec<OAuth2PermissionScope>,
    scope: OAuth2PermissionScope,
    is_edit: bool,
) -> Result<Vec<OAuth2PermissionScope>, UiError> {
    if scopes
        .iter()
        .any(|s| s.id != scope.id && s.value.eq_ignore_ascii_case(&scope.value))
    {
        return Err(UiError::validation(
            "duplicate_scope_value",
            format!(
                "A scope named '{}' already exists on this API.",
                scope.value
            ),
        ));
    }
    if is_edit {
        let Some(existing) = scopes.iter_mut().find(|s| s.id == scope.id) else {
            return Err(UiError::not_found(
                "scope",
                "Scope no longer exists on the application; refresh and retry.",
            ));
        };
        *existing = scope;
    } else {
        scopes.push(scope);
    }
    Ok(scopes)
}

/// The two PATCH bodies a scope deletion may need.
struct ScopeRemoval {
    /// Scope list with the target disabled — sent first when the scope is
    /// still enabled (Graph rejects removing an enabled scope outright).
    disable_first: Option<Vec<OAuth2PermissionScope>>,
    /// Scope list without the target.
    scopes: Vec<OAuth2PermissionScope>,
    /// Pre-authorized clients with the scope id stripped. A client left
    /// authorized for nothing is dropped entirely — Graph rejects dangling
    /// `delegatedPermissionIds`, and an empty entry is meaningless.
    pre_authorized: Vec<PreAuthorizedApplication>,
}

/// Plans the removal of `scope_id` from the live `api` block. `None` when the
/// scope is already gone (the deletion's goal state — treated as success).
fn plan_scope_removal(api: &ApiApplication, scope_id: &str) -> Option<ScopeRemoval> {
    let target = api
        .oauth2_permission_scopes
        .iter()
        .find(|s| s.id == scope_id)?;
    // Graph's default for a missing isEnabled is true, so only an explicit
    // false skips the disable round-trip.
    let disable_first = target.is_enabled.unwrap_or(true).then(|| {
        api.oauth2_permission_scopes
            .iter()
            .cloned()
            .map(|mut s| {
                if s.id == scope_id {
                    s.is_enabled = Some(false);
                }
                s
            })
            .collect()
    });
    let scopes = api
        .oauth2_permission_scopes
        .iter()
        .filter(|s| s.id != scope_id)
        .cloned()
        .collect();
    let pre_authorized = api
        .pre_authorized_applications
        .iter()
        .cloned()
        .map(|mut p| {
            p.delegated_permission_ids.retain(|id| id != scope_id);
            p
        })
        .filter(|p| !p.delegated_permission_ids.is_empty())
        .collect();
    Some(ScopeRemoval {
        disable_first,
        scopes,
        pre_authorized,
    })
}

/// Replaces (or appends) the pre-authorized entry for `client_app_id` with the
/// given scope-id set.
fn upsert_pre_authorized(
    mut list: Vec<PreAuthorizedApplication>,
    client_app_id: &str,
    scope_ids: Vec<String>,
) -> Vec<PreAuthorizedApplication> {
    match list
        .iter_mut()
        .find(|p| p.app_id.eq_ignore_ascii_case(client_app_id))
    {
        Some(existing) => existing.delegated_permission_ids = scope_ids,
        None => list.push(PreAuthorizedApplication {
            app_id: client_app_id.to_string(),
            delegated_permission_ids: scope_ids,
        }),
    }
    list
}

// ---------------- Commands ----------------

/// Reads the app's Expose-an-API state (Application ID URIs, defined scopes,
/// pre-authorized clients). A live read — these fields aren't on the cached
/// list shape, so the tab fetches them on demand.
#[tauri::command]
pub async fn get_expose_api(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<ExposeApiDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let info = fetch_expose_api(&client, &object_id).await?;
    Ok(ExposeApiDto {
        identifier_uris: info.identifier_uris,
        scopes: info.api.oauth2_permission_scopes,
        pre_authorized_applications: info.api.pre_authorized_applications,
    })
}

/// Full-replace write of the app's `identifierUris` (the Application ID URIs).
/// The editor loads the current list and sends the complete desired set.
#[tauri::command]
pub async fn set_identifier_uris(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    uris: Vec<String>,
) -> Result<(), UiError> {
    let uris: Vec<String> = uris.iter().map(|u| u.trim().to_string()).collect();
    for (i, uri) in uris.iter().enumerate() {
        validate_identifier_uri(uri)?;
        if uris[..i].iter().any(|u| u.eq_ignore_ascii_case(uri)) {
            return Err(UiError::validation(
                "duplicate_identifier_uri",
                format!("Application ID URI '{uri}' is listed twice."),
            ));
        }
    }
    let client = state.graph_for(&tenant_id);
    let body = ApplicationExposeApiPatch {
        identifier_uris: Some(uris),
        api: None,
    };
    client
        .patch_application_expose_api(&object_id, &body)
        .await?;
    // No cache invalidation: identifierUris isn't carried by any cached
    // payload (the typed Application / ServicePrincipal shapes omit it); the
    // tab and the SSO views re-read it live.
    Ok(())
}

/// Creates (`input.id = None`, GUID generated here) or updates one delegated
/// scope, then writes the full scope list back.
#[tauri::command]
pub async fn upsert_api_scope(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: UpsertApiScopeInput,
) -> Result<(), UiError> {
    validate_scope_input(&input)?;
    let client = state.graph_for(&tenant_id);
    let live = fetch_expose_api(&client, &object_id).await?;
    let is_edit = input.id.is_some();
    let scope = build_scope(&input, input.id.clone().unwrap_or_else(new_scope_guid));
    let scopes = merge_scope(live.api.oauth2_permission_scopes, scope, is_edit)?;
    let body = ApplicationExposeApiPatch {
        identifier_uris: None,
        api: Some(ApiApplicationPatch {
            oauth2_permission_scopes: Some(scopes),
            pre_authorized_applications: None,
        }),
    };
    client
        .patch_application_expose_api(&object_id, &body)
        .await?;
    // Entra mirrors the app's api scopes onto the paired SP's
    // oauth2PermissionScopes, which the cached detail payloads embed.
    invalidate_app_details(&state.cache, &tenant_id);
    Ok(())
}

/// Deletes one delegated scope, disabling it first when needed (Graph rejects
/// removing an enabled scope) and stripping it from pre-authorized clients.
/// Idempotent: a scope that's already gone is success. If the second PATCH
/// fails after the disable, the scope is left disabled — harmless; a retry
/// completes the removal.
#[tauri::command]
pub async fn delete_api_scope(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    scope_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let live = fetch_expose_api(&client, &object_id).await?;
    let Some(plan) = plan_scope_removal(&live.api, &scope_id) else {
        return Ok(());
    };
    if let Some(disabled) = plan.disable_first {
        let body = ApplicationExposeApiPatch {
            identifier_uris: None,
            api: Some(ApiApplicationPatch {
                oauth2_permission_scopes: Some(disabled),
                pre_authorized_applications: None,
            }),
        };
        client
            .patch_application_expose_api(&object_id, &body)
            .await?;
    }
    let body = ApplicationExposeApiPatch {
        identifier_uris: None,
        api: Some(ApiApplicationPatch {
            oauth2_permission_scopes: Some(plan.scopes),
            pre_authorized_applications: Some(plan.pre_authorized),
        }),
    };
    client
        .patch_application_expose_api(&object_id, &body)
        .await?;
    invalidate_app_details(&state.cache, &tenant_id);
    Ok(())
}

/// Adds or updates a pre-authorized client application: `scope_ids` is the
/// full set of this API's scopes the client may use without a consent prompt.
#[tauri::command]
pub async fn set_pre_authorized_app(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: SetPreAuthorizedAppInput,
) -> Result<(), UiError> {
    let client_app_id = input.client_app_id.trim().to_string();
    if !is_guid(&client_app_id) {
        return Err(UiError::validation(
            "invalid_client_app_id",
            "Client ID must be the application (client) ID GUID of the client app.",
        ));
    }
    let mut scope_ids = input.scope_ids;
    scope_ids.sort();
    scope_ids.dedup();
    if scope_ids.is_empty() {
        return Err(UiError::validation(
            "no_scopes_selected",
            "Select at least one scope to authorize.",
        ));
    }
    let client = state.graph_for(&tenant_id);
    let live = fetch_expose_api(&client, &object_id).await?;
    if let Some(unknown) = scope_ids.iter().find(|id| {
        !live
            .api
            .oauth2_permission_scopes
            .iter()
            .any(|s| &s.id == *id)
    }) {
        return Err(UiError::validation(
            "unknown_scope_id",
            format!("Scope {unknown} is not defined on this API; refresh and retry."),
        ));
    }
    let pre_authorized = upsert_pre_authorized(
        live.api.pre_authorized_applications,
        &client_app_id,
        scope_ids,
    );
    let body = ApplicationExposeApiPatch {
        identifier_uris: None,
        api: Some(ApiApplicationPatch {
            oauth2_permission_scopes: None,
            pre_authorized_applications: Some(pre_authorized),
        }),
    };
    client
        .patch_application_expose_api(&object_id, &body)
        .await?;
    Ok(())
}

/// Removes a pre-authorized client application. Idempotent: an entry that's
/// already gone is success.
#[tauri::command]
pub async fn remove_pre_authorized_app(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    client_app_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let live = fetch_expose_api(&client, &object_id).await?;
    let before = live.api.pre_authorized_applications.len();
    let pre_authorized: Vec<PreAuthorizedApplication> = live
        .api
        .pre_authorized_applications
        .into_iter()
        .filter(|p| !p.app_id.eq_ignore_ascii_case(&client_app_id))
        .collect();
    if pre_authorized.len() == before {
        return Ok(());
    }
    let body = ApplicationExposeApiPatch {
        identifier_uris: None,
        api: Some(ApiApplicationPatch {
            oauth2_permission_scopes: None,
            pre_authorized_applications: Some(pre_authorized),
        }),
    };
    client
        .patch_application_expose_api(&object_id, &body)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(id: &str, value: &str, enabled: Option<bool>) -> OAuth2PermissionScope {
        OAuth2PermissionScope {
            id: id.into(),
            value: value.into(),
            admin_consent_display_name: Some(format!("{value} (admin)")),
            admin_consent_description: Some(format!("Allows {value}.")),
            user_consent_display_name: None,
            user_consent_description: None,
            r#type: Some("User".into()),
            is_enabled: enabled,
        }
    }

    fn input(value: &str) -> UpsertApiScopeInput {
        UpsertApiScopeInput {
            id: None,
            value: value.into(),
            scope_type: "User".into(),
            admin_consent_display_name: "Read".into(),
            admin_consent_description: "Allows reading.".into(),
            user_consent_display_name: None,
            user_consent_description: None,
            is_enabled: true,
        }
    }

    #[test]
    fn new_scope_guid_is_v4_format() {
        let g = new_scope_guid();
        assert!(is_guid(&g), "not a GUID: {g}");
        assert_eq!(g.as_bytes()[14], b'4'); // version nibble
    }

    #[test]
    fn scope_input_validation_rejects_bad_fields() {
        assert!(validate_scope_input(&input("Files.Read")).is_ok());
        assert!(validate_scope_input(&input("")).is_err());
        assert!(validate_scope_input(&input("has space")).is_err());

        let mut bad_type = input("ok");
        bad_type.scope_type = "Both".into();
        assert!(validate_scope_input(&bad_type).is_err());

        let mut no_admin = input("ok");
        no_admin.admin_consent_description = "  ".into();
        assert!(validate_scope_input(&no_admin).is_err());
    }

    #[test]
    fn build_scope_trims_and_drops_empty_user_consent() {
        let mut i = input("  Files.Read  ");
        i.user_consent_display_name = Some("  ".into());
        i.user_consent_description = Some(" Read your files ".into());
        let s = build_scope(&i, "id-1".into());
        assert_eq!(s.value, "Files.Read");
        assert_eq!(s.user_consent_display_name, None);
        assert_eq!(
            s.user_consent_description.as_deref(),
            Some("Read your files")
        );
        assert_eq!(s.r#type.as_deref(), Some("User"));
        assert_eq!(s.is_enabled, Some(true));
    }

    #[test]
    fn merge_scope_appends_replaces_and_rejects_duplicates() {
        let existing = vec![scope("a", "Files.Read", Some(true))];

        // Append a new scope.
        let merged = merge_scope(
            existing.clone(),
            scope("b", "Files.Write", Some(true)),
            false,
        )
        .unwrap();
        assert_eq!(merged.len(), 2);

        // Replace by id keeps list length and applies the new fields.
        let merged = merge_scope(
            existing.clone(),
            scope("a", "Files.ReadAll", Some(false)),
            true,
        )
        .unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].value, "Files.ReadAll");

        // Duplicate value (other id, case-insensitive) is rejected.
        assert!(merge_scope(
            existing.clone(),
            scope("b", "files.read", Some(true)),
            false
        )
        .is_err());

        // Editing an id Graph no longer has is a not-found, not a silent append.
        assert!(merge_scope(existing, scope("gone", "New.Scope", Some(true)), true).is_err());
    }

    #[test]
    fn plan_scope_removal_disables_enabled_scopes_first() {
        let api = ApiApplication {
            oauth2_permission_scopes: vec![
                scope("a", "Files.Read", Some(true)),
                scope("b", "Files.Write", Some(true)),
            ],
            pre_authorized_applications: vec![],
        };
        let plan = plan_scope_removal(&api, "a").unwrap();
        let disabled = plan
            .disable_first
            .expect("enabled scope needs a disable pass");
        assert_eq!(
            disabled.iter().find(|s| s.id == "a").unwrap().is_enabled,
            Some(false)
        );
        assert_eq!(
            disabled.iter().find(|s| s.id == "b").unwrap().is_enabled,
            Some(true)
        );
        assert_eq!(plan.scopes.len(), 1);
        assert_eq!(plan.scopes[0].id, "b");

        // A missing isEnabled means enabled (Graph default) — still two-step.
        let api = ApiApplication {
            oauth2_permission_scopes: vec![scope("a", "Files.Read", None)],
            pre_authorized_applications: vec![],
        };
        assert!(plan_scope_removal(&api, "a")
            .unwrap()
            .disable_first
            .is_some());

        // An already-disabled scope removes in one PATCH.
        let api = ApiApplication {
            oauth2_permission_scopes: vec![scope("a", "Files.Read", Some(false))],
            pre_authorized_applications: vec![],
        };
        assert!(plan_scope_removal(&api, "a")
            .unwrap()
            .disable_first
            .is_none());

        // Already gone ⇒ nothing to do.
        assert!(plan_scope_removal(&api, "zz").is_none());
    }

    #[test]
    fn plan_scope_removal_strips_pre_authorized_clients() {
        let api = ApiApplication {
            oauth2_permission_scopes: vec![
                scope("a", "Files.Read", Some(false)),
                scope("b", "Files.Write", Some(false)),
            ],
            pre_authorized_applications: vec![
                PreAuthorizedApplication {
                    app_id: "client-1".into(),
                    delegated_permission_ids: vec!["a".into(), "b".into()],
                },
                PreAuthorizedApplication {
                    app_id: "client-2".into(),
                    delegated_permission_ids: vec!["a".into()],
                },
            ],
        };
        let plan = plan_scope_removal(&api, "a").unwrap();
        // client-1 keeps its remaining scope; client-2, authorized for nothing,
        // is dropped entirely.
        assert_eq!(plan.pre_authorized.len(), 1);
        assert_eq!(plan.pre_authorized[0].app_id, "client-1");
        assert_eq!(
            plan.pre_authorized[0].delegated_permission_ids,
            vec!["b".to_string()]
        );
    }

    #[test]
    fn upsert_pre_authorized_replaces_or_appends() {
        let list = vec![PreAuthorizedApplication {
            app_id: "AAAA".into(),
            delegated_permission_ids: vec!["a".into()],
        }];
        // Same client (case-insensitive appId) ⇒ replace the scope set.
        let updated = upsert_pre_authorized(list.clone(), "aaaa", vec!["b".into()]);
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].delegated_permission_ids, vec!["b".to_string()]);
        // New client ⇒ append.
        let updated = upsert_pre_authorized(list, "BBBB", vec!["a".into()]);
        assert_eq!(updated.len(), 2);
    }

    #[test]
    fn identifier_uri_validation() {
        assert!(validate_identifier_uri("api://1234").is_ok());
        assert!(validate_identifier_uri("https://contoso.com/api").is_ok());
        assert!(validate_identifier_uri("").is_err());
        assert!(validate_identifier_uri("api://has space").is_err());
        assert!(validate_identifier_uri("no-scheme").is_err());
    }
}
