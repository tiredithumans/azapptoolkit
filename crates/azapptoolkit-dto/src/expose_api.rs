//! "Expose an API" IPC DTOs: the app's identifier URIs, the delegated scopes
//! it defines, and the pre-authorized client applications — the portal's
//! "Expose an API" blade.

use azapptoolkit_core::models::{OAuth2PermissionScope, PreAuthorizedApplication};
use serde::{Deserialize, Serialize};

/// Current Expose-an-API state for an app registration. Returned by
/// `get_expose_api` — a live read, like the SSO / Authentication tabs: these
/// fields aren't on the cached list shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposeApiDto {
    pub identifier_uris: Vec<String>,
    pub scopes: Vec<OAuth2PermissionScope>,
    pub pre_authorized_applications: Vec<PreAuthorizedApplication>,
    /// Display name per pre-authorized client, keyed by lowercased appId,
    /// resolved from the tenant SP index. Best-effort: a client with no
    /// service principal in this tenant — or an index that couldn't be read —
    /// is absent, and the row shows the bare application id.
    #[serde(default)]
    pub client_display_names: std::collections::BTreeMap<String, String>,
}

/// Create or update one delegated scope via `upsert_api_scope`. `id: None` ⇒
/// create (the backend generates the scope GUID, like the portal);
/// `Some` ⇒ replace the matching scope's fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertApiScopeInput {
    pub id: Option<String>,
    /// Scope name as it appears in tokens (`scp` claim), e.g. `Files.Read`.
    pub value: String,
    /// Who can consent — Graph's `permissionScope.type`: `"Admin"` (admins
    /// only) or `"User"` (admins and users).
    pub scope_type: String,
    pub admin_consent_display_name: String,
    pub admin_consent_description: String,
    pub user_consent_display_name: Option<String>,
    pub user_consent_description: Option<String>,
    pub is_enabled: bool,
}

/// Add or update a pre-authorized client via `set_pre_authorized_app`:
/// `scope_ids` is the **full** set of this API's scope ids the client may use
/// (a replace, not a merge).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPreAuthorizedAppInput {
    pub client_app_id: String,
    pub scope_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `clientDisplayNames` is additive: a payload without it (an older
    /// backend, a fixture) still deserializes, to an empty map.
    #[test]
    fn expose_api_dto_client_names_are_additive() {
        let json = serde_json::json!({
            "identifierUris": ["api://a"],
            "scopes": [],
            "preAuthorizedApplications": [],
        });
        let dto: ExposeApiDto = serde_json::from_value(json).unwrap();
        assert!(dto.client_display_names.is_empty());

        let mut dto = ExposeApiDto::default();
        dto.client_display_names
            .insert("aaaa".into(), "Contoso Portal".into());
        let back = serde_json::to_value(&dto).unwrap();
        assert_eq!(back["clientDisplayNames"]["aaaa"], "Contoso Portal");
    }

    /// The bindings serialize inputs camelCase (Tauri's JS-side convention);
    /// pin the wire shape so a field rename can't silently break the IPC.
    #[test]
    fn upsert_scope_input_wire_shape_is_camel_case() {
        let json = serde_json::json!({
            "id": null,
            "value": "Files.Read",
            "scopeType": "User",
            "adminConsentDisplayName": "Read files",
            "adminConsentDescription": "Allows reading files.",
            "userConsentDisplayName": null,
            "userConsentDescription": null,
            "isEnabled": true,
        });
        let input: UpsertApiScopeInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.value, "Files.Read");
        assert_eq!(input.scope_type, "User");
        assert!(input.is_enabled);
        assert!(input.id.is_none());

        let back = serde_json::to_value(&input).unwrap();
        assert_eq!(back["adminConsentDisplayName"], "Read files");
        assert_eq!(back["isEnabled"], true);
    }
}
