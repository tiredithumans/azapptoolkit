use tauri::State;

use azapptoolkit_graph::client::{
    ApplicationAuthenticationPatch, ApplicationPublicClientPatch, ApplicationSpaPatch,
    ApplicationWebPatch, ImplicitGrantSettingsPatch,
};

use crate::dto::applications::{ApplicationAuthenticationDto, SetApplicationAuthenticationInput};
use crate::dto::UiError;
use crate::state::AppState;

use super::invalidate_app_detail_state;

/// Reads the app's Authentication-tab settings (per-platform reply URLs, logout
/// URL, implicit-grant flags, fallback-public-client flag). A live read — these
/// fields aren't on the cached list shape, so the tab fetches them on demand.
#[tauri::command]
pub async fn get_application_authentication(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<ApplicationAuthenticationDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let raw = client
        .get_application_auth_fields(&object_id)
        .await?
        .ok_or_else(|| UiError::not_found("application", "application not found"))?;
    Ok(extract_auth_fields(&raw))
}

/// Flattens the raw `/applications/{id}` JSON (the
/// `web`/`spa`/`publicClient`/`isFallbackPublicClient` projection) into the
/// Authentication DTO. A missing block ⇒ empty list / `false` / `None`.
pub(crate) fn extract_auth_fields(v: &serde_json::Value) -> ApplicationAuthenticationDto {
    let uris = |parent: &str| -> Vec<String> {
        v.get(parent)
            .and_then(|p| p.get("redirectUris"))
            .and_then(|u| u.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let web = v.get("web");
    let logout_url = web
        .and_then(|w| w.get("logoutUrl"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let implicit = web.and_then(|w| w.get("implicitGrantSettings"));
    let flag = |obj: Option<&serde_json::Value>, key: &str| -> bool {
        obj.and_then(|o| o.get(key))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };
    ApplicationAuthenticationDto {
        web_redirect_uris: uris("web"),
        spa_redirect_uris: uris("spa"),
        public_client_redirect_uris: uris("publicClient"),
        logout_url,
        is_fallback_public_client: flag(Some(v), "isFallbackPublicClient"),
        enable_access_token_issuance: flag(implicit, "enableAccessTokenIssuance"),
        enable_id_token_issuance: flag(implicit, "enableIdTokenIssuance"),
    }
}

/// Writes the app's Authentication-tab settings. Each redirect-URI list is a
/// full replace of that platform's set (an empty list clears it), so the editor
/// loads current values before saving. All URIs are validated (reusing the SSO
/// redirect rules — no wildcards, https or loopback-http or custom schemes only)
/// before the PATCH. On success the app-detail cache is busted, and the audit
/// cache too (the public-client / implicit-grant flags feed audit rules).
#[tauri::command]
pub async fn set_application_authentication(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: SetApplicationAuthenticationInput,
) -> Result<(), UiError> {
    for set in [
        &input.web_redirect_uris,
        &input.spa_redirect_uris,
        &input.public_client_redirect_uris,
    ] {
        azapptoolkit_core::redirect::validate_redirect_uris(set)
            .map_err(|e| UiError::validation("invalid_redirect_uri", e))?;
    }
    let client = state.graph_for(&tenant_id);
    let body = ApplicationAuthenticationPatch {
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(input.web_redirect_uris),
            // Full-replace: an empty string clears the front-channel logout URL.
            logout_url: Some(input.logout_url.unwrap_or_default()),
            implicit_grant_settings: Some(ImplicitGrantSettingsPatch {
                enable_access_token_issuance: Some(input.enable_access_token_issuance),
                enable_id_token_issuance: Some(input.enable_id_token_issuance),
            }),
        }),
        spa: Some(ApplicationSpaPatch {
            redirect_uris: Some(input.spa_redirect_uris),
        }),
        public_client: Some(ApplicationPublicClientPatch {
            redirect_uris: Some(input.public_client_redirect_uris),
        }),
        is_fallback_public_client: Some(input.is_fallback_public_client),
    };
    client.patch_application_web(&object_id, &body).await?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

#[cfg(test)]
mod auth_fields_tests {
    use super::extract_auth_fields;

    #[test]
    fn extracts_all_blocks() {
        let v = serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "isFallbackPublicClient": true,
            "web": {
                "redirectUris": ["https://app/cb", "https://app/cb2"],
                "logoutUrl": "https://app/logout",
                "implicitGrantSettings": {
                    "enableAccessTokenIssuance": true,
                    "enableIdTokenIssuance": false
                }
            },
            "spa": { "redirectUris": ["https://app/spa"] },
            "publicClient": { "redirectUris": ["http://localhost"] }
        });
        let dto = extract_auth_fields(&v);
        assert_eq!(dto.web_redirect_uris, ["https://app/cb", "https://app/cb2"]);
        assert_eq!(dto.spa_redirect_uris, ["https://app/spa"]);
        assert_eq!(dto.public_client_redirect_uris, ["http://localhost"]);
        assert_eq!(dto.logout_url.as_deref(), Some("https://app/logout"));
        assert!(dto.is_fallback_public_client);
        assert!(dto.enable_access_token_issuance);
        assert!(!dto.enable_id_token_issuance);
    }

    #[test]
    fn missing_blocks_default_empty() {
        // A bare app (no web/spa/publicClient) ⇒ empty lists, false flags, no logout.
        let dto = extract_auth_fields(&serde_json::json!({ "id": "obj-1", "appId": "app-1" }));
        assert!(dto.web_redirect_uris.is_empty());
        assert!(dto.spa_redirect_uris.is_empty());
        assert!(dto.public_client_redirect_uris.is_empty());
        assert!(dto.logout_url.is_none());
        assert!(!dto.is_fallback_public_client);
        assert!(!dto.enable_access_token_issuance);
        assert!(!dto.enable_id_token_issuance);
    }

    #[test]
    fn empty_logout_url_becomes_none() {
        let v = serde_json::json!({ "web": { "logoutUrl": "" } });
        assert!(extract_auth_fields(&v).logout_url.is_none());
    }
}
