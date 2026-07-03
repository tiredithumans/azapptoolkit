// Pure serde-shape guards: no mock server, so only the patch/request types
// (re-exported from the client module) are needed.
use super::super::*;

#[test]
fn federated_credential_request_serializes_to_graph_shape() {
    let req = FederatedCredentialRequest {
        name: "gh-actions".into(),
        issuer: "https://token.actions.githubusercontent.com".into(),
        subject: "repo:org/app:ref:refs/heads/main".into(),
        audiences: vec!["api://AzureADTokenExchange".into()],
        description: None,
    };
    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        serde_json::json!({
            "name": "gh-actions",
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": "repo:org/app:ref:refs/heads/main",
            "audiences": ["api://AzureADTokenExchange"],
            // description is sent as null when absent (not omitted), matching the
            // body the command originally hand-built.
            "description": null,
        })
    );
}

#[test]
fn federated_credential_patch_serializes_without_name() {
    let patch = FederatedCredentialPatch {
        issuer: "https://token.actions.githubusercontent.com".into(),
        subject: "repo:org/app:pull_request".into(),
        audiences: vec!["api://AzureADTokenExchange".into()],
        description: None,
    };
    assert_eq!(
        serde_json::to_value(&patch).unwrap(),
        serde_json::json!({
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": "repo:org/app:pull_request",
            "audiences": ["api://AzureADTokenExchange"],
            // null clears a previously-set description; `name` must never
            // appear — Graph rejects patches that touch it.
            "description": null,
        })
    );
}

#[test]
fn service_principal_patches_use_camel_case() {
    assert_eq!(
        serde_json::to_value(ServicePrincipalSsoModePatch {
            preferred_single_sign_on_mode: "saml".into(),
        })
        .unwrap(),
        serde_json::json!({ "preferredSingleSignOnMode": "saml" })
    );
    assert_eq!(
        serde_json::to_value(ServicePrincipalSigningKeyPatch {
            preferred_token_signing_key_thumbprint: "ABC123".into(),
        })
        .unwrap(),
        serde_json::json!({ "preferredTokenSigningKeyThumbprint": "ABC123" })
    );
}

#[test]
fn application_sso_patch_matches_saml_body_and_skips_unset() {
    // SAML: identifierUris + web (with logoutUrl), no spa.
    let saml = ApplicationSsoPatch {
        identifier_uris: Some(vec!["https://app/saml".into()]),
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(vec!["https://app/acs".into()]),
            logout_url: Some("https://app/logout".into()),
            implicit_grant_settings: None,
        }),
        spa: None,
    };
    assert_eq!(
        serde_json::to_value(&saml).unwrap(),
        serde_json::json!({
            "identifierUris": ["https://app/saml"],
            "web": { "redirectUris": ["https://app/acs"], "logoutUrl": "https://app/logout" },
        })
    );

    // OIDC web+spa replacement: no identifierUris, no logoutUrl.
    let oidc = ApplicationSsoPatch {
        identifier_uris: None,
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(vec!["https://app/cb".into()]),
            logout_url: None,
            implicit_grant_settings: None,
        }),
        spa: Some(ApplicationSpaPatch {
            redirect_uris: Some(vec!["https://app/spa".into()]),
        }),
    };
    assert_eq!(
        serde_json::to_value(&oidc).unwrap(),
        serde_json::json!({
            "web": { "redirectUris": ["https://app/cb"] },
            "spa": { "redirectUris": ["https://app/spa"] },
        })
    );
}

#[test]
fn application_authentication_patch_nests_implicit_grant_and_skips_unset() {
    // A full save: web (reply URLs + logout + implicit grant), spa, public
    // client, and the fallback-public-client flag. implicitGrantSettings must
    // nest under `web`, not appear at the top level.
    let full = ApplicationAuthenticationPatch {
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(vec!["https://app/cb".into()]),
            logout_url: Some("https://app/logout".into()),
            implicit_grant_settings: Some(ImplicitGrantSettingsPatch {
                enable_access_token_issuance: Some(false),
                enable_id_token_issuance: Some(true),
            }),
        }),
        spa: Some(ApplicationSpaPatch {
            redirect_uris: Some(vec!["https://app/spa".into()]),
        }),
        public_client: Some(ApplicationPublicClientPatch {
            redirect_uris: Some(vec!["http://localhost".into()]),
        }),
        is_fallback_public_client: Some(true),
    };
    assert_eq!(
        serde_json::to_value(&full).unwrap(),
        serde_json::json!({
            "web": {
                "redirectUris": ["https://app/cb"],
                "logoutUrl": "https://app/logout",
                "implicitGrantSettings": {
                    "enableAccessTokenIssuance": false,
                    "enableIdTokenIssuance": true,
                },
            },
            "spa": { "redirectUris": ["https://app/spa"] },
            "publicClient": { "redirectUris": ["http://localhost"] },
            "isFallbackPublicClient": true,
        })
    );

    // An all-default patch serializes to an empty object: every field is
    // skip_serializing_if = Option::is_none, so a no-op save sends nothing.
    assert_eq!(
        serde_json::to_value(ApplicationAuthenticationPatch::default()).unwrap(),
        serde_json::json!({})
    );
}

#[test]
fn expose_api_patch_uses_camel_case_and_skips_unset() {
    // A scopes-only patch must not touch identifierUris or the pre-authorized
    // list (Graph full-replaces every array it receives).
    let scopes_only = ApplicationExposeApiPatch {
        identifier_uris: None,
        api: Some(ApiApplicationPatch {
            oauth2_permission_scopes: Some(vec![OAuth2PermissionScope {
                id: "11111111-1111-1111-1111-111111111111".into(),
                value: "Files.Read".into(),
                admin_consent_display_name: Some("Read files".into()),
                admin_consent_description: Some("Allows reading files.".into()),
                user_consent_display_name: None,
                user_consent_description: None,
                r#type: Some("User".into()),
                is_enabled: Some(true),
            }]),
            pre_authorized_applications: None,
        }),
    };
    assert_eq!(
        serde_json::to_value(&scopes_only).unwrap(),
        serde_json::json!({
            "api": {
                "oauth2PermissionScopes": [{
                    "id": "11111111-1111-1111-1111-111111111111",
                    "value": "Files.Read",
                    "adminConsentDisplayName": "Read files",
                    "adminConsentDescription": "Allows reading files.",
                    "userConsentDisplayName": null,
                    "userConsentDescription": null,
                    "type": "User",
                    "isEnabled": true,
                }],
            },
        })
    );

    // URIs-only patch leaves the whole api block untouched.
    let uris_only = ApplicationExposeApiPatch {
        identifier_uris: Some(vec!["api://app-1".into()]),
        api: None,
    };
    assert_eq!(
        serde_json::to_value(&uris_only).unwrap(),
        serde_json::json!({ "identifierUris": ["api://app-1"] })
    );

    // Pre-authorized clients serialize with camelCase delegatedPermissionIds.
    let pre_only = ApplicationExposeApiPatch {
        identifier_uris: None,
        api: Some(ApiApplicationPatch {
            oauth2_permission_scopes: None,
            pre_authorized_applications: Some(vec![PreAuthorizedApplication {
                app_id: "22222222-2222-2222-2222-222222222222".into(),
                delegated_permission_ids: vec!["11111111-1111-1111-1111-111111111111".into()],
            }]),
        }),
    };
    assert_eq!(
        serde_json::to_value(&pre_only).unwrap(),
        serde_json::json!({
            "api": {
                "preAuthorizedApplications": [{
                    "appId": "22222222-2222-2222-2222-222222222222",
                    "delegatedPermissionIds": ["11111111-1111-1111-1111-111111111111"],
                }],
            },
        })
    );
}

#[test]
fn application_expose_api_deserializes_tolerantly() {
    // Graph can return a null api block / null arrays on older objects; the
    // projection must default them rather than fail the whole tab.
    let v: ApplicationExposeApi = serde_json::from_value(serde_json::json!({
        "id": "obj-1",
        "appId": "app-1",
        "identifierUris": null,
        "api": null,
    }))
    .unwrap();
    assert!(v.identifier_uris.is_empty());
    assert!(v.api.oauth2_permission_scopes.is_empty());

    let v: ApplicationExposeApi = serde_json::from_value(serde_json::json!({
        "id": "obj-1",
        "appId": "app-1",
        "identifierUris": ["api://app-1"],
        "api": {
            "oauth2PermissionScopes": [{
                "id": "s-1",
                "value": "Files.Read",
                "type": "Admin",
                "isEnabled": true,
            }],
            "preAuthorizedApplications": [{
                "appId": "client-1",
                "delegatedPermissionIds": ["s-1"],
            }],
        },
    }))
    .unwrap();
    assert_eq!(v.identifier_uris, vec!["api://app-1".to_string()]);
    assert_eq!(
        v.api.oauth2_permission_scopes[0].r#type.as_deref(),
        Some("Admin")
    );
    assert_eq!(
        v.api.pre_authorized_applications[0].delegated_permission_ids,
        vec!["s-1".to_string()]
    );
}
