//! Application-management IPC DTOs.

use azapptoolkit_core::audit::ListCredentialStatus;
use azapptoolkit_core::models::{
    AppRoleAssignment, Application, DirectoryObject, OAuth2PermissionGrant, PasswordCredential,
    ServicePrincipal,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::permissions::ResolvedPermission;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationDetail {
    pub application: Application,
    pub service_principal: Option<ServicePrincipal>,
    pub owners: Vec<DirectoryObject>,
    pub app_role_assignments: Vec<AppRoleAssignment>,
    pub oauth2_permission_grants: Vec<OAuth2PermissionGrant>,
    /// `required_resource_access` resolved against the bundled permissions
    /// catalog (and, on miss, live `/servicePrincipals(appId=...)` lookups).
    /// Same length / order as `application.required_resource_access`,
    /// flattened: one entry per `(resource, permission)` pair.
    #[serde(default)]
    pub resolved_permissions: Vec<ResolvedPermission>,
}

/// Lean App Registrations list row, flattened to the scalars the list and the
/// inventory export actually render, plus the paired Enterprise App SP id
/// (when one exists in this tenant). The credential arrays deliberately do
/// **not** cross IPC — at thousands of rows they dominate the payload — so
/// their list-relevant aspects arrive pre-computed (`credential_status`,
/// per-kind counts, soonest expiry) and the detail pane re-fetches the full
/// [`Application`]. Returned by `list_applications_with_pairing`; the original
/// `list_applications` shape is unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationListRowDto {
    pub id: String,
    pub app_id: String,
    pub display_name: String,
    pub sign_in_audience: Option<String>,
    pub publisher_domain: Option<String>,
    pub created_date_time: Option<DateTime<Utc>>,
    pub password_credential_count: usize,
    pub key_credential_count: usize,
    /// Soonest end date across secrets + certs (the export's expiry column).
    pub soonest_credential_expiry: Option<DateTime<Utc>>,
    pub credential_status: ListCredentialStatus,
    pub paired_service_principal_id: Option<String>,
}

impl ApplicationListRowDto {
    /// Flattens a Graph [`Application`] into the list row, classifying its
    /// credentials at `now` (injectable so the classification is testable).
    pub fn from_application(
        app: Application,
        paired_service_principal_id: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        let credential_status =
            ListCredentialStatus::classify(&app.password_credentials, &app.key_credentials, now);
        let soonest_credential_expiry = app
            .password_credentials
            .iter()
            .filter_map(|c| c.end_date_time)
            .chain(app.key_credentials.iter().filter_map(|c| c.end_date_time))
            .min();
        Self {
            id: app.id,
            app_id: app.app_id,
            display_name: app.display_name,
            sign_in_audience: app.sign_in_audience,
            publisher_domain: app.publisher_domain,
            created_date_time: app.created_date_time,
            password_credential_count: app.password_credentials.len(),
            key_credential_count: app.key_credentials.len(),
            soonest_credential_expiry,
            credential_status,
            paired_service_principal_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDescriptor {
    pub display_name: String,
    pub kind: String,
    pub resource_display_name: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApplicationInput {
    pub display_name: String,
    pub sign_in_audience: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub create_service_principal: bool,
    #[serde(default)]
    pub initial_owner_ids: Vec<String>,
    pub initial_secret_display_name: Option<String>,
    /// When `initial_secret_display_name` is set, create a secret valid for
    /// this many days. Defaults to 180 on the caller side when omitted.
    pub initial_secret_lifetime_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApplicationResult {
    pub application: Application,
    pub service_principal: Option<ServicePrincipal>,
    pub initial_secret: Option<PasswordCredential>,
    pub added_owner_ids: Vec<String>,
    #[serde(default)]
    pub failed_owner_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApplicationInput {
    pub display_name: Option<String>,
    pub sign_in_audience: Option<String>,
    pub description: Option<String>,
}

/// Current Authentication-tab settings for an app registration: per-platform
/// reply (redirect) URLs, the optional front-channel logout URL, the implicit-
/// grant flags, and the fallback-public-client flag. Returned by
/// `get_application_authentication`, which reads `web`/`spa`/`publicClient` —
/// none of which are on the list-shape [`Application`] — and accepted back by
/// `set_application_authentication` as its full-replace input (each list
/// replaces that platform's set wholesale, so the editor loads current values
/// before saving). One type for both directions so get/set can't drift.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationAuthenticationDto {
    pub web_redirect_uris: Vec<String>,
    pub spa_redirect_uris: Vec<String>,
    pub public_client_redirect_uris: Vec<String>,
    pub logout_url: Option<String>,
    pub is_fallback_public_client: bool,
    pub enable_access_token_issuance: bool,
    pub enable_id_token_issuance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPasswordInput {
    pub display_name: String,
    /// Lifetime from "now" — used by the preset Expires options. Ignored when
    /// `end_date_time` is set.
    pub lifetime_days: Option<u32>,
    /// Explicit validity window (portal "Custom" expiry). `end_date_time`
    /// takes precedence over `lifetime_days`; `start_date_time` may schedule a
    /// not-yet-valid secret. Capped at 24 months backend-side.
    #[serde(default)]
    pub start_date_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub end_date_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCertificateInput {
    pub display_name: String,
    pub pem_or_base64: String,
    pub end_date_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// A federated identity credential (workload identity federation) on an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedCredentialDto {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub subject: String,
    pub description: Option<String>,
    pub audiences: Vec<String>,
}

/// Input for creating a federated identity credential. `audiences` defaults to
/// `api://AzureADTokenExchange` server-side when absent or empty; only the
/// "Other issuer" flow sends an override.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFederatedCredentialInput {
    pub name: String,
    pub issuer: String,
    pub subject: String,
    pub description: Option<String>,
    #[serde(default)]
    pub audiences: Option<Vec<String>>,
}

/// Input for updating an existing federated identity credential. `name` is
/// immutable in Graph, so it is deliberately absent. `audiences` follows the
/// same default rule as [`AddFederatedCredentialInput`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFederatedCredentialInput {
    pub issuer: String,
    pub subject: String,
    pub description: Option<String>,
    #[serde(default)]
    pub audiences: Option<Vec<String>>,
}

/// Input for generating a self-signed certificate and attaching its public
/// part to an application as a key credential.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateCertificateInput {
    pub object_id: String,
    /// Subject common name; defaults to the app display name in the UI.
    pub subject: String,
    /// Certificate validity in days (default 365, clamped 1..=1095).
    pub validity_days: Option<u32>,
}

/// Result of generating a self-signed certificate. `private_key_pem` is
/// sensitive — shown once and never persisted by the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedCertificateResult {
    pub thumbprint: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    /// RFC3339 certificate expiry.
    pub expires: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFailure {
    pub key_id: String,
    pub message: String,
}

/// One owner add/remove that failed while applying a replace-all-owners
/// operation. `action` is `"add"` or `"remove"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerChangeFailure {
    pub principal_id: String,
    pub action: String,
    pub message: String,
}

/// Result of `set_application_owners`: the owner set was reconciled to exactly
/// the requested principals. Partial failures are surfaced rather than aborting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetOwnersResult {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub failures: Vec<OwnerChangeFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveExpiredResult {
    pub removed_key_ids: Vec<String>,
    pub failures: Vec<KeyFailure>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::KeyCredential;

    #[test]
    fn list_row_flattens_application_and_classifies_credentials() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let app = Application {
            id: "obj-1".into(),
            app_id: "app-1".into(),
            display_name: "Demo".into(),
            sign_in_audience: Some("AzureADMyOrg".into()),
            created_date_time: Some(now - chrono::Duration::days(10)),
            password_credentials: vec![PasswordCredential {
                end_date_time: Some(now + chrono::Duration::days(60)),
                ..Default::default()
            }],
            key_credentials: vec![KeyCredential {
                end_date_time: Some(now + chrono::Duration::days(7)),
                ..Default::default()
            }],
            ..Default::default()
        };
        let row = ApplicationListRowDto::from_application(app, Some("sp-1".into()), now);
        assert_eq!(row.id, "obj-1");
        assert_eq!(row.password_credential_count, 1);
        assert_eq!(row.key_credential_count, 1);
        // The cert (7d) is the soonest expiry; the 60d secret keeps it Active.
        assert_eq!(
            row.soonest_credential_expiry,
            Some(now + chrono::Duration::days(7))
        );
        assert_eq!(row.credential_status, ListCredentialStatus::Active);
        assert_eq!(row.paired_service_principal_id.as_deref(), Some("sp-1"));

        // Round trip; row DTOs stay snake_case (no rename_all), status lowercase.
        let json = serde_json::to_value(&row).unwrap();
        assert!(json.get("credential_status").is_some());
        assert_eq!(json["credential_status"], "active");
        assert!(json.get("password_credential_count").is_some());
        let back: ApplicationListRowDto = serde_json::from_value(json).unwrap();
        assert_eq!(back, row);
    }

    #[test]
    fn create_application_input_uses_camel_case_and_defaults() {
        let input = CreateApplicationInput {
            display_name: "TestApp".into(),
            sign_in_audience: Some("AzureADMyOrg".into()),
            description: None,
            create_service_principal: true,
            initial_owner_ids: vec!["owner-1".into()],
            initial_secret_display_name: Some("MySecret".into()),
            initial_secret_lifetime_days: Some(90),
        };
        let json = serde_json::to_value(&input).unwrap();
        for key in [
            "displayName",
            "signInAudience",
            "createServicePrincipal",
            "initialOwnerIds",
            "initialSecretDisplayName",
            "initialSecretLifetimeDays",
        ] {
            assert!(json.get(key).is_some(), "missing camelCase key {key}");
        }
        let back: CreateApplicationInput = serde_json::from_value(json).unwrap();
        assert_eq!(back.display_name, "TestApp");
        assert!(back.create_service_principal);
        assert_eq!(back.initial_secret_lifetime_days, Some(90));

        // create_service_principal + initial_owner_ids carry #[serde(default)],
        // so the minimal Tauri payload (just displayName) deserializes.
        let minimal: CreateApplicationInput =
            serde_json::from_str(r#"{"displayName":"Only"}"#).unwrap();
        assert_eq!(minimal.display_name, "Only");
        assert!(!minimal.create_service_principal);
        assert!(minimal.initial_owner_ids.is_empty());
    }

    #[test]
    fn set_application_authentication_input_uses_camel_case_and_round_trips() {
        let input = ApplicationAuthenticationDto {
            web_redirect_uris: vec!["https://app/cb".into()],
            spa_redirect_uris: vec!["https://app/spa".into()],
            public_client_redirect_uris: vec!["http://localhost".into()],
            logout_url: Some("https://app/logout".into()),
            is_fallback_public_client: true,
            enable_access_token_issuance: false,
            enable_id_token_issuance: true,
        };
        let json = serde_json::to_value(&input).unwrap();
        for key in [
            "webRedirectUris",
            "spaRedirectUris",
            "publicClientRedirectUris",
            "logoutUrl",
            "isFallbackPublicClient",
            "enableAccessTokenIssuance",
            "enableIdTokenIssuance",
        ] {
            assert!(json.get(key).is_some(), "missing camelCase key {key}");
        }
        let back: ApplicationAuthenticationDto = serde_json::from_value(json).unwrap();
        assert_eq!(back.web_redirect_uris, vec!["https://app/cb".to_string()]);
        assert!(back.is_fallback_public_client);
        assert!(back.enable_id_token_issuance);
        assert!(!back.enable_access_token_issuance);
    }

    #[test]
    fn add_password_input_window_fields_are_optional_and_camel_case() {
        // Pre-window payloads (no start/end keys) must still deserialize.
        let legacy: AddPasswordInput =
            serde_json::from_value(serde_json::json!({ "displayName": "s", "lifetimeDays": 90 }))
                .unwrap();
        assert_eq!(legacy.lifetime_days, Some(90));
        assert!(legacy.start_date_time.is_none() && legacy.end_date_time.is_none());

        let input = AddPasswordInput {
            display_name: "s".into(),
            lifetime_days: None,
            start_date_time: Some(
                chrono::DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            end_date_time: Some(
                chrono::DateTime::parse_from_rfc3339("2027-07-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
        };
        let json = serde_json::to_value(&input).unwrap();
        assert!(json.get("startDateTime").is_some() && json.get("endDateTime").is_some());
        let back: AddPasswordInput = serde_json::from_value(json).unwrap();
        assert_eq!(back.end_date_time, input.end_date_time);
    }

    #[test]
    fn federated_credential_inputs_default_audiences_and_round_trip() {
        // Pre-audiences payloads must still deserialize (None → server default).
        let legacy: AddFederatedCredentialInput = serde_json::from_value(serde_json::json!({
            "name": "n", "issuer": "i", "subject": "s", "description": null
        }))
        .unwrap();
        assert!(legacy.audiences.is_none());

        let update = UpdateFederatedCredentialInput {
            issuer: "https://accounts.google.com".into(),
            subject: "112633961854638529490".into(),
            description: Some("gcp".into()),
            audiences: Some(vec!["api://AzureADTokenExchange".into()]),
        };
        let json = serde_json::to_value(&update).unwrap();
        assert!(
            json.get("name").is_none(),
            "update input must not carry name"
        );
        let back: UpdateFederatedCredentialInput = serde_json::from_value(json).unwrap();
        assert_eq!(back.audiences, update.audiences);
        assert_eq!(back.subject, update.subject);
    }
}
