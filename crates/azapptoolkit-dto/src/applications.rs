//! Application-management IPC DTOs.

use azapptoolkit_core::audit::ListCredentialStatus;
use azapptoolkit_core::models::{
    AppRoleAssignment, Application, DirectoryObject, OAuth2PermissionGrant, PasswordCredential,
    ServicePrincipal,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::permissions::ResolvedPermission;

/// Safety cap on apps materialized by a tenant-wide enumeration; well above
/// real-world app-registration counts.
///
/// Shared by every tenant-wide enumeration so the caps can't drift: the browse
/// list, the Enterprise Apps pairing join, the audit, the credential sweep and
/// the backup must all reach the same depth, or one view silently knows about
/// apps another does not. (The Enterprise Apps join previously capped at 5000
/// and dropped pairings the App Registrations list had.) Defined here rather
/// than in the backend so the frontend's cap notice reads the same constant.
pub const APPS_MAX: usize = 10_000;

/// Coverage of the shared per-tenant service-principal index, for the surfaces
/// that render a filtered *subset* of it.
///
/// The App Registrations list can detect its own truncation (`total >=
/// APPS_MAX`) because its rows ARE the capped set. The Enterprise Applications
/// and Managed Identities lists cannot — both filter the SP index down
/// (dropping / keeping only managed identities) — so their row counts sit
/// below the cap even on a tenant whose index truncated, and a `len() >= cap`
/// check would never fire. They ask this instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryIndexStatus {
    /// The SP index hit its row cap, so every surface reading it covers only
    /// the first `sp_index_cap` service principals (the graph client's
    /// `SP_INDEX_MAX`).
    pub sp_index_truncated: bool,
    /// The cap itself, so the notice can name the number without the frontend
    /// keeping its own copy in sync.
    pub sp_index_cap: usize,
}

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
    /// `true` when a declared resource's service principal couldn't be read
    /// (throttling / a transient Graph error): that resource's rows carry no
    /// runtime grant ids and read as "Not granted" whether or not they are.
    /// Such a detail is never cached. `false` on payloads cached before the
    /// field existed.
    #[serde(default)]
    pub resolution_degraded: bool,
}

/// Lean App Registrations list row, flattened to the scalars the list and the
/// inventory export render, plus the paired Enterprise App SP id. The
/// credential arrays deliberately do **not** cross IPC — at thousands of rows
/// they dominate the payload — so their list-relevant aspects arrive
/// pre-computed (`credential_status`, per-kind counts, soonest expiry) and the
/// detail pane re-fetches the full [`Application`]. Returned by
/// `list_applications_with_pairing`; the original `list_applications` shape is
/// unchanged.
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

    /// Holds at least one client secret. The one predicate behind Home's
    /// "With secrets" count and the list's matching filter chip, so the count
    /// you click and the rows you land on can't disagree.
    pub fn has_secrets(&self) -> bool {
        self.password_credential_count > 0
    }

    /// Holds at least one certificate — the "With certs" count and chip.
    pub fn has_certs(&self) -> bool {
        self.key_credential_count > 0
    }
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
    /// this many days. Defaults to 180; clamped to `1..=730` like
    /// `add_password`.
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
    /// Free-text internal notes. `Some("")` clears; `None` leaves it untouched.
    pub notes: Option<String>,
}

/// Authentication-tab settings for an app registration: per-platform reply
/// (redirect) URLs, the front-channel logout URL, the implicit-grant flags,
/// and the fallback-public-client flag. `get_application_authentication`
/// returns it (reading `web`/`spa`/`publicClient` — none of which are on the
/// list-shape [`Application`]) and `set_application_authentication` accepts it
/// back as its full-replace input (each list replaces that platform's set
/// wholesale, so the editor loads current values before saving). One type for
/// both directions so get/set can't drift.
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
///
/// `subject` is `None` for a flexible (claims-matching expression) credential,
/// which has no subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedCredentialDto {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub subject: Option<String>,
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

/// What `add_certificate_credential` uploaded, read from the certificate
/// itself before it was sent — so the operator can confirm which certificate
/// went up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadedCertificate {
    /// SHA-1 thumbprint, uppercase hex — the value Entra stores as
    /// `customKeyIdentifier` and the portal lists as Thumbprint.
    pub thumbprint: String,
    /// The certificate's notAfter.
    pub not_after: DateTime<Utc>,
}

/// Result of generating a self-signed certificate. `private_key_pem`,
/// `pfx_base64` and `pfx_password` are all sensitive — shown once and never
/// persisted by the backend.
#[derive(Clone, Serialize, Deserialize)]
pub struct GeneratedCertificateResult {
    /// SHA-1 thumbprint, uppercase hex — the value Entra stores as
    /// `customKeyIdentifier` and a client assertion carries as `x5t`.
    /// Unqualified "thumbprint" means this one everywhere in Entra, so this is
    /// the value an operator acts on.
    pub thumbprint: String,
    /// SHA-256 thumbprint of the same DER, uppercase hex. Offered alongside for
    /// verification/pinning; it matches nothing Entra reports, so it is always
    /// labelled as SHA-256 where it is shown.
    pub thumbprint_sha256: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    /// The same certificate and the same private key as the two PEM fields
    /// above, bundled as PKCS#12 and encrypted under `pfx_password`. Base64
    /// because JSON has no byte type. Ciphertext, but redacted from `Debug`
    /// anyway: the password travels beside it, so the pair is one secret.
    pub pfx_base64: String,
    /// Password for `pfx_base64`, generated by the backend and shown once.
    pub pfx_password: String,
    /// RFC3339 certificate expiry.
    pub expires: String,
}

// Hand-written: the workspace treats a derived `Debug` on a secret as a
// defect — any `?dto` in a `tracing` macro puts the plaintext straight into
// the daily rolling log file. Mirrors `dto::backup::RegeneratedSecret`,
// `core::models::PasswordCredential`, `auth::AccessToken`,
// `keyvault::SecretValue` and `cert::GeneratedCert`.
impl std::fmt::Debug for GeneratedCertificateResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedCertificateResult")
            .field("thumbprint", &self.thumbprint)
            .field("thumbprint_sha256", &self.thumbprint_sha256)
            .field("certificate_pem", &self.certificate_pem)
            .field("private_key_pem", &"<redacted>")
            .field("pfx_base64", &"<redacted>")
            .field("pfx_password", &"<redacted>")
            .field("expires", &self.expires)
            .finish()
    }
}

/// One expired secret `remove_expired_passwords` could not remove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFailure {
    pub key_id: String,
    /// The [`UiError`](crate::UiError) code of the failure. A re-auth-fatal
    /// code ([`Self::is_reauth_fatal`]) means the sweep **stopped here**: the
    /// session is dead, so the secrets after this one were not attempted.
    /// Empty from a payload that predates the field.
    #[serde(default)]
    pub code: String,
    pub message: String,
}

impl KeyFailure {
    /// See [`UiError::is_reauth_fatal`](crate::UiError::is_reauth_fatal) —
    /// reads the one code set in `core::reauth::REAUTH_FATAL_CODES`.
    pub fn is_reauth_fatal(&self) -> bool {
        azapptoolkit_core::reauth::is_reauth_fatal(&self.code)
    }
}

/// One owner add/remove that failed while applying a replace-all-owners
/// operation. `action` is `"add"` or `"remove"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerChangeFailure {
    pub principal_id: String,
    pub action: String,
    /// The [`UiError`](crate::UiError) code of the failure. A re-auth-fatal
    /// code ([`Self::is_reauth_fatal`]) means the reconcile **stopped here**:
    /// the session is dead, so the later owner changes (and, after a failed
    /// add, every removal) were not attempted. Empty from a payload that
    /// predates the field.
    #[serde(default)]
    pub code: String,
    pub message: String,
}

impl OwnerChangeFailure {
    /// See [`UiError::is_reauth_fatal`](crate::UiError::is_reauth_fatal) —
    /// reads the one code set in `core::reauth::REAUTH_FATAL_CODES`.
    pub fn is_reauth_fatal(&self) -> bool {
        azapptoolkit_core::reauth::is_reauth_fatal(&self.code)
    }
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

    /// A plaintext RSA private key must never reach a `Debug` string; the
    /// daily rolling log appender writes whatever a `?dto` produces. The .pfx
    /// bundle and its password are the same key in another wrapper — the same
    /// rule — while the thumbprints, which identify the certificate, must
    /// still come through.
    #[test]
    fn a_generated_private_key_and_pfx_are_redacted_in_debug() {
        let result = GeneratedCertificateResult {
            thumbprint: "AABB".into(),
            thumbprint_sha256: "CCDD".into(),
            certificate_pem: "-----BEGIN CERTIFICATE-----".into(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----MIIsecret".into(),
            pfx_base64: "MIIpfxciphertext".into(),
            pfx_password: "pfxpasswordsecret".into(),
            expires: "2027-01-01T00:00:00Z".into(),
        };
        let dbg = format!("{result:?}");
        assert!(!dbg.contains("MIIsecret"), "{dbg}");
        assert!(!dbg.contains("MIIpfxciphertext"), "{dbg}");
        assert!(!dbg.contains("pfxpasswordsecret"), "{dbg}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(dbg.contains("AABB"), "{dbg}");
        assert!(dbg.contains("CCDD"), "{dbg}");
    }
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

    /// `code` is additive: a failure serialized before it existed still
    /// decodes (as a non-fatal empty code), and a fatal one reads as fatal.
    #[test]
    fn per_item_failures_default_their_code_and_read_the_fatal_set() {
        let key: KeyFailure =
            serde_json::from_value(serde_json::json!({ "key_id": "k", "message": "m" })).unwrap();
        assert_eq!(key.code, "");
        assert!(!key.is_reauth_fatal());
        let owner: OwnerChangeFailure = serde_json::from_value(
            serde_json::json!({ "principalId": "u", "action": "add", "message": "m" }),
        )
        .unwrap();
        assert_eq!(owner.code, "");
        assert!(!owner.is_reauth_fatal());

        let key = KeyFailure {
            code: "refresh_missing".into(),
            ..key
        };
        assert!(key.is_reauth_fatal());
        let owner = OwnerChangeFailure {
            code: "forbidden".into(),
            ..owner
        };
        assert!(!owner.is_reauth_fatal());
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
    fn directory_index_status_is_snake_case_on_the_wire() {
        let status = DirectoryIndexStatus {
            sp_index_truncated: true,
            sp_index_cap: 10_000,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "sp_index_truncated": true, "sp_index_cap": 10_000 })
        );
        let back: DirectoryIndexStatus = serde_json::from_value(json).unwrap();
        assert!(back.sp_index_truncated);
        assert_eq!(back.sp_index_cap, 10_000);
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

    #[test]
    fn federated_credential_dto_carries_a_null_subject() {
        let dto: FederatedCredentialDto = serde_json::from_value(serde_json::json!({
            "id": "f-1", "name": "gh-flex", "issuer": "i", "subject": null,
            "description": null, "audiences": ["api://AzureADTokenExchange"]
        }))
        .unwrap();
        assert!(dto.subject.is_none());
    }
}
