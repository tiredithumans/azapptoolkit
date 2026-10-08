//! Typed Microsoft Graph domain models.
//!
//! Field names use camelCase to match Graph JSON; `Option` wraps anything Graph
//! may omit so deserialization stays tolerant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::scoping::SelectedScopeLevel;

/// Deserialize a value, mapping an explicit JSON `null` to `T::default()`.
///
/// `#[serde(default)]` alone only covers a *missing* key — a key present with
/// a literal `null` still gets fed to `T`'s deserializer and fails for
/// non-`Option` fields (`invalid type: null, expected a string`/`a sequence`).
/// Graph emits explicit nulls for some apps (e.g. `displayName: null`, or a
/// `null` collection), so pair this with `#[serde(default)]` to stay tolerant.
///
/// A new `Vec`/`String` model field that carries `#[serde(default)]` should
/// pair it with this helper by default: `Paged<T>` deserializes as one
/// document, so a single literal `null` on one item fails the whole page.
/// `every_defaulted_vec_field_tolerates_null` pins this for `Vec` fields.
fn null_to_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(de)?.unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub id: String,
    pub app_id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub sign_in_audience: Option<String>,
    #[serde(default)]
    pub publisher_domain: Option<String>,
    #[serde(default)]
    pub created_date_time: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub password_credentials: Vec<PasswordCredential>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub key_credentials: Vec<KeyCredential>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub required_resource_access: Vec<RequiredResourceAccess>,
    /// Microsoft-verified publisher (the blue "verified" badge), when the app's
    /// publisher has completed publisher verification. `None` = unverified.
    #[serde(default)]
    pub verified_publisher: Option<VerifiedPublisher>,
    /// App instance property lock (`servicePrincipalLockConfiguration`). When
    /// disabled, anyone with directory write can add credentials to the SP and
    /// abuse the app's permissions — Microsoft says it "can and should be set by
    /// all applications". `None` means the field wasn't returned.
    #[serde(default)]
    pub service_principal_lock_configuration: Option<ServicePrincipalLockConfiguration>,
    /// `isFallbackPublicClient`: the fallback client type Entra uses when it can't
    /// determine the type (e.g. the ROPC flow without a redirect URI); also what
    /// the portal's "Allow public client flows" toggle sets. `true` does **not**
    /// prove the app is *only* a public client — a confidential app can have it set
    /// and still legitimately use credentials — so the audit's credential advisory
    /// is phrased conditionally rather than asserting removal.
    #[serde(default)]
    pub is_fallback_public_client: Option<bool>,
    /// Owners (directory objects). Populated only when the query `$expand`s
    /// `owners`; `None` means "not fetched", distinct from `Some(vec![])` =
    /// "fetched, no owners". Drives the audit's ownership rules.
    #[serde(default)]
    pub owners: Option<Vec<DirectoryObject>>,
    /// Graph `disabledByMicrosoftStatus`. Microsoft sets this to
    /// `DisabledDueToViolationOfServicesAgreement` when it disables an app for
    /// suspicious, abusive or malicious activity — Microsoft's own "this app is
    /// malicious" flag, and the explanation for "the integration silently
    /// stopped working" tickets. `None`/`Some("Success")` = never disabled.
    /// Read on both the application and its service principal.
    #[serde(default)]
    pub disabled_by_microsoft_status: Option<String>,
    /// Free-text internal notes (Graph `notes`, max 1024 chars) — the portal
    /// surfaces this as "Internal notes" under Branding & properties. Only
    /// fetched for the detail view; the Overview tab edits it.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Microsoft publisher-verification status on an application
/// (`verifiedPublisher`). Present only once the publisher has been verified.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedPublisher {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub verified_publisher_id: Option<String>,
    #[serde(default)]
    pub added_date_time: Option<DateTime<Utc>>,
}

/// App instance property lock (`servicePrincipalLockConfiguration`). `is_enabled`
/// plus `all_properties` is the recommended "lock everything" posture; the
/// granular flags cover the sensitive sign/verify credential and token-encryption
/// properties when `all_properties` is not set.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipalLockConfiguration {
    #[serde(default)]
    pub is_enabled: Option<bool>,
    #[serde(default)]
    pub all_properties: Option<bool>,
    #[serde(default)]
    pub credentials_with_usage_verify: Option<bool>,
    #[serde(default)]
    pub credentials_with_usage_sign: Option<bool>,
    #[serde(default)]
    pub token_encryption_key_id: Option<bool>,
}

impl ServicePrincipalLockConfiguration {
    /// True only when the lock is on **and** covers every sensitive property —
    /// either via `all_properties` or all the granular sign/verify/token flags.
    /// Anything less leaves a property an attacker (or a stray directory writer)
    /// can mutate, so the audit treats it as not fully locked.
    pub fn is_fully_locked(&self) -> bool {
        if self.is_enabled != Some(true) {
            return false;
        }
        if self.all_properties == Some(true) {
            return true;
        }
        self.credentials_with_usage_verify == Some(true)
            && self.credentials_with_usage_sign == Some(true)
            && self.token_encryption_key_id == Some(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipal {
    pub id: String,
    pub app_id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub display_name: String,
    #[serde(default)]
    pub account_enabled: Option<bool>,
    /// Graph `disabledByMicrosoftStatus` — see
    /// [`Application::disabled_by_microsoft_status`]. Microsoft disables the
    /// service principal alongside the application when it blocks an app for
    /// policy violation, so SP-only rows (foreign apps, managed identities)
    /// can carry the flag even where the application object lives in another
    /// tenant.
    #[serde(default)]
    pub disabled_by_microsoft_status: Option<String>,
    #[serde(default)]
    pub app_role_assignment_required: Option<bool>,
    #[serde(default)]
    pub service_principal_type: Option<String>,
    /// Client secrets (password credentials) — fetched for the detail view.
    #[serde(default, deserialize_with = "null_to_default")]
    pub password_credentials: Vec<PasswordCredential>,
    /// Certificates (key credentials) — fetched for the detail view.
    #[serde(default, deserialize_with = "null_to_default")]
    pub key_credentials: Vec<KeyCredential>,
    /// App roles defined by this SP — fetched for the detail view.
    #[serde(default, deserialize_with = "null_to_default")]
    pub app_roles: Vec<AppRole>,
    /// OAuth2 permission scopes — fetched for the detail view.
    #[serde(default, deserialize_with = "null_to_default")]
    pub oauth2_permission_scopes: Vec<OAuth2PermissionScope>,
    /// Home tenant of the application this SP represents. When this differs
    /// from the current tenant id, the SP is a foreign-tenant Enterprise App
    /// the user has consented to.
    #[serde(default)]
    pub app_owner_organization_id: Option<String>,
    /// Populated for managed-identity SPs. User-assigned MIs include an ARM
    /// resource id containing `userAssignedIdentities`; the absence of that
    /// substring marks a system-assigned MI.
    #[serde(default, deserialize_with = "null_to_default")]
    pub alternative_names: Vec<String>,
    /// Custom tags. The `HideApp` tag hides the app from the My Apps portal;
    /// the enterprise-app detail toggles it.
    #[serde(default, deserialize_with = "null_to_default")]
    pub tags: Vec<String>,
    /// When the app was created — used for date filtering on lists.
    #[serde(default)]
    pub created_date_time: Option<DateTime<Utc>>,
    /// Free-text management notes (max 1024 chars). Only fetched for the detail
    /// view; the enterprise-app Overview tab edits it.
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppRole {
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub allowed_member_types: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    // Graph marks `value` as nullable, and gallery/enterprise SPs publish a
    // default role (e.g. `msiam_access`) with `value: null`. A bare `String`
    // here fails with `invalid type: null` when loading such an app's detail.
    #[serde(default, deserialize_with = "null_to_default")]
    pub value: String,
    #[serde(default)]
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2PermissionScope {
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub value: String,
    #[serde(default)]
    pub admin_consent_display_name: Option<String>,
    #[serde(default)]
    pub admin_consent_description: Option<String>,
    #[serde(default)]
    pub user_consent_display_name: Option<String>,
    #[serde(default)]
    pub user_consent_description: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub is_enabled: Option<bool>,
}

/// A client application pre-authorized to use this API
/// (`api.preAuthorizedApplications`): the client's `appId` plus the ids of the
/// scopes it may request without a user/admin consent prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreAuthorizedApplication {
    pub app_id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub delegated_permission_ids: Vec<String>,
}

/// The `api` block of an application — the "Expose an API" surface: the
/// delegated scopes this app defines plus the clients pre-authorized to use
/// them. Only the fields this toolkit reads/writes are modeled; PATCHing a
/// subset leaves the others (`acceptMappedClaims`, `knownClientApplications`,
/// `requestedAccessTokenVersion`) untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApiApplication {
    #[serde(default, deserialize_with = "null_to_default")]
    pub oauth2_permission_scopes: Vec<OAuth2PermissionScope>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub pre_authorized_applications: Vec<PreAuthorizedApplication>,
}

/// Projection of an application's Expose-an-API fields (`identifierUris` +
/// `api`). Like the SSO / Authentication projections, these fields are kept
/// off the list-shape [`Application`] and fetched live by the tab that edits
/// them.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationExposeApi {
    pub id: String,
    pub app_id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub identifier_uris: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub api: ApiApplication,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PasswordCredential {
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_date_time: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_date_time: Option<DateTime<Utc>>,
    /// Only populated on `addPassword` responses. Skipped from serialization
    /// when absent so list/read responses never carry a `"secretText": null`
    /// field to the frontend, and never leak the plaintext via `Debug`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_text: Option<String>,
}

impl std::fmt::Debug for PasswordCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordCredential")
            .field("key_id", &self.key_id)
            .field("display_name", &self.display_name)
            .field("hint", &self.hint)
            .field("start_date_time", &self.start_date_time)
            .field("end_date_time", &self.end_date_time)
            .field(
                "secret_text",
                &self.secret_text.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeyCredential {
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_date_time: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_date_time: Option<DateTime<Utc>>,
    /// Base64-encoded certificate thumbprint bytes (SHA-1) as Graph reports
    /// them. Crosses IPC as-is inside `Application` — renaming or retyping
    /// this field is a wire-format change. Also echoed back verbatim by the
    /// fetch-modify-PATCH key-credential flows, so dropping it would strip the
    /// thumbprint from live credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_key_identifier: Option<String>,
}

/// A federated identity credential on an application — workload identity
/// federation (GitHub Actions, Kubernetes, AWS, …). Lets an external OIDC
/// workload authenticate as the app with no client secret.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIdentityCredential {
    pub id: String,
    pub name: String,
    pub issuer: String,
    // Graph returns `subject: null` for a *flexible* credential — one matched
    // by `claimsMatchingExpression` (a beta-only property, so our v1.0
    // `$select` never reads it). A bare `String` here failed the whole
    // `Paged<>` list, which broke the Federated tab and made DR backup skip
    // the app. `None` = expression-matched (flexible).
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub audiences: Vec<String>,
}

/// PATCH-body subset of [`KeyCredential`] used when appending a new
/// certificate to an application. Graph assigns `keyId` server-side on
/// success; our struct omits it. We keep the two types separate because
/// [`KeyCredential`] always has a server-assigned `keyId` after the first
/// read — callers who need to echo existing credentials in a PATCH can
/// `serde_json::to_value(cred)` and merge.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewKeyCredential {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date_time: Option<DateTime<Utc>>,
    /// Base64-encoded DER bytes of the certificate.
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RequiredResourceAccess {
    pub resource_app_id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub resource_access: Vec<ResourceAccess>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAccess {
    pub id: String,
    /// `Role` = application permission, `Scope` = delegated permission.
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppRoleAssignment {
    pub id: String,
    pub principal_id: String,
    pub resource_id: String,
    pub app_role_id: String,
    #[serde(default)]
    pub principal_display_name: Option<String>,
    /// `User`, `Group`, or `ServicePrincipal` — present on `appRoleAssignedTo`.
    #[serde(default)]
    pub principal_type: Option<String>,
    #[serde(default)]
    pub resource_display_name: Option<String>,
    #[serde(default)]
    pub created_date_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2PermissionGrant {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub client_id: String,
    pub resource_id: String,
    /// `AllPrincipals` = admin consent, `Principal` = per-user.
    pub consent_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    // Graph returns `scope` as `null` for a grant carrying no delegated scopes;
    // a bare `String` would fail deserialization on that row.
    #[serde(default, deserialize_with = "null_to_default")]
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryObject {
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub user_principal_name: Option<String>,
    /// Mail address — populated for mail-enabled groups / distribution lists
    /// (used as an SSO notification-email source); `None` for most objects.
    #[serde(default)]
    pub mail: Option<String>,
    #[serde(default, rename = "@odata.type")]
    pub odata_type: Option<String>,
}

/// One row of `/me/transitiveMemberOf/microsoft.graph.directoryRole`: an
/// **activated** directory role's display name plus its immutable
/// `roleTemplateId`. Consumers must match on the template id — long-lived
/// tenants' `directoryRole` objects carry legacy display names ("SharePoint
/// Service Administrator", "Company Administrator").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ActiveDirectoryRole {
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub role_template_id: Option<String>,
}

/// Lean projection of a Graph `group` — the fields the membership views need.
/// `group_types` distinguishes Microsoft 365 groups (`Unified`) and rule-based
/// membership (`DynamicMembership`, which rejects direct member adds);
/// `security_enabled` marks the security groups that group-gated APIs (e.g.
/// Power BI tenant settings) honor.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub security_enabled: Option<bool>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub group_types: Vec<String>,
}

/// One row of the Entra beta `reports/servicePrincipalSignInActivities` report:
/// a service principal's app id and its most recent sign-in. Used to detect
/// unused applications in the security audit.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipalSignInActivity {
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub last_sign_in_activity: Option<SignInActivity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SignInActivity {
    #[serde(default)]
    pub last_sign_in_date_time: Option<DateTime<Utc>>,
}

/// One row of the Entra beta `reports/appCredentialSignInActivities` report
/// (preview, **global cloud only**): a credential's last-seen sign-in plus
/// context. The audit joins these onto credential rows by `(appId, keyId)`.
/// Rows appear for credentials the preview report tracks; a null
/// `signInActivity.lastSignInDateTime` means tracked but no use observed,
/// while a credential **absent** from the report is unknown, not unused —
/// see the audit deep-dive before inferring anything from absence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppCredentialSignInActivity {
    #[serde(default)]
    pub app_id: Option<String>,
    /// The credential's keyId — matches `PasswordCredential::key_id` /
    /// `KeyCredential::key_id` on the application (and its mirrored SP copy).
    #[serde(default)]
    pub key_id: Option<String>,
    /// `clientSecret` | `certificate` | `unknownFutureValue`.
    #[serde(default)]
    pub key_type: Option<String>,
    /// `application` | `servicePrincipal` — the same credential can report
    /// from either side; both rows carry the same `keyId` and dates.
    #[serde(default)]
    pub credential_origin: Option<String>,
    #[serde(default)]
    pub service_principal_object_id: Option<String>,
    /// The resource the credential last presented to.
    #[serde(default)]
    pub resource_id: Option<String>,
    #[serde(default)]
    pub sign_in_activity: Option<SignInActivity>,
}

// ---------- App management policies (tenant credential-lifetime caps) ----------

/// One `passwordCredentials`/`keyCredentials` restriction entry inside an
/// app-management policy. The secret and certificate planes share this shape;
/// only `*Lifetime` entries carry `max_lifetime` (an ISO 8601 duration string,
/// e.g. `P90D` or `P4DT12H30M5S`).
///
/// `restrict_for_apps_created_after_date_time` gates the restriction: `null`
/// is **retroactive** (applies to every app, whenever created); a date means
/// it applies only to apps created *after* it.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRestrictionConfiguration {
    /// `passwordAddition` | `passwordLifetime` | `symmetricKeyAddition` |
    /// `symmetricKeyLifetime` | `customPasswordAddition` — each appears at
    /// most once per policy, and only `passwordLifetime` caps secrets.
    #[serde(default)]
    pub restriction_type: Option<String>,
    /// `enabled` | `disabled` — only `enabled` is enforced.
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub max_lifetime: Option<String>,
    #[serde(default)]
    pub restrict_for_apps_created_after_date_time: Option<DateTime<Utc>>,
}

/// The restriction container shared by the policy shapes: the tenant default's
/// `applicationRestrictions` (`appManagementApplicationConfiguration`), the
/// per-app `restrictions` (`customAppManagementConfiguration`, which repeats
/// the same fields *and* nests one under `applicationRestrictions`), and
/// `servicePrincipalRestrictions`. Tolerating the doubled shape is the read
/// side's job — see [`AppManagementConfiguration::password_entries`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppManagementConfiguration {
    #[serde(default, deserialize_with = "null_to_default")]
    pub key_credentials: Vec<CredentialRestrictionConfiguration>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub password_credentials: Vec<CredentialRestrictionConfiguration>,
    #[serde(default)]
    pub application_restrictions: Option<Box<AppManagementConfiguration>>,
}

impl AppManagementConfiguration {
    /// Every secret-restriction entry this container carries — top level and
    /// the nested `applicationRestrictions` copy alike. The per-app
    /// `customAppManagementConfiguration` has been seen storing the array in
    /// either place, so resolution must read both.
    pub fn password_entries(&self) -> impl Iterator<Item = &CredentialRestrictionConfiguration> {
        self.password_credentials.iter().chain(
            self.application_restrictions
                .as_deref()
                .into_iter()
                .flat_map(|nested| nested.password_credentials.iter()),
        )
    }
}

/// The tenant-wide default app-management policy
/// (`GET /policies/defaultAppManagementPolicy`). `is_enabled` defaults to
/// **false**: a tenant that never touched the feature has either no policy
/// object or a disabled one — both mean "no enforced credential lifetime".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TenantAppManagementPolicy {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub is_enabled: bool,
    #[serde(default)]
    pub application_restrictions: Option<AppManagementConfiguration>,
}

/// A per-application (or per-service-principal) policy override
/// (`appManagementPolicy`, read via the `applications/{id}/appManagementPolicies`
/// nav or the `/policies/appManagementPolicies` collection with
/// `$expand=appliesTo`). When one is assigned, the app adopts it **over** the
/// tenant-wide default — and only one policy is typically assigned per app.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppManagementPolicy {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub is_enabled: bool,
    #[serde(default)]
    pub restrictions: Option<AppManagementConfiguration>,
    /// Filled only when the read used `$expand=appliesTo`; empty otherwise
    /// (including on the per-app nav read, which needs no targets).
    #[serde(default, deserialize_with = "null_to_default")]
    pub applies_to: Vec<PolicySubjectRef>,
}

/// One `appliesTo` subject — a heterogeneous `directoryObject` collection, so
/// the `@odata.type` discriminator may or may not ride along. Kept for the
/// app↔SP matching only; the value itself is never shown.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicySubjectRef {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "@odata.type")]
    pub odata_type: Option<String>,
}

/// The tenant admin consent request (workflow) policy
/// (`GET /policies/adminConsentRequestPolicy`). Only `isEnabled` is modeled —
/// the payload also carries `version`, `notifyReviewers`, `remindersEnabled`,
/// `requestDurationInDays` and reviewer scopes, none of which any display
/// shows. A missing policy object is read as "never enabled": the workflow
/// requires the object to be created, so absence really is "not enabled"
/// (same reading as an absent default app-management policy above).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdminConsentRequestPolicy {
    #[serde(default)]
    pub is_enabled: bool,
}

/// A SCIM provisioning (synchronization) job on a service principal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SynchronizationJob {
    pub id: String,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub status: Option<SynchronizationStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SynchronizationStatus {
    /// `Active`, `Paused`, `Quarantine`, `Disabled`, …
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub last_execution: Option<SynchronizationExecution>,
    #[serde(default)]
    pub quarantine: Option<SynchronizationQuarantine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SynchronizationExecution {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub time_ended: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SynchronizationQuarantine {
    #[serde(default)]
    pub reason: Option<String>,
}

/// A single directory audit-log entry (`/auditLogs/directoryAudits`) — one
/// administrative change in the tenant. Every field is optional/defaulted
/// because Graph omits fields on some entries (and on deleted target resources).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryAuditLog {
    #[serde(default)]
    pub id: Option<String>,
    /// Human-readable activity, e.g. "Update application – Certificates and secrets management".
    #[serde(default)]
    pub activity_display_name: Option<String>,
    #[serde(default)]
    pub activity_date_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub category: Option<String>,
    /// "success" / "failure" / "timeout" / "unknownFutureValue".
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub result_reason: Option<String>,
    #[serde(default)]
    pub initiated_by: Option<AuditActivityInitiator>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub target_resources: Vec<AuditLogTargetResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditActivityInitiator {
    #[serde(default)]
    pub user: Option<AuditUserIdentity>,
    #[serde(default)]
    pub app: Option<AuditAppIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditUserIdentity {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub user_principal_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditAppIdentity {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub service_principal_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogTargetResource {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Graph emits this as `type`; some payloads capitalize it as `Type`.
    #[serde(rename = "type", alias = "Type", default)]
    pub resource_type: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub modified_properties: Vec<AuditModifiedProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditModifiedProperty {
    #[serde(default)]
    pub display_name: Option<String>,
    /// Graph encodes old/new values as JSON-in-a-string (e.g. `"[\"...\"]"`).
    #[serde(default)]
    pub old_value: Option<String>,
    #[serde(default)]
    pub new_value: Option<String>,
}

/// A Conditional Access policy (`/identity/conditionalAccess/policies`). Only
/// the fields needed to show which policies apply to an app and what they
/// enforce; everything is optional/defaulted to stay tolerant of Graph's nulls.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalAccessPolicy {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    /// "enabled" / "disabled" / "enabledForReportingButNotEnforced".
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub conditions: Option<CaConditions>,
    #[serde(default)]
    pub grant_controls: Option<CaGrantControls>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaConditions {
    #[serde(default)]
    pub applications: Option<CaApplications>,
    /// The **client axis** of the policy (`conditionalAccessClientApplications`):
    /// which workload identities / service principals may act as the client.
    /// `None` (or an all-empty body) means the policy does not constrain
    /// clients — the pre-workload-identity shape every user policy uses.
    #[serde(default)]
    pub client_applications: Option<CaClientApplications>,
}

/// `conditionalAccessClientApplications`. Targets the *client* of a sign-in
/// (who is connecting), as opposed to `applications`, which targets the
/// *resource* (what is being reached). A workload-identity CA policy is often
/// `applications: All` + `clientApplications: <workload ids>` — reading only
/// the resource axis reports it as "applies (all)" to every app.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaClientApplications {
    /// Service-principal **object ids**, or the well-known all-client tokens
    /// (`All`, `workloadIdentityAll` …) the CA blade writes for workload
    /// identities.
    #[serde(default, deserialize_with = "null_to_default")]
    pub include_service_principals: Vec<String>,
    /// Excluded client SP object ids — exclude wins over any include.
    #[serde(default, deserialize_with = "null_to_default")]
    pub exclude_service_principals: Vec<String>,
    /// Attribute filter on clients (`servicePrincipalFilter`); same
    /// `{mode, rule}` shape as the application filter and equally
    /// non-evaluable client-side.
    #[serde(default)]
    pub service_principal_filter: Option<CaApplicationFilter>,
}

impl CaClientApplications {
    /// True when the axis carries no targeting at all (Graph echoes
    /// `"clientApplications": {"excludeServicePrincipals": [], …}` for plain
    /// user policies) — treated as "clients unconstrained".
    pub fn is_empty(&self) -> bool {
        self.include_service_principals.is_empty()
            && self.exclude_service_principals.is_empty()
            && self.service_principal_filter.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaApplications {
    /// App ids (or the well-known tokens `All` / `Office365` /
    /// `MicrosoftAdminPortals`) the policy targets.
    #[serde(default, deserialize_with = "null_to_default")]
    pub include_applications: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub exclude_applications: Vec<String>,
    /// When non-empty (and `include_applications` empty), the policy targets
    /// user actions (e.g. `urn:user:registersecurityinfo`), not apps.
    #[serde(default, deserialize_with = "null_to_default")]
    pub include_user_actions: Vec<String>,
    #[serde(default)]
    pub application_filter: Option<CaApplicationFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaApplicationFilter {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaGrantControls {
    /// e.g. `mfa`, `compliantDevice`, `domainJoinedDevice`, `block`,
    /// `approvedApplication`, `compliantApplication`, `passwordChange`.
    #[serde(default, deserialize_with = "null_to_default")]
    pub built_in_controls: Vec<String>,
    /// "AND" / "OR" — how the controls combine.
    #[serde(default)]
    pub operator: Option<String>,
}

/// One row of the Identity Protection risky-service-principal report
/// (`GET /identityProtection/riskyServicePrincipals`). The audit joins these
/// onto principals by `service_principal_id` (the SP **object** id, not its
/// appId). `risk_state` is the finding (`confirmedCompromised` / `atRisk` are
/// the risky ones); the rest is context for the operator.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RiskyServicePrincipal {
    #[serde(default)]
    pub id: Option<String>,
    /// The service principal's object id — the join key onto `AuditItem`.
    #[serde(default)]
    pub service_principal_id: Option<String>,
    /// `none` | `confirmedCompromised` | `atRisk` | `remediated` |
    /// `dismissed` | `atRiskConfirmed`.
    #[serde(default)]
    pub risk_state: Option<String>,
    /// `low` | `medium` | `high` | `none`.
    #[serde(default)]
    pub risk_level: Option<String>,
    /// e.g. `adminGeneratedAccountCompromised`, `anonymousIP`, `maliciousIP`.
    #[serde(default)]
    pub risk_detail: Option<String>,
    #[serde(default)]
    pub risk_last_updated_date_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: String,
    pub display_name: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub verified_domains: Vec<VerifiedDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedDomain {
    pub name: String,
    #[serde(default)]
    pub is_default: Option<bool>,
    #[serde(default)]
    pub is_initial: Option<bool>,
}

/// A SharePoint site, resolved from its URL.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
}

/// A site permission entry (the Sites.Selected model). For app grants the
/// principal is under `granted_to_identities[].application`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SitePermission {
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub roles: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub granted_to_identities: Vec<SiteIdentitySet>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SiteIdentitySet {
    #[serde(default)]
    pub application: Option<SiteIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SiteIdentity {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// A permission entry on a securable *below* the site collection — a list, a
/// list item, or a driveItem (the `*.SelectedOperations.Selected` model).
///
/// Deliberately a separate type from [`SitePermission`] rather than an extra
/// field on it, because the two endpoint families disagree about the principal:
/// `POST /sites/{id}/permissions` reads and writes `grantedToIdentities` (an
/// array), while the list / listItem / driveItem endpoints use **`grantedToV2`**
/// (a single identity set) and, per Graph's reference, do not accept the array
/// forms at all. Folding them into one struct invites writing the wrong one.
///
/// `granted_to` is read as a fallback because the driveItem endpoint echoes the
/// deprecated singular form alongside `grantedToV2` in its response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SelectedPermission {
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub roles: Vec<String>,
    #[serde(default)]
    pub granted_to_v2: Option<SiteIdentitySet>,
    #[serde(default)]
    pub granted_to: Option<SiteIdentitySet>,
}

impl SelectedPermission {
    /// The application client id this permission grants to, if it is an app
    /// grant at all. A permission granted to a user or a SharePoint group has no
    /// `application` and yields `None` — those are ordinary SharePoint sharing
    /// entries, not Selected-scope grants, and must never be reported as one.
    pub fn app_id(&self) -> Option<&str> {
        self.granted_to_v2
            .as_ref()
            .or(self.granted_to.as_ref())
            .and_then(|set| set.application.as_ref())
            .and_then(|app| app.id.as_deref())
    }

    /// The display name recorded with the grant, when Graph echoed one back.
    pub fn app_display_name(&self) -> Option<&str> {
        self.granted_to_v2
            .as_ref()
            .or(self.granted_to.as_ref())
            .and_then(|set| set.application.as_ref())
            .and_then(|app| app.display_name.as_deref())
    }
}

/// A document library, as returned by `GET /sites/{id}/drives`. `web_url` is
/// what the resolver prefix-matches an operator's pasted URL against.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Drive {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
}

/// A list in a site, as returned by `GET /sites/{id}/lists`. A document library
/// appears both here and under `/drives`; the two are joined by `web_url`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SiteList {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
}

impl SiteList {
    /// The best operator-facing name Graph offered, preferring the display name.
    pub fn label(&self) -> Option<&str> {
        self.display_name.as_deref().or(self.name.as_deref())
    }
}

/// Presence marks a driveItem as a folder; the count is informational.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FolderFacet {
    #[serde(default)]
    pub child_count: Option<i64>,
}

/// Presence marks a driveItem as a file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileFacet {
    #[serde(default)]
    pub mime_type: Option<String>,
}

/// The SharePoint identifiers behind a driveItem. This is the join that makes
/// item-level grants possible: an operator pastes a *drive* path, but the
/// permission endpoint Microsoft documents for a folder is the **listItem** one,
/// which needs `list_id` + `list_item_id`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SharePointIds {
    #[serde(default)]
    pub list_id: Option<String>,
    #[serde(default)]
    pub list_item_id: Option<String>,
    #[serde(default)]
    pub site_id: Option<String>,
}

/// An item in a document library — a file or a folder.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DriveItem {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub folder: Option<FolderFacet>,
    #[serde(default)]
    pub file: Option<FileFacet>,
    #[serde(default)]
    pub sharepoint_ids: Option<SharePointIds>,
}

impl DriveItem {
    /// True when the item is a folder. Graph signals this by the *presence* of
    /// the `folder` facet, not by a type field.
    pub fn is_folder(&self) -> bool {
        self.folder.is_some()
    }
}

/// A SharePoint URL resolved to the securable a Selected-scope grant addresses.
///
/// Unlike its neighbours this is a *composed* result rather than a Graph wire
/// shape: reaching a folder takes a site lookup, a drive listing and a
/// path-addressed driveItem read, and every caller needs the same joined
/// answer. It carries the identifiers for **both** grant endpoints because the
/// level decides which one is used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedSharePointResource {
    /// What the URL turned out to point at. Checked against the cart's scope by
    /// [`crate::scoping::selected_scope_accepts`] before anything is granted.
    pub level: SelectedScopeLevel,
    pub site_id: String,
    #[serde(default)]
    pub site_url: Option<String>,
    #[serde(default)]
    pub site_name: Option<String>,
    /// Set for every level below the site — the list or library containing the
    /// target, and the list the item-level endpoint is addressed through.
    #[serde(default)]
    pub list_id: Option<String>,
    #[serde(default)]
    pub list_name: Option<String>,
    /// Set only at item level.
    #[serde(default)]
    pub item_id: Option<String>,
    #[serde(default)]
    pub drive_id: Option<String>,
    /// True when the item is a folder rather than a file. Purely for operator
    /// copy — the grant call is identical either way.
    #[serde(default)]
    pub is_folder: bool,
    /// Operator-facing path, e.g. `Finance / Documents / Invoices / 2026`.
    pub display_path: String,
}

/// The `application` + `servicePrincipal` pair returned by
/// `applicationTemplates/{id}/instantiate`. A single call creates both objects.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationServicePrincipal {
    pub application: Application,
    pub service_principal: ServicePrincipal,
}

/// A Microsoft Entra **application gallery** template (`GET /applicationTemplates`).
/// Instantiating one (`applicationTemplates/{id}/instantiate`) creates a paired
/// app + service principal preconfigured for that gallery app (e.g. Salesforce).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationTemplate {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub categories: Vec<String>,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub supported_single_sign_on_modes: Vec<String>,
}

/// Response of the service-principal `addTokenSigningCertificate` action — a
/// freshly minted self-signed SAML token-signing certificate. `key` carries the
/// base64-encoded certificate (and, for the signing entry, the private key) and
/// is returned exactly once; treat it as a secret.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SelfSignedCertificate {
    pub thumbprint: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub start_date_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end_date_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub usage: Option<String>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

impl std::fmt::Debug for SelfSignedCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `key` contains the private key on the signing entry — never print it.
        f.debug_struct("SelfSignedCertificate")
            .field("thumbprint", &self.thumbprint)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .field("key_id", &self.key_id)
            .field("start_date_time", &self.start_date_time)
            .field("end_date_time", &self.end_date_time)
            .field("usage", &self.usage)
            .field("kind", &self.kind)
            .finish()
    }
}

/// A claims-mapping policy (`/policies/claimsMappingPolicies`). `definition`
/// holds the policy JSON as a single-element string array, per Graph's schema.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClaimsMappingPolicy {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub definition: Vec<String>,
    #[serde(default)]
    pub is_organization_default: Option<bool>,
}

/// The custom claims policy the Entra admin center writes for an app's
/// "Attributes & Claims" (`GET /beta/servicePrincipals/{id}/claimsPolicy`).
/// Read-only here: the claims list is polymorphic (`customClaim`,
/// `samlNameIdClaim`), told apart by `@odata.type`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CustomClaimsPolicy {
    #[serde(default)]
    pub include_basic_claim_set: Option<bool>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub claims: Vec<CustomClaim>,
}

/// One entry of [`CustomClaimsPolicy::claims`]: a `customClaim` or the
/// `samlNameIdClaim` (the Name ID, with its `nameIdFormat`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CustomClaim {
    #[serde(default, rename = "@odata.type")]
    pub odata_type: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub token_format: Vec<String>,
    #[serde(default)]
    pub saml_attribute_name_format: Option<String>,
    /// Set on the `samlNameIdClaim` only.
    #[serde(default)]
    pub name_id_format: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub configurations: Vec<CustomClaimConfiguration>,
}

impl CustomClaim {
    /// Whether this entry is the Name ID claim.
    pub fn is_name_id(&self) -> bool {
        self.odata_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("#microsoft.graph.samlNameIdClaim"))
    }
}

/// How a custom claim is sourced, optionally under a condition.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CustomClaimConfiguration {
    #[serde(default)]
    pub condition: Option<serde_json::Value>,
    #[serde(default)]
    pub attribute: Option<CustomClaimAttribute>,
    /// Polymorphic transformations (`joinTransformation`, …), kept raw: the
    /// view only names them and lists their inputs.
    #[serde(default, deserialize_with = "null_to_default")]
    pub transformations: Vec<serde_json::Value>,
}

/// A claim value's source: a `sourcedAttribute` (`source` + `id`) or a
/// `valueBasedAttribute` (a constant `value`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CustomClaimAttribute {
    #[serde(default, rename = "@odata.type")]
    pub odata_type: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub is_extension_attribute: Option<bool>,
}

/// One entry of the app-recycle-bin read
/// `/directory/deletedItems/microsoft.graph.application`.
///
/// Deleted items are `directoryObject` projections, not full `Application`s:
/// Graph answers with the pairing scalars (`appId`, `displayName`) and
/// `deletedDateTime`, but entries for some deleted objects carry **limited
/// info** (only `id` + `@odata.type`), so every non-key field is optional and
/// defaults through `serde`. Unknown keys (`@odata.type` and friends) are
/// ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedApplication {
    pub id: String,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub deleted_date_time: Option<DateTime<Utc>>,
}

/// One entry of the recycle-bin read
/// `/directory/deletedItems/microsoft.graph.servicePrincipal`. Used only to
/// find the service principals paired with a restored application (Graph does
/// NOT cascade-restore the paired SP) — same limited-info caveat as
/// [`DeletedApplication`], which is why `app_id` is optional and an SP that
/// reports no `appId` simply cannot be paired.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedServicePrincipal {
    pub id: String,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paged<T> {
    #[serde(rename = "value")]
    pub items: Vec<T>,
    #[serde(rename = "@odata.nextLink", default)]
    pub next_link: Option<String>,
    #[serde(rename = "@odata.count", default)]
    pub total_count: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleted_items_decode_full_and_limited_info_entries() {
        // A full app entry (with `@odata.type` + fields a typed read ignores)
        // next to the documented "limited info" shape — only id and type.
        let json = r##"{"value":[
            {"@odata.type":"#microsoft.graph.application","id":"app-1","deletedDateTime":"2026-09-20T10:00:00Z","appId":"11111111-1111-1111-1111-111111111111","displayName":"CRM","extraKey":"ignored"},
            {"@odata.type":"#microsoft.graph.application","id":"app-2"}
        ]}"##;
        let page: Paged<DeletedApplication> = serde_json::from_str(json).unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].display_name.as_deref(), Some("CRM"));
        assert!(page.items[0].deleted_date_time.is_some());
        assert!(page.items[1].display_name.is_none());
        assert!(page.items[1].app_id.is_none());

        let json = r##"{"value":[
            {"@odata.type":"#microsoft.graph.servicePrincipal","id":"sp-1","appId":"11111111-1111-1111-1111-111111111111","displayName":"CRM"},
            {"id":"sp-2","displayName":null}
        ]}"##;
        let page: Paged<DeletedServicePrincipal> = serde_json::from_str(json).unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(page.items[0].app_id.is_some());
        assert!(page.items[1].display_name.is_none());
    }

    #[test]
    fn application_deserializes_with_missing_optional_fields() {
        let json = r#"{"id":"abc","appId":"def","displayName":"Demo"}"#;
        let app: Application = serde_json::from_str(json).unwrap();
        assert_eq!(app.id, "abc");
        assert_eq!(app.app_id, "def");
        assert_eq!(app.display_name, "Demo");
        assert!(app.password_credentials.is_empty());
    }

    #[test]
    fn application_tolerates_explicit_null_fields() {
        // Graph emits explicit `null` (not omission) for these fields on some
        // apps; `#[serde(default)]` alone fails on a literal null, which
        // surfaced as `deserialize_error: invalid type: null` on the App
        // Registrations tab.
        let json = r#"{
            "id":"abc",
            "appId":"def",
            "displayName":null,
            "passwordCredentials":null,
            "keyCredentials":null,
            "requiredResourceAccess":null
        }"#;
        let app: Application = serde_json::from_str(json).unwrap();
        assert_eq!(app.display_name, "");
        assert!(app.password_credentials.is_empty());
        assert!(app.key_credentials.is_empty());
        assert!(app.required_resource_access.is_empty());
    }

    #[test]
    fn required_resource_access_tolerates_null_resource_access() {
        let json =
            r#"{"resourceAppId":"00000003-0000-0000-c000-000000000000","resourceAccess":null}"#;
        let rra: RequiredResourceAccess = serde_json::from_str(json).unwrap();
        assert!(rra.resource_access.is_empty());
    }

    #[test]
    fn directory_audit_log_tolerates_null_collections_and_type_alias() {
        // Graph emits explicit `null` collections and capitalizes the target
        // resource's `type` as `Type` on some entries.
        let json = r#"{
            "id":"audit-1",
            "activityDisplayName":"Add owner",
            "targetResources":[{
                "id":"obj-1",
                "displayName":"My App",
                "Type":"Application",
                "modifiedProperties":null
            }]
        }"#;
        let log: DirectoryAuditLog = serde_json::from_str(json).unwrap();
        assert_eq!(log.target_resources.len(), 1);
        assert_eq!(
            log.target_resources[0].resource_type.as_deref(),
            Some("Application")
        );
        assert!(log.target_resources[0].modified_properties.is_empty());

        // A fully-null collection at the top level must not fail.
        let null_targets = r#"{"id":"a","targetResources":null}"#;
        let log: DirectoryAuditLog = serde_json::from_str(null_targets).unwrap();
        assert!(log.target_resources.is_empty());
    }

    #[test]
    fn service_principal_tolerates_null_role_and_scope_strings() {
        // Gallery/enterprise SPs publish a default app role with `value: null`
        // (e.g. `msiam_access`); Graph also returns null permission-scope
        // values. A bare `String` failed with `invalid type: null` when the
        // app-detail fan-out loaded such an SP (the "↔ App Reg" jump).
        let json = r#"{
            "id":"sp-1",
            "appId":"app-1",
            "displayName":"Gallery App",
            "appRoles":[{
                "id":"00000000-0000-0000-0000-000000000000",
                "displayName":null,
                "value":null
            }],
            "oauth2PermissionScopes":[{"id":"scope-1","value":null}]
        }"#;
        let sp: ServicePrincipal = serde_json::from_str(json).unwrap();
        assert_eq!(sp.app_roles.len(), 1);
        assert_eq!(sp.app_roles[0].value, "");
        assert_eq!(sp.app_roles[0].display_name, "");
        assert_eq!(sp.oauth2_permission_scopes[0].value, "");
    }

    #[test]
    fn oauth2_grant_tolerates_null_scope() {
        let json = r#"{
            "clientId":"c-1",
            "resourceId":"r-1",
            "consentType":"AllPrincipals",
            "scope":null
        }"#;
        let grant: OAuth2PermissionGrant = serde_json::from_str(json).unwrap();
        assert_eq!(grant.scope, "");
    }

    #[test]
    fn federated_credential_tolerates_null_subject() {
        // A flexible credential has `subject: null` plus a (beta-only)
        // `claimsMatchingExpression`; one such item used to fail the whole
        // page. The unknown key is ignored (no `deny_unknown_fields`).
        let json = r#"{"value":[
            {"id":"f-1","name":"gh-main","issuer":"https://token.actions.githubusercontent.com",
             "subject":"repo:contoso/app:ref:refs/heads/main",
             "audiences":["api://AzureADTokenExchange"]},
            {"id":"f-2","name":"gh-flex","issuer":"https://token.actions.githubusercontent.com",
             "subject":null,
             "claimsMatchingExpression":{"value":"claims['sub'] matches 'repo:contoso/*'","languageVersion":1},
             "audiences":["api://AzureADTokenExchange"]}
        ]}"#;
        let page: Paged<FederatedIdentityCredential> = serde_json::from_str(json).unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(
            page.items[0].subject.as_deref(),
            Some("repo:contoso/app:ref:refs/heads/main")
        );
        assert!(page.items[1].subject.is_none());

        // A missing key is the same as null.
        let missing: FederatedIdentityCredential =
            serde_json::from_str(r#"{"id":"f-3","name":"n","issuer":"i"}"#).unwrap();
        assert!(missing.subject.is_none());
    }

    #[test]
    fn bare_collections_tolerate_null() {
        let role: AppRole =
            serde_json::from_str(r#"{"id":"r","allowedMemberTypes":null}"#).unwrap();
        assert!(role.allowed_member_types.is_empty());
        let group: GroupSummary = serde_json::from_str(r#"{"id":"g","groupTypes":null}"#).unwrap();
        assert!(group.group_types.is_empty());
        let site: SitePermission =
            serde_json::from_str(r#"{"id":"p","roles":null,"grantedToIdentities":null}"#).unwrap();
        assert!(site.roles.is_empty());
        assert!(site.granted_to_identities.is_empty());
        let selected: SelectedPermission =
            serde_json::from_str(r#"{"id":"p","roles":null}"#).unwrap();
        assert!(selected.roles.is_empty());
        let template: ApplicationTemplate = serde_json::from_str(
            r#"{"id":"t","categories":null,"supportedSingleSignOnModes":null}"#,
        )
        .unwrap();
        assert!(template.categories.is_empty());
        assert!(template.supported_single_sign_on_modes.is_empty());
    }

    /// Source scan: every `Vec` field defaulted with `#[serde(default…)]`
    /// also maps an explicit `null` through `null_to_default`. `Paged.items`
    /// carries no default (Graph never nulls `value`), so it is exempt by
    /// construction.
    #[test]
    fn every_defaulted_vec_field_tolerates_null() {
        let src = include_str!("models.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        let lines: Vec<&str> = body.lines().collect();
        let mut vec_fields = 0;
        let mut offenders = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let Some(rest) = t.strip_prefix("pub ") else {
                continue;
            };
            let Some((ident, ty)) = rest.split_once(':') else {
                continue;
            };
            if !ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                || !ty.trim_start().starts_with("Vec<")
            {
                continue;
            }
            vec_fields += 1;
            let prev = if i > 0 { lines[i - 1] } else { "" };
            if prev.contains("serde(default") && !prev.contains("null_to_default") {
                offenders.push(format!("line {}: {t}", i + 1));
            }
        }
        assert!(
            vec_fields >= 20,
            "scan found only {vec_fields} Vec fields; the matcher is broken"
        );
        assert!(
            offenders.is_empty(),
            "defaulted Vec fields without null_to_default: {offenders:#?}"
        );
    }

    #[test]
    fn instantiate_response_parses_app_and_sp() {
        // `applicationTemplates/{id}/instantiate` returns both objects nested.
        let json = r#"{
            "application":{"id":"app-obj-1","appId":"client-1","displayName":"My SAML App"},
            "servicePrincipal":{"id":"sp-1","appId":"client-1","displayName":"My SAML App"}
        }"#;
        let pair: ApplicationServicePrincipal = serde_json::from_str(json).unwrap();
        assert_eq!(pair.application.id, "app-obj-1");
        assert_eq!(pair.service_principal.id, "sp-1");
        assert_eq!(pair.application.app_id, pair.service_principal.app_id);
    }

    #[test]
    fn self_signed_certificate_parses_and_redacts_key() {
        let json = r#"{
            "thumbprint":"C2DDD8044C956ACD0269A75A64B7862DB9DDAC3E",
            "key":"MIICqjCCAZKg-secret-bytes",
            "keyId":"4c266507-3e74-4b91-aeba-18a25b450f6e",
            "endDateTime":"2027-01-22T00:00:00Z",
            "usage":"Verify",
            "type":"AsymmetricX509Cert"
        }"#;
        let cert: SelfSignedCertificate = serde_json::from_str(json).unwrap();
        assert_eq!(cert.thumbprint, "C2DDD8044C956ACD0269A75A64B7862DB9DDAC3E");
        assert_eq!(cert.usage.as_deref(), Some("Verify"));
        // Debug must never leak the key material.
        let dbg = format!("{cert:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("secret-bytes"));
    }

    #[test]
    fn claims_mapping_policy_tolerates_null_definition() {
        let json = r#"{"id":"pol-1","displayName":"AWS Claims","definition":null}"#;
        let policy: ClaimsMappingPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.id, "pol-1");
        assert!(policy.definition.is_empty());
    }

    #[test]
    fn paged_response_parses_next_link_and_count() {
        let json = r#"{
            "@odata.count": 42,
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/applications?$skiptoken=abc",
            "value": [{"id":"1","appId":"x","displayName":"one"}]
        }"#;
        let page: Paged<Application> = serde_json::from_str(json).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.total_count, Some(42));
        assert!(page.next_link.is_some());
    }
}
