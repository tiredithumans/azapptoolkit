//! Enterprise-application (non-MI service principal) IPC DTOs.
//!
//! Surfaces the third Azure identity-object type alongside App Registrations
//! and Managed Identities. Includes the foreign-tenant marker, paired App
//! Registration id, credential data, and app roles.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseApplicationDto {
    /// Service principal object id.
    pub id: String,
    pub app_id: String,
    pub display_name: String,
    pub account_enabled: Option<bool>,
    /// Whether users must be explicitly assigned to the app before they can
    /// sign in / it appears on My Apps. Only populated on the detail (the list
    /// index doesn't `$select` it).
    pub app_role_assignment_required: Option<bool>,
    pub service_principal_type: Option<String>,
    /// Home tenant of the underlying application. When this differs from the
    /// signed-in tenant, the SP represents a consented foreign-tenant app.
    pub app_owner_organization_id: Option<String>,
    pub is_foreign_tenant: bool,
    /// `Some` when an App Registration in *this* tenant has a matching
    /// `appId`. Drives the row-level pairing arrow.
    pub paired_app_registration_id: Option<String>,
    /// Client secrets (password credentials) — non-empty for the detail view.
    pub password_credentials: Vec<azapptoolkit_core::models::PasswordCredential>,
    /// Certificates (key credentials) — non-empty for the detail view.
    pub key_credentials: Vec<azapptoolkit_core::models::KeyCredential>,
    /// App roles defined by this SP — non-empty for the detail view.
    pub app_roles: Vec<azapptoolkit_core::models::AppRole>,
    /// OAuth2 permission scopes — non-empty for the detail view.
    pub oauth2_permission_scopes: Vec<azapptoolkit_core::models::OAuth2PermissionScope>,
    /// When the app was created (from Graph). Used for date filtering on the list.
    pub created_date_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Custom tags. `HideApp` present ⇒ hidden from the My Apps portal. Only
    /// populated on the detail (the list index doesn't `$select` tags).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Free-text management notes (max 1024 chars). Only populated on the detail
    /// (the list index doesn't `$select` it); the Overview tab edits it.
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseApplicationDetail {
    pub service_principal: EnterpriseApplicationDto,
    pub owners: Vec<azapptoolkit_core::models::DirectoryObject>,
}

/// One SCIM provisioning (synchronization) job's status for an enterprise app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningJobDto {
    pub id: String,
    pub template_id: Option<String>,
    /// `Active`, `Paused`, `Quarantine`, … (None when Graph omits it).
    pub status_code: Option<String>,
    /// Result of the last sync run (`Succeeded`, `Failed`, …).
    pub last_state: Option<String>,
    /// RFC3339 timestamp of the last sync run.
    pub last_run: Option<String>,
    /// Populated when the job is quarantined — why provisioning is stalled.
    pub quarantine_reason: Option<String>,
}

/// One group a service principal is a direct member of — the outbound
/// "what groups does this SP belong to" direction (the reverse of
/// [`AppAssignmentDto`]). Group-gated APIs (e.g. Power BI tenant settings)
/// admit service principals via security-group membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMembershipDto {
    /// Group object id.
    pub id: String,
    pub display_name: String,
    /// `Some(true)` for security groups (the kind group-gated APIs honor).
    pub security_enabled: Option<bool>,
    /// Graph `groupTypes`: `Unified` = Microsoft 365 group,
    /// `DynamicMembership` = rule-based (direct member changes are rejected).
    pub group_types: Vec<String>,
}

/// Input for creating (`id = None` — a GUID is generated server-side) or
/// updating (`id = Some`) one **exposed** app role on an enterprise application
/// (the Entra "App roles" blade — the role definitions the app publishes, not
/// the role *assignments* in [`AppAssignmentDto`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRoleInput {
    /// `None` ⇒ create; `Some` ⇒ edit the role with this id.
    pub id: Option<String>,
    pub display_name: String,
    /// The value emitted in the `roles` claim (no spaces; ≤ 250 chars).
    pub value: String,
    pub description: Option<String>,
    /// `User` (users/groups) and/or `Application` (apps/daemons) — who may be
    /// assigned the role.
    pub allowed_member_types: Vec<String>,
    pub is_enabled: bool,
}

/// The exposed app roles of an enterprise application plus where they're
/// defined: `application` when a local app registration backs the service
/// principal (the canonical home — Entra mirrors edits onto the SP), else
/// `servicePrincipal` (gallery / foreign-tenant apps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRolesView {
    pub target_kind: String,
    pub roles: Vec<azapptoolkit_core::models::AppRole>,
}

/// One principal (user/group/service principal) assigned to an enterprise
/// application's app role — the "who has access" view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAssignmentDto {
    pub assignment_id: String,
    pub principal_display_name: Option<String>,
    pub principal_type: Option<String>,
    /// The assigned app role's id. The all-zero GUID is the "default access"
    /// assignment (no specific role); the UI resolves real ids against the SP's
    /// `app_roles`.
    pub app_role_id: String,
}

/// A Microsoft Entra application-gallery template surfaced in the "Browse the
/// gallery" search — the fields the picker renders. Mirrors
/// `azapptoolkit_core::models::ApplicationTemplate` (a `display_name` always
/// present here; the command drops templates without one).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationTemplateDto {
    pub id: String,
    pub display_name: String,
    pub publisher: Option<String>,
    pub description: Option<String>,
    pub categories: Vec<String>,
    pub logo_url: Option<String>,
    /// SSO modes the gallery app supports (e.g. `saml`, `password`, `oidc`).
    pub supported_single_sign_on_modes: Vec<String>,
}

/// Result of creating an enterprise application from a gallery template
/// (`instantiate`): the identifiers of the freshly created app + service
/// principal, so the UI can confirm and refresh the list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GalleryAppSummary {
    pub object_id: String,
    pub service_principal_id: String,
    pub app_id: String,
    pub display_name: String,
}
