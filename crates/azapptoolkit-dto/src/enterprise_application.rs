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
