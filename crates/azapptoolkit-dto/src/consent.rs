//! Consent / OAuth2 permission-grant audit IPC DTOs.

use serde::{Deserialize, Serialize};

/// One tenant-wide **application** permission an app holds on a resource API
/// (an `appRoleAssignment` where the principal is a service principal), with the
/// permission value resolved and risk-classified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPermissionGrantDto {
    /// The holding app's service-principal object id (deep-link target).
    pub client_sp_id: String,
    pub client_display_name: String,
    /// The resolved permission value (e.g. `Directory.ReadWrite.All`).
    pub permission: String,
    /// The resource API the permission is on (e.g. `Microsoft Graph`).
    pub resource_display_name: String,
    /// `high`, `medium`, or `low`.
    pub risk: String,
}

/// One tenant-wide delegated (OAuth2) permission grant, with client/resource
/// names resolved and scopes split out + risk-classified for the consent audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2GrantDto {
    pub grant_id: Option<String>,
    /// The client application's service-principal object id (deep-link target).
    pub client_sp_id: String,
    pub client_display_name: String,
    pub client_app_id: Option<String>,
    pub resource_display_name: String,
    /// `AllPrincipals` = admin consent (applies to every user); `Principal` =
    /// a single user's consent.
    pub consent_type: String,
    /// All granted delegated scopes.
    pub scopes: Vec<String>,
    /// The subset of `scopes` classified high-risk for consent review.
    pub risky_scopes: Vec<String>,
}
