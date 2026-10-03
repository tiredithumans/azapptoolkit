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

/// Tenant consent-setting posture (F274) — the tenant configuration that
/// *produces* the delegated grants the audit inventories. One read pair on the
/// `Policy.Read.All` token: `authorizationPolicy` +
/// `adminConsentRequestPolicy`.
///
/// Whole-DTO contract, shared with the F265 signature-verification fields and
/// the F260 credential-lifetime advisory: `None` means **unknown** (read
/// failed, property absent, or Graph returned `null`), and unknown renders
/// nothing — never "consent is restricted", never "all clear". `available:
/// false` is the all-unknown state (no token, either read failed); a partial
/// policy picture is deliberately no picture, so the two reads are all-or-
/// nothing. A successful run always sets `available: true`, even when every
/// field below stays `None`.
///
/// Deliberately NOT read (verified against the v1.0 docs on 2026-10-03):
/// `permissionGrantPolicies` is a *catalog* — assigning a policy to the
/// default user role is what enables user consent, and the assignment list
/// (`default_user_role_consent_policies` above) already names the policies;
/// the bodies would also need `Policy.Read.PermissionGrant`, which the
/// `Policy.Read.All` token does not carry. Pending `appConsentRequests` are a
/// deferred second step (their read needs a dedicated consent-requests scope).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantConsentPostureDto {
    /// `false` = the policy pair could not be read at all → render nothing.
    #[serde(default)]
    pub available: bool,
    /// `authorizationPolicy.allowUserConsentForRiskyApps`. `None` covers both
    /// "property absent" and Graph's `null` (the docs say default-false, the
    /// example response says `null` — only `Some(true)` is actionable).
    #[serde(default)]
    pub risky_app_user_consent: Option<bool>,
    /// `defaultUserRolePermissions.permissionGrantPoliciesAssigned`. `None` =
    /// the payload did not carry it (unknown). `Some(vec![])` = the tenant
    /// confirmed there is NO self-consent policy on the default user role.
    /// Non-empty = users CAN consent themselves under those policies; the
    /// names are shown verbatim because whether each still allows what its
    /// name implies is not knowable from this read.
    #[serde(default)]
    pub default_user_role_consent_policies: Option<Vec<String>>,
    /// `adminConsentRequestPolicy.isEnabled`. `Some(false)` includes "the
    /// policy object does not exist" — the workflow needs the policy to be
    /// created, so absence really is "not enabled" (same reading as an absent
    /// default app-management policy in F260).
    #[serde(default)]
    pub admin_consent_workflow_enabled: Option<bool>,
}
