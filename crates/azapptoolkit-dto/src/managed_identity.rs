//! Managed-identity IPC DTOs.
//!
//! Managed identities are surfaced as service principals
//! (`servicePrincipalType == "ManagedIdentity"`); granting one an application
//! permission is an app-role assignment on that service principal, reusing the
//! same Graph machinery as ordinary admin consent.

use serde::{Deserialize, Serialize};

/// Managed-identity sub-type, derived from the SP's `alternativeNames`.
/// User-assigned MIs include an ARM resource id containing
/// `userAssignedIdentities`; system-assigned MIs are tied to a single
/// Azure resource (their parent), and may have an empty `alternativeNames`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MiSubtype {
    SystemAssigned,
    UserAssigned,
    Unknown,
}

impl MiSubtype {
    /// Substring heuristic that matches both casings Graph has been observed
    /// to emit. Empty `alternative_names` returns [`MiSubtype::Unknown`].
    pub fn from_alternative_names<S: AsRef<str>>(alternative_names: &[S]) -> Self {
        if alternative_names.is_empty() {
            return MiSubtype::Unknown;
        }
        let user_assigned = alternative_names.iter().any(|n| {
            n.as_ref()
                .to_ascii_lowercase()
                .contains("userassignedidentities")
        });
        if user_assigned {
            MiSubtype::UserAssigned
        } else {
            MiSubtype::SystemAssigned
        }
    }
}

/// A managed-identity service principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedIdentityDto {
    /// Service principal object id (the principal that receives app roles).
    pub id: String,
    pub app_id: String,
    pub display_name: String,
    pub account_enabled: Option<bool>,
    pub mi_subtype: MiSubtype,
}

/// One application permission (app-role assignment) **held by** a service
/// principal — a managed identity *or* an enterprise application. Both surface
/// the permissions a principal has been granted via the same Graph
/// `appRoleAssignments` call, so they share this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleGrantDto {
    pub assignment_id: String,
    pub resource_id: String,
    pub resource_display_name: Option<String>,
    pub app_role_id: String,
    /// Resolved permission value (e.g. `Mail.Read`) when known — currently
    /// filled for Microsoft Graph roles; `None` for other resources.
    pub app_role_value: Option<String>,
}

/// One Azure RBAC role assignment held by a managed identity (from ARM) — the
/// Azure-resource side of its privilege, complementing the Graph app-role view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureRoleDto {
    pub role_name: String,
    /// The ARM scope the role is granted at.
    pub scope: String,
    /// Derived from `scope`: Subscription / Resource group / Resource / ….
    pub scope_level: String,
    /// Display name (or id) of the owning subscription.
    pub subscription: String,
    /// True for broadly-privileged roles (Owner, Contributor, …).
    pub high_privilege: bool,
}

/// Result of an Azure-RBAC scan for a managed identity, with the coverage of
/// the scan so the UI can warn when it was incomplete. A managed identity shown
/// with "no high-privilege roles" could be Owner on an unscanned subscription,
/// so a partial scan must never read as authoritative.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AzureRolesResult {
    pub roles: Vec<AzureRoleDto>,
    /// Subscriptions actually scanned (capped for safety).
    pub scanned: usize,
    /// Subscriptions the signed-in user can reach (before the cap).
    pub total: usize,
    /// Scanned subscriptions whose role-assignment lookup failed and was skipped.
    pub skipped: usize,
}

/// Outcome of `grant_managed_identity_permission`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantManagedIdentityResult {
    pub managed_identity_id: String,
    /// Role values newly granted.
    pub granted: Vec<String>,
    /// Role values already assigned (skipped, idempotent).
    pub skipped: Vec<String>,
    /// Human-readable failures (unknown role, Graph error, …).
    pub failures: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_alternative_names_yields_unknown() {
        let names: [&str; 0] = [];
        assert_eq!(
            MiSubtype::from_alternative_names(&names),
            MiSubtype::Unknown
        );
    }

    #[test]
    fn user_assigned_match_is_case_insensitive() {
        let names = [
            "isExplicit=True",
            "/subscriptions/x/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1",
        ];
        assert_eq!(
            MiSubtype::from_alternative_names(&names),
            MiSubtype::UserAssigned
        );
    }

    #[test]
    fn non_user_assigned_marker_falls_back_to_system_assigned() {
        let names = [
            "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        ];
        assert_eq!(
            MiSubtype::from_alternative_names(&names),
            MiSubtype::SystemAssigned
        );
    }
}
