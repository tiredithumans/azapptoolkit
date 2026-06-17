//! Minimal typed projections of the Exchange Online objects returned by the
//! Admin API. The API returns the full PowerShell object (dozens of
//! properties) using PascalCase keys; we deserialize only the fields the
//! toolkit acts on and ignore the rest.

use serde::{Deserialize, Serialize};

/// Pointer to an Entra service principal, as registered in Exchange via
/// `New-ServicePrincipal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExoServicePrincipal {
    #[serde(rename = "ObjectId", default)]
    pub object_id: Option<String>,
    #[serde(rename = "AppId", default)]
    pub app_id: Option<String>,
    #[serde(rename = "DisplayName", default)]
    pub display_name: Option<String>,
    #[serde(rename = "Identity", default)]
    pub identity: Option<String>,
}

/// A management scope created via `New-ManagementScope`. `RecipientFilter`
/// holds the OPATH filter (e.g. a `MemberOfGroup -eq '<DN>'` expression).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExoManagementScope {
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
    #[serde(rename = "Identity", default)]
    pub identity: Option<String>,
    #[serde(rename = "RecipientFilter", default)]
    pub recipient_filter: Option<String>,
}

/// A management role assignment created via `New-ManagementRoleAssignment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExoRoleAssignment {
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
    #[serde(rename = "Role", default)]
    pub role: Option<String>,
    #[serde(rename = "RoleAssigneeName", default)]
    pub role_assignee_name: Option<String>,
    #[serde(rename = "CustomResourceScope", default)]
    pub custom_resource_scope: Option<String>,
    #[serde(rename = "Identity", default)]
    pub identity: Option<String>,
}

/// A recipient group (mail-enabled security group, M365 group, or
/// distribution list). The `DistinguishedName` is what a `MemberOfGroup`
/// recipient filter must reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExoGroup {
    #[serde(rename = "DistinguishedName", default)]
    pub distinguished_name: Option<String>,
    #[serde(rename = "PrimarySmtpAddress", default)]
    pub primary_smtp_address: Option<String>,
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
    #[serde(rename = "Identity", default)]
    pub identity: Option<String>,
}

/// One member of a distribution / mail-enabled security group, as returned by
/// `Get-DistributionGroupMember`. Used to list the membership of a toolkit
/// managed scope group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExoGroupMember {
    #[serde(rename = "DisplayName", default)]
    pub display_name: Option<String>,
    #[serde(rename = "PrimarySmtpAddress", default)]
    pub primary_smtp_address: Option<String>,
    #[serde(rename = "RecipientType", default)]
    pub recipient_type: Option<String>,
    #[serde(rename = "Guid", default)]
    pub guid: Option<String>,
}

/// A legacy Application Access Policy, read during migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExoApplicationAccessPolicy {
    #[serde(rename = "Identity", default)]
    pub identity: Option<String>,
    #[serde(rename = "AppId", default)]
    pub app_id: Option<String>,
    /// The mail-enabled security group the policy scopes to.
    #[serde(rename = "ScopeName", default)]
    pub scope_name: Option<String>,
    #[serde(rename = "ScopeIdentity", default)]
    pub scope_identity: Option<String>,
    #[serde(rename = "AccessRight", default)]
    pub access_right: Option<String>,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
}

/// Result of `Test-ApplicationAccessPolicy` — the live evaluation of the
/// legacy Application Access Policy gate for one app against one mailbox.
/// Note this gate constrains only the permissions granted in Microsoft Entra
/// ID; Exchange RBAC-for-Applications assignments are unaffected by it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExoAppAccessPolicyTestResult {
    #[serde(rename = "AppId", default)]
    pub app_id: Option<String>,
    #[serde(rename = "Mailbox", default)]
    pub mailbox: Option<String>,
    /// `Some(true)` = Granted, `Some(false)` = Denied, `None` = the cmdlet
    /// returned something unrecognized (treat as indeterminate, never as a
    /// verdict in either direction).
    #[serde(
        rename = "AccessCheckResult",
        default,
        deserialize_with = "ps_access_check"
    )]
    pub granted: Option<bool>,
}

/// Tolerant parse of the `AccessCheckResult` enum (`Granted` / `Denied`),
/// which PowerShell may serialize as a string or a raw boolean. Anything else
/// maps to `None` so an unexpected value degrades to "indeterminate" instead
/// of failing the whole response or fabricating a verdict.
fn ps_access_check<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::Bool(b)) => Some(b),
        Some(serde_json::Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "granted" | "true" => Some(true),
            "denied" | "false" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

/// One row from `Test-ServicePrincipalAuthorization`. `in_scope` answers
/// whether the assigned permission applies to the tested resource mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExoAuthorizationResult {
    #[serde(rename = "RoleName", default)]
    pub role_name: Option<String>,
    #[serde(rename = "GrantedPermissions", default)]
    pub granted_permissions: Option<String>,
    #[serde(rename = "AllowedResourceScope", default)]
    pub allowed_resource_scope: Option<String>,
    #[serde(rename = "ScopeType", default)]
    pub scope_type: Option<String>,
    /// `None` means the scope-membership check didn't run: the cmdlet reports
    /// a real boolean only when a `-Resource` mailbox was supplied, and the
    /// literal string `"Not Run"` otherwise — which is the *normal* case for
    /// the Scope-column resolver (it never passes a resource).
    #[serde(rename = "InScope", default, deserialize_with = "ps_optional_bool")]
    pub in_scope: Option<bool>,
}

/// Tolerant boolean for PowerShell-serialized cmdlet output: accepts a JSON
/// boolean, a stringified `"True"`/`"False"` (any case), and maps anything
/// else — notably `Test-ServicePrincipalAuthorization`'s `"Not Run"` — to
/// `None` instead of failing the whole response.
fn ps_optional_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::Bool(b)) => Some(b),
        Some(serde_json::Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_scope_of(json: serde_json::Value) -> Option<bool> {
        serde_json::from_value::<ExoAuthorizationResult>(json)
            .expect("row deserializes")
            .in_scope
    }

    #[test]
    fn in_scope_not_run_string_is_none() {
        // The live shape when no -Resource is passed (the Scope-column
        // resolver's only mode) — must not fail deserialization.
        assert_eq!(
            in_scope_of(serde_json::json!({
                "RoleName": "Application Mail.Read",
                "InScope": "Not Run"
            })),
            None
        );
    }

    #[test]
    fn in_scope_accepts_real_and_stringified_booleans() {
        assert_eq!(
            in_scope_of(serde_json::json!({ "InScope": true })),
            Some(true)
        );
        assert_eq!(
            in_scope_of(serde_json::json!({ "InScope": "False" })),
            Some(false)
        );
    }

    #[test]
    fn in_scope_absent_or_null_is_none() {
        assert_eq!(in_scope_of(serde_json::json!({})), None);
        assert_eq!(in_scope_of(serde_json::json!({ "InScope": null })), None);
    }

    fn access_check_of(json: serde_json::Value) -> Option<bool> {
        serde_json::from_value::<ExoAppAccessPolicyTestResult>(json)
            .expect("result deserializes")
            .granted
    }

    #[test]
    fn access_check_result_parses_granted_denied_and_booleans() {
        assert_eq!(
            access_check_of(serde_json::json!({ "AccessCheckResult": "Granted" })),
            Some(true)
        );
        assert_eq!(
            access_check_of(serde_json::json!({ "AccessCheckResult": "denied" })),
            Some(false)
        );
        assert_eq!(
            access_check_of(serde_json::json!({ "AccessCheckResult": true })),
            Some(true)
        );
    }

    #[test]
    fn access_check_result_unrecognized_is_indeterminate() {
        // An unexpected enum serialization must degrade to None (the caller
        // treats it as "couldn't verify"), never default to a verdict.
        assert_eq!(
            access_check_of(serde_json::json!({ "AccessCheckResult": 1 })),
            None
        );
        assert_eq!(access_check_of(serde_json::json!({})), None);
        assert_eq!(
            access_check_of(serde_json::json!({ "AccessCheckResult": null })),
            None
        );
    }
}
