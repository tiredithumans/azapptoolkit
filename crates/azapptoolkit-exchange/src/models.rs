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
///
/// `Default` is derived so the pure migration planner's tests can build one
/// field at a time; every field is already `Option` + `#[serde(default)]`, so
/// the default is the same "nothing was reported" shape a sparse EXO response
/// deserializes to.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// `None` when Exchange reported no readable `AccessRight` (absent, blank,
    /// or not a string) — never guessed at in either direction.
    #[serde(rename = "AccessRight", default, deserialize_with = "ps_access_right")]
    pub access_right: Option<AapAccessRight>,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
}

impl ExoApplicationAccessPolicy {
    /// Whether this is a `RestrictAccess` (allow-list) policy — the single
    /// definition the migration planner (`aap.rs`) and the audit / permission
    /// tester verdict (`verdict.rs`) share. They used to spell it separately,
    /// and only one trimmed, so a padded `" RestrictAccess "` was migrated as
    /// confining by one and reported org-wide by the other.
    pub fn is_restrict_access(&self) -> bool {
        self.access_right
            .as_ref()
            .is_some_and(AapAccessRight::is_restrict)
    }
}

/// `AccessRight` of a legacy Application Access Policy. `RestrictAccess`
/// (allow-list) vs `DenyAccess` (blocklist) is the migration's most
/// consequential decision — rebuilding a blocklist as a management scope
/// inverts it — so it is parsed ONCE, trimmed and case-folded, here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AapAccessRight {
    RestrictAccess,
    DenyAccess,
    /// Any other non-blank value, trimmed, as Exchange reported it.
    Other(String),
}

impl AapAccessRight {
    /// Tolerant parse: trims, folds ASCII case, and maps a blank value to
    /// `None` ("no readable AccessRight").
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else if trimmed.eq_ignore_ascii_case("RestrictAccess") {
            Some(Self::RestrictAccess)
        } else if trimmed.eq_ignore_ascii_case("DenyAccess") {
            Some(Self::DenyAccess)
        } else {
            Some(Self::Other(trimmed.to_string()))
        }
    }

    pub fn is_restrict(&self) -> bool {
        matches!(self, Self::RestrictAccess)
    }

    /// The canonical spelling (`RestrictAccess` / `DenyAccess`), or the
    /// unrecognised text as reported.
    pub fn as_str(&self) -> &str {
        match self {
            Self::RestrictAccess => "RestrictAccess",
            Self::DenyAccess => "DenyAccess",
            Self::Other(s) => s,
        }
    }
}

impl std::fmt::Display for AapAccessRight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serializes as the plain string, so the policy keeps its wire shape.
impl Serialize for AapAccessRight {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// For builders; a blank value becomes `Other("")`, which is never
/// `RestrictAccess` (the wire path maps blank to `None` instead).
impl From<&str> for AapAccessRight {
    fn from(raw: &str) -> Self {
        Self::parse(raw).unwrap_or_else(|| Self::Other(String::new()))
    }
}

impl From<String> for AapAccessRight {
    fn from(raw: String) -> Self {
        Self::from(raw.as_str())
    }
}

/// Tolerant parse of `AccessRight`, following [`ps_access_check`]: a string
/// goes through [`AapAccessRight::parse`]; anything else (null, a number, a
/// bool) is `None` — no readable AccessRight, which every caller fails closed
/// on.
fn ps_access_right<'de, D>(deserializer: D) -> Result<Option<AapAccessRight>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::String(s)) => AapAccessRight::parse(&s),
        _ => None,
    })
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
    fn access_right_parses_tolerantly_and_round_trips() {
        fn right_of(json: serde_json::Value) -> Option<AapAccessRight> {
            serde_json::from_value::<ExoApplicationAccessPolicy>(json)
                .expect("policy deserializes")
                .access_right
        }
        for raw in ["RestrictAccess", " restrictaccess ", "RESTRICTACCESS\t"] {
            assert_eq!(
                right_of(serde_json::json!({ "AccessRight": raw })),
                Some(AapAccessRight::RestrictAccess),
                "{raw:?}"
            );
        }
        assert_eq!(
            right_of(serde_json::json!({ "AccessRight": " DenyAccess" })),
            Some(AapAccessRight::DenyAccess)
        );
        assert_eq!(
            right_of(serde_json::json!({ "AccessRight": "Weird" })),
            Some(AapAccessRight::Other("Weird".into()))
        );
        // No readable AccessRight: never guessed at.
        for json in [
            serde_json::json!({ "AccessRight": "" }),
            serde_json::json!({ "AccessRight": "  " }),
            serde_json::json!({ "AccessRight": null }),
            serde_json::json!({}),
            serde_json::json!({ "AccessRight": 1 }),
        ] {
            assert_eq!(right_of(json.clone()), None, "{json}");
        }

        // The wire shape is unchanged: a plain string, canonically spelled.
        let policy: ExoApplicationAccessPolicy =
            serde_json::from_value(serde_json::json!({ "AccessRight": " restrictaccess " }))
                .unwrap();
        assert!(policy.is_restrict_access());
        let out = serde_json::to_value(&policy).unwrap();
        assert_eq!(out["AccessRight"], "RestrictAccess");
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
