//! Permissions catalog & admin-consent IPC DTOs.

use azapptoolkit_core::models::{AppRoleAssignment, OAuth2PermissionGrant};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogResourceSummary {
    pub app_id: String,
    pub display_name: String,
    pub role_count: usize,
    pub scope_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleEntry {
    pub id: String,
    pub value: String,
    pub display_name: String,
    pub description: Option<String>,
    /// Graph's `appRoles[].allowedMemberTypes`. The picker filters to entries
    /// containing `"Application"` when granting to a service principal /
    /// managed identity, since user-only roles can't be assigned that way.
    #[serde(default)]
    pub allowed_member_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeEntry {
    pub id: String,
    pub value: String,
    pub admin_consent_display_name: Option<String>,
    pub admin_consent_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePermissions {
    pub app_id: String,
    pub display_name: String,
    pub app_roles: Vec<RoleEntry>,
    pub oauth2_permission_scopes: Vec<ScopeEntry>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedRole {
    pub resource_app_id: String,
    pub app_role_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeGrantSummary {
    pub resource_app_id: String,
    pub grant: OAuth2PermissionGrant,
    pub scopes_added: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantFailure {
    pub resource_app_id: String,
    pub permission_id: Option<String>,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantResult {
    pub client_service_principal_id: String,
    pub role_assignments_created: Vec<AppRoleAssignment>,
    pub role_assignments_skipped: Vec<SkippedRole>,
    pub scope_grants_upserted: Vec<ScopeGrantSummary>,
    pub failures: Vec<GrantFailure>,
}

/// Application permission ("Role") vs delegated ("Scope"). `Unknown` is used
/// when the catalog and live SP lookup both miss — the GUIDs are still shown
/// in the UI so power users can copy them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionKind {
    Application,
    Delegated,
    Unknown,
}

impl PermissionKind {
    pub fn from_catalog_kind(kind: &str) -> Self {
        match kind {
            "Role" => PermissionKind::Application,
            "Scope" => PermissionKind::Delegated,
            _ => PermissionKind::Unknown,
        }
    }
}

/// One declared `requiredResourceAccess` entry, resolved to human-readable
/// fields where the catalog or a live SP lookup could match the GUIDs.
/// The raw GUIDs are preserved so the UI can show them as a secondary line
/// / tooltip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedPermission {
    pub resource_app_id: String,
    pub resource_display_name: Option<String>,
    pub permission_id: String,
    /// The OAuth scope / app role `value` (e.g. `Mail.Read`).
    pub permission_value: Option<String>,
    /// The human label (`adminConsentDisplayName` for scopes, `displayName`
    /// for roles).
    pub permission_display_name: Option<String>,
    pub permission_kind: PermissionKind,
    /// `appRoleAssignment.id` when this Application permission has been
    /// granted to the app's service principal. `None` when only declared.
    #[serde(default)]
    pub runtime_assignment_id: Option<String>,
    /// `oauth2PermissionGrant.id` when this Delegated permission is part of
    /// an admin-consented grant. `None` when only declared.
    #[serde(default)]
    pub runtime_grant_id: Option<String>,
}

/// Outcome of revoking a single delegated scope from an `oauth2PermissionGrant`.
/// `Deleted` means the scope was the last one and the grant itself was removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RevokeScopeOutcome {
    Updated { remaining: String },
    Deleted,
}

/// Outcome of swapping a broad application permission for a narrower one
/// (the least-privilege "Downgrade…" action). Flags report what actually
/// changed against live state — all `false` means there was nothing to do
/// (the broad permission was already gone), so the UI can report honestly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DowngradeOutcome {
    /// A new appRoleAssignment for the narrower permission was created.
    pub narrow_granted: bool,
    /// The broad permission's appRoleAssignment was revoked.
    pub broad_revoked: bool,
    /// `requiredResourceAccess` was patched (broad entry out, narrow entry in).
    pub declaration_swapped: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_permission_round_trips_and_defaults_runtime_ids() {
        let perm = ResolvedPermission {
            resource_app_id: "00000003-0000-0000-c000-000000000000".into(),
            resource_display_name: Some("Microsoft Graph".into()),
            permission_id: "abc-123".into(),
            permission_value: Some("Mail.Read".into()),
            permission_display_name: Some("Read mail".into()),
            permission_kind: PermissionKind::Application,
            runtime_assignment_id: Some("assign-1".into()),
            runtime_grant_id: None,
        };
        let back: ResolvedPermission =
            serde_json::from_str(&serde_json::to_string(&perm).unwrap()).unwrap();
        assert_eq!(back.resource_app_id, perm.resource_app_id);
        assert_eq!(back.permission_kind, PermissionKind::Application);
        assert_eq!(back.runtime_assignment_id.as_deref(), Some("assign-1"));
        assert_eq!(back.runtime_grant_id, None);

        // The two runtime ids carry #[serde(default)], so a "declared only"
        // payload that omits them still deserializes.
        let declared: ResolvedPermission = serde_json::from_str(
            r#"{"resource_app_id":"r","resource_display_name":null,"permission_id":"p",
                "permission_value":null,"permission_display_name":null,
                "permission_kind":"delegated"}"#,
        )
        .unwrap();
        assert_eq!(declared.permission_kind, PermissionKind::Delegated);
        assert_eq!(declared.runtime_assignment_id, None);
        assert_eq!(declared.runtime_grant_id, None);
    }

    #[test]
    fn permission_kind_serializes_camel_case() {
        assert_eq!(
            serde_json::to_value(PermissionKind::Application).unwrap(),
            serde_json::json!("application")
        );
        assert_eq!(
            serde_json::to_value(PermissionKind::Delegated).unwrap(),
            serde_json::json!("delegated")
        );
    }

    #[test]
    fn revoke_scope_outcome_is_internally_tagged() {
        let json = serde_json::to_value(RevokeScopeOutcome::Updated {
            remaining: "Mail.Read".into(),
        })
        .unwrap();
        assert_eq!(json["kind"], "updated");
        assert_eq!(json["remaining"], "Mail.Read");
        match serde_json::from_value(json).unwrap() {
            RevokeScopeOutcome::Updated { remaining } => assert_eq!(remaining, "Mail.Read"),
            RevokeScopeOutcome::Deleted => panic!("expected Updated"),
        }

        let deleted = serde_json::to_value(RevokeScopeOutcome::Deleted).unwrap();
        assert_eq!(deleted["kind"], "deleted");
        assert!(matches!(
            serde_json::from_value(deleted).unwrap(),
            RevokeScopeOutcome::Deleted
        ));
    }
}
