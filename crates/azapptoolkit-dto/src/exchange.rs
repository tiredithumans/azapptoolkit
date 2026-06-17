//! Exchange Online RBAC-for-Applications IPC DTOs.
//!
//! These describe the result of scoping an application's mailbox access via
//! Exchange RBAC (the replacement for Application Access Policies) and of
//! migrating existing policies.

use azapptoolkit_core::audit::MailPermissionScope;
use serde::{Deserialize, Serialize};

/// The effective Exchange-mailbox scoping verdict for one Graph mail permission
/// an application declares. Returned by `get_mail_permission_scopes` so the
/// Permissions tab can show whether each mailbox permission
/// is org-wide or confined to specific mailboxes via RBAC for Applications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailScopeEntry {
    /// The Graph permission value, e.g. `Mail.Send`.
    pub graph_permission: String,
    /// The Exchange application role it maps to, e.g. `Application Mail.Send`.
    pub exchange_role: String,
    pub scope: MailPermissionScope,
}

/// A recipient group used as a scope source, with its resolved
/// `DistinguishedName` (what the `MemberOfGroup` filter references).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeGroupRef {
    /// The identifier the caller supplied (email, name, or GUID).
    pub identifier: String,
    /// `None` if the group could not be resolved in Exchange.
    pub distinguished_name: Option<String>,
}

/// A single Exchange management role assignment for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRoleAssignmentDto {
    pub name: Option<String>,
    pub role: Option<String>,
    pub custom_resource_scope: Option<String>,
    pub identity: Option<String>,
}

/// One member of the toolkit-managed scope group, for the "mailboxes in scope"
/// list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeGroupMemberDto {
    pub display_name: Option<String>,
    pub primary_smtp_address: Option<String>,
    pub recipient_type: Option<String>,
}

/// State of the toolkit-managed scope group (`azapptoolkit_<appId>`) for one
/// principal: whether it exists yet, how to reference it (its SMTP / DN), and
/// its current direct members. Returned by `list_exchange_scope_group`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeScopeGroupDto {
    /// The toolkit naming-convention name, `azapptoolkit_<appId>`.
    pub group_name: String,
    /// `false` until the group has been created (e.g. by adding the first
    /// mailbox).
    pub exists: bool,
    /// Primary SMTP of the group — the most robust identifier to feed into a
    /// scoped grant's `groups` list. `None` until the group exists.
    pub primary_smtp_address: Option<String>,
    /// `DistinguishedName` the `MemberOfGroup` management-scope filter references.
    pub distinguished_name: Option<String>,
    pub members: Vec<ExchangeGroupMemberDto>,
}

/// A mailbox that couldn't be added to / removed from the scope group, with the
/// reason — so a partial failure surfaces per-mailbox instead of aborting the
/// whole batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeMemberFailure {
    pub mailbox: String,
    pub reason: String,
}

/// Outcome of adding or removing scope-group members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeMemberMutationResult {
    pub group_name: String,
    /// `true` when this call created the managed group (add path only).
    pub group_created: bool,
    /// Mailboxes successfully added / removed (by the identifier supplied).
    pub succeeded: Vec<String>,
    pub failed: Vec<ExchangeMemberFailure>,
}

/// Outcome of `grant_exchange_mailbox_access`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeAccessResult {
    pub app_id: String,
    pub service_principal_object_id: Option<String>,
    pub scope_name: String,
    pub scope_filter: String,
    pub groups: Vec<ExchangeGroupRef>,
    /// Exchange application roles that were assigned (e.g. `Application Mail.Read`).
    pub roles_assigned: Vec<String>,
    /// Exchange roles that were already present and therefore skipped.
    pub roles_skipped: Vec<String>,
    /// Unscoped Entra app-role assignments removed so RBAC scoping takes effect
    /// (the Graph permission value, e.g. `Mail.Read`).
    pub removed_entra_grants: Vec<String>,
    pub warnings: Vec<String>,
}

/// Outcome of `remove_exchange_mailbox_access`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeAccessRemovalResult {
    pub app_id: String,
    pub removed_assignments: Vec<String>,
    pub warnings: Vec<String>,
}

/// Per-application result of migrating a legacy Application Access Policy to
/// RBAC for Applications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AapMigrationItem {
    pub app_id: String,
    pub source_policy_identity: Option<String>,
    pub scope_name: Option<String>,
    pub scope_filter: Option<String>,
    pub roles_assigned: Vec<String>,
    pub removed_entra_grants: Vec<String>,
    pub removed_policy: bool,
    /// `planned` for a dry run; `migrated` / `failed` for a real run.
    pub status: String,
    pub warnings: Vec<String>,
}

/// Aggregate report from `migrate_application_access_policies`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AapMigrationReport {
    pub dry_run: bool,
    pub items: Vec<AapMigrationItem>,
    pub failures: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_group_dto_round_trips() {
        let dto = ExchangeScopeGroupDto {
            group_name: "azapptoolkit_app-1".into(),
            exists: true,
            primary_smtp_address: Some("azapptoolkit_app-1@contoso.com".into()),
            distinguished_name: Some("CN=azapptoolkit_app-1,DC=prod".into()),
            members: vec![ExchangeGroupMemberDto {
                display_name: Some("Ada".into()),
                primary_smtp_address: Some("ada@contoso.com".into()),
                recipient_type: Some("UserMailbox".into()),
            }],
        };
        let json = serde_json::to_string(&dto).unwrap();
        // snake_case on the wire (shared crate, no rename) — mirrors the other
        // Exchange DTOs in this module.
        assert!(json.contains("\"group_name\""));
        assert!(json.contains("\"primary_smtp_address\""));
        let back: ExchangeScopeGroupDto = serde_json::from_str(&json).unwrap();
        assert_eq!(back.members.len(), 1);
        assert!(back.exists);
    }

    #[test]
    fn member_mutation_result_round_trips() {
        let dto = ExchangeMemberMutationResult {
            group_name: "azapptoolkit_app-1".into(),
            group_created: true,
            succeeded: vec!["ada@contoso.com".into()],
            failed: vec![ExchangeMemberFailure {
                mailbox: "ghost@contoso.com".into(),
                reason: "couldn't be found".into(),
            }],
        };
        let json = serde_json::to_string(&dto).unwrap();
        let back: ExchangeMemberMutationResult = serde_json::from_str(&json).unwrap();
        assert!(back.group_created);
        assert_eq!(back.succeeded, vec!["ada@contoso.com".to_string()]);
        assert_eq!(back.failed[0].mailbox, "ghost@contoso.com");
    }
}
