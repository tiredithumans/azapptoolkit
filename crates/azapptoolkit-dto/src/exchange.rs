//! Exchange Online RBAC-for-Applications IPC DTOs.
//!
//! These describe the result of scoping an application's mailbox access via
//! Exchange RBAC (the replacement for Application Access Policies) and of
//! migrating existing policies.

use azapptoolkit_core::audit::MailPermissionScope;
use serde::{Deserialize, Serialize};

/// One application permission a principal holds, **with the resource that
/// exposes it** — the input to `get_mail_scopes_for_principal`.
///
/// The resource is not decoration. Mailbox permissions live on two resources
/// (Microsoft Graph and the legacy Office 365 Exchange Online), both expose
/// appRoles literally named `Mail.*`, and only Graph's are confinable — plus the
/// EWS `full_access_as_app` scope, which exists *only* on the Office 365
/// resource. So neither "assume Graph" nor "match on the value" is right.
///
/// This crossed IPC as a bare `Vec<String>`, with the backend re-deriving
/// scopability from the value alone. Both front-end callers happened to
/// pre-filter resource-aware, so the shipped behaviour was correct — but the
/// command is a public IPC entry point, and the value-only gate would have
/// accepted an Office 365 `Mail.Read` as scopable and reported a mailbox
/// confinement that does not exist for it. AGENTS.md: carry the resource, never
/// the bare value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalPermission {
    pub resource_app_id: String,
    pub value: String,
}

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

/// State of the toolkit-managed scope group (by default
/// `app_scope_group_<appId>`) for one principal: whether it exists yet, how to
/// reference it (its SMTP / DN), and its current direct members. Returned by
/// `list_exchange_scope_group`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeScopeGroupDto {
    /// The resolved toolkit naming-convention name (the tenant's
    /// `group_name_pattern`, default `app_scope_group_<appId>`).
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

/// A group a consolidation left behind: the scope no longer references it, so
/// it is the operator's cleanup candidate.
///
/// **`still_referenced_by` being empty does NOT mean the group is unused.** It
/// means the toolkit found no reference in the two places it can actually
/// enumerate — other management scopes' recipient filters and legacy
/// Application Access Policies. Exchange offers no reverse lookup for the rest:
/// transport rules, DLP/retention policies, people and systems that simply mail
/// the address, nesting inside other groups, or anything outside Exchange.
/// Deleting a distribution group is not reversible, so the UI states that limit
/// and the delete stays an explicit, separately confirmed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetiredScopeGroupDto {
    /// The group's `Name`, when it resolved.
    pub display_name: Option<String>,
    pub primary_smtp_address: Option<String>,
    /// What the old scope filter referenced — always present, since that is how
    /// the group was found in the first place.
    pub distinguished_name: String,
    /// Human-readable references the toolkit *did* find, e.g.
    /// `management scope 'app_scope_other-app'`. Non-empty ⇒ do not delete.
    pub still_referenced_by: Vec<String>,
    /// `false` when a reference check itself failed (the answer is UNKNOWN, not
    /// "clean") — the delete affordance is withheld either way.
    pub reference_check_complete: bool,
}

/// Per-application result of migrating legacy Application Access Policies to
/// RBAC for Applications.
///
/// One item per **application**, not per policy: an app can carry several
/// `RestrictAccess` policies, whose combined effect is access to the union of
/// their groups, so they migrate into ONE management scope spanning every group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AapMigrationItem {
    pub app_id: String,
    /// Identities of every policy folded into this app's migration.
    pub source_policy_identities: Vec<String>,
    pub scope_name: Option<String>,
    /// The scope's filter as it stands after the run (a dry run changes
    /// nothing, so it reports the filter in effect today).
    pub scope_filter: Option<String>,
    /// The toolkit-managed group the legacy group's mailboxes are consolidated
    /// onto, so the old group can be retired.
    pub managed_group_name: Option<String>,
    /// Mailboxes copied into the managed group (dry run: that would be copied).
    pub members_copied: Vec<String>,
    /// Mailboxes that could NOT be verified in the managed group. Non-empty
    /// means the scope was deliberately left on its legacy group(s) rather than
    /// narrowed to an incomplete copy — see `scope_dns_after_consolidation`.
    pub members_unverified: Vec<String>,
    pub roles_assigned: Vec<String>,
    pub removed_entra_grants: Vec<String>,
    /// Identities of the policies actually deleted. Empty when the policies were
    /// deliberately **kept** — they still confine the app's org-wide grants, so
    /// deleting one whose permissions weren't fully re-scoped would widen access.
    pub removed_policies: Vec<String>,
    /// The legacy policy group(s) the new management scope no longer references
    /// — named so the operator knows exactly what is left to clean up. Empty
    /// unless the consolidation actually repointed the scope. Note a kept policy
    /// still references its group, which shows up in `still_referenced_by`.
    #[serde(default)]
    pub retired_groups: Vec<RetiredScopeGroupDto>,
    /// `planned` for a dry run; `migrated` / `partial` / `failed` for a real run.
    pub status: String,
    pub warnings: Vec<String>,
}

/// Outcome of `move_exchange_scope_to_managed_group` — consolidating an
/// already-scoped app onto the toolkit-managed group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeScopeConsolidationResult {
    pub app_id: String,
    pub scope_name: String,
    pub group_name: String,
    /// The scope's filter before the move.
    pub previous_filter: Option<String>,
    /// The filter after it — equal to `previous_filter` unless `repointed`.
    pub scope_filter: Option<String>,
    /// Mailboxes copied into the managed group (dry run: that would be copied).
    pub members_copied: Vec<String>,
    /// Mailboxes that couldn't be verified in the managed group. Non-empty
    /// means the scope kept its previous filter rather than narrowing.
    pub members_unverified: Vec<String>,
    /// `true` only when the management scope now names the managed group.
    pub repointed: bool,
    /// The group(s) the scope pointed at before the move — the cleanup
    /// candidates, named rather than left as "the previous group". Empty unless
    /// `repointed`: while the scope still references them they are in use by
    /// definition.
    #[serde(default)]
    pub retired_groups: Vec<RetiredScopeGroupDto>,
    pub dry_run: bool,
    pub warnings: Vec<String>,
}

/// Aggregate report from `migrate_application_access_policies`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AapMigrationReport {
    pub dry_run: bool,
    pub items: Vec<AapMigrationItem>,
    pub failures: Vec<String>,
    /// The run stopped before every app was processed — the operator cancelled,
    /// or the session died partway.
    ///
    /// A whole-tenant migration that stopped early has left some apps on their
    /// legacy policies, so a report without this flag reads as "every app is
    /// migrated" when it means "the apps listed are". Same rule the audit and DR
    /// reports follow: a partial run is never presented as a complete one.
    #[serde(default)]
    pub incomplete: bool,
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
