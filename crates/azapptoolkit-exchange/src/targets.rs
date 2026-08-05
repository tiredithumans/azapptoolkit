//! Deriving what to scope: turning an application's declared or granted mailbox
//! permissions into concrete Exchange RBAC targets.
//!
//! This is the invariant-bearing half of mailbox scoping, and it is pure — given
//! resolved resource role indexes it needs no `State`, no Tauri, and no live
//! Graph client. It lived inside the Tauri command handler, where the only way
//! to reach it was a signed-in session, so the rules below could be checked by
//! review but not by tests. Two of them had already gone wrong that way: the
//! app-registration entry point scoped an empty target set (pinning a
//! management scope forever), and target derivation once read Microsoft Graph
//! alone, which made the EWS `full_access_as_app` scope invisible and silently
//! widened an app's reach to every mailbox.
//!
//! The load-bearing rule throughout: mailbox permissions live on **two**
//! resources, and both expose appRoles literally named `Mail.Read`. Every target
//! therefore carries its own `(resource, appRole id)` pair, and nothing here
//! keys a decision on a bare permission value.

use std::collections::HashSet;

use azapptoolkit_core::models::{AppRoleAssignment, Application};

use crate::roles::{
    MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID, exchange_role_for_resource_permission,
};

/// One resource's appRole index: its service-principal object id (what an
/// `appRoleAssignment.resourceId` points at) and `appRoleId -> value`.
#[derive(Debug, Clone)]
pub struct ResourceRoles {
    /// The resource's *application* id — the stable well-known GUID, which is
    /// what `azapptoolkit_core::scoping` keys its role map on.
    pub app_id: &'static str,
    /// The resource service principal's object id in *this* tenant.
    pub sp_object_id: String,
    pub role_value_by_id: std::collections::HashMap<String, String>,
}

impl ResourceRoles {
    /// The appRole id for `value` on this resource, if it exposes one.
    fn role_id_for(&self, value: &str) -> Option<&str> {
        self.role_value_by_id
            .iter()
            .find(|(_, v)| v.as_str() == value)
            .map(|(id, _)| id.as_str())
    }
}

/// Looks up which mailbox resource an `appRoleAssignment` was granted on, and
/// the permission value it names: `(resource_app_id, resource_sp_object_id, value)`.
/// `None` when the grant is on some other resource, or names a role this tenant's
/// resource SP doesn't expose.
pub fn resolve_grant<'a>(
    resources: &'a [ResourceRoles],
    resource_sp_id: &str,
    app_role_id: &str,
) -> Option<(&'a str, &'a str, &'a str)> {
    let r = resources
        .iter()
        .find(|r| r.sp_object_id == resource_sp_id)?;
    let value = r.role_value_by_id.get(app_role_id)?;
    Some((r.app_id, r.sp_object_id.as_str(), value.as_str()))
}

/// Resolves a bare permission `value` to the mailbox resource that exposes it:
/// `(resource_app_id, resource_sp_object_id, app_role_id)`. For callers handed a
/// permission list with no resource context (a managed-identity grant form, a
/// caller-supplied value set). Resources are searched in order, so Microsoft
/// Graph wins a name it shares with Office 365 Exchange Online — which is the
/// right precedence: the Graph permission is the one RBAC for Applications can
/// scope.
pub fn resolve_value<'a>(
    resources: &'a [ResourceRoles],
    value: &str,
) -> Option<(&'a str, &'a str, &'a str)> {
    resources.iter().find_map(|r| {
        let role_id = r.role_id_for(value)?;
        Some((r.app_id, r.sp_object_id.as_str(), role_id))
    })
}

/// An Exchange permission the app declares/holds, paired with its Exchange
/// application role and the *exact* Entra app-role grant that backs it — the
/// resource plus the appRole id — so the unscoped grant can be removed without
/// ambiguity.
///
/// The resource is load-bearing: `full_access_as_app` lives on Office 365
/// Exchange Online while every other scopable value lives on Microsoft Graph,
/// and both resources expose appRoles named `Mail.Read`. Keying a strip on the
/// value alone would either miss the grant or remove the wrong one.
#[derive(Debug, Clone)]
pub struct ExchangeTarget {
    /// Permission value, e.g. `Mail.Send` or `full_access_as_app`.
    pub graph_value: String,
    pub exchange_role: &'static str,
    pub app_role_id: String,
    /// Object id of the resource service principal the grant is against.
    pub resource_sp_object_id: String,
}

/// The request resolved no permission RBAC for Applications can confine.
///
/// A distinct type rather than a bare `bool` so a caller cannot accidentally
/// treat "nothing to scope" as success — see [`require_scopable_targets`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoScopablePermission;

/// Builds an [`ExchangeTarget`] for a permission on a known resource, or `None`
/// when that resource doesn't expose it as an Exchange-scopable permission. The
/// single construction point shared by all three target-derivation paths
/// (declared perms, granted assignments, and the managed-identity value list),
/// so the `ExchangeTarget` shape and the scopability check live in one place.
pub fn exchange_target(
    resource_app_id: &str,
    resource_sp_object_id: &str,
    app_role_id: String,
    graph_value: String,
) -> Option<ExchangeTarget> {
    exchange_role_for_resource_permission(resource_app_id, &graph_value).map(|exchange_role| {
        ExchangeTarget {
            graph_value,
            exchange_role,
            app_role_id,
            resource_sp_object_id: resource_sp_object_id.to_string(),
        }
    })
}

/// Fail-closed guard that **both** mailbox-scoping entry points must pass.
///
/// Scoping nothing is not a harmless no-op. With an empty target set the caller
/// still calls `ensure_management_scope`, creating the app's single management
/// scope pinned to the requested group filter while assigning no roles at all.
/// `ensure_management_scope` then keeps that EXISTING scope as-is rather than
/// rewriting its filter, so every later *correct* scoping request for the app
/// can only warn that its groups were not applied — an unrecoverable mis-scope
/// produced by a request that scoped nothing.
///
/// The two entry points diverged here once (one returned an error, the other
/// pushed a warning and carried on); sharing the guard is what stops them
/// drifting again.
pub fn require_scopable_targets(targets: &[ExchangeTarget]) -> Result<(), NoScopablePermission> {
    if targets.is_empty() {
        return Err(NoScopablePermission);
    }
    Ok(())
}

/// Targets derived from the app's *declared* permissions
/// (`requiredResourceAccess`), across **every** mailbox-bearing resource — not
/// Microsoft Graph alone, or a declared EWS `full_access_as_app` would be
/// silently unscopable.
pub fn targets_from_declared(
    app: &Application,
    resources: &[ResourceRoles],
) -> Vec<ExchangeTarget> {
    let mut out = Vec::new();
    for declared in &app.required_resource_access {
        let Some(resource) = resources
            .iter()
            .find(|r| r.app_id == declared.resource_app_id)
        else {
            continue;
        };
        for access in &declared.resource_access {
            if access.r#type != "Role" {
                continue;
            }
            if let Some(value) = resource.role_value_by_id.get(&access.id)
                && let Some(t) = exchange_target(
                    resource.app_id,
                    &resource.sp_object_id,
                    access.id.clone(),
                    value.clone(),
                )
            {
                out.push(t);
            }
        }
    }
    out
}

/// Targets derived from the app's *granted* Entra app-role assignments, across
/// **every** mailbox-bearing resource. Used during migration, where the app
/// already holds org-wide grants.
pub fn targets_from_grants(
    assignments: &[AppRoleAssignment],
    resources: &[ResourceRoles],
) -> Vec<ExchangeTarget> {
    let mut out = Vec::new();
    for a in assignments {
        if let Some((resource_app_id, resource_sp_id, value)) =
            resolve_grant(resources, &a.resource_id, &a.app_role_id)
            && let Some(t) = exchange_target(
                resource_app_id,
                resource_sp_id,
                a.app_role_id.clone(),
                value.to_string(),
            )
        {
            out.push(t);
        }
    }
    out
}

/// Narrows `targets` to the requested permission values. `None` keeps every
/// target (scope all declared mail permissions); `Some` keeps only those whose
/// `graph_value` is listed — the per-permission "scope this one permission"
/// path. An empty `Some` list therefore retains nothing.
pub fn filter_targets_by_value(
    targets: Vec<ExchangeTarget>,
    only: Option<&[String]>,
) -> Vec<ExchangeTarget> {
    match only {
        None => targets,
        Some(values) => {
            let set: HashSet<&str> = values.iter().map(String::as_str).collect();
            targets
                .into_iter()
                .filter(|t| set.contains(t.graph_value.as_str()))
                .collect()
        }
    }
}

/// Given each target paired with whether its scoped Exchange role is now in place
/// (newly assigned **or** already present), returns the subset whose org-wide
/// Entra grant is safe to strip. A target whose scoped role assignment *failed*
/// is excluded, so the broad grant is never removed out from under a principal
/// that has no scoped replacement — the Exchange analogue of SharePoint's
/// `should_remove_orgwide` grant-before-strip guard.
pub fn targets_safe_to_strip(scoped: Vec<(ExchangeTarget, bool)>) -> Vec<ExchangeTarget> {
    scoped
        .into_iter()
        .filter_map(|(t, role_in_place)| role_in_place.then_some(t))
        .collect()
}

/// Whether the resource resolution saw **both** mailbox-bearing resources.
/// Gates the fail-closed branch of [`policies_safe_to_remove`]: an Application
/// Access Policy can confine grants on either, so a partial view cannot prove a
/// policy governs nothing.
pub fn mailbox_resources_complete(resources: &[ResourceRoles]) -> bool {
    [MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID]
        .iter()
        .all(|id| resources.iter().any(|r| r.app_id == *id))
}

/// Whether the legacy Application Access Policies for an app may be deleted.
///
/// Fail-closed on an unverifiable view: Office 365 Exchange Online resolves
/// best-effort, so an empty target set read as "this policy governs nothing"
/// when in truth we may simply not have looked at the resource whose grant it
/// confines. "Delete" would then remove the only thing confining that grant,
/// widening the app to every mailbox in the tenant. An empty target set is
/// trustworthy only when we know we looked at every resource an AAP can
/// constrain.
pub fn policies_safe_to_remove(
    target_count: usize,
    removed_grant_count: usize,
    resources_complete: bool,
) -> bool {
    if !resources_complete {
        return false;
    }
    target_count == 0 || removed_grant_count == target_count
}

/// One `MemberOfGroup -eq '…'` comparison located in an OPATH filter: the byte
/// range it occupies, and the group DN it names with escaping undone.
struct MemberClause {
    span: (usize, usize),
    dn: String,
}

/// Reads the OPATH single-quoted literal whose opening quote sits at `open`,
/// undoing the `''` escape. Returns the decoded value and the index one past
/// the closing quote, or `None` if the literal is unterminated.
fn read_opath_literal(s: &str, open: usize) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut i = open + 1;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            // A doubled '' is an escaped quote inside the value, not a close.
            if bytes.get(i + 1) == Some(&b'\'') {
                out.push('\'');
                i += 2;
                continue;
            }
            return Some((out, i + 1));
        }
        let ch = s[i..].chars().next()?;
        out.push(ch);
        i += ch.len_utf8();
    }
    None
}

/// Locates every `MemberOfGroup -eq '…'` comparison in an OPATH filter.
///
/// Deliberately narrow: it matches the property, the `-eq` operator and the
/// quoted operand, so a quoted literal belonging to some *other* property is
/// not mistaken for a group DN. Reading any quoted string as a group DN is what
/// let `RecipientTypeDetails -eq 'UserMailbox'` be re-emitted as a
/// `MemberOfGroup` clause, which both widened the scope and dropped the
/// restriction it came from.
fn member_of_group_clauses(filter: &str) -> Vec<MemberClause> {
    const KEY: &str = "memberofgroup";
    let lower = filter.to_ascii_lowercase();
    let bytes = filter.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(KEY) {
        let start = from + rel;
        let mut i = start + KEY.len();
        from = i;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if !lower[i..].starts_with("-eq") {
            continue;
        }
        i += "-eq".len();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b'\'') {
            continue;
        }
        let Some((dn, end)) = read_opath_literal(filter, i) else {
            continue;
        };
        out.push(MemberClause {
            span: (start, end),
            dn,
        });
        from = end;
    }
    out
}

/// The groups a management scope's recipient filter confines access to.
///
/// `complete` is the load-bearing field: `false` means the filter holds a
/// `MemberOfGroup` token this parser could not read as a plain `-eq` operand,
/// so `dns` is a *partial* view. A caller asking "does this filter reference
/// group X" must treat an incomplete answer as "it might" — the empty set means
/// "no reference" only when the filter was fully understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeGroups {
    pub dns: HashSet<String>,
    pub complete: bool,
}

/// Parses a management scope's recipient filter into the group DNs it names.
/// Handles OPATH's doubled-quote escaping (`''` → `'`), so a group whose DN
/// contains an apostrophe round-trips through
/// [`member_of_group_filter`](crate::member_of_group_filter) rather than
/// vanishing.
pub fn scope_groups_in_filter(filter: &str) -> ScopeGroups {
    let clauses = member_of_group_clauses(filter);
    ScopeGroups {
        complete: clauses.len() == count_member_of_group(filter),
        dns: clauses.into_iter().map(|c| c.dn).collect(),
    }
}

/// The group DNs a filter names, for callers that only compare one filter's
/// group *set* to another's without depending on Exchange's exact
/// whitespace/paren formatting. Use [`scope_groups_in_filter`] where a missing
/// DN would be read as an absence of reference.
pub fn group_dns_in_filter(filter: &str) -> HashSet<String> {
    scope_groups_in_filter(filter).dns
}

/// Counts `MemberOfGroup` clauses in an OPATH recipient filter (the number of
/// groups a management scope confines access to).
pub fn count_member_of_group(filter: &str) -> usize {
    filter.to_ascii_lowercase().matches("memberofgroup").count()
}

/// Why a stored recipient filter cannot be rewritten from a list of group DNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnrewritableFilter {
    /// Not built from group membership at all, so its mailboxes can't be
    /// copied into a group.
    NoGroupClauses,
    /// A `MemberOfGroup` token that isn't a plain `-eq '…'` comparison.
    UnparsedClause,
    /// Something beyond `MemberOfGroup` clauses OR-ed together — an `-and`
    /// restriction, a `-not` exclusion, or a condition on another property.
    UnsupportedClause { leftover: String },
}

impl std::fmt::Display for UnrewritableFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoGroupClauses => f.write_str("it isn't built from group membership"),
            Self::UnparsedClause => f.write_str(
                "it uses a MemberOfGroup comparison this toolkit can't read (only `-eq 'DN'` is understood)",
            ),
            Self::UnsupportedClause { leftover } => write!(
                f,
                "it combines group membership with conditions this toolkit can't preserve ({leftover})",
            ),
        }
    }
}

/// The group DNs a scope filter confines access to — or a refusal when the
/// filter is anything other than `MemberOfGroup` comparisons OR-ed together.
///
/// **Fail closed.** Rewriting a scope means writing a *new* filter from this DN
/// list, and Exchange applies a management scope's filter to **every** role
/// assignment on it. Any clause not modelled here — an `-and` recipient-type
/// restriction, a `-not` exclusion, a hand-written condition — would be dropped
/// by that rewrite, and the app's mailbox reach would widen silently in the one
/// product area whose entire purpose is narrowing it. Refusing is the correct
/// outcome, not a fallback: the scope keeps working exactly as it is.
pub fn rewritable_scope_dns(filter: &str) -> Result<Vec<String>, UnrewritableFilter> {
    let clauses = member_of_group_clauses(filter);
    if clauses.is_empty() {
        return Err(UnrewritableFilter::NoGroupClauses);
    }
    if clauses.len() != count_member_of_group(filter) {
        return Err(UnrewritableFilter::UnparsedClause);
    }
    // Blank out the clauses we understand; whatever survives is a clause we
    // would silently drop on rewrite.
    let mut residue = String::with_capacity(filter.len());
    let mut cursor = 0usize;
    for c in &clauses {
        residue.push_str(&filter[cursor..c.span.0]);
        cursor = c.span.1;
    }
    residue.push_str(&filter[cursor..]);
    let leftover: String = residue
        .to_ascii_lowercase()
        .replace("-or", " ")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '(' && *c != ')')
        .collect();
    if !leftover.is_empty() {
        return Err(UnrewritableFilter::UnsupportedClause { leftover });
    }
    let mut dns: Vec<String> = clauses.into_iter().map(|c| c.dn).collect();
    dns.sort();
    dns.dedup();
    Ok(dns)
}

/// A consolidation the caller may apply: the group DNs the scope filter should
/// name afterwards, and whether that differs from what it names today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsolidationPlan {
    pub scope_dns: Vec<String>,
    pub repoint: bool,
}

/// Why a consolidation was refused. Every variant leaves the scope exactly as
/// it is, so nothing the app can reach changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The stored filter is a shape a rewrite would not preserve.
    Filter(UnrewritableFilter),
    /// Source groups whose membership could not be read. An **empty** group
    /// counts as unreadable: `Get-DistributionGroupMember` is also silent for a
    /// Microsoft 365 group (its members need `Get-UnifiedGroupLinks`), and
    /// consolidating that onto an empty managed group would cut the app off
    /// from every mailbox at once.
    UnreadableSourceGroups(Vec<String>),
    /// The toolkit-managed group's DN could not be resolved.
    ManagedGroupUnresolved,
    /// Source members not verified present in the managed group after the copy
    /// — an add that failed, or one that reported success but didn't land
    /// (EXO silently ignores some recipient types).
    UnverifiedMembers(usize),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filter(why) => {
                write!(f, "the management scope's filter can't be rewritten: {why}")
            }
            Self::UnreadableSourceGroups(groups) => write!(
                f,
                "the membership of {} couldn't be read (an empty result is treated as unreadable, \
                 not as \"no mailboxes\")",
                groups.join(", "),
            ),
            Self::ManagedGroupUnresolved => {
                f.write_str("the toolkit-managed group's distinguished name couldn't be resolved")
            }
            Self::UnverifiedMembers(n) => write!(
                f,
                "{n} mailbox(es) couldn't be verified present in the toolkit-managed group",
            ),
        }
    }
}

/// Decides — fail closed — whether a management scope may be repointed at the
/// toolkit-managed group, and what its filter should then name.
///
/// The scope only moves once **all four** hold: the current filter is a shape a
/// rewrite preserves exactly, every source group's membership was readable, the
/// managed group's DN resolved, and every source member is *verified present*
/// in it. Otherwise the scope keeps its current filter.
///
/// The asymmetry is deliberate in both directions. Repointing at a
/// partially-populated group silently drops mailboxes out of the app's reach,
/// and a mailbox an integration can no longer read fails as "not found" rather
/// than "denied" — the hardest kind of outage to trace back to a permission
/// change. Rewriting a filter whose other clauses we cannot reproduce widens
/// reach instead. Both are refusals, not fallbacks.
///
/// `current_filter` is re-parsed here rather than taken as a DN list, so the
/// plan can never disagree with the filter that is about to be overwritten.
pub fn plan_consolidation(
    current_filter: &str,
    managed_dn: Option<&str>,
    unreadable_source_groups: &[String],
    unverified_members: usize,
) -> Result<ConsolidationPlan, Refusal> {
    let source_dns = rewritable_scope_dns(current_filter).map_err(Refusal::Filter)?;
    if !unreadable_source_groups.is_empty() {
        return Err(Refusal::UnreadableSourceGroups(
            unreadable_source_groups.to_vec(),
        ));
    }
    let Some(managed_dn) = managed_dn else {
        return Err(Refusal::ManagedGroupUnresolved);
    };
    if unverified_members > 0 {
        return Err(Refusal::UnverifiedMembers(unverified_members));
    }
    Ok(ConsolidationPlan {
        repoint: !(source_dns.len() == 1 && source_dns[0] == managed_dn),
        scope_dns: vec![managed_dn.to_string()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::EWS_FULL_ACCESS_AS_APP;
    use azapptoolkit_core::models::{RequiredResourceAccess, ResourceAccess};
    use std::collections::HashMap;

    fn target(value: &str) -> ExchangeTarget {
        ExchangeTarget {
            graph_value: value.to_string(),
            exchange_role: "Application Mail.Read",
            app_role_id: "role-id".to_string(),
            resource_sp_object_id: "graph-sp".to_string(),
        }
    }

    /// The two mailbox resources as they resolve in a tenant, with one appRole
    /// each keyed `role-<value>`.
    fn mailbox_resources() -> Vec<ResourceRoles> {
        let index = |values: &[&str]| -> HashMap<String, String> {
            values
                .iter()
                .map(|v| (format!("role-{v}"), v.to_string()))
                .collect()
        };
        vec![
            ResourceRoles {
                app_id: MICROSOFT_GRAPH_APP_ID,
                sp_object_id: "graph-sp".to_string(),
                role_value_by_id: index(&["Mail.Read", "Mail.Send", "User.Read.All"]),
            },
            ResourceRoles {
                app_id: OFFICE365_EXCHANGE_ONLINE_APP_ID,
                sp_object_id: "exo-sp".to_string(),
                // The legacy resource exposes the EWS scope AND its own
                // Outlook-REST `Mail.Read` appRole (a different GUID).
                role_value_by_id: [
                    (
                        format!("exo-role-{EWS_FULL_ACCESS_AS_APP}"),
                        EWS_FULL_ACCESS_AS_APP.to_string(),
                    ),
                    ("exo-role-Mail.Read".to_string(), "Mail.Read".to_string()),
                ]
                .into(),
            },
        ]
    }

    fn declared(resource_app_id: &str, role_ids: &[&str]) -> RequiredResourceAccess {
        RequiredResourceAccess {
            resource_app_id: resource_app_id.to_string(),
            resource_access: role_ids
                .iter()
                .map(|id| ResourceAccess {
                    id: id.to_string(),
                    r#type: "Role".to_string(),
                })
                .collect(),
        }
    }

    fn values(targets: &[ExchangeTarget]) -> Vec<&str> {
        targets.iter().map(|t| t.graph_value.as_str()).collect()
    }

    #[test]
    fn empty_target_set_is_refused() {
        // Regression: the app-registration entry point used to push a warning
        // and carry on, which pinned the app's one management scope to that
        // group set forever — a later correct request keeps the existing scope
        // and only warns.
        assert_eq!(
            require_scopable_targets(&[]),
            Err(NoScopablePermission),
            "an empty target set must fail closed"
        );
        assert!(require_scopable_targets(&[target("Mail.Read")]).is_ok());
    }

    #[test]
    fn declared_targets_span_graph_and_the_legacy_ews_scope() {
        let app = Application {
            required_resource_access: vec![
                declared(MICROSOFT_GRAPH_APP_ID, &["role-Mail.Read"]),
                declared(
                    OFFICE365_EXCHANGE_ONLINE_APP_ID,
                    &[&format!("exo-role-{EWS_FULL_ACCESS_AS_APP}")],
                ),
            ],
            ..Default::default()
        };
        let targets = targets_from_declared(&app, &mailbox_resources());
        let mut got = values(&targets);
        got.sort_unstable();
        // ASCII sort: uppercase `M` sorts before lowercase `f`.
        assert_eq!(got, vec!["Mail.Read", EWS_FULL_ACCESS_AS_APP]);
    }

    #[test]
    fn declared_targets_skip_the_legacy_resources_own_mail_roles() {
        // Office 365 Exchange Online's own `Mail.Read` appRole (retired Outlook
        // REST) has no RBAC counterpart, so it is not a scopable target — only
        // the EWS scope is, on that resource.
        let app = Application {
            required_resource_access: vec![declared(
                OFFICE365_EXCHANGE_ONLINE_APP_ID,
                &["exo-role-Mail.Read"],
            )],
            ..Default::default()
        };
        assert!(
            targets_from_declared(&app, &mailbox_resources()).is_empty(),
            "the legacy resource's Mail.Read is not RBAC-confinable"
        );
    }

    #[test]
    fn a_non_mail_permission_resolves_no_target() {
        // The precondition that trips the fail-closed guard.
        let app = Application {
            required_resource_access: vec![declared(
                MICROSOFT_GRAPH_APP_ID,
                &["role-User.Read.All"],
            )],
            ..Default::default()
        };
        assert!(targets_from_declared(&app, &mailbox_resources()).is_empty());
    }

    #[test]
    fn granted_targets_keep_the_two_resources_apart() {
        // Both resources expose an appRole named Mail.Read; a grant must resolve
        // against the resource it was actually made on.
        let grants = vec![
            AppRoleAssignment {
                id: "a1".into(),
                resource_id: "graph-sp".into(),
                app_role_id: "role-Mail.Read".into(),
                ..Default::default()
            },
            AppRoleAssignment {
                id: "a2".into(),
                resource_id: "exo-sp".into(),
                app_role_id: format!("exo-role-{EWS_FULL_ACCESS_AS_APP}"),
                ..Default::default()
            },
        ];
        let targets = targets_from_grants(&grants, &mailbox_resources());
        let mut got: Vec<&str> = targets
            .iter()
            .map(|t| t.resource_sp_object_id.as_str())
            .collect();
        got.sort_unstable();
        assert_eq!(got, vec!["exo-sp", "graph-sp"]);
    }

    #[test]
    fn only_targets_whose_scoped_role_landed_may_be_stripped() {
        let stripped = targets_safe_to_strip(vec![
            (target("Mail.Read"), true),
            (target("Mail.Send"), false),
        ]);
        assert_eq!(
            values(&stripped),
            vec!["Mail.Read"],
            "a failed scoped assignment must keep its org-wide grant"
        );
    }

    #[test]
    fn filter_some_keeps_only_requested() {
        let all = vec![target("Mail.Read"), target("Mail.Send")];
        let only = ["Mail.Send".to_string()];
        assert_eq!(
            values(&filter_targets_by_value(all.clone(), Some(&only))),
            vec!["Mail.Send"]
        );
        assert_eq!(values(&filter_targets_by_value(all, None)).len(), 2);
    }

    #[test]
    fn policies_are_never_removed_on_an_unverifiable_resource_view() {
        // The fail-closed rule: an empty target set means "governs nothing" ONLY
        // when both mailbox resources actually resolved.
        assert!(!policies_safe_to_remove(0, 0, false));
        assert!(policies_safe_to_remove(0, 0, true));
        assert!(policies_safe_to_remove(2, 2, true));
        assert!(!policies_safe_to_remove(2, 1, true));
    }

    #[test]
    fn resource_completeness_requires_both_mailbox_resources() {
        assert!(mailbox_resources_complete(&mailbox_resources()));
        assert!(!mailbox_resources_complete(&mailbox_resources()[..1]));
    }

    #[test]
    fn only_member_of_group_operands_are_read_as_group_dns() {
        // A quoted literal belonging to another property is NOT a group DN.
        // Reading it as one re-emitted `RecipientTypeDetails -eq 'UserMailbox'`
        // as a MemberOfGroup clause on rewrite — widening the scope and
        // dropping the restriction it came from.
        let f = "RecipientTypeDetails -eq 'UserMailbox' -and MemberOfGroup -eq 'CN=b,DC=x'";
        let got = group_dns_in_filter(f);
        assert_eq!(got, HashSet::from(["CN=b,DC=x".to_string()]));
        assert_eq!(count_member_of_group(f), 1);
    }

    #[test]
    fn a_dn_containing_an_apostrophe_round_trips_through_the_filter() {
        // `escape_opath` writes `''`; the scanner used to SKIP any value
        // containing one. That hid a live reference from the irreversible
        // group-delete check and silently shrank a scope on move.
        let dns = vec!["CN=O'Brien Mailboxes,OU=Groups,DC=x".to_string()];
        let filter = crate::client::member_of_group_filter(&dns);
        assert!(filter.contains("O''Brien"), "escaping must be exercised");
        assert_eq!(
            group_dns_in_filter(&filter),
            HashSet::from([dns[0].clone()])
        );
        assert_eq!(rewritable_scope_dns(&filter).unwrap(), dns);
        assert!(scope_groups_in_filter(&filter).complete);
    }

    #[test]
    fn a_pure_or_chain_is_rewritable_whatever_its_formatting() {
        let dns = vec!["CN=a,DC=x".to_string(), "CN=b,DC=y".to_string()];
        assert_eq!(
            rewritable_scope_dns(&crate::client::member_of_group_filter(&dns)).unwrap(),
            dns
        );
        assert_eq!(
            rewritable_scope_dns(
                "( MemberOfGroup -eq 'CN=a,DC=x' )  -Or ( MemberOfGroup -eq 'CN=b,DC=y' )"
            )
            .unwrap(),
            dns
        );
    }

    #[test]
    fn a_filter_a_rewrite_would_not_preserve_is_refused() {
        // Each of these silently WIDENS if rebuilt as a pure OR-chain.
        for (filter, why) in [
            (
                "MemberOfGroup -eq 'CN=a,DC=x' -and RecipientTypeDetails -eq 'UserMailbox'",
                "an -and restriction",
            ),
            ("-not (MemberOfGroup -eq 'CN=a,DC=x')", "a -not exclusion"),
            (
                "MemberOfGroup -eq 'CN=a,DC=x' -or CustomAttribute1 -eq 'keep'",
                "a condition on another property",
            ),
            (
                "MemberOfGroup -like 'CN=a*'",
                "a MemberOfGroup comparison that isn't -eq",
            ),
        ] {
            assert!(
                rewritable_scope_dns(filter).is_err(),
                "{why} must refuse the rewrite, not be dropped from it: {filter}"
            );
        }
        assert_eq!(
            rewritable_scope_dns("RecipientTypeDetails -eq 'UserMailbox'"),
            Err(UnrewritableFilter::NoGroupClauses)
        );
    }

    #[test]
    fn an_unreadable_member_of_group_clause_marks_the_parse_incomplete() {
        // `complete: false` is what stops an empty/partial DN set from reading
        // as "this filter doesn't reference the group".
        let got = scope_groups_in_filter("MemberOfGroup -like 'CN=a*'");
        assert!(got.dns.is_empty());
        assert!(
            !got.complete,
            "a MemberOfGroup token we can't read must not report a clean absence"
        );
    }

    fn managed() -> Option<&'static str> {
        Some("CN=Managed,DC=x")
    }

    #[test]
    fn consolidation_repoints_only_on_a_fully_verified_copy() {
        let legacy = crate::client::member_of_group_filter(&["CN=Legacy,DC=x".to_string()]);
        assert_eq!(
            plan_consolidation(&legacy, managed(), &[], 0).unwrap(),
            ConsolidationPlan {
                scope_dns: vec!["CN=Managed,DC=x".to_string()],
                repoint: true,
            },
        );
    }

    #[test]
    fn consolidation_is_refused_on_anything_unproved() {
        // Fail closed: one mailbox that didn't make it into the managed group
        // means repointing would cut it out of the app's reach.
        let legacy = crate::client::member_of_group_filter(&["CN=Legacy,DC=x".to_string()]);
        assert_eq!(
            plan_consolidation(&legacy, managed(), &[], 1),
            Err(Refusal::UnverifiedMembers(1)),
            "an unverified member must leave the scope alone"
        );
        assert_eq!(
            plan_consolidation(&legacy, None, &[], 0),
            Err(Refusal::ManagedGroupUnresolved),
            "an unresolved managed-group DN must leave the scope alone"
        );
        assert_eq!(
            plan_consolidation(&legacy, managed(), &["CN=Legacy,DC=x".to_string()], 0),
            Err(Refusal::UnreadableSourceGroups(vec![
                "CN=Legacy,DC=x".to_string()
            ])),
            "an unreadable (or empty) source group must leave the scope alone"
        );
        assert!(
            matches!(
                plan_consolidation(
                    "MemberOfGroup -eq 'CN=Legacy,DC=x' -and RecipientTypeDetails -eq 'UserMailbox'",
                    managed(),
                    &[],
                    0,
                ),
                Err(Refusal::Filter(_))
            ),
            "a filter the rewrite would not preserve must leave the scope alone"
        );
    }

    #[test]
    fn consolidation_folds_several_source_groups_into_one() {
        // Several RestrictAccess policies migrate as a union; consolidating that
        // union onto the managed group collapses the filter to a single clause.
        let legacy = crate::client::member_of_group_filter(&[
            "CN=A,DC=x".to_string(),
            "CN=B,DC=x".to_string(),
        ]);
        let plan = plan_consolidation(&legacy, managed(), &[], 0).unwrap();
        assert_eq!(plan.scope_dns.len(), 1);
        assert_eq!(
            count_member_of_group(&crate::client::member_of_group_filter(&plan.scope_dns)),
            1
        );
    }

    #[test]
    fn consolidation_is_a_no_op_when_the_scope_is_already_managed() {
        let already = crate::client::member_of_group_filter(&["CN=Managed,DC=x".to_string()]);
        let plan = plan_consolidation(&already, managed(), &[], 0).unwrap();
        assert!(!plan.repoint, "no rewrite when the scope already names it");
    }
}
