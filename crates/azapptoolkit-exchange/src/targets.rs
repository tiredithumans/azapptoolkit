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

/// Extracts the set of group DistinguishedNames quoted in a `MemberOfGroup`
/// OPATH filter (`… -eq 'CN=a,DC=x' -or …`). Lets a caller compare a stored
/// scope filter to a freshly-built one by group *set*, without depending on
/// Exchange's exact whitespace/paren formatting. Handles OPATH's doubled-quote
/// escaping (`''` → `'`).
pub fn group_dns_in_filter(filter: &str) -> HashSet<&str> {
    let mut out = HashSet::new();
    let bytes = filter.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\'' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() {
            if bytes[j] == b'\'' {
                // A doubled '' is an escaped quote inside the value, not a close.
                if bytes.get(j + 1) == Some(&b'\'') {
                    j += 2;
                    continue;
                }
                break;
            }
            j += 1;
        }
        // Only record values with no embedded escaped quote — DNs never contain
        // apostrophes, so a clean slice is the common (and only relevant) case.
        if !filter[start..j].contains("''") {
            out.insert(&filter[start..j]);
        }
        i = j + 1;
    }
    out
}

/// Counts `MemberOfGroup` clauses in an OPATH recipient filter (the number of
/// groups a management scope confines access to).
pub fn count_member_of_group(filter: &str) -> usize {
    filter.to_ascii_lowercase().matches("memberofgroup").count()
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
    fn group_dns_in_filter_extracts_the_dn_set() {
        let f = "RecipientFilter -eq 'CN=a,DC=x' -or MemberOfGroup -eq 'CN=b,DC=x'";
        let got = group_dns_in_filter(f);
        assert!(got.contains("CN=a,DC=x") && got.contains("CN=b,DC=x"));
        assert_eq!(count_member_of_group(f), 1);
    }
}
