//! Which Exchange objects still reference a group — the check behind
//! "is this retired scope group safe to delete?".
//!
//! Pure, like its siblings in this crate: it takes the enumerated management
//! scopes and Application Access Policies and returns reference strings. It
//! lived in the Tauri command layer, which is where `e853205` began moving the
//! mailbox-scope *decisions* out of; this is the same move for the reference
//! matching, so every pure Exchange decision now sits beside the others
//! (`targets`, `verdict`, `aap`) rather than half here and half in a 2871-line
//! command file.
//!
//! **Fail closed.** Reporting a reference only ever WITHHOLDS an irreversible
//! delete, so an unreadable filter counts as a possible reference. What this
//! cannot see is the important part — transport rules, DLP/retention policies,
//! group nesting, anything outside Exchange, and humans who simply mail the
//! address — so an empty result means "no reference the toolkit can enumerate",
//! never "safe to delete".

use crate::models::{ExoApplicationAccessPolicy, ExoManagementScope};
use crate::targets::scope_groups_in_filter;

/// The identifiers one group answers to, for reference matching: Exchange
/// records a group's DN in a management-scope filter but its *name* (or a
/// canonical identity) in an Application Access Policy, so a single key can't
/// match both.
#[derive(Debug, Default)]
pub struct GroupIdentity {
    pub distinguished_name: String,
    pub name: Option<String>,
    pub primary_smtp_address: Option<String>,
}

impl GroupIdentity {
    /// Case-insensitive match against any identifier this group answers to.
    pub fn matches(&self, candidate: &str) -> bool {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            return false;
        }
        [
            Some(self.distinguished_name.as_str()),
            self.name.as_deref(),
            self.primary_smtp_address.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|id| id.eq_ignore_ascii_case(candidate))
    }
}

/// Everything that still references `group`, as far as Exchange lets us ask —
/// pure, so the matching rules are unit-testable without a live tenant.
///
/// Two enumerable authorities: **management scopes** (matched on the group DN in
/// their `MemberOfGroup` filter) and **legacy Application Access Policies**
/// (matched on `ScopeName`/`ScopeIdentity`, which carry the group *name*).
///
/// **The calling app's own scope is NOT excluded**, deliberately. It is read
/// after the repoint, so normally it no longer names the group — but the
/// migration skips its repoint when an operator-supplied `scope_name` override
/// may be shared with other apps, and `ensure_management_scope` is create-only,
/// so a pre-existing scope can still point at the legacy group. Excluding it by
/// name reported that group as unreferenced and offered to delete a group the
/// app was still scoped to. Reporting a scope that hasn't caught up yet only
/// *withholds* the delete, which is the safe direction.
///
/// What this can NOT see is the important part, and the UI says so: transport
/// rules, DLP/retention policies, nesting inside other groups, anything outside
/// Exchange, and — the common case — humans and systems that simply send mail to
/// the address. An empty result is "no reference the toolkit can enumerate",
/// never "safe to delete".
pub fn references_to_group(
    group: &GroupIdentity,
    scopes: &[ExoManagementScope],
    policies: &[ExoApplicationAccessPolicy],
) -> Vec<String> {
    let mut out = Vec::new();
    for scope in scopes {
        let scope_name = scope
            .name
            .as_deref()
            .or(scope.identity.as_deref())
            .unwrap_or("(unnamed)");
        let Some(filter) = scope.recipient_filter.as_deref() else {
            continue;
        };
        // Fail closed on a filter we can't fully read: an unparsed clause could
        // name this group, and reporting a reference only WITHHOLDS an
        // irreversible delete, which is the safe direction.
        let groups = scope_groups_in_filter(filter);
        if groups.dns.iter().any(|dn| group.matches(dn)) {
            out.push(format!("management scope '{scope_name}'"));
        } else if !groups.complete {
            out.push(format!(
                "management scope '{scope_name}' (filter not fully readable — it may reference this group)"
            ));
        }
    }
    for policy in policies {
        let scope_ref = policy
            .scope_name
            .as_deref()
            .filter(|s| group.matches(s))
            .or_else(|| {
                policy
                    .scope_identity
                    .as_deref()
                    .filter(|s| group.matches(s))
            });
        if scope_ref.is_some() {
            out.push(format!(
                "Application Access Policy '{}' (app {})",
                policy.identity.as_deref().unwrap_or("(unnamed)"),
                policy.app_id.as_deref().unwrap_or("unknown"),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::member_of_group_filter;

    fn scope(name: &str, filter: &str) -> ExoManagementScope {
        ExoManagementScope {
            name: Some(name.into()),
            identity: Some(name.into()),
            recipient_filter: Some(filter.into()),
        }
    }

    fn aap(app_id: &str, access_right: &str, scope: Option<&str>) -> ExoApplicationAccessPolicy {
        ExoApplicationAccessPolicy {
            identity: Some(format!("policy-{app_id}")),
            app_id: Some(app_id.into()),
            access_right: Some(access_right.into()),
            scope_name: scope.map(str::to_string),
            scope_identity: scope.map(str::to_string),
            description: None,
        }
    }

    fn retired(dn: &str, name: &str) -> GroupIdentity {
        GroupIdentity {
            distinguished_name: dn.into(),
            name: Some(name.into()),
            primary_smtp_address: Some(format!("{}@contoso.com", name.to_ascii_lowercase())),
        }
    }

    #[test]
    fn group_references_span_both_authorities_including_this_apps_own_scope() {
        let group = retired("CN=Sales,DC=x", "Sales");
        let scopes = [
            // THIS app's scope, still naming the group: the migration skips its
            // repoint when an operator-set scope name may be shared with other
            // apps, so this really happens — and excluding it by name is what
            // used to offer a delete on a group the app was still scoped to.
            scope("app_scope_app-1", "MemberOfGroup -eq 'CN=Sales,DC=x'"),
            // Another app's scope (case-folded DN match).
            scope("app_scope_app-2", "MemberOfGroup -eq 'cn=sales,dc=x'"),
            scope("app_scope_app-3", "MemberOfGroup -eq 'CN=Other,DC=x'"),
        ];
        // A policy names the group by NAME, not DN — matching on one key alone
        // would miss one of the two authorities entirely.
        let policies = [aap("app-9", "RestrictAccess", Some("Sales"))];

        let refs = references_to_group(&group, &scopes, &policies);
        assert_eq!(refs.len(), 3, "{refs:?}");
        assert!(refs.iter().any(|r| r.contains("app_scope_app-1")));
        assert!(refs.iter().any(|r| r.contains("app_scope_app-2")));
        assert!(refs.iter().any(|r| r.contains("Application Access Policy")));
        assert!(!refs.iter().any(|r| r.contains("app_scope_app-3")));
    }

    #[test]
    fn a_group_nothing_references_reports_clean() {
        // The normal post-repoint shape: this app's scope now names the managed
        // group, and no policy names the retired one.
        let group = retired("CN=Retired,DC=x", "Retired");
        let refs = references_to_group(
            &group,
            &[scope(
                "app_scope_app-1",
                "MemberOfGroup -eq 'CN=Managed,DC=x'",
            )],
            &[aap("app-9", "RestrictAccess", Some("Something Else"))],
        );
        assert!(refs.is_empty(), "{refs:?}");
    }

    #[test]
    fn a_group_named_with_an_apostrophe_is_still_seen_as_referenced() {
        // `member_of_group_filter` writes the DN escaped as `''`. The scanner
        // used to skip any value containing one, which hid this reference and
        // offered an irreversible delete of a group still in a live scope.
        let dn = "CN=O'Brien Mailboxes,DC=x";
        let group = retired(dn, "O'Brien Mailboxes");
        let filter = member_of_group_filter(&[dn.to_string()]);
        assert!(filter.contains("O''Brien"), "escaping must be exercised");
        let refs = references_to_group(&group, &[scope("app_scope_app-1", &filter)], &[]);
        assert_eq!(refs.len(), 1, "{refs:?}");
    }

    #[test]
    fn a_filter_we_cannot_fully_read_counts_as_a_possible_reference() {
        // Fail closed: an unparsed MemberOfGroup clause could name this group,
        // and withholding the delete is the safe direction.
        let group = retired("CN=Retired,DC=x", "Retired");
        let refs = references_to_group(
            &group,
            &[scope("app_scope_app-1", "MemberOfGroup -like 'CN=Ret*'")],
            &[],
        );
        assert_eq!(refs.len(), 1, "{refs:?}");
        assert!(refs[0].contains("not fully readable"), "{refs:?}");
    }
}
