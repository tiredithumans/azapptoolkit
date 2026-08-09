//! Pure planning for the legacy **Application Access Policy** migration and for
//! consolidating a management scope's source groups onto the toolkit-managed
//! group.
//!
//! This is the half of `commands::exchange`'s migration flow that has no I/O in
//! it. It lived in the command layer, where a Tauri `State<AppState>` and a live
//! `ExchangeClient` sit between a test and the logic — for the most
//! consequential decisions this app makes: which policies may be rebuilt as an
//! allow-list, and whether a scope may be narrowed onto a group whose
//! membership was only partly verified. Down here they are ordinary functions
//! over ordinary data, so the awkward cases are cheap to pin.
//!
//! The command layer keeps what genuinely needs the client: enumerating
//! policies and group membership, creating the group, copying members in, and
//! writing the scope filter.
//!
//! Everything here is **fail-closed**. A decision that cannot be *proved* safe
//! leaves the scope on its original groups rather than narrowing what an app can
//! reach: an integration that silently stops seeing a mailbox reports "not
//! found", not "denied", which is the hardest kind of outage to trace back to a
//! permission change.

use crate::models::{ExoApplicationAccessPolicy, ExoGroupMember};

/// The `RestrictAccess` policies to migrate, batched **per application**, plus a
/// human-readable line per policy that was deliberately left alone.
///
/// Two rules, both load-bearing:
///
/// - **`RestrictAccess` only.** A `DenyAccess` policy is a *blocklist* (every
///   mailbox EXCEPT its group), while an RBAC management scope is an allow-list.
///   Rebuilding one as the other inverts the policy — the app would gain exactly
///   the mailboxes it was denied and lose the rest — so those are reported,
///   never migrated. A policy with no readable `AccessRight` is equally unsafe
///   to guess at, so it is excluded too.
/// - **One batch per application.** Several `RestrictAccess` policies on one app
///   grant access to the *union* of their groups
///   (`New-ApplicationAccessPolicy` evaluation rule 3), and an app gets exactly
///   one management scope. Migrating them one at a time meant the second
///   policy's group was silently dropped — `ensure_management_scope` keeps the
///   existing scope — after which both policies were deleted and those mailboxes
///   lost access.
///
/// Batching is **case-insensitive on the AppId**. Exchange echoes the value back
/// in whatever case it stored, and a GUID differing only in case is the same
/// application — so a case-sensitive grouping splits one app into two batches
/// and reproduces exactly the failure the second rule exists to prevent. Every
/// other comparison in this module already casefolds (`AccessRight`,
/// `SourceMember::key`); this one did not.
pub fn group_policies_for_migration(
    policies: Vec<ExoApplicationAccessPolicy>,
) -> (Vec<(String, Vec<ExoApplicationAccessPolicy>)>, Vec<String>) {
    let mut batches: Vec<(String, Vec<ExoApplicationAccessPolicy>)> = Vec::new();
    let mut excluded = Vec::new();
    for policy in policies {
        let Some(policy_app_id) = policy.app_id.clone() else {
            excluded.push("policy without an AppId skipped".to_string());
            continue;
        };
        match policy.access_right.as_deref().map(str::trim) {
            Some(right) if right.eq_ignore_ascii_case("RestrictAccess") => {}
            Some(right) => {
                excluded.push(format!(
                    "{policy_app_id}: skipped a {right} policy — only RestrictAccess policies are \
                     migratable. A DenyAccess policy blocks its group and allows every other \
                     mailbox, whereas an RBAC management scope allows only what it names, so \
                     migrating it would invert the policy. Re-express the exclusion as a \
                     management-scope recipient filter instead."
                ));
                continue;
            }
            None => {
                excluded.push(format!(
                    "{policy_app_id}: skipped a policy with no readable AccessRight — \
                     RestrictAccess and DenyAccess migrate to opposite scopes, so it can't be \
                     guessed."
                ));
                continue;
            }
        }
        match batches
            .iter_mut()
            .find(|(a, _)| a.eq_ignore_ascii_case(&policy_app_id))
        {
            Some((_, batch)) => batch.push(policy),
            None => batches.push((policy_app_id, vec![policy])),
        }
    }
    (batches, excluded)
}

/// A member of a source group, as identified for copy + verification.
///
/// `identity` is what `Add-DistributionGroupMember` is given; `key` is the
/// case-folded value the post-copy membership check compares on. The two are
/// separate because EXO echoes addresses back in whatever case it stores them,
/// and a case-sensitive comparison would report every copied member unverified —
/// which fails closed, but pointlessly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMember {
    pub identity: String,
    pub key: String,
}

/// Identifies one group member for copying, or `None` when it cannot be.
///
/// Primary SMTP first (stable, and what the members list shows), GUID as the
/// fallback for a mail-less recipient. A member with neither can't be copied
/// *or* verified, so it isn't one — the caller counts it as unverifiable rather
/// than quietly leaving it behind.
pub fn source_member(m: &ExoGroupMember) -> Option<SourceMember> {
    let identity = m
        .primary_smtp_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            m.guid
                .as_deref()
                .map(str::trim)
                .filter(|s: &&str| !s.is_empty())
        })?;
    Some(SourceMember {
        identity: identity.to_string(),
        key: identity.to_ascii_lowercase(),
    })
}

/// What one source group's enumeration returned: its DN and either the member
/// list or the error text from trying to read it.
pub struct SourceGroupRead<'a> {
    pub dn: &'a str,
    pub members: Result<&'a [ExoGroupMember], String>,
}

/// The de-duplicated membership to copy, or the per-group reasons it could not
/// be established.
///
/// A non-empty `Err` means **refuse**: the caller leaves the scope on its source
/// groups.
///
/// The rule that matters is the empty-list one. An EMPTY source group is treated
/// as unreadable, **not** as "this group has no mailboxes":
/// `Get-DistributionGroupMember` also returns nothing for a Microsoft 365 group
/// (whose members need `Get-UnifiedGroupLinks`), and consolidating that onto an
/// empty managed group would cut the app off from every mailbox at once — the
/// exact outage this module exists to prevent. "Nothing came back" and "there is
/// nothing" are indistinguishable here, so the ambiguous answer must fail
/// closed.
pub fn plan_source_membership(
    reads: &[SourceGroupRead<'_>],
) -> Result<Vec<SourceMember>, Vec<String>> {
    let mut members: Vec<SourceMember> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut unreadable: Vec<String> = Vec::new();

    for read in reads {
        let dn = read.dn;
        match &read.members {
            Ok(list) if !list.is_empty() => {
                let mut unidentifiable = 0_usize;
                for m in list.iter() {
                    match source_member(m) {
                        Some(sm) if seen.insert(sm.key.clone()) => members.push(sm),
                        Some(_) => {}
                        None => unidentifiable += 1,
                    }
                }
                if unidentifiable > 0 {
                    unreadable.push(format!(
                        "{dn} ({unidentifiable} member(s) with no address or GUID to copy)"
                    ));
                }
            }
            Ok(_) => unreadable.push(format!("{dn} (no readable members)")),
            Err(err) => unreadable.push(format!("{dn} ({err})")),
        }
    }

    if unreadable.is_empty() {
        Ok(members)
    } else {
        Err(unreadable)
    }
}

/// The members that could NOT be confirmed present in the managed group, by
/// identity.
///
/// Compares against the group's **actual** re-read membership rather than
/// trusting the add calls: EXO accepts some recipient types and then does not
/// list them, so a successful `Add-DistributionGroupMember` is not evidence the
/// mailbox is in the group. Any non-empty result makes `plan_consolidation`
/// refuse.
pub fn unverified_members(intended: &[SourceMember], present_keys: &[String]) -> Vec<String> {
    let present: std::collections::HashSet<&str> =
        present_keys.iter().map(String::as_str).collect();
    intended
        .iter()
        .filter(|m| !present.contains(m.key.as_str()))
        .map(|m| m.identity.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aap(app_id: &str, right: &str, group: Option<&str>) -> ExoApplicationAccessPolicy {
        ExoApplicationAccessPolicy {
            app_id: Some(app_id.to_string()),
            access_right: Some(right.to_string()),
            scope_name: group.map(str::to_string),
            ..Default::default()
        }
    }

    fn member(smtp: Option<&str>, guid: Option<&str>) -> ExoGroupMember {
        ExoGroupMember {
            display_name: None,
            primary_smtp_address: smtp.map(str::to_string),
            recipient_type: None,
            guid: guid.map(str::to_string),
        }
    }

    #[test]
    fn a_deny_access_policy_is_never_migrated() {
        // The single most dangerous mistake available here. A DenyAccess policy
        // blocks its group and allows every other mailbox; a management scope
        // allows only what it names. Rebuilding one as the other hands the app
        // exactly the mailboxes it was denied.
        let (batches, excluded) =
            group_policies_for_migration(vec![aap("app-1", "DenyAccess", Some("Execs"))]);
        assert!(
            batches.is_empty(),
            "a blocklist must not become an allowlist"
        );
        assert_eq!(excluded.len(), 1);
        assert!(excluded[0].contains("invert"), "{}", excluded[0]);
    }

    #[test]
    fn an_unreadable_access_right_is_not_guessed_at() {
        let mut policy = aap("app-1", "RestrictAccess", Some("Execs"));
        policy.access_right = None;
        let (batches, excluded) = group_policies_for_migration(vec![policy]);
        assert!(batches.is_empty());
        assert_eq!(excluded.len(), 1);
    }

    #[test]
    fn a_policy_with_no_app_id_is_skipped() {
        let mut policy = aap("app-1", "RestrictAccess", Some("Execs"));
        policy.app_id = None;
        let (batches, excluded) = group_policies_for_migration(vec![policy]);
        assert!(batches.is_empty());
        assert_eq!(excluded.len(), 1);
    }

    #[test]
    fn every_policy_for_one_app_lands_in_one_batch() {
        // Several RestrictAccess policies on one app grant the UNION of their
        // groups, and an app gets exactly one management scope. Migrating them
        // separately dropped the second group and then deleted both policies —
        // those mailboxes lost access silently.
        let (batches, excluded) = group_policies_for_migration(vec![
            aap("app-1", "RestrictAccess", Some("Sales")),
            aap("app-2", "RestrictAccess", Some("Support")),
            aap("app-1", "RestrictAccess", Some("Execs")),
        ]);
        assert!(excluded.is_empty());
        assert_eq!(batches.len(), 2, "one batch per application");
        let app1 = batches.iter().find(|(a, _)| a == "app-1").unwrap();
        assert_eq!(
            app1.1.len(),
            2,
            "both of app-1's groups must migrate together"
        );
    }

    #[test]
    fn the_access_right_match_tolerates_casing_and_padding() {
        let (batches, excluded) =
            group_policies_for_migration(vec![aap("app-1", "  restrictaccess  ", Some("Sales"))]);
        assert!(excluded.is_empty(), "{excluded:?}");
        assert_eq!(batches.len(), 1);
    }

    #[test]
    fn source_member_prefers_smtp_and_folds_case_for_verification() {
        let m = source_member(&member(Some("Sales@Contoso.com"), Some("guid-1"))).unwrap();
        assert_eq!(m.identity, "Sales@Contoso.com", "copied as EXO reports it");
        assert_eq!(m.key, "sales@contoso.com", "compared case-insensitively");
    }

    #[test]
    fn source_member_falls_back_to_guid_then_gives_up() {
        assert_eq!(
            source_member(&member(None, Some("guid-1")))
                .unwrap()
                .identity,
            "guid-1"
        );
        assert!(source_member(&member(None, None)).is_none());
        assert!(
            source_member(&member(Some("  "), None)).is_none(),
            "whitespace is not an identity"
        );
    }

    #[test]
    fn an_empty_source_group_reads_as_unreadable_not_as_no_mailboxes() {
        // `Get-DistributionGroupMember` returns nothing for a Microsoft 365
        // group too. Treating that as "no mailboxes" would consolidate the scope
        // onto an empty managed group and cut the app off from everything.
        let empty: Vec<ExoGroupMember> = Vec::new();
        let err = plan_source_membership(&[SourceGroupRead {
            dn: "CN=Sales",
            members: Ok(&empty),
        }])
        .unwrap_err();
        assert_eq!(err.len(), 1);
        assert!(err[0].contains("no readable members"), "{}", err[0]);
    }

    #[test]
    fn a_failed_enumeration_refuses_and_names_the_group() {
        let err = plan_source_membership(&[SourceGroupRead {
            dn: "CN=Sales",
            members: Err("access denied".to_string()),
        }])
        .unwrap_err();
        assert_eq!(err, vec!["CN=Sales (access denied)"]);
    }

    #[test]
    fn one_uncopyable_member_refuses_the_whole_group() {
        // A member with neither address nor GUID cannot be copied OR verified,
        // so consolidating would drop it from the app's reach with nothing to
        // report afterwards.
        let list = vec![member(Some("a@contoso.com"), None), member(None, None)];
        let err = plan_source_membership(&[SourceGroupRead {
            dn: "CN=Sales",
            members: Ok(&list),
        }])
        .unwrap_err();
        assert!(
            err[0].contains("1 member(s) with no address or GUID"),
            "{}",
            err[0]
        );
    }

    #[test]
    fn membership_is_deduplicated_across_source_groups() {
        // Two policies naming overlapping groups is ordinary; copying a mailbox
        // twice is harmless but reporting it twice is misleading.
        let sales = vec![member(Some("a@contoso.com"), None)];
        let execs = vec![
            member(Some("A@CONTOSO.COM"), None),
            member(Some("b@contoso.com"), None),
        ];
        let members = plan_source_membership(&[
            SourceGroupRead {
                dn: "CN=Sales",
                members: Ok(&sales),
            },
            SourceGroupRead {
                dn: "CN=Execs",
                members: Ok(&execs),
            },
        ])
        .unwrap();
        assert_eq!(members.len(), 2, "the case-variant duplicate is one member");
    }

    #[test]
    fn a_member_absent_from_the_re_read_is_unverified() {
        let intended = vec![
            SourceMember {
                identity: "a@contoso.com".into(),
                key: "a@contoso.com".into(),
            },
            SourceMember {
                identity: "b@contoso.com".into(),
                key: "b@contoso.com".into(),
            },
        ];
        let unverified = unverified_members(&intended, &["a@contoso.com".to_string()]);
        assert_eq!(unverified, vec!["b@contoso.com"]);
    }

    #[test]
    fn verification_matches_case_insensitively() {
        let intended = vec![SourceMember {
            identity: "A@Contoso.com".into(),
            key: "a@contoso.com".into(),
        }];
        assert!(
            unverified_members(&intended, &["a@contoso.com".to_string()]).is_empty(),
            "EXO echoes addresses in its own casing; a case-sensitive check would \
             report every member unverified and refuse every consolidation"
        );
    }
}
