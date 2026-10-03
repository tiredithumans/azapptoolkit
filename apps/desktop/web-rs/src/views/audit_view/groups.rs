//! Finding-group taxonomy for the findings-first Security workbench.
//!
//! One catalog entry per finding key (the same keys core's `matches_finding`
//! understands, so Home drills and the characterization tests share one
//! vocabulary), classified into two sections: **Actionable** findings ranked by
//! their own worst severity, and demoted **Healthy** positives
//! (confirmed-scoped access). The classifier delegates to `matches_finding` per
//! key — the load-bearing `.contains(SCOPED_VIA_RBAC)` vs `.starts_with`
//! asymmetry lives in exactly one place.

use std::cmp::Reverse;

use azapptoolkit_core::audit::{AuditItem, RemediationKind, RiskLevel, matches_finding};

use crate::components::bulk_action_bar::BulkAction;
use crate::components::ui::BadgeTone;

/// Which section of the Findings pane a group renders in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GroupSection {
    /// Ranked worst-severity first; hidden at zero affected principals.
    Actionable,
    /// Positive signals (already-scoped access), demoted below the ranked list.
    Healthy,
}

/// Static catalog entry for one finding group.
#[derive(PartialEq)]
pub(super) struct GroupSpec {
    pub key: &'static str,
    pub title: &'static str,
    /// One-sentence explanation shown in the expanded panel.
    pub blurb: &'static str,
    /// The detail-pane tab a row's "Open" deep-link lands on **from this
    /// section** — where the operator acts on *this* rule, not on whatever
    /// else the app was scored for. `target_tab`'s item-wide scan serves the
    /// ungrouped All-apps pane; here the section already names the finding, so
    /// it decides. Managed identities are clamped to their two-tab pane
    /// (`row::target_tab`).
    pub tab: &'static str,
    pub section: GroupSection,
}

/// Display catalog, in tie-break (and Healthy display) order. Advisory groups
/// (no group-level fix) still render — visibility with an Open deep-link beats
/// hiding a finding the audit scored.
pub(super) const GROUP_CATALOG: &[GroupSpec] = &[
    GroupSpec {
        key: "expired",
        title: "Expired credentials",
        blurb: "Apps holding already-expired secrets or certificates. Removing them can't break a working sign-in — expired credentials can't authenticate.",
        tab: "credentials",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "orgwide_mailbox",
        title: "Org-wide mailbox access",
        blurb: "Mail permissions that reach every mailbox in the tenant. Confine them to specific mail-enabled groups via Exchange RBAC for Applications.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "legacy_mailbox_scope",
        title: "Legacy Application Access Policy scoping",
        blurb: "Mailbox access confined by an Application Access Policy — legacy (replaced by RBAC for Applications; Microsoft has said its deprecation will be announced), per-app, and blind to anything granted through Exchange RBAC. Migrate each app to a management scope with scoped role assignments; the fix plans the change before applying it.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "orgwide_sharepoint",
        title: "Org-wide SharePoint access",
        blurb: "Sites.* permissions that reach every site collection. Convert them to the Sites.Selected model on the sites the app actually needs.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    // Files is its own finding, not a variant of the SharePoint one: the site
    // path has a one-click Sites.Selected conversion, the file path has none —
    // the wizard only scopes Files.SelectedOperations.Selected to chosen
    // files/libraries, and removing the org-wide grant stays admin-judged.
    GroupSpec {
        key: "orgwide_files",
        title: "Org-wide Files access",
        blurb: "Files.* permissions (e.g. Files.ReadWrite.All) that reach every file across all site collections and OneDrive. Convert to Files.SelectedOperations.Selected and grant only the files or libraries the app actually uses — advisory, no bulk Fix.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "redundant_perms",
        title: "Redundant permissions",
        blurb: "Narrower application permissions a broader held permission already fully covers — pure attack surface, safe to remove.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "ownership",
        title: "Missing or single owner",
        blurb: "Apps with no owner (accountability gap) or a single owner (vulnerable to departure). Adding an owner is purely additive.",
        tab: "owners",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "unused",
        title: "Unused applications",
        blurb: "No sign-in activity in the report window. Disable sign-in (reversible) to verify nothing breaks, or delete when confirmed obsolete.",
        tab: "overview",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "high_risk_perms",
        title: "High-risk application permissions",
        blurb: "Broad application permissions (e.g. Mail.ReadWrite, Directory.ReadWrite.All). Reducing them is an admin-judged change — open the app's Permissions tab to review downgrades or scoping.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    // Org-wide reach the toolkit cannot confine — advisory siblings of
    // `high_risk_perms`, split by the scorer's advice (remove vs. review).
    GroupSpec {
        key: "unscopable_legacy_mailbox",
        title: "Legacy Exchange Online mailbox grants",
        blurb: "Mail, calendar, contacts and mailbox-settings permissions granted on the legacy Office 365 Exchange Online resource. They reach every mailbox and RBAC for Applications cannot confine them (it covers Microsoft Graph and EWS only); the Outlook REST endpoints they authorized were decommissioned in March 2024. Remove the grant and use the identically named Microsoft Graph permission instead.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "unconfinable_orgwide",
        title: "Org-wide access that can't be confined here",
        blurb: "Mailbox or SharePoint permissions that reach every mailbox or site, but that neither RBAC for Applications nor Sites.Selected can confine from this toolkit: a mail permission with no supported Exchange application role or whose resource could not be resolved, or Sites.* granted on Office 365 SharePoint Online. Review whether each grant is needed; where it is, re-declare it as a Microsoft Graph permission that can be scoped.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    // Rule 21 — Microsoft disabled the app/SP for a Services Agreement
    // violation. Its own group, not folded into `expired` or
    // `external_exposure`: the flag is about the principal's conduct and
    // fires on SP-only rows too, where the credential and audience lenses
    // don't apply. No group Fix — deleting or disabling is admin-judged.
    GroupSpec {
        key: "disabled_by_microsoft",
        title: "Disabled by Microsoft",
        blurb: "Microsoft blocked these apps for suspicious, abusive or malicious activity (disabledByMicrosoftStatus). Sign-ins are already blocked; the credentials and grants remain. Investigate why each was blocked before re-enabling anything — delete the ones that aren't mistaken blocks.",
        tab: "overview",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "external_exposure",
        title: "Reachable outside this tenant",
        blurb: "Apps whose sign-in audience lets other directories (or personal Microsoft accounts) consent to them, while they hold application permissions or credentials — so their access isn't confined here. Confirm each is meant to be multi-tenant; verify the publisher if it is.",
        tab: "overview",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "high_risk_delegated",
        title: "High-risk delegated permissions",
        blurb: "Delegated scopes that let the app act as a signed-in user (Directory.AccessAsUser.All, user_impersonation), and broad-reach scopes (mail, files, directory, sites…) an admin consented to for every user. If the tenant's consent grants couldn't be read, requested broad scopes are listed too. Review on the principal's Permissions tab; delegated scopes are requested by name, so removal is admin-judged.",
        tab: "permissions",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "no_local_app",
        title: "No local app registration",
        blurb: "Foreign-tenant enterprise apps, managed identities, and orphaned service principals — scored from their granted roles. Credentials and manifest live in their home tenant; their scope fixes are offered in the mailbox and SharePoint findings, which list these principals too.",
        tab: "overview",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "scoped_mailbox",
        title: "Mailbox access scoped",
        blurb: "Mail permissions confirmed confined to specific mailboxes via Exchange RBAC — the configuration the org-wide fix moves apps toward.",
        tab: "permissions",
        section: GroupSection::Healthy,
    },
    GroupSpec {
        key: "scoped_sites",
        title: "SharePoint scoped to selected sites",
        blurb: "SharePoint access on the least-privilege Sites.Selected model.",
        tab: "permissions",
        section: GroupSection::Healthy,
    },
];

/// One computed finding group: which items (as indices into the run's item
/// slice, original risk-ranked order) match, and the worst risk level among
/// them — the key that ranks the Actionable section.
/// `Clone + PartialEq` so the pane's `Memo<Option<Vec<FindingGroup>>>` can
/// hand out and diff runs.
#[derive(Clone, PartialEq)]
pub(super) struct FindingGroup {
    pub spec: &'static GroupSpec,
    pub item_indices: Vec<usize>,
    pub worst: RiskLevel,
}

/// The one ordering both rankers sort by: Actionable before Healthy, then the
/// group's worst severity descending (`RiskLevel`'s `Ord` is severity order),
/// then its affected-principal count descending. Shared by [`group_findings`]
/// and [`ranked_actionable_findings`] so the Home card lists findings in the
/// order the workbench shows them.
fn rank_key(section: GroupSection, worst: RiskLevel, count: usize) -> impl Ord {
    (
        matches!(section, GroupSection::Healthy),
        Reverse(worst),
        Reverse(count),
    )
}

/// Classifies `items` into every catalog group and ranks the Actionable
/// section worst-severity first, breaking ties on affected-principal count.
/// Healthy groups keep catalog order at the end. Empty groups are returned too
/// — the pane hides empty Actionable groups but renders Healthy ones
/// count-muted.
pub(super) fn group_findings(items: &[AuditItem]) -> Vec<FindingGroup> {
    let mut groups: Vec<FindingGroup> = GROUP_CATALOG
        .iter()
        .map(|spec| {
            let item_indices: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, i)| matches_finding(i, spec.key))
                .map(|(idx, _)| idx)
                .collect();
            let worst = item_indices
                .iter()
                .map(|&i| items[i].risk_level)
                .max()
                .unwrap_or(RiskLevel::Low);
            FindingGroup {
                spec,
                item_indices,
                worst,
            }
        })
        .collect();
    // Stable sort: Actionable before Healthy, then worst severity descending,
    // then count descending. Stability keeps catalog order as the final
    // tie-break within an equal (section, severity, count).
    //
    // Severity is the group's OWN worst, not Σ `risk_score` over its members:
    // a member's total score is everything the app was scored for, most of it
    // by other rules. Ownership contributes no points at all (there is no PTS
    // constant for Rule 14) yet matched a large fraction of any tenant, so its
    // members' unrelated permission risk summed to the top of a findings-first
    // workbench — pushing a twelve-app Critical org-wide-mailbox group below
    // the fold. Count only breaks ties, so breadth still ranks within a tier
    // without ever outvoting severity.
    groups.sort_by_key(|g| rank_key(g.spec.section, g.worst, g.item_indices.len()));
    groups
}

/// The Findings pane's Actionable groups, in the SAME ranking ([`rank_key`]),
/// as `(key, title, tone, count)` — for surfaces outside the workbench (the Home
/// posture card) that hold precomputed tallies instead of the run's items.
///
/// `tally` answers `(count, worst)` for a finding key, or `None` to leave that
/// finding out; zero-count findings are dropped too (a zero line is noise,
/// mirroring the pane hiding empty Actionable groups). Healthy groups are
/// excluded. `tone` is the finding's worst-severity colour, matching the
/// workbench's finding-group tone dot.
pub(crate) fn ranked_actionable_findings(
    tally: impl Fn(&str) -> Option<(usize, RiskLevel)>,
) -> Vec<(&'static str, &'static str, BadgeTone, usize)> {
    let mut ranked: Vec<(&'static GroupSpec, usize, RiskLevel)> = GROUP_CATALOG
        .iter()
        .filter(|spec| matches!(spec.section, GroupSection::Actionable))
        .filter_map(|spec| {
            let (count, worst) = tally(spec.key)?;
            (count > 0).then_some((spec, count, worst))
        })
        .collect();
    // Stable, over catalog order — the same final tie-break `group_findings` has.
    ranked.sort_by_key(|&(spec, count, worst)| rank_key(spec.section, worst, count));
    ranked
        .into_iter()
        .map(|(spec, count, worst)| (spec.key, spec.title, tone(worst), count))
        .collect()
}

/// The one `RiskLevel` → tone mapping; `finding_group_view`, `risk_tone` and
/// (via [`ranked_actionable_findings`]) the Home card all derive from it. Its
/// `Display` is the `--{tone}` suffix the finding-group dots share.
pub(super) fn tone(level: RiskLevel) -> BadgeTone {
    match level {
        RiskLevel::Critical => BadgeTone::Critical,
        RiskLevel::High => BadgeTone::Danger,
        RiskLevel::Medium => BadgeTone::Warning,
        RiskLevel::Low => BadgeTone::Ok,
    }
}

/// The bulk fix(es) a group's `BulkActionBar` offers — paired with the rule the
/// action actually fixes (this is where the old `audit_bulk_actions` mapping of
/// Over-privileged → RemoveRedundant, a *different* rule, was retired).
/// Advisory groups return an empty set: their rows keep per-row Open/Fixes but
/// there is no safe uniform bulk mutation.
pub(super) fn group_bulk_actions(key: &str) -> Vec<BulkAction> {
    match key {
        "expired" => vec![BulkAction::RemoveExpired],
        "orgwide_mailbox" => vec![BulkAction::ScopeMailbox],
        "orgwide_sharepoint" => vec![BulkAction::ScopeSharePoint],
        "redundant_perms" => vec![BulkAction::RemoveRedundant],
        "ownership" => vec![BulkAction::AddOwner],
        "unused" => vec![BulkAction::DisableSignIn, BulkAction::Delete],
        _ => Vec::new(),
    }
}

/// The one-click Fix(es) a group's **rows** may offer — the per-row counterpart
/// to [`group_bulk_actions`], and paired with the same rule.
///
/// An `AuditItem` carries every remediation the scorer attached across *all*
/// the rules it tripped, and the same item is listed under each finding group
/// it matches. Rendering the whole set on every row put unrelated buttons in a
/// section ("Remove 1 expired credential" inside Legacy Application Access
/// Policy scoping) — and firing one cleared the row's remediations, taking the
/// section's own Fix with it. A section shows only the Fix for its own rule;
/// the others are one click away in the section that owns them.
///
/// Advisory groups (`high_risk_perms`, `unscopable_legacy_mailbox`,
/// `unconfinable_orgwide`, `disabled_by_microsoft`, `external_exposure`,
/// `high_risk_delegated`,
/// `no_local_app`) and the Healthy positives own none —
/// their rows keep the "Open" deep-link alone. Kinds are disjoint across
/// groups, pinned by the tests below.
pub(super) fn group_remediation_kinds(key: &str) -> &'static [RemediationKind] {
    match key {
        "expired" => &[RemediationKind::RemoveExpiredCredentials],
        "orgwide_mailbox" => &[RemediationKind::ScopeMailboxAccess],
        "legacy_mailbox_scope" => &[RemediationKind::MigrateApplicationAccessPolicy],
        "orgwide_sharepoint" => &[RemediationKind::ScopeSharePointAccess],
        "redundant_perms" => &[RemediationKind::RemoveRedundantPermissions],
        "ownership" => &[RemediationKind::AddOwner],
        "unused" => &[RemediationKind::DisableSignIn],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::{AuditPrincipalKind, CredentialStatus, issue, posture_counts};
    use azapptoolkit_dto::audit::CachedAuditSummary;

    fn blank() -> AuditItem {
        AuditItem {
            application_name: "App".into(),
            app_id: "app-1".into(),
            object_id: "obj-1".into(),
            created_date: None,
            publisher: None,
            sign_in_audience: None,
            risk_score: 0,
            risk_level: RiskLevel::Low,
            issues: vec![],
            recommendations: vec![],
            remediations: vec![],
            credential_status: CredentialStatus::Active,
            permission_count: 0,
            service_principal_enabled: None,
            days_since_created: None,
            certificates: vec![],
            secrets: vec![],
            last_sign_in: None,
            unused: false,
            sign_in_report_available: false,
            principal_kind: AuditPrincipalKind::Application,
            app_owner_organization_id: None,
        }
    }

    fn with_issue(text: String, score: u32, level: RiskLevel) -> AuditItem {
        AuditItem {
            issues: vec![text],
            risk_score: score,
            risk_level: level,
            ..blank()
        }
    }

    fn group<'a>(groups: &'a [FindingGroup], key: &str) -> &'a FindingGroup {
        groups
            .iter()
            .find(|g| g.spec.key == key)
            .unwrap_or_else(|| panic!("no group {key}"))
    }

    #[test]
    fn every_group_key_is_a_real_finding_key() {
        // `matches_finding` falls through to `true` on an unknown key, which
        // would silently turn a typo'd catalog key into an "everything matches"
        // group. Pin: an item with no findings matches no catalog key.
        let clean = blank();
        for spec in GROUP_CATALOG {
            assert!(
                !matches_finding(&clean, spec.key),
                "catalog key {:?} matched a finding-less item — unknown key falling through?",
                spec.key
            );
        }
    }

    #[test]
    fn classification_covers_marker_and_structured_findings() {
        let expired = AuditItem {
            credential_status: CredentialStatus::Expired,
            risk_score: 8,
            risk_level: RiskLevel::Medium,
            ..blank()
        };
        let mailbox = with_issue(
            format!("{} Mail.Read", issue::ORG_WIDE_MAILBOX),
            10,
            RiskLevel::High,
        );
        // The mid-string marker (`.contains`, not `.starts_with`) must reach
        // the healthy scoped-mailbox group through the shared predicate.
        let scoped = with_issue(
            format!("Mail.Read {} (Sales)", issue::SCOPED_VIA_RBAC),
            0,
            RiskLevel::Low,
        );
        let sp_only = AuditItem {
            principal_kind: AuditPrincipalKind::ServicePrincipal,
            ..blank()
        };
        let items = vec![expired, mailbox, scoped, sp_only];
        let groups = group_findings(&items);

        assert_eq!(group(&groups, "expired").item_indices, vec![0]);
        assert_eq!(group(&groups, "orgwide_mailbox").item_indices, vec![1]);
        assert_eq!(group(&groups, "scoped_mailbox").item_indices, vec![2]);
        assert_eq!(group(&groups, "no_local_app").item_indices, vec![3]);
        assert!(group(&groups, "unused").item_indices.is_empty());
    }

    #[test]
    fn actionable_groups_rank_by_worst_severity_then_count() {
        // The regression this pins: ownership matches three Low principals
        // whose members' TOTAL scores sum to 60 — none of it contributed by the
        // ownership rule, which carries no points — against a single Critical
        // org-wide-mailbox principal scoring 25. Ranked by Σ risk_score the
        // zero-weight group led the workbench and the Critical one sat below it.
        let mailbox = with_issue(
            format!("{} Mail.ReadWrite", issue::ORG_WIDE_MAILBOX),
            25,
            RiskLevel::Critical,
        );
        let owner_a = with_issue(format!("{} x", issue::NO_OWNERS), 20, RiskLevel::Low);
        let owner_b = with_issue(format!("{} x", issue::SINGLE_OWNER), 20, RiskLevel::Low);
        let owner_c = with_issue(format!("{} y", issue::NO_OWNERS), 20, RiskLevel::Low);
        let redundant_a = with_issue(
            format!("{} a", issue::REDUNDANT_APP_PERMS),
            0,
            RiskLevel::Low,
        );
        let redundant_b = with_issue(
            format!("{} b", issue::REDUNDANT_APP_PERMS),
            0,
            RiskLevel::Low,
        );
        let expired = AuditItem {
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        let sharepoint = with_issue(
            format!("{} Sites.ReadWrite.All", issue::ORG_WIDE_SHAREPOINT),
            0,
            RiskLevel::Low,
        );
        let items = vec![
            mailbox,
            owner_a,
            owner_b,
            owner_c,
            redundant_a,
            redundant_b,
            expired,
            sharepoint,
        ];
        let groups = group_findings(&items);

        let order: Vec<&str> = groups.iter().map(|g| g.spec.key).collect();
        let pos = |k: &str| order.iter().position(|x| *x == k).unwrap();
        assert!(
            pos("orgwide_mailbox") < pos("ownership"),
            "one Critical principal outranks three Low ones scoring 60 between \
             them: {order:?}"
        );
        // Within one severity tier, breadth ranks: 3 affected before 2 before 1.
        assert!(pos("ownership") < pos("redundant_perms"), "{order:?}");
        assert!(pos("redundant_perms") < pos("expired"), "{order:?}");
        // Equal severity AND equal count keeps catalog order (stable sort) —
        // `expired` is catalogued before `orgwide_sharepoint`.
        assert!(pos("expired") < pos("orgwide_sharepoint"), "{order:?}");
        // Empty groups sort last within the tier (count 0), still in catalog
        // order; the pane hides them.
        assert!(
            pos("orgwide_sharepoint") < pos("high_risk_perms"),
            "{order:?}"
        );
        // Healthy groups always trail every actionable group.
        assert!(pos("scoped_mailbox") > pos("no_local_app"));
        assert!(pos("scoped_sites") > pos("scoped_mailbox"));

        let ownership = group(&groups, "ownership");
        assert_eq!(ownership.worst, RiskLevel::Low);
        assert_eq!(ownership.item_indices, vec![1, 2, 3]);
        assert_eq!(group(&groups, "orgwide_mailbox").worst, RiskLevel::Critical);
    }

    /// The Home card ranks from the backend's precomputed tallies, the
    /// workbench from the items — both through `rank_key`, but the counts and
    /// worst levels come from core's posture predicates on one side and the
    /// group classifier on the other. Pin that they agree: same keys, same
    /// order, same tone, same count.
    #[test]
    fn summary_ranking_matches_the_workbench_ranking() {
        let items = vec![
            with_issue(
                format!("{} Mail.ReadWrite", issue::ORG_WIDE_MAILBOX),
                25,
                RiskLevel::Critical,
            ),
            with_issue(format!("{} x", issue::NO_OWNERS), 20, RiskLevel::Low),
            with_issue(format!("{} x", issue::SINGLE_OWNER), 20, RiskLevel::Low),
            with_issue(format!("{} y", issue::NO_OWNERS), 20, RiskLevel::Low),
            with_issue(
                format!("{} a", issue::REDUNDANT_APP_PERMS),
                0,
                RiskLevel::Low,
            ),
            AuditItem {
                credential_status: CredentialStatus::Expired,
                risk_level: RiskLevel::High,
                ..blank()
            },
            AuditItem {
                credential_status: CredentialStatus::Expired,
                ..blank()
            },
            with_issue(
                format!("{} Sites.ReadWrite.All", issue::ORG_WIDE_SHAREPOINT),
                0,
                RiskLevel::Low,
            ),
            AuditItem {
                unused: true,
                risk_level: RiskLevel::Medium,
                ..blank()
            },
            with_issue(
                format!("{}: Mail.Read", issue::UNSCOPABLE_LEGACY_MAILBOX),
                0,
                RiskLevel::High,
            ),
        ];
        let summary = CachedAuditSummary::from_items(&items, None);
        let from_summary: Vec<(&str, BadgeTone, usize)> =
            ranked_actionable_findings(|k| summary.finding_tally(k))
                .into_iter()
                .map(|(key, _, tone, n)| (key, tone, n))
                .collect();
        let from_items: Vec<(&str, BadgeTone, usize)> = group_findings(&items)
            .into_iter()
            .filter(|g| matches!(g.spec.section, GroupSection::Actionable))
            .filter(|g| !g.item_indices.is_empty())
            // The summary counts the posture buckets only (not redundant /
            // external exposure), so compare over the keys it answers for.
            .filter(|g| summary.finding_tally(g.spec.key).is_some())
            .map(|g| (g.spec.key, tone(g.worst), g.item_indices.len()))
            .collect();
        assert!(
            from_summary.len() >= 5,
            "fixture too thin: {from_summary:?}"
        );
        assert_eq!(from_summary, from_items);
    }

    /// Every posture bucket must equal the size of the Findings-pane group it
    /// summarizes — the Home card and the strip quote these numbers next to
    /// the groups, so a divergent predicate would contradict the workbench.
    #[test]
    fn posture_counts_agree_with_finding_groups() {
        let marker = |m: &str| AuditItem {
            issues: vec![format!("{m}: x")],
            ..blank()
        };
        let items = vec![
            marker(issue::HIGH_RISK_APP_PERMS),
            marker(issue::HIGH_RISK_DELEGATED_PERMS),
            marker(issue::ORG_WIDE_MAILBOX),
            marker(issue::LEGACY_MAILBOX_POLICY),
            marker(issue::UNSCOPABLE_LEGACY_MAILBOX),
            marker(issue::UNCONFINABLE_MAILBOX),
            marker(issue::UNCONFINABLE_SHAREPOINT),
            marker(issue::ORG_WIDE_SHAREPOINT),
            marker(issue::ORG_WIDE_FILES),
            marker(issue::SCOPED_SHAREPOINT),
            marker(issue::NO_OWNERS),
            marker(issue::SINGLE_OWNER),
            AuditItem {
                issues: vec![format!("Mail.Read {} (Sales)", issue::SCOPED_VIA_RBAC)],
                ..blank()
            },
            AuditItem {
                credential_status: CredentialStatus::Expired,
                ..blank()
            },
            AuditItem {
                unused: true,
                ..blank()
            },
            AuditItem {
                principal_kind: AuditPrincipalKind::ServicePrincipal,
                ..blank()
            },
        ];
        let c = posture_counts(&items);
        let groups = group_findings(&items);
        for key in azapptoolkit_core::audit::POSTURE_FINDING_KEYS {
            let count = c.finding(key).unwrap_or_else(|| panic!("no bucket {key}"));
            assert!(count > 0, "fixture leaves {key} empty");
            assert_eq!(
                count,
                group(&groups, key).item_indices.len(),
                "posture count for {key}"
            );
        }
        assert_eq!(c.unconfinable_orgwide, 2);
        assert_eq!(c.unowned, 2);
    }

    #[test]
    fn group_bulk_actions_pair_each_fix_with_its_own_rule() {
        assert_eq!(
            group_bulk_actions("expired"),
            vec![BulkAction::RemoveExpired]
        );
        assert_eq!(
            group_bulk_actions("redundant_perms"),
            vec![BulkAction::RemoveRedundant]
        );
        assert_eq!(group_bulk_actions("ownership"), vec![BulkAction::AddOwner]);
        assert_eq!(
            group_bulk_actions("unused"),
            vec![BulkAction::DisableSignIn, BulkAction::Delete]
        );
        // The retired mismatch: Over-privileged (Rule 1) must NOT offer
        // RemoveRedundant (Rule 18) — it's advisory now.
        assert!(group_bulk_actions("high_risk_perms").is_empty());
        assert!(group_bulk_actions("high_risk_delegated").is_empty());
        // Migrating a legacy policy is per-app and plan-first (the operator
        // reads which mailboxes the new scope will cover before committing), so
        // it stays a per-row Fix — a uniform bulk form has nothing to show.
        assert!(group_bulk_actions("legacy_mailbox_scope").is_empty());
        assert!(group_bulk_actions("no_local_app").is_empty());
        assert!(group_bulk_actions("scoped_mailbox").is_empty());
        // Unconfinable reach has no safe uniform mutation: removing or
        // re-declaring the grant is the operator's call.
        assert!(group_bulk_actions("unscopable_legacy_mailbox").is_empty());
        assert!(group_bulk_actions("unconfinable_orgwide").is_empty());
        // Org-wide Files is advisory: the wizard scopes the
        // `Files.SelectedOperations.Selected` end state, nothing rewrites a
        // held `Files.*.All`, so there is no uniform mutation to offer.
        assert!(group_bulk_actions("orgwide_files").is_empty());
    }

    /// The scorer keeps unconfinable reach out of the fixable org-wide groups
    /// (their bulk Fix can't apply), so these rows need their own advisory
    /// homes — and the legacy-resource one stays apart from the other two,
    /// because "remove the grant" is the wrong advice for them.
    #[test]
    fn unconfinable_reach_lands_in_its_own_advisory_groups() {
        let legacy = with_issue(
            format!("{}: Mail.Read", issue::UNSCOPABLE_LEGACY_MAILBOX),
            0,
            RiskLevel::Medium,
        );
        let mailbox = with_issue(
            format!("{}: Mail.ReadWrite.Shared", issue::UNCONFINABLE_MAILBOX),
            0,
            RiskLevel::Medium,
        );
        let sharepoint = with_issue(
            format!("{}: Sites.Read.All", issue::UNCONFINABLE_SHAREPOINT),
            0,
            RiskLevel::High,
        );
        let items = vec![legacy, mailbox, sharepoint];
        let groups = group_findings(&items);
        assert_eq!(
            group(&groups, "unscopable_legacy_mailbox").item_indices,
            vec![0]
        );
        assert_eq!(
            group(&groups, "unconfinable_orgwide").item_indices,
            vec![1, 2]
        );
        for key in [
            "orgwide_mailbox",
            "orgwide_sharepoint",
            "orgwide_files",
            "legacy_mailbox_scope",
            "scoped_mailbox",
            "scoped_sites",
        ] {
            assert!(
                group(&groups, key).item_indices.is_empty(),
                "unconfinable reach leaked into {key}"
            );
        }
    }

    /// The F127 regression class: a marker the scorer emits for a reach/risk
    /// finding but that no group matches is scored yet invisible on the
    /// findings-first pane. Every such marker must land in at least one group.
    /// INSTANCE_LOCK_DISABLED, PUBLIC_CLIENT_CREDENTIALS and
    /// PREFER_CERT_OVER_SECRET are hygiene notes deliberately left to the
    /// All-apps issue column.
    #[test]
    fn every_reach_marker_has_a_group() {
        for marker in [
            issue::ORG_WIDE_MAILBOX,
            issue::UNSCOPABLE_LEGACY_MAILBOX,
            issue::UNCONFINABLE_MAILBOX,
            issue::LEGACY_MAILBOX_POLICY,
            issue::ORG_WIDE_SHAREPOINT,
            issue::ORG_WIDE_FILES,
            issue::UNCONFINABLE_SHAREPOINT,
            issue::SCOPED_SHAREPOINT,
            issue::HIGH_RISK_APP_PERMS,
            issue::HIGH_RISK_DELEGATED_PERMS,
            issue::REDUNDANT_APP_PERMS,
            issue::NO_OWNERS,
            issue::SINGLE_OWNER,
            issue::MULTITENANT_AUDIENCE,
            issue::UNVERIFIED_PUBLISHER,
        ] {
            let item = with_issue(format!("{marker}: x"), 0, RiskLevel::Low);
            assert!(
                GROUP_CATALOG
                    .iter()
                    .any(|spec| matches_finding(&item, spec.key)),
                "marker {marker:?} belongs to no finding group"
            );
        }
    }

    /// A section's `tab` is a deep-link target: an unknown value doesn't error,
    /// it silently clamps (app/enterprise panes) or renders an empty tab body
    /// (the managed-identity pane), so a typo would read as a dead "Open".
    #[test]
    fn every_group_tab_is_a_real_detail_pane_tab() {
        use crate::views::tabs::AppTab;
        for spec in GROUP_CATALOG {
            assert_eq!(
                AppTab::from_str(spec.tab).value(),
                spec.tab,
                "group {} points at unknown tab {:?}",
                spec.key,
                spec.tab
            );
        }
    }

    /// Every remediation the scorer can attach must be offered by exactly ONE
    /// finding group. Zero owners hides a Fix the audit computed; two owners
    /// puts the same button in two sections — the cross-section leakage this
    /// mapping exists to stop.
    #[test]
    fn every_remediation_kind_is_owned_by_exactly_one_group() {
        // Exhaustive by construction: a new variant won't compile until it is
        // listed here, and won't pass until a group claims it.
        let all = [
            RemediationKind::RemoveExpiredCredentials,
            RemediationKind::ScopeMailboxAccess,
            RemediationKind::ScopeSharePointAccess,
            RemediationKind::RemoveRedundantPermissions,
            RemediationKind::AddOwner,
            RemediationKind::MigrateApplicationAccessPolicy,
            RemediationKind::DisableSignIn,
        ];
        for kind in all {
            let owners: Vec<&str> = GROUP_CATALOG
                .iter()
                .filter(|s| group_remediation_kinds(s.key).contains(&kind))
                .map(|s| s.key)
                .collect();
            assert_eq!(owners.len(), 1, "{kind:?} is owned by {owners:?}");
        }
    }

    #[test]
    fn advisory_and_healthy_groups_offer_no_row_fix() {
        // Advisory groups: the change is admin-judged, so the row offers "Open"
        // only — it must not inherit a sibling rule's Fix.
        for key in [
            "high_risk_perms",
            "high_risk_delegated",
            "external_exposure",
            "disabled_by_microsoft",
            "no_local_app",
            "unscopable_legacy_mailbox",
            "unconfinable_orgwide",
        ] {
            assert!(group_remediation_kinds(key).is_empty(), "advisory {key}");
        }
        // Healthy positives are the end state a fix moves apps toward.
        for spec in GROUP_CATALOG
            .iter()
            .filter(|s| matches!(s.section, GroupSection::Healthy))
        {
            assert!(
                group_remediation_kinds(spec.key).is_empty(),
                "healthy {}",
                spec.key
            );
        }
        // Unlike `matches_finding` (which falls through to `true`), an unknown
        // key here must fall through to NO fixes, never to every fix.
        assert!(group_remediation_kinds("not-a-group").is_empty());
    }
}
