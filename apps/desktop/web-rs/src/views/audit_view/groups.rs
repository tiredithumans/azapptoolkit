//! Finding-group taxonomy for the findings-first Security workbench.
//!
//! One catalog entry per finding key (the same keys `filter::matches_finding`
//! understands, so Home drills and the characterization tests share one
//! vocabulary), classified into two sections: **Actionable** findings ranked by
//! impact, and demoted **Healthy** positives (confirmed-scoped access). The
//! classifier delegates to `matches_finding` per key — the load-bearing
//! `.contains(SCOPED_VIA_RBAC)` vs `.starts_with` asymmetry lives in exactly
//! one place.

use azapptoolkit_core::audit::{AuditItem, RiskLevel};

use crate::components::bulk_action_bar::BulkAction;

use super::filter::matches_finding;

/// Which section of the Findings pane a group renders in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GroupSection {
    /// Ranked by impact; hidden at zero affected principals.
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
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "orgwide_mailbox",
        title: "Org-wide mailbox access",
        blurb: "Mail permissions that reach every mailbox in the tenant. Confine them to specific mail-enabled groups via Exchange RBAC for Applications.",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "orgwide_sharepoint",
        title: "Org-wide SharePoint access",
        blurb: "Sites.* permissions that reach every site collection. Convert them to the Sites.Selected model on the sites the app actually needs.",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "redundant_perms",
        title: "Redundant permissions",
        blurb: "Narrower application permissions a broader held permission already fully covers — pure attack surface, safe to remove.",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "ownership",
        title: "Missing or single owner",
        blurb: "Apps with no owner (accountability gap) or a single owner (vulnerable to departure). Adding an owner is purely additive.",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "unused",
        title: "Unused applications",
        blurb: "No sign-in activity in the report window. Disable sign-in (reversible) to verify nothing breaks, or delete when confirmed obsolete.",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "high_risk_perms",
        title: "High-risk application permissions",
        blurb: "Broad application permissions (e.g. Mail.ReadWrite, Directory.ReadWrite.All). Reducing them is an admin-judged change — open the app's Permissions tab to review downgrades or scoping.",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "high_risk_delegated",
        title: "High-risk delegated permissions",
        blurb: "Admin-consented delegated scopes with broad reach. Review on the principal's Permissions tab; delegated scopes are requested by name, so removal is admin-judged.",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "no_local_app",
        title: "No local app registration",
        blurb: "Foreign-tenant enterprise apps, managed identities, and orphaned service principals — scored from their granted roles. Credentials and manifest live in their home tenant; scope fixes still apply here.",
        section: GroupSection::Actionable,
    },
    GroupSpec {
        key: "scoped_mailbox",
        title: "Mailbox access scoped",
        blurb: "Mail permissions confirmed confined to specific mailboxes via Exchange RBAC — the configuration the org-wide fix moves apps toward.",
        section: GroupSection::Healthy,
    },
    GroupSpec {
        key: "scoped_sites",
        title: "SharePoint scoped to selected sites",
        blurb: "SharePoint access on the least-privilege Sites.Selected model.",
        section: GroupSection::Healthy,
    },
];

/// One computed finding group: which items (as indices into the run's item
/// slice, original risk-ranked order) match, the worst risk level among them,
/// and the impact (Σ risk_score) that ranks the Actionable section.
/// `Clone + PartialEq` so the pane's `Memo<Option<Vec<FindingGroup>>>` can
/// hand out and diff runs.
#[derive(Clone, PartialEq)]
pub(super) struct FindingGroup {
    pub spec: &'static GroupSpec,
    pub item_indices: Vec<usize>,
    pub worst: RiskLevel,
    pub impact: u32,
}

fn sev_rank(level: RiskLevel) -> u8 {
    match level {
        RiskLevel::Critical => 3,
        RiskLevel::High => 2,
        RiskLevel::Medium => 1,
        RiskLevel::Low => 0,
    }
}

/// Classifies `items` into every catalog group and ranks the Actionable
/// section by impact (descending; catalog order breaks ties). Healthy groups
/// keep catalog order at the end. Empty groups are returned too — the pane
/// hides empty Actionable groups but renders Healthy ones count-muted.
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
                .max_by_key(|&l| sev_rank(l))
                .unwrap_or(RiskLevel::Low);
            let impact = item_indices.iter().map(|&i| items[i].risk_score).sum();
            FindingGroup {
                spec,
                item_indices,
                worst,
                impact,
            }
        })
        .collect();
    // Stable sort: Actionable before Healthy, then impact descending. Stability
    // keeps catalog order as the tie-break within equal (section, impact).
    groups.sort_by_key(|g| {
        (
            matches!(g.spec.section, GroupSection::Healthy),
            std::cmp::Reverse(g.impact),
        )
    });
    groups
}

/// The Findings pane's Actionable groups, in the SAME impact ranking, as
/// `(key, title, tone)` — for surfaces outside the workbench (the Home posture
/// card) that echo the order + severity tone without re-deriving them. Healthy
/// groups are excluded; empty groups stay (the caller decides whether a
/// zero-count finding is worth showing). `tone` is the group's worst-severity
/// colour, matching the workbench's finding-group tone dot.
pub(crate) fn ranked_actionable_findings(
    items: &[AuditItem],
) -> Vec<(&'static str, &'static str, &'static str)> {
    group_findings(items)
        .into_iter()
        .filter(|g| matches!(g.spec.section, GroupSection::Actionable))
        .map(|g| (g.spec.key, g.spec.title, tone(g.worst)))
        .collect()
}

/// Maps a risk level to the shared tone-dot colour vocabulary (the same mapping
/// `finding_group_view` uses inline).
fn tone(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "critical",
        RiskLevel::High => "danger",
        RiskLevel::Medium => "warning",
        RiskLevel::Low => "ok",
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

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::{AuditPrincipalKind, CredentialStatus, issue};

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
    fn actionable_groups_rank_by_impact_then_catalog_order() {
        // ownership outscores expired here, so it must rank first despite its
        // later catalog position; zero-impact groups keep catalog order (stable
        // sort) after the scored ones.
        let expired = AuditItem {
            credential_status: CredentialStatus::Expired,
            risk_score: 8,
            risk_level: RiskLevel::Medium,
            ..blank()
        };
        let owner_a = with_issue(format!("{} x", issue::NO_OWNERS), 30, RiskLevel::Critical);
        let owner_b = with_issue(format!("{} x", issue::SINGLE_OWNER), 5, RiskLevel::Low);
        let items = vec![expired, owner_a, owner_b];
        let groups = group_findings(&items);

        let order: Vec<&str> = groups.iter().map(|g| g.spec.key).collect();
        let pos = |k: &str| order.iter().position(|x| *x == k).unwrap();
        assert!(
            pos("ownership") < pos("expired"),
            "impact 35 ranks above impact 8: {order:?}"
        );
        // Equal-impact (zero) actionable groups keep catalog order.
        assert!(pos("orgwide_mailbox") < pos("orgwide_sharepoint"));
        // Healthy groups always trail every actionable group.
        assert!(pos("scoped_mailbox") > pos("no_local_app"));
        assert!(pos("scoped_sites") > pos("scoped_mailbox"));

        let ownership = group(&groups, "ownership");
        assert_eq!(ownership.impact, 35);
        assert_eq!(ownership.worst, RiskLevel::Critical);
        assert_eq!(ownership.item_indices, vec![1, 2]);
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
        assert!(group_bulk_actions("no_local_app").is_empty());
        assert!(group_bulk_actions("scoped_mailbox").is_empty());
    }
}
