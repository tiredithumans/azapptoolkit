//! Shared per-bucket posture counts over a cached audit run.
//!
//! The single count source for every surface that summarizes the audit — the
//! Security tab's posture strip and the Home dashboard's Security Posture card
//! — so the numbers can never disagree (Home previously re-derived them with
//! duplicate helpers). Finding buckets classify through
//! `filter::matches_finding`, the same predicate the Findings pane's groups
//! use, so a count can't diverge from the group it summarizes. Computed once
//! per scan, never per keystroke.

use azapptoolkit_core::audit::{AuditItem, RiskLevel};

use super::filter::matches_finding;

/// Per-bucket counts across one audit run. Finding counts are tenant-wide
/// totals (never intersected with an active severity filter).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PostureCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub expired: usize,
    pub unused: usize,
    pub over_privileged: usize,
    pub high_risk_delegated: usize,
    pub orgwide_mailbox: usize,
    pub scoped_mailbox: usize,
    pub legacy_mailbox_scope: usize,
    pub unscopable_legacy_mailbox: usize,
    pub unconfinable_orgwide: usize,
    pub orgwide_sharepoint: usize,
    pub scoped_sites: usize,
    pub unowned: usize,
    pub no_local_app: usize,
}

pub fn posture_counts(items: &[AuditItem]) -> PostureCounts {
    PostureCounts {
        critical: count_level(items, RiskLevel::Critical),
        high: count_level(items, RiskLevel::High),
        medium: count_level(items, RiskLevel::Medium),
        low: count_level(items, RiskLevel::Low),
        // Already-expired only — expiring-soon lives in the Credential-expiry
        // lens, mirroring the audit's `expired` finding.
        expired: count_finding(items, "expired"),
        unused: count_finding(items, "unused"),
        over_privileged: count_finding(items, "high_risk_perms"),
        high_risk_delegated: count_finding(items, "high_risk_delegated"),
        orgwide_mailbox: count_finding(items, "orgwide_mailbox"),
        scoped_mailbox: count_finding(items, "scoped_mailbox"),
        legacy_mailbox_scope: count_finding(items, "legacy_mailbox_scope"),
        unscopable_legacy_mailbox: count_finding(items, "unscopable_legacy_mailbox"),
        unconfinable_orgwide: count_finding(items, "unconfinable_orgwide"),
        orgwide_sharepoint: count_finding(items, "orgwide_sharepoint"),
        scoped_sites: count_finding(items, "scoped_sites"),
        // NO_OWNERS or SINGLE_OWNER — the one `ownership` group.
        unowned: count_finding(items, "ownership"),
        no_local_app: count_finding(items, "no_local_app"),
    }
}

fn count_level(items: &[AuditItem], level: RiskLevel) -> usize {
    items.iter().filter(|i| i.risk_level == level).count()
}

/// Principals in the `key` finding — the Findings pane's own classifier, so a
/// posture count and its group's size are the same number by construction.
fn count_finding(items: &[AuditItem], key: &str) -> usize {
    items.iter().filter(|i| matches_finding(i, key)).count()
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

    #[test]
    fn buckets_count_their_own_signal_only() {
        let critical_expired = AuditItem {
            risk_level: RiskLevel::Critical,
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        // ExpiringSoon must NOT count as expired (the lens owns lead-time).
        let expiring = AuditItem {
            credential_status: CredentialStatus::ExpiringSoon,
            ..blank()
        };
        let no_owner = AuditItem {
            issues: vec![format!("{} x", issue::NO_OWNERS)],
            ..blank()
        };
        let single_owner = AuditItem {
            issues: vec![format!("{} x", issue::SINGLE_OWNER)],
            ..blank()
        };
        let scoped = AuditItem {
            issues: vec![format!("Mail.Read {} (Sales)", issue::SCOPED_VIA_RBAC)],
            ..blank()
        };
        let sp = AuditItem {
            principal_kind: AuditPrincipalKind::ServicePrincipal,
            ..blank()
        };
        let c = posture_counts(&[
            critical_expired,
            expiring,
            no_owner,
            single_owner,
            scoped,
            sp,
        ]);
        assert_eq!(c.critical, 1);
        assert_eq!(c.low, 5);
        assert_eq!(c.expired, 1, "expiring-soon must not count as expired");
        // Disjoint markers sum exactly.
        assert_eq!(c.unowned, 2);
        assert_eq!(c.scoped_mailbox, 1, "mid-string marker counts via contains");
        assert_eq!(c.no_local_app, 1);
        assert_eq!(c.unused, 0);
    }

    /// Every finding bucket must equal the size of the Findings-pane group it
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
        let groups = super::super::groups::group_findings(&items);
        let size = |key: &str| {
            groups
                .iter()
                .find(|g| g.spec.key == key)
                .unwrap_or_else(|| panic!("no group {key}"))
                .item_indices
                .len()
        };
        for (key, count) in [
            ("expired", c.expired),
            ("unused", c.unused),
            ("high_risk_perms", c.over_privileged),
            ("high_risk_delegated", c.high_risk_delegated),
            ("orgwide_mailbox", c.orgwide_mailbox),
            ("scoped_mailbox", c.scoped_mailbox),
            ("legacy_mailbox_scope", c.legacy_mailbox_scope),
            ("unscopable_legacy_mailbox", c.unscopable_legacy_mailbox),
            ("unconfinable_orgwide", c.unconfinable_orgwide),
            ("orgwide_sharepoint", c.orgwide_sharepoint),
            ("scoped_sites", c.scoped_sites),
            ("ownership", c.unowned),
            ("no_local_app", c.no_local_app),
        ] {
            assert!(count > 0, "fixture leaves {key} empty");
            assert_eq!(count, size(key), "posture count for {key}");
        }
        assert_eq!(c.unconfinable_orgwide, 2);
        assert_eq!(c.unowned, 2);
    }
}
