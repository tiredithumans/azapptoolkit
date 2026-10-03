//! Shared per-bucket posture counts over one audit run.
//!
//! The single count source for every surface that summarizes the audit — the
//! Security tab's posture strip (computed over the run it holds) and the Home
//! dashboard's Security Posture card (computed backend-side into a
//! `CachedAuditSummary`, so Home never pulls the run itself) — so the numbers
//! can never disagree. Finding buckets classify through [`matches_finding`],
//! the same predicate the Findings pane's groups use, so a count can't diverge
//! from the group it summarizes. Computed once per scan, never per keystroke.

use serde::{Deserialize, Serialize};

use super::{AuditItem, RiskLevel, matches_finding};

/// Per-bucket counts across one audit run. Finding counts are tenant-wide
/// totals (never intersected with an active severity filter).
///
/// Crosses IPC inside `CachedAuditSummary`; snake_case on the wire like
/// [`AuditItem`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    pub orgwide_files: usize,
    pub scoped_sites: usize,
    pub unowned: usize,
    pub no_local_app: usize,
}

/// The finding keys [`PostureCounts`] counts — each one a key
/// [`PostureCounts::finding`] answers for.
pub const POSTURE_FINDING_KEYS: [&str; 14] = [
    "expired",
    "unused",
    "high_risk_perms",
    "high_risk_delegated",
    "orgwide_mailbox",
    "scoped_mailbox",
    "legacy_mailbox_scope",
    "unscopable_legacy_mailbox",
    "unconfinable_orgwide",
    "orgwide_sharepoint",
    "orgwide_files",
    "scoped_sites",
    "ownership",
    "no_local_app",
];

impl PostureCounts {
    /// The count for a finding key (the Findings pane's group key) — the one
    /// key→field map, so a surface that walks the group catalog reads the
    /// same number the strip shows. `None` for a key no bucket counts.
    pub fn finding(&self, key: &str) -> Option<usize> {
        Some(match key {
            "expired" => self.expired,
            "unused" => self.unused,
            "high_risk_perms" => self.over_privileged,
            "high_risk_delegated" => self.high_risk_delegated,
            "orgwide_mailbox" => self.orgwide_mailbox,
            "scoped_mailbox" => self.scoped_mailbox,
            "legacy_mailbox_scope" => self.legacy_mailbox_scope,
            "unscopable_legacy_mailbox" => self.unscopable_legacy_mailbox,
            "unconfinable_orgwide" => self.unconfinable_orgwide,
            "orgwide_sharepoint" => self.orgwide_sharepoint,
            "orgwide_files" => self.orgwide_files,
            "scoped_sites" => self.scoped_sites,
            "ownership" => self.unowned,
            "no_local_app" => self.no_local_app,
            _ => return None,
        })
    }
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
        orgwide_files: count_finding(items, "orgwide_files"),
        scoped_sites: count_finding(items, "scoped_sites"),
        // NO_OWNERS or SINGLE_OWNER — the one `ownership` group.
        unowned: count_finding(items, "ownership"),
        no_local_app: count_finding(items, "no_local_app"),
    }
}

/// The worst risk level among the principals in the `key` finding — what the
/// Findings pane ranks a group by and colours its tone dot with. `None` when
/// the finding is empty.
pub fn finding_worst(items: &[AuditItem], key: &str) -> Option<RiskLevel> {
    items
        .iter()
        .filter(|i| matches_finding(i, key))
        .map(|i| i.risk_level)
        .max()
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
    use crate::audit::{AuditPrincipalKind, CredentialStatus, issue};

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
            sp_risk_state: None,
            sp_risk_level: None,
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

    /// `finding` is the one key→field map: every listed key answers with the
    /// size of its own finding, and a key no bucket counts answers `None`
    /// rather than a neighbour's number.
    #[test]
    fn every_posture_key_reads_its_own_finding_count() {
        let marker = |m: &str| AuditItem {
            issues: vec![format!("{m}: x")],
            ..blank()
        };
        // A distinct number of members per finding, so a crossed field in
        // `finding` can't read back the right count by coincidence.
        let mut items = Vec::new();
        for (n, m) in [
            issue::HIGH_RISK_APP_PERMS,
            issue::HIGH_RISK_DELEGATED_PERMS,
            issue::ORG_WIDE_MAILBOX,
            issue::LEGACY_MAILBOX_POLICY,
            issue::UNSCOPABLE_LEGACY_MAILBOX,
            issue::UNCONFINABLE_MAILBOX,
            issue::ORG_WIDE_SHAREPOINT,
            issue::ORG_WIDE_FILES,
            issue::SCOPED_SHAREPOINT,
            issue::NO_OWNERS,
        ]
        .into_iter()
        .enumerate()
        {
            items.extend(std::iter::repeat_with(|| marker(m)).take(n + 1));
        }
        items.extend((0..10).map(|_| AuditItem {
            issues: vec![format!("Mail.Read {} (Sales)", issue::SCOPED_VIA_RBAC)],
            ..blank()
        }));
        items.extend((0..11).map(|_| AuditItem {
            credential_status: CredentialStatus::Expired,
            ..blank()
        }));
        items.extend((0..12).map(|_| AuditItem {
            unused: true,
            ..blank()
        }));
        items.extend((0..13).map(|_| AuditItem {
            principal_kind: AuditPrincipalKind::ManagedIdentity,
            ..blank()
        }));
        let c = posture_counts(&items);
        for key in POSTURE_FINDING_KEYS {
            let expected = items.iter().filter(|i| matches_finding(i, key)).count();
            assert!(expected > 0, "fixture leaves {key} empty");
            assert_eq!(c.finding(key), Some(expected), "posture count for {key}");
        }
        for key in ["redundant_perms", "external_exposure", "all", "nope"] {
            assert_eq!(c.finding(key), None, "{key} is not a posture bucket");
        }
    }

    #[test]
    fn worst_is_the_highest_member_level_and_none_when_empty() {
        let expired = |level| AuditItem {
            risk_level: level,
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        let items = [
            expired(RiskLevel::Low),
            expired(RiskLevel::Critical),
            expired(RiskLevel::Medium),
            // Critical, but not in the finding — must not lift another's worst.
            AuditItem {
                risk_level: RiskLevel::Critical,
                issues: vec![format!("{} x", issue::NO_OWNERS)],
                ..blank()
            },
            AuditItem {
                risk_level: RiskLevel::Medium,
                unused: true,
                ..blank()
            },
        ];
        assert_eq!(finding_worst(&items, "expired"), Some(RiskLevel::Critical));
        assert_eq!(finding_worst(&items, "unused"), Some(RiskLevel::Medium));
        assert_eq!(finding_worst(&items, "orgwide_mailbox"), None);
    }
}
