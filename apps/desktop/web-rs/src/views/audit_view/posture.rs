//! Shared per-bucket posture counts over a cached audit run.
//!
//! The single count source for every surface that summarizes the audit — the
//! Security tab's posture strip and the Home dashboard's Security Posture card
//! — so the numbers can never disagree (Home previously re-derived them with
//! duplicate helpers). Computed once per scan, never per keystroke.

use azapptoolkit_core::audit::{AuditItem, AuditPrincipalKind, CredentialStatus, RiskLevel, issue};

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
        expired: items
            .iter()
            .filter(|i| matches!(i.credential_status, CredentialStatus::Expired))
            .count(),
        unused: items.iter().filter(|i| i.unused).count(),
        over_privileged: count_issue_prefix(items, issue::HIGH_RISK_APP_PERMS),
        high_risk_delegated: count_issue_prefix(items, issue::HIGH_RISK_DELEGATED_PERMS),
        orgwide_mailbox: count_issue_prefix(items, issue::ORG_WIDE_MAILBOX),
        // Mid-string marker — `.contains`, the same load-bearing asymmetry as
        // the scoped_mailbox finding predicate.
        scoped_mailbox: items
            .iter()
            .filter(|i| i.issues.iter().any(|x| x.contains(issue::SCOPED_VIA_RBAC)))
            .count(),
        orgwide_sharepoint: count_issue_prefix(items, issue::ORG_WIDE_SHAREPOINT),
        scoped_sites: count_issue_prefix(items, issue::SCOPED_SHAREPOINT),
        // NO_OWNERS and SINGLE_OWNER are disjoint per app, so the sum is exact.
        unowned: items
            .iter()
            .filter(|i| {
                i.issues
                    .iter()
                    .any(|x| x.starts_with(issue::NO_OWNERS) || x.starts_with(issue::SINGLE_OWNER))
            })
            .count(),
        no_local_app: items
            .iter()
            .filter(|i| i.principal_kind != AuditPrincipalKind::Application)
            .count(),
    }
}

fn count_level(items: &[AuditItem], level: RiskLevel) -> usize {
    items.iter().filter(|i| i.risk_level == level).count()
}

fn count_issue_prefix(items: &[AuditItem], prefix: &str) -> usize {
    items
        .iter()
        .filter(|i| i.issues.iter().any(|x| x.starts_with(prefix)))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
