//! The audit table's filter, as pure functions over the item set.
//!
//! The filter is two INDEPENDENT dimensions — risk **severity** and **finding**
//! type — intersected with the name/appId search. They're split so an auditor
//! can stack them (e.g. Critical apps *with* expiring credentials) instead of
//! picking one flat facet at a time.

use azapptoolkit_core::audit::{AuditItem, AuditPrincipalKind, RiskLevel, issue};

/// The audit table's filter, as a pure function over the item set: returns the
/// indices (in original order) of items matching the severity dimension AND the
/// finding dimension AND the already-lowercased name/appId query. Extracted so
/// the severity × finding × search interplay is pinned by tests, and so the
/// renderer can window over these indices and clone only the rows it renders —
/// instead of deep-cloning the whole multi-MB matching set on every keystroke.
/// `query_lower` must already be lowercased (the caller lowercases once); an
/// empty query matches all. Each dimension's `"all"` value matches everything.
pub(super) fn filter_indices(
    items: &[AuditItem],
    severity: &str,
    finding: &str,
    query_lower: &str,
) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, i)| matches_severity(i, severity))
        .filter(|(_, i)| matches_finding(i, finding))
        .filter(|(_, i)| {
            query_lower.is_empty()
                || i.application_name.to_lowercase().contains(query_lower)
                || i.app_id.to_lowercase().contains(query_lower)
        })
        .map(|(idx, _)| idx)
        .collect()
}

/// Risk-severity dimension: `"all"` plus the four `RiskLevel` buckets.
pub(super) fn matches_severity(i: &AuditItem, severity: &str) -> bool {
    match severity {
        "all" => true,
        "critical" => matches!(i.risk_level, RiskLevel::Critical),
        "high" => matches!(i.risk_level, RiskLevel::High),
        "medium" => matches!(i.risk_level, RiskLevel::Medium),
        "low" => matches!(i.risk_level, RiskLevel::Low),
        _ => true,
    }
}

/// Finding-type dimension: `"all"` plus the structured/marker-driven findings.
pub(super) fn matches_finding(i: &AuditItem, finding: &str) -> bool {
    match finding {
        "all" => true,
        // Already-expired credentials only — proactive "expiring soon" rotation
        // lead-time lives in the Credential-expiry lens (≤7d / ≤30d facets).
        "expired" => {
            use azapptoolkit_core::audit::CredentialStatus;
            matches!(i.credential_status, CredentialStatus::Expired)
        }
        "high_risk_perms" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::HIGH_RISK_APP_PERMS)),
        "high_risk_delegated" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::HIGH_RISK_DELEGATED_PERMS)),
        // Effective mailbox scoping findings. Scoping is resolved on every run, but
        // degrades to org-wide when the signed-in user lacks Exchange-admin rights.
        "orgwide_mailbox" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::ORG_WIDE_MAILBOX)),
        // Load-bearing asymmetry: `SCOPED_VIA_RBAC` is embedded MID-issue
        // ("Mail.Read scoped via Exchange RBAC…"), not a prefix like its siblings,
        // so this must stay `.contains` — a "normalize to starts_with" sweep would
        // silently empty the Scoped-mailbox finding (pinned by the tests below).
        "scoped_mailbox" => i.issues.iter().any(|x| x.contains(issue::SCOPED_VIA_RBAC)),
        "orgwide_sharepoint" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::ORG_WIDE_SHAREPOINT)),
        "scoped_sites" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::SCOPED_SHAREPOINT)),
        "ownership" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::NO_OWNERS) || x.starts_with(issue::SINGLE_OWNER)),
        // Structured flag set by the audit runner from the sign-in activity
        // report — no longer parsed from the issue text.
        "unused" => i.unused,
        // Structured kind field: SP-only rows (foreign enterprise apps, managed
        // identities, orphaned SPs) — principals scored from their granted app
        // roles because no local application object exists.
        "no_local_app" => matches!(
            i.principal_kind,
            AuditPrincipalKind::ServicePrincipal | AuditPrincipalKind::ManagedIdentity
        ),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::CredentialStatus;

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

    fn with_issue(text: String) -> AuditItem {
        AuditItem {
            issues: vec![text],
            ..blank()
        }
    }

    fn named(name: &str, app_id: &str, level: RiskLevel) -> AuditItem {
        AuditItem {
            application_name: name.into(),
            app_id: app_id.into(),
            risk_level: level,
            ..blank()
        }
    }

    // ---- filter_indices characterization (T-M7) ----------------------------
    // These pin the severity × finding × search interplay so the windowed,
    // index-based renderer is provably behavior-preserving. The query is passed
    // already-lowercased, mirroring the call site
    // (`search_debounced.get().to_lowercase()`). Both dimension args take "all"
    // to mean "no constraint".

    #[test]
    fn filter_indices_empty_query_keeps_severity_matches_in_order() {
        let items = vec![
            named("Alpha", "aaa", RiskLevel::Critical),
            named("Beta", "bbb", RiskLevel::Low),
            named("Gamma", "ccc", RiskLevel::Critical),
        ];
        // "all"/"all", empty query → every index, original order.
        assert_eq!(filter_indices(&items, "all", "all", ""), vec![0, 1, 2]);
        // A severity filter keeps only its matches, preserving order.
        assert_eq!(filter_indices(&items, "critical", "all", ""), vec![0, 2]);
        assert_eq!(filter_indices(&items, "low", "all", ""), vec![1]);
    }

    #[test]
    fn filter_indices_query_matches_name_or_appid_case_insensitively() {
        let items = vec![
            named("Payroll API", "1111-aaaa", RiskLevel::Low),
            named("HR Sync", "2222-bbbb", RiskLevel::Low),
        ];
        // Name substring (caller lowercases the query; data is lowercased here).
        assert_eq!(filter_indices(&items, "all", "all", "payroll"), vec![0]);
        // AppId substring also matches.
        assert_eq!(filter_indices(&items, "all", "all", "2222"), vec![1]);
        // No match → empty.
        assert!(filter_indices(&items, "all", "all", "zzz").is_empty());
    }

    #[test]
    fn filter_indices_combines_severity_and_query_as_intersection() {
        let items = vec![
            named("Critical Payroll", "aaa", RiskLevel::Critical),
            named("Low Payroll", "bbb", RiskLevel::Low),
            named("Critical Other", "ccc", RiskLevel::Critical),
        ];
        // All predicates must hold: critical AND name contains "payroll".
        assert_eq!(
            filter_indices(&items, "critical", "all", "payroll"),
            vec![0]
        );
        // Severity excludes the matching-name low-risk row.
        assert_eq!(
            filter_indices(&items, "high", "all", "payroll"),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn filter_indices_intersects_severity_and_finding() {
        use azapptoolkit_core::audit::CredentialStatus;
        let expired_critical = AuditItem {
            risk_level: RiskLevel::Critical,
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        let active_critical = AuditItem {
            risk_level: RiskLevel::Critical,
            credential_status: CredentialStatus::Active,
            ..blank()
        };
        let expired_low = AuditItem {
            risk_level: RiskLevel::Low,
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        // ExpiringSoon must NOT match the "expired" finding (narrowed to already
        // expired only — expiring-soon lives in the Credential-expiry lens).
        let expiring_soon_critical = AuditItem {
            risk_level: RiskLevel::Critical,
            credential_status: CredentialStatus::ExpiringSoon,
            ..blank()
        };
        let items = vec![
            expired_critical,
            active_critical,
            expired_low,
            expiring_soon_critical,
        ];
        // The two dimensions intersect: only the critical AND expired row.
        assert_eq!(filter_indices(&items, "critical", "expired", ""), vec![0]);
        // Either dimension alone is broader.
        assert_eq!(filter_indices(&items, "critical", "all", ""), vec![0, 1, 3]);
        // "expired" matches only the two already-expired rows, not the soon one.
        assert_eq!(filter_indices(&items, "all", "expired", ""), vec![0, 2]);
    }

    #[test]
    fn filter_indices_indices_address_the_original_slice() {
        // The renderer indexes `items[idx]`, so every returned index must be a
        // valid, correct address into the *unfiltered* slice.
        let items = vec![
            named("keep me", "aaa", RiskLevel::Low),
            named("skip", "bbb", RiskLevel::Low),
            named("keep me too", "ccc", RiskLevel::Low),
        ];
        let idx = filter_indices(&items, "all", "all", "keep");
        assert_eq!(idx, vec![0, 2]);
        for i in idx {
            assert!(items[i].application_name.contains("keep"));
        }
    }

    #[test]
    fn matches_severity_matches_only_its_own_bucket() {
        let crit = named("c", "c", RiskLevel::Critical);
        // "all" matches every level; each named level matches only its bucket.
        assert!(matches_severity(&crit, "all"));
        assert!(matches_severity(&crit, "critical"));
        assert!(!matches_severity(&crit, "high"));
        assert!(!matches_severity(&crit, "medium"));
        assert!(!matches_severity(&crit, "low"));
        let low = named("l", "l", RiskLevel::Low);
        assert!(matches_severity(&low, "low"));
        assert!(!matches_severity(&low, "critical"));
    }

    // Consumer half of the structured-signals invariant: the producer side is
    // pinned by core's `emitted_issue_markers_are_stable`; this pins that each
    // marker-driven finding matches exactly its own marker and no sibling's.
    #[test]
    fn issue_marker_findings_match_exactly_their_finding() {
        let cases = [
            (
                format!("{} something", issue::HIGH_RISK_APP_PERMS),
                "high_risk_perms",
            ),
            (
                format!("{} something", issue::HIGH_RISK_DELEGATED_PERMS),
                "high_risk_delegated",
            ),
            (
                format!("{} something", issue::ORG_WIDE_MAILBOX),
                "orgwide_mailbox",
            ),
            (
                format!("{} something", issue::ORG_WIDE_SHAREPOINT),
                "orgwide_sharepoint",
            ),
            (
                format!("{} something", issue::SCOPED_SHAREPOINT),
                "scoped_sites",
            ),
            (format!("{} something", issue::NO_OWNERS), "ownership"),
        ];
        let marker_findings = [
            "high_risk_perms",
            "high_risk_delegated",
            "orgwide_mailbox",
            "scoped_mailbox",
            "orgwide_sharepoint",
            "scoped_sites",
            "ownership",
        ];
        for (text, expect) in &cases {
            let item = with_issue(text.clone());
            for f in marker_findings {
                assert_eq!(
                    matches_finding(&item, f),
                    f == *expect,
                    "issue {text:?} vs finding {f}"
                );
            }
        }
    }

    #[test]
    fn no_local_app_finding_matches_sp_and_mi_kinds_only() {
        // Structured-field finding (like "unused"/"expired"): keys off
        // `principal_kind`, never issue text.
        let app = blank();
        let sp = AuditItem {
            principal_kind: AuditPrincipalKind::ServicePrincipal,
            ..blank()
        };
        let mi = AuditItem {
            principal_kind: AuditPrincipalKind::ManagedIdentity,
            ..blank()
        };
        assert!(!matches_finding(&app, "no_local_app"));
        assert!(matches_finding(&sp, "no_local_app"));
        assert!(matches_finding(&mi, "no_local_app"));
        // And the kind alone trips no marker-driven finding.
        for f in ["high_risk_perms", "orgwide_mailbox", "orgwide_sharepoint"] {
            assert!(!matches_finding(&sp, f), "kind alone matched finding {f}");
        }
    }

    #[test]
    fn scoped_mailbox_finding_matches_the_mid_string_marker() {
        // SCOPED_VIA_RBAC is deliberately matched with `.contains` — the
        // scorer embeds it mid-issue ("Mail.Read scoped via Exchange RBAC…"),
        // not as a prefix like every sibling marker. Load-bearing asymmetry:
        // a well-meaning "make them all starts_with" sweep would silently
        // empty the Scoped-mailbox finding.
        let item = with_issue(format!("Mail.Read {} (Sales Team)", issue::SCOPED_VIA_RBAC));
        assert!(matches_finding(&item, "scoped_mailbox"));
        assert!(!matches_finding(&item, "orgwide_mailbox"));
    }
}
