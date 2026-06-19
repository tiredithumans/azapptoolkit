//! The audit table's facet × search filter, as pure functions over the item set.

use azapptoolkit_core::audit::{issue, AuditItem, RiskLevel};

/// The audit table's filter, as a pure function over the item set: returns the
/// indices (in original order) of items matching both the facet and the
/// already-lowercased name/appId query. Extracted so the facet × search
/// interplay is pinned by tests, and so the perf rewrite can window over these
/// indices and clone only the rows it renders — instead of deep-cloning the
/// whole multi-MB matching set on every keystroke. `query_lower` must already
/// be lowercased (the caller lowercases once); an empty query matches all.
pub(super) fn filter_indices(items: &[AuditItem], facet: &str, query_lower: &str) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, i)| matches_facet(i, facet))
        .filter(|(_, i)| {
            query_lower.is_empty()
                || i.application_name.to_lowercase().contains(query_lower)
                || i.app_id.to_lowercase().contains(query_lower)
        })
        .map(|(idx, _)| idx)
        .collect()
}

pub(super) fn matches_facet(i: &AuditItem, facet: &str) -> bool {
    match facet {
        "all" => true,
        "critical" => matches!(i.risk_level, RiskLevel::Critical),
        "high" => matches!(i.risk_level, RiskLevel::High),
        "medium" => matches!(i.risk_level, RiskLevel::Medium),
        "low" => matches!(i.risk_level, RiskLevel::Low),
        "expiring" => {
            use azapptoolkit_core::audit::CredentialStatus;
            matches!(
                i.credential_status,
                CredentialStatus::ExpiringSoon | CredentialStatus::Expired
            )
        }
        "high_risk_perms" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::HIGH_RISK_APP_PERMS)),
        "high_risk_delegated" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::HIGH_RISK_DELEGATED_PERMS)),
        // Effective mailbox scoping facets. Scoping is resolved on every run, but
        // degrades to org-wide when the signed-in user lacks Exchange-admin rights.
        "orgwide_mailbox" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::ORG_WIDE_MAILBOX)),
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
    // These pin the facet × search interplay before the at-scale perf rewrite
    // (windowed, index-based rendering) so the rewrite is provably
    // behavior-preserving. The query is passed already-lowercased, mirroring
    // the call site (`search_debounced.get().to_lowercase()`).

    #[test]
    fn filter_indices_empty_query_keeps_facet_matches_in_order() {
        let items = vec![
            named("Alpha", "aaa", RiskLevel::Critical),
            named("Beta", "bbb", RiskLevel::Low),
            named("Gamma", "ccc", RiskLevel::Critical),
        ];
        // "all" facet, empty query → every index, original order.
        assert_eq!(filter_indices(&items, "all", ""), vec![0, 1, 2]);
        // A risk facet keeps only its matches, preserving order.
        assert_eq!(filter_indices(&items, "critical", ""), vec![0, 2]);
        assert_eq!(filter_indices(&items, "low", ""), vec![1]);
    }

    #[test]
    fn filter_indices_query_matches_name_or_appid_case_insensitively() {
        let items = vec![
            named("Payroll API", "1111-aaaa", RiskLevel::Low),
            named("HR Sync", "2222-bbbb", RiskLevel::Low),
        ];
        // Name substring (caller lowercases the query; data is lowercased here).
        assert_eq!(filter_indices(&items, "all", "payroll"), vec![0]);
        // AppId substring also matches.
        assert_eq!(filter_indices(&items, "all", "2222"), vec![1]);
        // No match → empty.
        assert!(filter_indices(&items, "all", "zzz").is_empty());
    }

    #[test]
    fn filter_indices_combines_facet_and_query_as_intersection() {
        let items = vec![
            named("Critical Payroll", "aaa", RiskLevel::Critical),
            named("Low Payroll", "bbb", RiskLevel::Low),
            named("Critical Other", "ccc", RiskLevel::Critical),
        ];
        // Both predicates must hold: critical AND name contains "payroll".
        assert_eq!(filter_indices(&items, "critical", "payroll"), vec![0]);
        // Facet excludes the matching-name low-risk row.
        assert_eq!(
            filter_indices(&items, "high", "payroll"),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn filter_indices_indices_address_the_original_slice() {
        // The rewrite renders `items[idx]`, so every returned index must be a
        // valid, correct address into the *unfiltered* slice.
        let items = vec![
            named("keep me", "aaa", RiskLevel::Low),
            named("skip", "bbb", RiskLevel::Low),
            named("keep me too", "ccc", RiskLevel::Low),
        ];
        let idx = filter_indices(&items, "all", "keep");
        assert_eq!(idx, vec![0, 2]);
        for i in idx {
            assert!(items[i].application_name.contains("keep"));
        }
    }

    // Consumer half of the structured-signals invariant: the producer side is
    // pinned by core's `emitted_issue_markers_are_stable`; this pins that each
    // marker-driven facet matches exactly its own marker and no sibling's.
    #[test]
    fn issue_marker_facets_match_exactly_their_facet() {
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
        let marker_facets = [
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
            for f in marker_facets {
                assert_eq!(
                    matches_facet(&item, f),
                    f == *expect,
                    "issue {text:?} vs facet {f}"
                );
            }
        }
    }

    #[test]
    fn scoped_mailbox_facet_matches_the_mid_string_marker() {
        // SCOPED_VIA_RBAC is deliberately matched with `.contains` — the
        // scorer embeds it mid-issue ("Mail.Read scoped via Exchange RBAC…"),
        // not as a prefix like every sibling marker. Load-bearing asymmetry:
        // a well-meaning "make them all starts_with" sweep would silently
        // empty the Scoped-mailbox facet.
        let item = with_issue(format!("Mail.Read {} (Sales Team)", issue::SCOPED_VIA_RBAC));
        assert!(matches_facet(&item, "scoped_mailbox"));
        assert!(!matches_facet(&item, "orgwide_mailbox"));
    }
}
