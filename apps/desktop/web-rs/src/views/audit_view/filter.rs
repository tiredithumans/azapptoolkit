//! The audit table's filter, as pure functions over the item set.
//!
//! The filter is two INDEPENDENT dimensions — risk **severity** and **finding**
//! type — intersected with the name/appId search. They're split so an auditor
//! can stack them (e.g. Critical apps *with* expiring credentials) instead of
//! picking one flat facet at a time.

use azapptoolkit_core::audit::{AuditItem, AuditPrincipalKind, RiskLevel, issue};

use crate::util::contains_ignore_case;

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
                || contains_ignore_case(&i.application_name, query_lower)
                || contains_ignore_case(&i.app_id, query_lower)
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

/// The per-issue predicate behind a marker-driven finding: does THIS issue line
/// belong to `finding`? `None` for `"all"`, for an unknown key, and for the
/// findings that key off a structured `AuditItem` field instead of issue text.
///
/// The key→marker table living here exactly once is the point:
/// [`matches_finding`] asks "does any issue match?" and [`issue_lines_for`] asks
/// "which ones?", so a group's membership and the line a row quotes for it can
/// never diverge — including the load-bearing `.contains` arm below.
fn issue_marker(finding: &str) -> Option<fn(&str) -> bool> {
    let marks: fn(&str) -> bool = match finding {
        "high_risk_perms" => |x| x.starts_with(issue::HIGH_RISK_APP_PERMS),
        "high_risk_delegated" => |x| x.starts_with(issue::HIGH_RISK_DELEGATED_PERMS),
        // Reach beyond this directory. Both markers live in one group: the
        // publisher finding only ever fires alongside the audience one, so
        // splitting them would produce a group that is always a subset of
        // another.
        "external_exposure" => |x| {
            x.starts_with(issue::MULTITENANT_AUDIENCE) || x.starts_with(issue::UNVERIFIED_PUBLISHER)
        },
        // Effective mailbox scoping findings. Scoping is resolved on every run, but
        // degrades to org-wide when the signed-in user lacks Exchange-admin rights.
        "orgwide_mailbox" => |x| x.starts_with(issue::ORG_WIDE_MAILBOX),
        // Load-bearing asymmetry: `SCOPED_VIA_RBAC` is embedded MID-issue
        // ("Mail.Read scoped via Exchange RBAC…"), not a prefix like its siblings,
        // so this must stay `.contains` — a "normalize to starts_with" sweep would
        // silently empty the Scoped-mailbox finding (pinned by the tests below).
        "scoped_mailbox" => |x| x.contains(issue::SCOPED_VIA_RBAC),
        // Confined, but by the deprecated per-app Application Access Policy
        // rather than RBAC for Applications. Its own finding, not a variant of
        // `orgwide_mailbox` (the access IS confined) and not of `scoped_mailbox`
        // (that group is the healthy end state this one migrates toward) — the
        // scorer keeps `SCOPED_VIA_RBAC` off these advisories so the two can't
        // both match.
        "legacy_mailbox_scope" => |x| x.starts_with(issue::LEGACY_MAILBOX_POLICY),
        "orgwide_sharepoint" => |x| x.starts_with(issue::ORG_WIDE_SHAREPOINT),
        // Rule 18 — held narrower permissions a broader held one already covers.
        // Its own finding key (not folded into `high_risk_perms`) so the
        // RemoveRedundant group/bulk action pairs with the rule it actually
        // fixes.
        "redundant_perms" => |x| x.starts_with(issue::REDUNDANT_APP_PERMS),
        "scoped_sites" => |x| x.starts_with(issue::SCOPED_SHAREPOINT),
        "ownership" => |x| x.starts_with(issue::NO_OWNERS) || x.starts_with(issue::SINGLE_OWNER),
        _ => return None,
    };
    Some(marks)
}

/// Finding-type dimension: `"all"` plus the structured/marker-driven findings.
/// The marker-driven half delegates to [`issue_marker`]; what stays here is the
/// half that reads a structured field, which carries no issue line at all.
pub(super) fn matches_finding(i: &AuditItem, finding: &str) -> bool {
    if let Some(marks) = issue_marker(finding) {
        return i.issues.iter().any(|x| marks(x.as_str()));
    }
    match finding {
        // Already-expired credentials only — proactive "expiring soon" rotation
        // lead-time lives in the Credential-expiry lens (≤7d / ≤30d facets).
        "expired" => {
            use azapptoolkit_core::audit::CredentialStatus;
            matches!(i.credential_status, CredentialStatus::Expired)
        }
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
        // `"all"` — and, deliberately, an unknown key: no constraint.
        _ => true,
    }
}

/// The issue line(s) on `item` that put it in the `key` finding — the "what,
/// exactly?" a Findings-pane row shows. A pane grouped BY finding otherwise
/// says nothing about the finding: under "Org-wide mailbox access" the operator
/// could not see WHICH mail permission was org-wide, or on which resource,
/// without opening every row. The scorer already writes that into `issues`
/// ("Organization-wide mailbox access: Mail.ReadWrite (Microsoft Graph),
/// Mail.Send"); quoting it through the same predicate that classified the row
/// keeps the quoted line and the group membership from ever disagreeing.
///
/// Empty for `"all"` and for the structured findings — `expired`, `unused` and
/// `no_local_app` key off a field, so there is no line to quote and the row's
/// own columns carry the evidence (the Fix preview names the expired
/// credentials, Last sign-in carries `unused`, the principal kind IS
/// `no_local_app`). Empty for an unknown key too: the Detail cell must degrade
/// to nothing, never to a dump of every issue the app tripped.
pub(super) fn issue_lines_for<'a>(item: &'a AuditItem, key: &str) -> Vec<&'a str> {
    let Some(marks) = issue_marker(key) else {
        return Vec::new();
    };
    item.issues
        .iter()
        .filter(|x| marks(x.as_str()))
        .map(String::as_str)
        .collect()
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

    /// The external-exposure group must match on EITHER of its two markers —
    /// the publisher finding rides the same group as the audience one, so a
    /// group that only matched the audience marker would drop nothing today but
    /// would silently diverge the moment the rules stop firing together.
    #[test]
    fn external_exposure_matches_either_marker() {
        let audience = with_issue(format!(
            "{} — reaches any Entra tenant",
            issue::MULTITENANT_AUDIENCE
        ));
        let publisher = with_issue(format!(
            "{} — cannot be attributed",
            issue::UNVERIFIED_PUBLISHER
        ));
        let unrelated = with_issue(format!("{} Mail.Read", issue::HIGH_RISK_APP_PERMS));
        assert!(matches_finding(&audience, "external_exposure"));
        assert!(matches_finding(&publisher, "external_exposure"));
        assert!(!matches_finding(&unrelated, "external_exposure"));
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
                format!("{} something", issue::LEGACY_MAILBOX_POLICY),
                "legacy_mailbox_scope",
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
            (
                format!("{} something", issue::REDUNDANT_APP_PERMS),
                "redundant_perms",
            ),
        ];
        let marker_findings = [
            "high_risk_perms",
            "high_risk_delegated",
            "orgwide_mailbox",
            "scoped_mailbox",
            "legacy_mailbox_scope",
            "orgwide_sharepoint",
            "scoped_sites",
            "ownership",
            "redundant_perms",
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

    /// The Findings pane quotes these lines beside each row, so the set must be
    /// exactly the issues that put the item in the group: every one of its own
    /// (or the cell under-reports the finding) and none of a sibling's (or the
    /// cell contradicts the group header it sits under).
    #[test]
    fn issue_lines_for_quotes_only_this_findings_own_lines() {
        let item = AuditItem {
            issues: vec![
                format!(
                    "{}: Mail.ReadWrite (Microsoft Graph), Mail.Send",
                    issue::ORG_WIDE_MAILBOX
                ),
                format!("{}: Sites.ReadWrite.All", issue::ORG_WIDE_SHAREPOINT),
                "Long-lived secrets (>1 year): old-secret".to_string(),
            ],
            ..blank()
        };
        assert_eq!(
            issue_lines_for(&item, "orgwide_mailbox"),
            vec![item.issues[0].as_str()]
        );
        assert_eq!(
            issue_lines_for(&item, "orgwide_sharepoint"),
            vec![item.issues[1].as_str()]
        );
        // A finding this item doesn't trip quotes nothing — never the unmatched
        // rest of the issue list.
        assert!(issue_lines_for(&item, "ownership").is_empty());
    }

    #[test]
    fn issue_lines_for_covers_multi_marker_and_mid_string_findings() {
        // Two markers, one group: both lines belong in the cell.
        let external = AuditItem {
            issues: vec![
                format!("{} — reaches any Entra tenant", issue::MULTITENANT_AUDIENCE),
                format!("{} — cannot be attributed", issue::UNVERIFIED_PUBLISHER),
            ],
            ..blank()
        };
        assert_eq!(issue_lines_for(&external, "external_exposure").len(), 2);

        // The `.contains` asymmetry reaches the quoted line too: matched with
        // `.starts_with`, every healthy scoped row would render an empty cell.
        let scoped = with_issue(format!(
            "High-risk mailbox permissions {} (reduced risk): Mail.Read",
            issue::SCOPED_VIA_RBAC
        ));
        assert_eq!(issue_lines_for(&scoped, "scoped_mailbox").len(), 1);
    }

    #[test]
    fn issue_lines_for_is_empty_for_structured_and_unknown_findings() {
        // These three classify off a field, so there is no line to quote — the
        // row's other columns carry their evidence. An unknown key (and "all")
        // must degrade to nothing rather than dumping the whole issue list.
        let item = AuditItem {
            credential_status: CredentialStatus::Expired,
            unused: true,
            principal_kind: AuditPrincipalKind::ServicePrincipal,
            issues: vec!["All credentials expired: old-secret".to_string()],
            ..blank()
        };
        for key in ["expired", "unused", "no_local_app", "all", "not-a-finding"] {
            assert!(issue_lines_for(&item, key).is_empty(), "finding {key}");
        }
    }

    #[test]
    fn legacy_policy_scoping_is_neither_org_wide_nor_healthy_scoped() {
        // The three mailbox findings are mutually exclusive by construction:
        // legacy-policy scoping is confined (so not org-wide) but deprecated (so
        // not the healthy RBAC group). The separation rests on the scorer
        // keeping SCOPED_VIA_RBAC out of this advisory — if that leaks back in,
        // `scoped_mailbox`'s `.contains` would swallow the row and the
        // migration finding would look empty.
        let item = with_issue(format!("{}: Mail.Read", issue::LEGACY_MAILBOX_POLICY));
        assert!(matches_finding(&item, "legacy_mailbox_scope"));
        assert!(!matches_finding(&item, "scoped_mailbox"));
        assert!(!matches_finding(&item, "orgwide_mailbox"));
    }
}
