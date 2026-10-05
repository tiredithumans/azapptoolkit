//! The finding-key classifier: which audit finding (Findings-pane group,
//! posture bucket, Home "Top findings" line) an [`AuditItem`] belongs to.
//!
//! Lives in core, not in the Security workbench, because the backend counts
//! with it too — `CachedAuditSummary` is computed here so the Home card never
//! pulls the whole run over IPC — and a count must classify through the very
//! predicate the workbench's groups use, or the card and the pane it opens
//! would disagree.

use super::{AuditItem, AuditPrincipalKind, CredentialStatus, issue};

/// The per-issue predicate behind a marker-driven finding: does THIS issue line
/// belong to `finding`? `None` for `"all"`, for an unknown key, and for the
/// findings that key off a structured `AuditItem` field instead of issue text.
///
/// The key→marker table living here exactly once is the point:
/// [`matches_finding`] asks "does any issue match?" and the Findings pane's
/// `issue_lines_for` asks "which ones?", so a group's membership and the line a row quotes for it can
/// never diverge — including the load-bearing `.contains` arm below.
pub fn finding_issue_marker(finding: &str) -> Option<fn(&str) -> bool> {
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
        // degrades to org-wide when the signed-in user lacks Exchange-admin rights —
        // the run's `mailbox_scoping_resolved` flag says so, and the group shows it.
        "orgwide_mailbox" => |x| x.starts_with(issue::ORG_WIDE_MAILBOX),
        // Load-bearing asymmetry: `SCOPED_VIA_RBAC` is embedded MID-issue
        // ("Mail.Read scoped via Exchange RBAC…"), not a prefix like its siblings,
        // so this must stay `.contains` — a "normalize to starts_with" sweep would
        // silently empty the Scoped-mailbox finding (pinned by the tests below).
        "scoped_mailbox" => |x| x.contains(issue::SCOPED_VIA_RBAC),
        // Confined, but by the legacy per-app Application Access Policy
        // rather than RBAC for Applications. Its own finding, not a variant of
        // `orgwide_mailbox` (the access IS confined) and not of `scoped_mailbox`
        // (that group is the healthy end state this one migrates toward) — the
        // scorer keeps `SCOPED_VIA_RBAC` off these advisories so the two can't
        // both match.
        "legacy_mailbox_scope" => |x| x.starts_with(issue::LEGACY_MAILBOX_POLICY),
        "orgwide_sharepoint" => |x| x.starts_with(issue::ORG_WIDE_SHAREPOINT),
        // Org-wide FILES reach is its own finding, not a variant of
        // `orgwide_sharepoint`: the site path has a one-click `Sites.Selected`
        // conversion and the file path has none (the wizard only scopes the
        // Selected end state). Folding them would put Files rows under a group
        // whose bulk Fix cannot apply — the same trap the unconfinable markers
        // were split out to avoid.
        "orgwide_files" => |x| x.starts_with(issue::ORG_WIDE_FILES),
        // Org-wide reach the toolkit cannot confine. Kept out of
        // `orgwide_mailbox` / `orgwide_sharepoint` so these rows never sit under
        // a group whose bulk Fix can't apply to them, and split in two because
        // the scorer's advice differs: the legacy Office 365 Exchange Online
        // mail roles should be removed, while the unconfinable ones (no
        // supported RBAC role, an unresolved resource, or Sites.* on Office 365
        // SharePoint Online) may be legitimate and are reviewed / re-declared on
        // Microsoft Graph instead.
        "unscopable_legacy_mailbox" => |x| x.starts_with(issue::UNSCOPABLE_LEGACY_MAILBOX),
        "unconfinable_orgwide" => |x| {
            x.starts_with(issue::UNCONFINABLE_MAILBOX)
                || x.starts_with(issue::UNCONFINABLE_SHAREPOINT)
        },
        // Rule 18 — held narrower permissions a broader held one already covers.
        // Its own finding key (not folded into `high_risk_perms`) so the
        // RemoveRedundant group/bulk action pairs with the rule it actually
        // fixes.
        "redundant_perms" => |x| x.starts_with(issue::REDUNDANT_APP_PERMS),
        // Rule 23 — roles granted to the app's SP that its manifest does not
        // declare. Its own finding, not folded into `high_risk_perms`: the
        // grants are scored there by value, while this names the hiding place
        // (and fires for an undeclared grant of ANY risk).
        "granted_undeclared" => |x| x.starts_with(issue::GRANTED_NOT_DECLARED),
        "scoped_sites" => |x| x.starts_with(issue::SCOPED_SHAREPOINT),
        // Rule 21 — Microsoft's own disable flag. Its own group (not folded
        // into the credential or exposure findings): the flag is about the
        // principal's conduct, and fires on SP-only rows too.
        "disabled_by_microsoft" => |x| x.starts_with(issue::DISABLED_BY_MICROSOFT),
        // Rule 22 — the vendor's own risk flag from the Identity Protection
        // risky-service-principal report. Its own group (not folded into the
        // disabled flag): a risky SP is *still enabled* most of the time, and
        // the two findings call for opposite urgency — investigate/disable now.
        "risky_service_principal" => |x| x.starts_with(issue::RISKY_SERVICE_PRINCIPAL),
        // Advisory post-pass (per-credential last-used). Its own group, kept
        // out of the expired-credential finding: an unused-but-valid secret
        // has no expiry problem, and the two call for different actions
        // (rotate/renew vs confirm-then-remove). No remediation, so no bulk
        // action pairs with it.
        "unused_credential" => |x| x.starts_with(issue::UNUSED_CREDENTIAL),
        "ownership" => |x| x.starts_with(issue::NO_OWNERS) || x.starts_with(issue::SINGLE_OWNER),
        _ => return None,
    };
    Some(marks)
}

/// Finding-type dimension: `"all"` plus the structured/marker-driven findings.
/// The marker-driven half delegates to [`finding_issue_marker`]; what stays
/// here is the half that reads a structured field, which carries no issue line at all.
pub fn matches_finding(i: &AuditItem, finding: &str) -> bool {
    if let Some(marks) = finding_issue_marker(finding) {
        return i.issues.iter().any(|x| marks(x.as_str()));
    }
    match finding {
        // Already-expired credentials only — proactive "expiring soon" rotation
        // lead-time lives in the Credential-expiry lens (≤7d / ≤30d facets).
        "expired" => matches!(i.credential_status, CredentialStatus::Expired),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::RiskLevel;

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

    fn with_issue(text: String) -> AuditItem {
        AuditItem {
            issues: vec![text],
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
                format!("{} something", issue::ORG_WIDE_FILES),
                "orgwide_files",
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
            (
                format!("{} something", issue::MULTITENANT_AUDIENCE),
                "external_exposure",
            ),
            (
                format!("{}: Mail.Read", issue::UNSCOPABLE_LEGACY_MAILBOX),
                "unscopable_legacy_mailbox",
            ),
            (
                format!("{}: Mail.ReadWrite.Shared", issue::UNCONFINABLE_MAILBOX),
                "unconfinable_orgwide",
            ),
            (
                format!("{}: Sites.Read.All", issue::UNCONFINABLE_SHAREPOINT),
                "unconfinable_orgwide",
            ),
            (
                format!(
                    "{} — Services Agreement violation",
                    issue::DISABLED_BY_MICROSOFT
                ),
                "disabled_by_microsoft",
            ),
            (
                format!(
                    "{} — Identity Protection flags it",
                    issue::RISKY_SERVICE_PRINCIPAL
                ),
                "risky_service_principal",
            ),
            (
                format!(
                    "{} secret \"x\" — no sign-in activity",
                    issue::UNUSED_CREDENTIAL
                ),
                "unused_credential",
            ),
            (
                format!(
                    "{} RoleManagement.ReadWrite.Directory on Microsoft Graph",
                    issue::GRANTED_NOT_DECLARED
                ),
                "granted_undeclared",
            ),
        ];
        let marker_findings = [
            "high_risk_perms",
            "high_risk_delegated",
            "orgwide_mailbox",
            "scoped_mailbox",
            "legacy_mailbox_scope",
            "orgwide_sharepoint",
            "orgwide_files",
            "scoped_sites",
            "ownership",
            "redundant_perms",
            "external_exposure",
            "unscopable_legacy_mailbox",
            "unconfinable_orgwide",
            "disabled_by_microsoft",
            "risky_service_principal",
            "unused_credential",
            "granted_undeclared",
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

    #[test]
    fn legacy_policy_scoping_is_neither_org_wide_nor_healthy_scoped() {
        // The three mailbox findings are mutually exclusive by construction:
        // legacy-policy scoping is confined (so not org-wide) but legacy (so
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
