//! Audit IPC DTOs.

use std::collections::BTreeMap;

use azapptoolkit_core::audit::{
    AuditItem, POSTURE_FINDING_KEYS, PostureCounts, RiskLevel, finding_worst, posture_counts,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditProgress {
    pub done: usize,
    pub total: usize,
    pub current_app: Option<String>,
    pub in_flight_cap: usize,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRunResult {
    pub tenant_id: String,
    pub total_apps: usize,
    pub items: Vec<AuditItem>,
    pub cancelled: bool,
    /// Whether the sign-in activity report was available this run (needs
    /// `AuditLog.Read.All` + Entra ID P1/P2). Drives the "Unused" tab's empty
    /// state: when `false`, no app could be flagged unused.
    #[serde(default)]
    pub sign_in_report_available: bool,
    /// `true` when the sign-in report was unavailable specifically because
    /// `AuditLog.Read.All` is not yet consented — the view shows a "Grant consent"
    /// button (`request_scope_consent(tenant_id, "audit_log")`) so the user can
    /// enable unused-app detection and re-run. Distinct from a license/P1-P2 gap.
    #[serde(default)]
    pub sign_in_consent_required: bool,
    /// Whether the tenant's app-management policies were readable this run
    /// (`Policy.Read.All`, the default policy + per-app override pair). When
    /// `false`, no credential-lifetime advisory could be made. Deliberately
    /// NOT a [`Self::degraded`] gap like the sign-in report: the advisory adds
    /// operator context, it never hides a finding, and a tenant without the
    /// policy feature (or its consent) must not read as permanently degraded.
    #[serde(default)]
    pub credential_policy_available: bool,
    /// The tenant's DEFAULT app-management policy secret cap in days, when one
    /// is enforced (date gates ignored — this is the tenant posture number;
    /// per-app coverage is decided per audit row). `None` = policy unavailable,
    /// disabled, or enforcing no lifetime limit.
    #[serde(default)]
    pub credential_policy_max_days: Option<i64>,
    /// `true` when the tenant holds more app registrations than one run scores
    /// (`MAX_APPS_PER_RUN`), so this scan covered an arbitrary prefix of them.
    ///
    /// A semantic sibling of [`Self::cancelled`] — both mean "an incomplete
    /// view", so neither is cached and neither may be presented as an
    /// all-clear — kept separate because the remedy differs: a cancelled run is
    /// re-runnable as-is, a truncated one needs the tenant narrowed or the cap
    /// raised. `#[serde(default)]` so runs cached before this field
    /// deserialize as untruncated.
    #[serde(default)]
    pub truncated: bool,
    /// Reads that FAILED this run, each disabling a piece of the analysis.
    /// Empty on a fully-covered run.
    ///
    /// Third sibling of [`Self::cancelled`] and [`Self::truncated`], and the
    /// one that was missing: those two mean "we did not look at every app",
    /// this mostly means "we looked, but with part of the analysis switched
    /// off" — with [`AuditCoverageGap::PerPrincipalScoring`] the exception that
    /// also covers individual apps dropped mid-run. Each prefetch was
    /// best-effort by design (a failure logged at `info!`, an empty map
    /// returned) — correct for availability, wrong for reporting: an empty map
    /// is indistinguishable from "the tenant has none of these", so the run
    /// scored LOWER risk than the truth and presented a clean, complete scan.
    ///
    /// Like its siblings, a run with gaps is not cached: a cached partial
    /// analysis is indistinguishable from a full one on the next read.
    #[serde(default)]
    pub degraded: Vec<AuditCoverageGap>,
    /// When the run finished, RFC3339 UTC; `None` only for a run recorded
    /// before this field existed.
    ///
    /// **Stamped by the runner and stored WITH the items** in the
    /// `CacheKind::Audit` entry, so a cache hit reports the original run time
    /// rather than the moment it was read back. Without it nothing on the
    /// Security workbench or the Home posture card said how old the numbers
    /// were — with the 60-minute in-process TTL the counts could be an hour
    /// stale, and the "no audit" copy claimed none had ever been run when the
    /// truth was that this session had not.
    #[serde(default)]
    pub completed_at: Option<String>,
    /// `false` when some mail permission could not be checked against
    /// Exchange mailbox scoping this run — no Exchange client, the legacy
    /// Application Access Policy list unreadable, or an app left unprobed
    /// (the breaker tripped or its probe failed). Those permissions were
    /// scored at org-wide weight, so some "Org-wide mailbox access" findings
    /// may already be confined to specific mailboxes by Exchange RBAC or an
    /// AAP.
    ///
    /// Deliberately NOT a [`Self::degraded`] gap: the degrade over-reports and
    /// never under-reports, so the run stays cacheable — the same call as the
    /// sign-in report precedent. It still has to be *said*, on the org-wide
    /// mailbox group and in every export ([`MAILBOX_SCOPING_UNRESOLVED`]).
    /// Defaults to `true` so a run cached before the field existed reads as
    /// it was presented then.
    #[serde(default = "default_true")]
    pub mailbox_scoping_resolved: bool,
}

fn default_true() -> bool {
    true
}

/// The one sentence the export's coverage notes and the workbench's org-wide
/// mailbox Callout both use when [`AuditRunResult::mailbox_scoping_resolved`]
/// is `false` — defined once so the file and the screen can't drift apart.
pub const MAILBOX_SCOPING_UNRESOLVED: &str = "Mailbox scoping could not be resolved for this run — some applications listed with org-wide mailbox access may already be confined to specific mailboxes through Exchange RBAC or an application access policy. Sign in as an Exchange administrator and re-run to refine.";

/// One run's coverage caveats, minus its items — what an export needs in order
/// to say what the scan did *not* cover.
///
/// The workbench qualifies a cancelled, truncated or degraded run everywhere,
/// but the exported file is the artifact that leaves the app and reaches an
/// auditor, and it carried none of it: `save_audit_to_file` received a bare
/// `Vec<AuditItem>` while every caveat stayed behind on [`AuditRunResult`]. A
/// **cancelled** run is specifically the one that ships its items to the
/// exporter (it is never cached) — the case with the most to disclose
/// disclosed nothing.
///
/// A separate struct rather than the whole [`AuditRunResult`] so the
/// by-reference export path keeps the multi-MB item vector off the IPC bridge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditExportCoverage {
    /// Principals the run SET OUT to score — the denominator a partial run
    /// needs (the numerator is the exported item count).
    pub total_apps: usize,
    pub cancelled: bool,
    pub truncated: bool,
    pub degraded: Vec<AuditCoverageGap>,
    pub sign_in_report_available: bool,
    /// RFC3339 UTC, from [`AuditRunResult::completed_at`].
    pub completed_at: Option<String>,
    /// From [`AuditRunResult::mailbox_scoping_resolved`]; a caveat, not a
    /// completeness gap — [`Self::is_complete`] deliberately ignores it.
    #[serde(default = "default_true")]
    pub mailbox_scoping_resolved: bool,
}

/// A clean run's coverage: nothing cancelled, truncated or degraded, and
/// mailbox scoping resolved — so `Default` still means "no caveats".
impl Default for AuditExportCoverage {
    fn default() -> Self {
        Self {
            total_apps: 0,
            cancelled: false,
            truncated: false,
            degraded: Vec::new(),
            sign_in_report_available: false,
            completed_at: None,
            mailbox_scoping_resolved: true,
        }
    }
}

/// What the Home dashboard's Security Posture card needs from the cached run:
/// counts, never items.
///
/// The cached run is up to 10 000 [`AuditItem`]s — several to tens of MB of
/// JSON. Home used to receive all of it over IPC on every audit reload (while
/// the Security tab held a second copy) only to reduce it to a dozen numbers;
/// the backend now reduces it with the same [`posture_counts`] core the
/// Security strip runs over its own copy, so the two surfaces share one count
/// source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedAuditSummary {
    /// The stamp the RUN wrote (RFC3339 UTC), never the read time — see
    /// [`AuditRunResult::completed_at`]. `Option` to mirror it.
    pub completed_at: Option<String>,
    pub posture: PostureCounts,
    /// Worst member risk level per non-empty posture finding, keyed by the
    /// finding key ([`POSTURE_FINDING_KEYS`]) — what ranks the card's "Top
    /// findings" and colours their tone dots, as the Findings pane does.
    pub worst: BTreeMap<String, RiskLevel>,
    /// The cached run's app-management policy availability, mirrored from
    /// [`AuditRunResult::credential_policy_available`] so the Home posture
    /// line survives a cache read instead of quietly disappearing on it.
    #[serde(default)]
    pub credential_policy_available: bool,
    /// Mirrors [`AuditRunResult::credential_policy_max_days`] — the tenant's
    /// default-policy secret cap in days, when one is enforced.
    #[serde(default)]
    pub credential_policy_max_days: Option<i64>,
}

impl CachedAuditSummary {
    pub fn from_items(
        items: &[AuditItem],
        completed_at: Option<String>,
        credential_policy_available: bool,
        credential_policy_max_days: Option<i64>,
    ) -> Self {
        let worst = POSTURE_FINDING_KEYS
            .iter()
            .filter_map(|&key| finding_worst(items, key).map(|w| (key.to_string(), w)))
            .collect();
        Self {
            completed_at,
            posture: posture_counts(items),
            worst,
            credential_policy_available,
            credential_policy_max_days,
        }
    }

    /// `(count, worst)` for a finding key; `None` for a key the posture counts
    /// don't cover. An empty finding reads `(0, Low)`.
    pub fn finding_tally(&self, key: &str) -> Option<(usize, RiskLevel)> {
        let count = self.posture.finding(key)?;
        let worst = self.worst.get(key).copied().unwrap_or(RiskLevel::Low);
        Some((count, worst))
    }
}

impl AuditRunResult {
    /// This run's caveats, for the exporter. Derived rather than restated so a
    /// new coverage signal on the run reaches the export by editing one place.
    pub fn coverage(&self) -> AuditExportCoverage {
        AuditExportCoverage {
            total_apps: self.total_apps,
            cancelled: self.cancelled,
            truncated: self.truncated,
            degraded: self.degraded.clone(),
            sign_in_report_available: self.sign_in_report_available,
            completed_at: self.completed_at.clone(),
            mailbox_scoping_resolved: self.mailbox_scoping_resolved,
        }
    }
}

impl AuditExportCoverage {
    /// `true` when the run reached every principal with its whole analysis
    /// intact — the only shape that may be presented as a complete scan. Same
    /// conjunction as the runner's cache guard (`run_is_cacheable`), for the
    /// same reason: those three flags are what separates "clean" from
    /// "unexamined".
    pub fn is_complete(&self) -> bool {
        !self.cancelled && !self.truncated && self.degraded.is_empty()
    }
}

/// A read that failed, and what the audit could no longer do. Tenant-wide for
/// every variant except [`AuditCoverageGap::PerPrincipalScoring`].
///
/// Serialized as a plain string so the field can gain variants without a
/// wire-format change; unknown variants deserialize as
/// [`AuditCoverageGap::Other`] rather than failing a cached run's read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuditCoverageGap {
    /// The tenant-wide `appRoleAssignedTo` read on the Microsoft Graph SP.
    ///
    /// The most consequential of the three: its result drives BOTH the
    /// org-wide vs scoped mailbox reconciliation — without it `orgwide_granted`
    /// is empty, so a `Scoped` verdict is never defeated and an un-stripped
    /// org-wide grant scores at the reduced scoped weight — AND the SP-only
    /// scoring phase, which then finds no enterprise apps, managed identities
    /// or orphaned service principals at all — AND the granted-but-undeclared
    /// merge, so an app's Graph roles granted outside its manifest go unscored.
    GraphAppRoleAssignments,
    /// The tenant-wide `appRoleAssignedTo` read on the legacy Office 365
    /// Exchange Online SP, which finds org-wide EWS `full_access_as_app`
    /// grants. Such a grant reaches every mailbox and defeats any RBAC mailbox
    /// scope on the same principal, so without it a scoped verdict can be
    /// reported for a principal that in fact has full mailbox access.
    EwsFullAccessGrants,
    /// One or more individual principals could not be scored, and were dropped
    /// from the result.
    ///
    /// Unlike its siblings this is a per-app read: a transient scoring failure
    /// (or a task that panicked) was logged at `warn!` and the app silently
    /// omitted from `items`, while `total_apps` still counted it — the run
    /// reported cancelled=false, truncated=false, degraded=[], a *complete*
    /// scan missing exactly the apps that hit trouble, and cached itself as
    /// authoritative. Those apps are disproportionately the interesting ones: a
    /// scoring failure usually means a Graph or Exchange probe failed on that
    /// specific principal.
    PerPrincipalScoring,
    /// A resource's permission index could not be resolved, so the permissions
    /// declared against it were skipped.
    ///
    /// Quieter than [`AuditCoverageGap::PerPrincipalScoring`] and worse to
    /// miss: the affected apps are still in `items`, scored and shown — with
    /// an empty permission set, so they read as holding nothing rather than
    /// as unexamined. A failed resolve is memoized for the run, so one
    /// transient failure on the Microsoft Graph resource silently emptied the
    /// permissions of every app in the tenant while the run reported itself
    /// complete and cached itself as authoritative. Grants on such a resource
    /// are still scored, but never labelled "not in the manifest" (the
    /// declarations were what failed to resolve).
    PermissionResolution,
    /// The tenant-wide service-principal index read that supplies the candidate
    /// pool for the SP-only scoring phase.
    ///
    /// Its failure has the same consequence
    /// [`AuditCoverageGap::GraphAppRoleAssignments`] documents — no enterprise
    /// apps, managed identities or orphaned service principals are scored at
    /// all — but it is a different read, and for a long time it had no gap of
    /// its own: the error was logged at `info!`, an empty vec was returned,
    /// and the run reported itself complete and cached itself as
    /// authoritative. An operator could not tell "no SP-only findings" from
    /// "never looked".
    ServicePrincipalIndex,
    /// The Identity Protection risky-service-principal report could not be
    /// read even though the tenant looked entitled to it (a genuine request
    /// failure — an un-consented or unlicensed tenant reports the feature as
    /// *unavailable* instead, which is not a gap).
    ///
    /// The report is the audit's compromised-principal signal: without it, a
    /// service principal Identity Protection flags `confirmedCompromised` is
    /// scored and shown as if no vendor flagged it.
    RiskyServicePrincipals,
    /// The tenant-wide `appRoleAssignedTo` read on the legacy Office 365
    /// SharePoint Online SP. That resource is not Microsoft Graph, so its
    /// `Sites.*` / `User.*` roles are in no other matrix: without this read a
    /// service principal holding only SharePoint Online roles is not scored at
    /// all, and an app holding them undeclared is scored below its reach.
    SharePointOnlineGrants,
    /// The tenant-wide `oauth2PermissionGrants` read. Without it no principal
    /// carries the admin-consent flag (Rule 3), SP-only rows lose their
    /// delegated scopes, and Rule 13 falls back to declared scopes — the run
    /// under-reports delegated risk while looking complete. It used to log at
    /// `info!` and return empty, so the run was cached as authoritative.
    DelegatedConsentGrants,
    /// A gap recorded by a newer build than the one reading it back.
    #[serde(other)]
    Other,
}

impl AuditCoverageGap {
    /// One sentence naming what this run could not determine — written for an
    /// operator deciding whether to trust the result, not for a log.
    pub fn description(self) -> &'static str {
        match self {
            AuditCoverageGap::GraphAppRoleAssignments => {
                "Tenant-wide Microsoft Graph app-role assignments could not be read, so \
                 enterprise applications, managed identities and orphaned service principals \
                 were not scored, Microsoft Graph permissions granted to an application but \
                 missing from its manifest were not found, and mailbox permissions could not be \
                 checked for an un-stripped org-wide grant."
            }
            AuditCoverageGap::ServicePrincipalIndex => {
                "The tenant's service-principal list could not be read, so enterprise \
                 applications, managed identities and orphaned service principals were not \
                 scored. App registrations were still covered."
            }
            AuditCoverageGap::EwsFullAccessGrants => {
                "Office 365 Exchange Online permission grants could not be read, so an \
                 application shown as scoped to specific mailboxes may still reach every mailbox, \
                 and service principals holding only Exchange Online roles were not scored."
            }
            AuditCoverageGap::SharePointOnlineGrants => {
                "Office 365 SharePoint Online permission grants could not be read, so service \
                 principals holding only SharePoint Online roles were not scored, and \
                 applications may hold SharePoint access this run does not show."
            }
            AuditCoverageGap::DelegatedConsentGrants => {
                "The tenant's delegated permission grants could not be read, so admin-consented \
                 delegated permissions were not flagged and delegated risk may be under-reported."
            }
            AuditCoverageGap::PerPrincipalScoring => {
                "Some applications could not be scored and are missing from these results, \
                 so a risk this run does not show may simply not have been looked at."
            }
            AuditCoverageGap::PermissionResolution => {
                "The permissions an application programming interface defines could not be \
                 read, so applications holding those permissions were scored as though they \
                 held none — they may look clean here while holding high-risk access — and \
                 whether their granted permissions are missing from the manifest could not be \
                 checked."
            }
            AuditCoverageGap::RiskyServicePrincipals => {
                "The Identity Protection risky-service-principal report could not be read, so \
                 this run did not check for compromised or risky service principals — one may \
                 be flagged in Identity Protection while reading clean here."
            }
            AuditCoverageGap::Other => {
                "Part of this run's tenant-wide analysis could not be completed."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_carries_counts_worst_and_the_runs_own_stamp() {
        use azapptoolkit_core::audit::{AuditPrincipalKind, CredentialStatus};
        let item = |level, status, unused| AuditItem {
            application_name: "App".into(),
            app_id: "app-1".into(),
            object_id: "obj-1".into(),
            created_date: None,
            publisher: None,
            sign_in_audience: None,
            risk_score: 0,
            risk_level: level,
            issues: vec![],
            recommendations: vec![],
            remediations: vec![],
            credential_status: status,
            permission_count: 0,
            service_principal_enabled: None,
            days_since_created: None,
            certificates: vec![],
            secrets: vec![],
            last_sign_in: None,
            unused,
            sign_in_report_available: false,
            principal_kind: AuditPrincipalKind::Application,
            app_owner_organization_id: None,
            sp_risk_state: None,
            sp_risk_level: None,
        };
        let items = [
            item(RiskLevel::High, CredentialStatus::Expired, false),
            item(RiskLevel::Low, CredentialStatus::Expired, false),
            item(RiskLevel::Medium, CredentialStatus::Active, false),
        ];
        let s = CachedAuditSummary::from_items(
            &items,
            Some("2026-01-01T00:00:00Z".into()),
            true,
            Some(90),
        );
        assert_eq!(s.completed_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(s.posture, posture_counts(&items));
        assert_eq!(s.finding_tally("expired"), Some((2, RiskLevel::High)));
        // An empty finding is a zero tally, not a missing one.
        assert_eq!(s.finding_tally("unused"), Some((0, RiskLevel::Low)));
        assert!(!s.worst.contains_key("unused"));
        assert_eq!(s.finding_tally("redundant_perms"), None);
        // Survives the IPC round trip.
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(
            serde_json::from_str::<CachedAuditSummary>(&json).unwrap(),
            s
        );
    }

    #[test]
    fn coverage_gaps_round_trip_and_unknown_variants_degrade_to_other() {
        // The enum is serialized as a plain camelCase string so a new variant
        // is not a wire-format change: an older build reading a newer build's
        // cached run must land on `Other` (which still reads as "part of this
        // run could not be completed") rather than failing the whole read and
        // losing the result.
        for gap in [
            AuditCoverageGap::GraphAppRoleAssignments,
            AuditCoverageGap::ServicePrincipalIndex,
            AuditCoverageGap::EwsFullAccessGrants,
            AuditCoverageGap::PerPrincipalScoring,
            AuditCoverageGap::PermissionResolution,
            AuditCoverageGap::RiskyServicePrincipals,
            AuditCoverageGap::SharePointOnlineGrants,
            AuditCoverageGap::DelegatedConsentGrants,
            AuditCoverageGap::Other,
        ] {
            let json = serde_json::to_string(&gap).expect("serialize");
            assert_eq!(
                serde_json::from_str::<AuditCoverageGap>(&json).expect("round trip"),
                gap
            );
            assert!(
                !gap.description().trim().is_empty(),
                "{gap:?} needs an operator-facing description"
            );
            // A multi-line literal missing its `\` continuation keeps the
            // newline's indentation — a run of spaces the UI (`pre-wrap`) and
            // the CSV export both show verbatim.
            assert!(
                !gap.description().contains("  ") && !gap.description().contains('\n'),
                "{gap:?}'s description carries a whitespace run: {:?}",
                gap.description()
            );
        }
        assert_eq!(
            serde_json::to_string(&AuditCoverageGap::PerPrincipalScoring).unwrap(),
            "\"perPrincipalScoring\""
        );
        assert_eq!(
            serde_json::from_str::<AuditCoverageGap>("\"somethingFromANewerBuild\"").unwrap(),
            AuditCoverageGap::Other
        );
    }

    fn run() -> AuditRunResult {
        AuditRunResult {
            tenant_id: "t1".into(),
            total_apps: 12,
            items: Vec::new(),
            cancelled: false,
            sign_in_report_available: true,
            sign_in_consent_required: false,
            credential_policy_available: false,
            credential_policy_max_days: None,
            truncated: false,
            degraded: Vec::new(),
            completed_at: Some("2026-09-02T10:00:00+00:00".into()),
            mailbox_scoping_resolved: true,
        }
    }

    /// The export's honesty rests on `coverage()` carrying every caveat off the
    /// run. A field added to [`AuditRunResult`] and forgotten here reaches the
    /// exported file as silence.
    #[test]
    fn coverage_carries_every_caveat_off_the_run() {
        let mut r = run();
        r.cancelled = true;
        r.truncated = true;
        r.degraded = vec![AuditCoverageGap::PerPrincipalScoring];
        r.mailbox_scoping_resolved = false;

        let c = r.coverage();
        assert!(!c.mailbox_scoping_resolved);
        assert_eq!(c.total_apps, 12);
        assert!(c.cancelled);
        assert!(c.truncated);
        assert_eq!(c.degraded, vec![AuditCoverageGap::PerPrincipalScoring]);
        assert!(c.sign_in_report_available);
        assert_eq!(c.completed_at.as_deref(), Some("2026-09-02T10:00:00+00:00"));
    }

    /// Each of the three flags alone is enough to disqualify a run from reading
    /// as complete — the failure mode is one of them being dropped from the
    /// conjunction, which a single-case test would miss.
    #[test]
    fn only_a_complete_undegraded_run_reads_as_complete() {
        assert!(run().coverage().is_complete());
        for mutate in [
            (|c: &mut AuditExportCoverage| c.cancelled = true) as fn(&mut AuditExportCoverage),
            |c: &mut AuditExportCoverage| c.truncated = true,
            |c: &mut AuditExportCoverage| c.degraded = vec![AuditCoverageGap::EwsFullAccessGrants],
        ] {
            let mut c = run().coverage();
            mutate(&mut c);
            assert!(!c.is_complete(), "{c:?} must not read as a complete scan");
        }
        // Unresolved mailbox scoping is a caveat, not a gap: the degrade
        // over-reports, so the run stays complete (and cacheable).
        let mut c = run().coverage();
        c.mailbox_scoping_resolved = false;
        assert!(c.is_complete());
        // `Default` is a clean run's coverage.
        assert!(AuditExportCoverage::default().mailbox_scoping_resolved);
    }

    /// `completed_at` is additive: a run cached (or exported) by a build from
    /// before the field existed must still deserialize, reporting an unknown
    /// run time rather than failing the read.
    #[test]
    fn a_run_without_a_timestamp_still_deserializes() {
        let json = r#"{"tenant_id":"t1","total_apps":0,"items":[],"cancelled":false}"#;
        let back: AuditRunResult = serde_json::from_str(json).expect("pre-field run");
        assert_eq!(back.completed_at, None);
        // A run cached before the flag existed reads as it was shown then.
        assert!(back.mailbox_scoping_resolved);
    }
}
