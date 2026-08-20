//! Audit IPC DTOs.

use azapptoolkit_core::audit::AuditItem;
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
    /// `true` when the tenant holds more app registrations than one run scores
    /// (`MAX_APPS_PER_RUN`), so this scan covered an arbitrary prefix of them.
    ///
    /// Semantically a sibling of [`Self::cancelled`]: both mean "an incomplete
    /// view", so neither is cached and neither may be presented as an
    /// all-clear. Kept separate because the remedy differs — a cancelled run is
    /// re-runnable as-is, a truncated one needs the tenant narrowed or the cap
    /// raised. `#[serde(default)]` so runs cached before this field deserialize
    /// as untruncated.
    #[serde(default)]
    pub truncated: bool,
    /// Reads that FAILED this run, each disabling a piece of the analysis.
    /// Empty on a fully-covered run.
    ///
    /// Third sibling of [`Self::cancelled`] and [`Self::truncated`], and the
    /// one that was missing. Those two mean "we did not look at every app";
    /// this mostly means "we looked, but with part of the analysis switched
    /// off" — with [`AuditCoverageGap::PerPrincipalScoring`] the exception that
    /// also covers individual apps dropped mid-run. Each
    /// prefetch here was best-effort by design — a failure logged at `info!` and
    /// returned an empty map — which is correct for availability and wrong for
    /// reporting: an empty map is indistinguishable from "the tenant has none
    /// of these", so the run scored LOWER risk than the truth and presented the
    /// result as a clean, complete scan. An operator reading it had no way to
    /// know a read had failed.
    ///
    /// Like its siblings, a run with gaps is not cached: a cached partial
    /// analysis is indistinguishable from a full one on the next read.
    #[serde(default)]
    pub degraded: Vec<AuditCoverageGap>,
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
    /// The most consequential of the three. Its result drives BOTH the org-wide
    /// vs scoped mailbox reconciliation — without it `orgwide_granted` is empty,
    /// so a `Scoped` verdict is never defeated and an app that still holds an
    /// un-stripped org-wide grant scores at the reduced scoped weight — AND the
    /// SP-only scoring phase, which then finds no enterprise apps, managed
    /// identities or orphaned service principals at all.
    GraphAppRoleAssignments,
    /// The tenant-wide `appRoleAssignedTo` read on the legacy Office 365
    /// Exchange Online SP, which finds org-wide EWS `full_access_as_app`
    /// grants. Such a grant reaches every mailbox and defeats any RBAC mailbox
    /// scope on the same principal, so without this read a scoped verdict can
    /// be reported for a principal that in fact has full mailbox access.
    EwsFullAccessGrants,
    /// One or more individual principals could not be scored, and were dropped
    /// from the result.
    ///
    /// Unlike its two siblings this is not a tenant-wide read but a per-app
    /// one: a transient scoring failure (or a task that panicked) was logged at
    /// `warn!` and the app silently omitted from `items`, while `total_apps`
    /// still counted it. The run then reported cancelled=false, truncated=false
    /// and degraded=[] — a *complete* scan missing exactly the apps whose
    /// scoring hit trouble — and cached itself as authoritative. Those apps are
    /// disproportionately the interesting ones: a scoring failure usually means
    /// a Graph or Exchange probe failed on that specific principal.
    PerPrincipalScoring,
    /// A resource's permission index could not be resolved, so the permissions
    /// declared against it were skipped.
    ///
    /// Quieter than [`AuditCoverageGap::PerPrincipalScoring`] and worse to
    /// miss: the affected apps are still present in `items`, scored, and shown
    /// — just with an empty permission set, so they read as holding nothing
    /// rather than as unexamined. A failed resolve is memoized for the run, so
    /// one transient failure on the Microsoft Graph resource silently emptied
    /// the permissions of every app in the tenant while the run reported itself
    /// complete and cached itself as authoritative.
    PermissionResolution,
    /// The tenant-wide service-principal index read that supplies the candidate
    /// pool for the SP-only scoring phase.
    ///
    /// Its failure has the same consequence
    /// [`AuditCoverageGap::GraphAppRoleAssignments`] documents — no enterprise
    /// apps, managed identities or orphaned service principals are scored at
    /// all — but it is a different read, and for a long time it had no gap of
    /// its own: the error was logged at `info!`, an empty vec was returned, and
    /// the run reported itself complete and cached itself as authoritative. An
    /// operator could not tell "no SP-only findings" from "never looked".
    ServicePrincipalIndex,
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
                "Tenant-wide Microsoft Graph app-role assignments could not be read, so                  enterprise applications, managed identities and orphaned service principals                  were not scored, and mailbox permissions could not be checked for an                  un-stripped org-wide grant."
            }
            AuditCoverageGap::ServicePrincipalIndex => {
                "The tenant's service-principal list could not be read, so enterprise \
                 applications, managed identities and orphaned service principals were not \
                 scored. App registrations were still covered."
            }
            AuditCoverageGap::EwsFullAccessGrants => {
                "Org-wide EWS full-mailbox-access grants could not be read, so an application                  shown as scoped to specific mailboxes may still reach every mailbox."
            }
            AuditCoverageGap::PerPrincipalScoring => {
                "Some applications could not be scored and are missing from these results,                  so a risk this run does not show may simply not have been looked at."
            }
            AuditCoverageGap::PermissionResolution => {
                "The permissions an application programming interface defines could not be                  read, so applications holding those permissions were scored as though they                  held none — they may look clean here while holding high-risk access."
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
    fn coverage_gaps_round_trip_and_unknown_variants_degrade_to_other() {
        // The enum is serialized as a plain camelCase string precisely so a new
        // variant is not a wire-format change: an older build reading a newer
        // build's cached run must land on `Other` (which still reads as "part of
        // this run could not be completed") rather than failing the whole read
        // and losing the result.
        for gap in [
            AuditCoverageGap::GraphAppRoleAssignments,
            AuditCoverageGap::EwsFullAccessGrants,
            AuditCoverageGap::PerPrincipalScoring,
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
}
