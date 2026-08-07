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
    /// Tenant-wide reads that FAILED this run, each disabling a piece of the
    /// analysis. Empty on a fully-covered run.
    ///
    /// Third sibling of [`Self::cancelled`] and [`Self::truncated`], and the
    /// one that was missing. Those two mean "we did not look at every app";
    /// this means "we looked, but with part of the analysis switched off". Each
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

/// A tenant-wide read that failed, and what the audit could no longer do.
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
            AuditCoverageGap::EwsFullAccessGrants => {
                "Org-wide EWS full-mailbox-access grants could not be read, so an application                  shown as scoped to specific mailboxes may still reach every mailbox."
            }
            AuditCoverageGap::Other => {
                "Part of this run's tenant-wide analysis could not be completed."
            }
        }
    }
}
