//! Permission-tester IPC DTOs.
//!
//! The tester answers "does this app actually have access to *this* Exchange
//! mailbox / *this* SharePoint site?" by exercising the authoritative live
//! checks (Exchange `Test-ServicePrincipalAuthorization`; SharePoint per-site
//! permissions unioned with org-wide `Sites.*` grants). Snake-case fields; the
//! Tauri IPC boundary handles the camelCase bridge.

use azapptoolkit_core::audit::AuditPrincipalKind;
use serde::{Deserialize, Serialize};

/// Machine-stable verdict of one access test — how far the principal reaches
/// the resource. The UI maps each to a badge + label.
///
/// The wire spellings are unchanged from when this was a bare `String`:
/// `org_wide` / `scoped` / `no_access` / `unknown`. Any spelling a newer
/// backend adds deserializes as [`AccessVerdict::Unknown`] (the
/// [`crate::audit::AuditCoverageGap`] precedent), which reads as "possible
/// access", never as "no access".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessVerdict {
    /// Reaches every resource of its kind (an unscoped grant).
    OrgWide,
    /// Reaches this resource through a scoped grant only.
    Scoped,
    /// Proven not to reach this resource.
    NoAccess,
    /// The check couldn't run or couldn't decide — possible access.
    #[serde(other)]
    Unknown,
}

impl AccessVerdict {
    /// The wire spelling, byte-identical to what serde writes — for text
    /// exports (the mailbox-reachers CSV).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OrgWide => "org_wide",
            Self::Scoped => "scoped",
            Self::NoAccess => "no_access",
            Self::Unknown => "unknown",
        }
    }

    /// `true` when the verdict proves access (org-wide or scoped).
    pub fn reaches(self) -> bool {
        matches!(self, Self::OrgWide | Self::Scoped)
    }

    /// Sort rank, highest reach first: org-wide, scoped, unknown (possible
    /// access), then no access. The one ordering the backend and the demo
    /// both sort reverse-lookup rows by.
    pub fn reach_rank(self) -> u8 {
        match self {
            Self::OrgWide => 0,
            Self::Scoped => 1,
            Self::Unknown => 2,
            Self::NoAccess => 3,
        }
    }
}

/// Outcome of a single permission test against one resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionTestResult {
    /// `true` when the app can reach the resource (via any path).
    pub has_access: bool,
    /// Machine-stable verdict; see [`AccessVerdict`] for the spellings.
    pub verdict: AccessVerdict,
    /// Role/permission names that grant the access (e.g. EXO role names, or
    /// SharePoint site roles like `read`/`write`/`owner`). Empty on no access.
    pub roles: Vec<String>,
    /// Human-readable explanation of the verdict (why access is/ isn't granted,
    /// or why it couldn't be determined).
    pub detail: Option<String>,
    /// Resolved resource label (the mailbox identity, or the site display name)
    /// echoed back so the UI can confirm what was actually tested.
    pub resource_label: String,
}

impl PermissionTestResult {
    /// Verdict shown when the check couldn't run (e.g. not an Exchange admin):
    /// never reported as "no access", which would be misleading.
    pub fn unknown(resource_label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            has_access: false,
            verdict: AccessVerdict::Unknown,
            roles: Vec::new(),
            detail: Some(detail.into()),
            resource_label: resource_label.into(),
        }
    }
}

/// Progress event payload for the mailbox reverse-lookup probe, emitted as
/// `mailbox-probe-progress` after each candidate principal is tested.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxProbeProgress {
    pub done: usize,
    pub total: usize,
    pub current_app: Option<String>,
    pub cancelled: bool,
}

/// One candidate principal's verdict against the target mailbox — the inverse
/// of [`PermissionTestResult`] (resource → identities instead of identity →
/// resource). Candidates are every service principal holding a mail-scopable
/// Graph application permission, plus every principal registered in
/// Exchange's SP store (the RBAC-for-Applications population — the only place
/// an app with no Entra grant is visible).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxReacherRow {
    pub app_id: String,
    pub principal_id: String,
    pub display_name: Option<String>,
    /// Mail-scopable application permissions the principal holds on Microsoft
    /// Graph, or the EWS `full_access_as_app` scope on Office 365 Exchange
    /// Online (the Entra side). Empty for a candidate discovered only via Exchange's SP
    /// store — its access, if any, comes solely from Exchange RBAC.
    pub held_permissions: Vec<String>,
    /// Same machine-stable verdict as [`PermissionTestResult::verdict`].
    pub verdict: AccessVerdict,
    /// Exchange role names backing the verdict, when Exchange answered.
    pub roles: Vec<String>,
    pub detail: Option<String>,
    /// Which detail pane the row's "Open" affordance routes to, mirroring the
    /// audit's routing: `Application` → the App Registration pane (`object_id`
    /// is the application object id); `ServicePrincipal` / `ManagedIdentity` →
    /// the enterprise / managed-identity pane (`object_id` is the SP object id).
    /// `#[serde(default)]` → `Application` so any older payload deserializes.
    #[serde(default)]
    pub principal_kind: AuditPrincipalKind,
    /// The id the "Open" affordance navigates to, per `principal_kind`: the
    /// application object id for a local registration, otherwise the service
    /// principal object id (equal to `principal_id`). Empty only when the SP
    /// couldn't be resolved at all.
    #[serde(default)]
    pub object_id: String,
}

/// Result of probing every candidate against one mailbox. `exchange_available`
/// is `false` when the Exchange client couldn't be built or its Exchange.Manage
/// token couldn't be acquired (no consent, no admin rights) — verdicts then
/// derive from the Entra grants alone (org-wide unless scoped, the audit's
/// never-under-report posture) and the UI should say so.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxReachersResult {
    pub tenant_id: String,
    pub mailbox: String,
    pub total_candidates: usize,
    pub rows: Vec<MailboxReacherRow>,
    pub exchange_available: bool,
    /// Exchange's SP store was listed — the only source of principals granted
    /// access solely through Exchange RBAC; `false` ⇒ those principals are
    /// absent from `rows`. `#[serde(default)]` so an older payload reads as
    /// "not read" rather than as complete coverage.
    #[serde(default)]
    pub exchange_sp_store_read: bool,
    pub cancelled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [AccessVerdict; 4] = [
        AccessVerdict::OrgWide,
        AccessVerdict::Scoped,
        AccessVerdict::NoAccess,
        AccessVerdict::Unknown,
    ];

    /// The spellings are a wire contract (the bindings, the CSV export and the
    /// export round trip read them), so pin each one and `as_str`'s agreement.
    #[test]
    fn access_verdict_wire_spellings_are_stable() {
        let expected = [
            (AccessVerdict::OrgWide, "org_wide"),
            (AccessVerdict::Scoped, "scoped"),
            (AccessVerdict::NoAccess, "no_access"),
            (AccessVerdict::Unknown, "unknown"),
        ];
        for (v, spelling) in expected {
            assert_eq!(
                serde_json::to_string(&v).unwrap(),
                format!("\"{spelling}\"")
            );
            assert_eq!(v.as_str(), spelling);
            let back: AccessVerdict = serde_json::from_str(&format!("\"{spelling}\"")).unwrap();
            assert_eq!(back, v);
        }
        for v in ALL {
            assert_eq!(
                serde_json::to_string(&v).unwrap(),
                format!("\"{}\"", v.as_str())
            );
        }
    }

    /// A spelling from a newer backend reads as "possible access", never as
    /// "no access", and a whole result still round-trips.
    #[test]
    fn unknown_verdict_spellings_degrade_to_unknown() {
        let v: AccessVerdict = serde_json::from_str("\"some_future_verdict\"").unwrap();
        assert_eq!(v, AccessVerdict::Unknown);

        let json = r#"{"has_access":true,"verdict":"org_wide","roles":["r"],"detail":null,"resource_label":"mbx"}"#;
        let r: PermissionTestResult = serde_json::from_str(json).unwrap();
        assert_eq!(r.verdict, AccessVerdict::OrgWide);
        assert_eq!(serde_json::to_string(&r).unwrap(), json);
    }

    #[test]
    fn reach_rank_orders_highest_reach_first() {
        let mut sorted = ALL;
        sorted.sort_by_key(|v| v.reach_rank());
        assert_eq!(
            sorted,
            [
                AccessVerdict::OrgWide,
                AccessVerdict::Scoped,
                AccessVerdict::Unknown,
                AccessVerdict::NoAccess,
            ]
        );
        for v in ALL {
            assert_eq!(
                v.reaches(),
                matches!(v, AccessVerdict::OrgWide | AccessVerdict::Scoped),
                "{v:?}"
            );
        }
        assert!(!AccessVerdict::Unknown.reaches());
        assert!(!AccessVerdict::NoAccess.reaches());
    }
}
