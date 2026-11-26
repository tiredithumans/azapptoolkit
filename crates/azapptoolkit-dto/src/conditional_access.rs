//! Conditional Access DTOs crossing the IPC boundary.
//!
//! A flattened projection of the CA policies that apply to a given app: the
//! applicability reason and the grant controls are pre-resolved so the frontend
//! renders a flat table without re-deriving CA condition semantics.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalAccessPolicyDto {
    pub id: String,
    pub display_name: String,
    /// Raw Graph state: `enabled` / `disabled` /
    /// `enabledForReportingButNotEnforced`. The frontend maps it to a label.
    pub state: String,
    /// Why this policy applies to the app — a stable code the frontend maps to
    /// a label. Resource-axis codes: `all`, `appId`, `office365`,
    /// `adminPortals`, `filter`, `filterExclude`. Client-axis codes (when only
    /// the policy's `clientApplications` names this app's SP): `sp`,
    /// `allWorkload`, `clientFilter`, `clientFilterExclude`. The
    /// non-`appId`/`all`/`sp` codes are "may apply" (the app is in a grouping
    /// or an unevaluable attribute filter).
    pub applies_reason: String,
    /// True when the policy narrows the **client** axis (`clientApplications`)
    /// to this app's service principal (or workload identities generally) —
    /// the table labels those rows "workload-identity clients".
    pub workload_clients: bool,
    /// Built-in grant controls (e.g. `mfa`, `compliantDevice`, `block`).
    pub grant_controls: Vec<String>,
    /// How the controls combine: `AND` / `OR`.
    pub grant_operator: Option<String>,
}

/// An IP named location, as the network-lock picker lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamedLocationDto {
    pub id: String,
    pub display_name: String,
    pub is_trusted: bool,
    pub range_count: u32,
}

/// The toolkit's own lock policy for an app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolkitLockDto {
    pub policy_id: String,
    /// Raw Graph state: `enabled` / `enabledForReportingButNotEnforced` / `disabled`.
    pub state: String,
    pub excluded_locations: Vec<NamedLocationDto>,
}

/// What a report-only lock would have blocked recently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportOnlyReadout {
    /// Sign-ins this policy produced any result for — zero right after the
    /// lock is created, before the app signs in again.
    pub evaluated: u32,
    pub would_block: u32,
    /// The sign-in read hit its row cap (newest first): the counts are a floor.
    pub truncated: bool,
    pub sample_ips: Vec<String>,
    pub window_days: u32,
}

/// The Network lock section's state for one app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkLockStatus {
    /// Why Conditional Access can't target this app, if it can't.
    pub ineligible: Option<azapptoolkit_core::conditional_access::LockIneligible>,
    /// The toolkit's own lock, in any state. Also set for an ineligible app
    /// that still has one (made before it went multi-tenant), so it can be
    /// removed.
    pub toolkit_lock: Option<ToolkitLockDto>,
    /// Every OTHER policy's verdict for this app on Microsoft Graph.
    pub other: azapptoolkit_core::conditional_access::NetworkLock,
    /// The first other policy that enforces a lock, by name.
    pub other_policy_name: Option<String>,
    /// Only for a report-only toolkit lock; `None` when the sign-in log
    /// couldn't be read.
    pub readout: Option<ReportOnlyReadout>,
}

/// A new untrusted IP named location to create with the lock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewLocationArgs {
    pub name: String,
    pub cidrs: Vec<String>,
}

/// The created lock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedLock {
    pub policy_id: String,
    pub created_location_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditional_access_policy_dto_camel_case_round_trip() {
        let policy = ConditionalAccessPolicyDto {
            id: "ca-1".into(),
            display_name: "Require MFA".into(),
            state: "enabled".into(),
            applies_reason: "appId".into(),
            workload_clients: false,
            grant_controls: vec!["mfa".into(), "compliantDevice".into()],
            grant_operator: Some("AND".into()),
        };
        let json = serde_json::to_value(&policy).unwrap();
        for key in [
            "displayName",
            "appliesReason",
            "workloadClients",
            "grantControls",
            "grantOperator",
        ] {
            assert!(json.get(key).is_some(), "missing camelCase key {key}");
        }
        let back: ConditionalAccessPolicyDto = serde_json::from_value(json).unwrap();
        assert_eq!(back.display_name, "Require MFA");
        assert_eq!(back.applies_reason, "appId");
        assert!(!back.workload_clients);
        assert_eq!(back.grant_controls.len(), 2);
        assert_eq!(back.grant_operator.as_deref(), Some("AND"));
    }
}
