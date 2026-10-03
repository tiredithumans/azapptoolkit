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
