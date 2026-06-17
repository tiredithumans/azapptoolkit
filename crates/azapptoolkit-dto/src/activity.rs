//! Directory activity / change-log DTOs crossing the IPC boundary.
//!
//! Flattened, display-ready projection of a Graph `directoryAudits` entry: the
//! initiator and target resources are already resolved to human strings so the
//! frontend renders a flat table without re-deriving identity shapes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityLogItem {
    pub id: String,
    /// Human-readable activity (Graph `activityDisplayName`).
    pub activity: String,
    pub activity_date_time: Option<DateTime<Utc>>,
    pub category: Option<String>,
    /// "success" / "failure" / … as reported by Graph.
    pub result: Option<String>,
    pub result_reason: Option<String>,
    /// Resolved initiator: a user UPN/display name, an app display name, or
    /// "system" when neither is present.
    pub initiated_by: String,
    /// Comma-joined target-resource display names (or "—" when none).
    pub target_summary: String,
    pub modified_properties: Vec<ModifiedPropertyDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifiedPropertyDto {
    pub name: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Per-app sign-in summary for the Activity tab: the service principal's most
/// recent recorded sign-in (from the beta `servicePrincipalSignInActivities`
/// report). Degrades gracefully — a missing scope/license/consent yields a
/// populated "unavailable" DTO (never an error), so the Activity tab keeps
/// rendering directory changes regardless.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInActivityDto {
    /// True when the report was readable (an `AuditLog.Read.All` token was
    /// acquired and the report returned). When false, see `message`.
    pub available: bool,
    /// True specifically when `AuditLog.Read.All` needs admin consent — drives a
    /// "Grant consent & retry" button.
    pub consent_required: bool,
    /// Most recent recorded sign-in for this app's SP, or `None` when the report
    /// is available but holds no entry for it (no sign-in observed in the window).
    pub last_sign_in_date_time: Option<DateTime<Utc>>,
    /// Friendly reason shown when `available` is false (license / transient / …).
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_log_item_camel_case_nested_and_datetime() {
        let item = ActivityLogItem {
            id: "change-123".into(),
            activity: "Update application".into(),
            activity_date_time: Some(
                chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            category: Some("ApplicationManagement".into()),
            result: Some("success".into()),
            result_reason: None,
            initiated_by: "admin@example.com".into(),
            target_summary: "App1, App2".into(),
            modified_properties: vec![ModifiedPropertyDto {
                name: "displayName".into(),
                old_value: Some("Old".into()),
                new_value: Some("New".into()),
            }],
        };
        let json = serde_json::to_value(&item).unwrap();
        for key in ["activityDateTime", "initiatedBy", "targetSummary"] {
            assert!(json.get(key).is_some(), "missing camelCase key {key}");
        }
        // Nested ModifiedPropertyDto renames too.
        assert_eq!(json["modifiedProperties"][0]["oldValue"], "Old");

        let back: ActivityLogItem = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "change-123");
        assert_eq!(back.result.as_deref(), Some("success"));
        assert_eq!(back.activity_date_time, item.activity_date_time);
        assert_eq!(back.modified_properties[0].name, "displayName");
    }

    #[test]
    fn sign_in_activity_dto_camel_case_and_round_trips() {
        let dto = SignInActivityDto {
            available: true,
            consent_required: false,
            last_sign_in_date_time: Some(
                chrono::DateTime::parse_from_rfc3339("2024-02-20T08:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            message: None,
        };
        let json = serde_json::to_value(&dto).unwrap();
        for key in ["consentRequired", "lastSignInDateTime"] {
            assert!(json.get(key).is_some(), "missing camelCase key {key}");
        }
        let back: SignInActivityDto = serde_json::from_value(json).unwrap();
        assert!(back.available);
        assert_eq!(back.last_sign_in_date_time, dto.last_sign_in_date_time);
    }
}
