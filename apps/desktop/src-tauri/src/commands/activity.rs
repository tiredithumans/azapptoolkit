//! Directory activity / change-log commands.
//!
//! Reads Graph `directoryAudits` for a given app (and its paired service
//! principal) via the on-demand `AuditLog.Read.All` token, flattening each
//! entry into a display-ready [`ActivityLogItem`]. Degrades gracefully: a
//! tenant without consent or an Entra ID P1/P2 license surfaces a friendly
//! "unavailable" message rather than a hard error.

use chrono::{DateTime, Utc};
use tauri::State;

use azapptoolkit_core::models::{DirectoryAuditLog, ServicePrincipalSignInActivity};
use azapptoolkit_graph::GraphError;

use crate::dto::activity::{ActivityLogItem, ModifiedPropertyDto, SignInActivityDto};
use crate::dto::UiError;
use crate::state::AppState;

// Graph keeps directory audit logs for only 30 days (longer with Entra ID P1/P2
// archival in some plans, but 30 is the floor we can rely on), so these caps
// bound a single recent slice of that window, not the whole tenant history. A
// busy tenant with more than `ACTIVITY_TOP` changes in the window will see only
// the most recent ones — acceptable for an at-a-glance "recent changes" tab.
/// Entries requested for the per-app filtered query (most recent first).
const ACTIVITY_TOP: u32 = 50;
/// Larger page pulled when the lambda filter is rejected and we filter locally
/// (the unfiltered feed is tenant-wide, so we over-fetch then narrow by id).
const ACTIVITY_FALLBACK_TOP: u32 = 200;

/// Recent directory changes targeting two related directory objects — typically
/// an app registration and its paired service principal (in either order; both
/// ids are simply OR-ed into the audit filter) — most-recent first. Always
/// fetched fresh: activity is live data and the tab's Refresh re-runs this.
#[tauri::command]
pub async fn list_directory_audits_for_app(
    state: State<'_, AppState>,
    tenant_id: String,
    primary_object_id: String,
    secondary_object_id: Option<String>,
) -> Result<Vec<ActivityLogItem>, UiError> {
    let mut ids = vec![primary_object_id];
    if let Some(other) = secondary_object_id.filter(|s| !s.is_empty()) {
        ids.push(other);
    }

    let client = state.graph_for(&tenant_id);
    let logs = match client
        .list_directory_audits_for_app(&ids, ACTIVITY_TOP)
        .await
    {
        Ok(l) => l,
        // Some tenants reject the `targetResources/any(...)` lambda filter (400).
        // Fall back to an unfiltered recent page and filter client-side.
        Err(GraphError::Api { status: 400, .. }) => {
            let all = client
                .list_directory_audits(ACTIVITY_FALLBACK_TOP)
                .await
                .map_err(map_activity_err)?;
            all.into_iter()
                .filter(|a| {
                    a.target_resources.iter().any(|t| {
                        t.id.as_deref()
                            .is_some_and(|id| ids.iter().any(|o| o == id))
                    })
                })
                .collect()
        }
        Err(e) => return Err(map_activity_err(e)),
    };

    let mut items: Vec<ActivityLogItem> = logs.into_iter().map(to_item).collect();
    // Order is not requested server-side (combining $filter + $orderby is the
    // fragile combo on directoryAudits); sort newest-first here instead. Undated
    // entries sort last.
    items.sort_by_key(|i| std::cmp::Reverse(i.activity_date_time));
    Ok(items)
}

/// Most recent recorded sign-in for an app's service principal (keyed on appId),
/// from the beta `servicePrincipalSignInActivities` report. Answers "is anything
/// still using this?" before an admin disables / deletes an app or pulls a
/// credential.
///
/// Degrades gracefully — never returns `Err` for a missing scope / license /
/// consent: instead a populated [`SignInActivityDto`] with `available = false`
/// (or `consent_required = true`), so the surrounding Activity tab keeps
/// rendering directory changes. The `AuditLog.Read.All` token is pre-acquired
/// with a typed call (like `run_audit`) so a missing-consent failure is
/// distinguishable and can drive a "Grant consent & retry" button.
#[tauri::command]
pub async fn get_app_sign_in_activity(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<SignInActivityDto, UiError> {
    // Distinguish a missing-consent rejection from a license / availability one
    // up front (mirrors `run_audit`).
    if let Err(err) = state.ensure_audit_log_token(&tenant_id).await {
        let ui = UiError::from(err);
        if ui.code == "consent_required" {
            return Ok(SignInActivityDto {
                available: false,
                consent_required: true,
                last_sign_in_date_time: None,
                message: Some(
                    "Sign-in activity needs admin consent for AuditLog.Read.All (and an Entra ID P1/P2 license)."
                        .into(),
                ),
            });
        }
        return Ok(sign_in_unavailable(
            "Couldn't acquire AuditLog.Read.All for sign-in activity; it needs admin consent and an Entra ID P1/P2 license.",
        ));
    }

    let client = state.graph_for(&tenant_id);
    match client.list_service_principal_sign_in_activities().await {
        Ok(items) => Ok(SignInActivityDto {
            available: true,
            consent_required: false,
            last_sign_in_date_time: pick_last_sign_in(items, &app_id),
            message: None,
        }),
        Err(err) => Ok(map_sign_in_err(err)),
    }
}

/// The most recent recorded sign-in for `app_id` within the report, or `None`
/// when the report has no row for it (no sign-in observed in the window).
fn pick_last_sign_in(
    items: Vec<ServicePrincipalSignInActivity>,
    app_id: &str,
) -> Option<DateTime<Utc>> {
    items
        .into_iter()
        .find(|a| a.app_id.as_deref() == Some(app_id))
        .and_then(|a| a.last_sign_in_activity)
        .and_then(|s| s.last_sign_in_date_time)
}

fn sign_in_unavailable(message: &str) -> SignInActivityDto {
    SignInActivityDto {
        available: false,
        consent_required: false,
        last_sign_in_date_time: None,
        message: Some(message.to_string()),
    }
}

/// Maps a Graph error from the sign-in report into a graceful "unavailable" DTO
/// (never a hard error). Like [`map_activity_err`], never leaks the raw body.
fn map_sign_in_err(err: GraphError) -> SignInActivityDto {
    match &err {
        GraphError::Forbidden(body) => {
            if looks_like_missing_license(body) {
                sign_in_unavailable("Sign-in activity requires an Entra ID P1 or P2 license, which this tenant doesn't appear to have.")
            } else {
                sign_in_unavailable("Sign-in activity requires admin consent for AuditLog.Read.All and a supported reader role.")
            }
        }
        GraphError::Token(_) => sign_in_unavailable(
            "Couldn't acquire AuditLog.Read.All for sign-in activity; it needs admin consent (and Entra ID P1/P2).",
        ),
        GraphError::Unauthorized => {
            sign_in_unavailable("Your session expired. Sign in again to view sign-in activity.")
        }
        GraphError::Throttled { .. } | GraphError::Server { .. } | GraphError::Network(_) => {
            sign_in_unavailable("Couldn't reach the sign-in activity report just now. Try Refresh in a moment.")
        }
        _ => sign_in_unavailable("Sign-in activity is unavailable for this app right now."),
    }
}

/// Flattens a Graph audit entry into the display-ready DTO.
fn to_item(log: DirectoryAuditLog) -> ActivityLogItem {
    let initiated_by = log
        .initiated_by
        .as_ref()
        .and_then(|i| {
            i.user
                .as_ref()
                .and_then(|u| {
                    u.user_principal_name
                        .clone()
                        .or_else(|| u.display_name.clone())
                })
                .or_else(|| i.app.as_ref().and_then(|a| a.display_name.clone()))
        })
        .unwrap_or_else(|| "system".to_string());

    let names: Vec<String> = log
        .target_resources
        .iter()
        .filter_map(|t| t.display_name.clone())
        .collect();
    let target_summary = if names.is_empty() {
        "—".to_string()
    } else {
        names.join(", ")
    };

    let modified_properties = log
        .target_resources
        .iter()
        .flat_map(|t| t.modified_properties.iter())
        .map(|p| ModifiedPropertyDto {
            name: p.display_name.clone().unwrap_or_default(),
            old_value: p.old_value.clone(),
            new_value: p.new_value.clone(),
        })
        .collect();

    ActivityLogItem {
        id: log.id.unwrap_or_default(),
        activity: log
            .activity_display_name
            .unwrap_or_else(|| "(activity)".to_string()),
        activity_date_time: log.activity_date_time,
        category: log.category,
        result: log.result,
        result_reason: log.result_reason,
        initiated_by,
        target_summary,
        modified_properties,
    }
}

/// True when a 403 body looks like a missing-license rejection rather than a
/// missing-consent one. Graph encodes the body as JSON, so the `error.code` and
/// `error.message` text are both present in the raw string — a substring scan
/// over the lowercased body covers both. Known license signals include the
/// `Authentication_RequestFromNonPremiumTenantOrB2CTenant` code and the
/// "doesn't have premium license" message.
fn looks_like_missing_license(body: &str) -> bool {
    let lower = body.to_lowercase();
    ["license", "premium", "requestfromnonpremium", " p1", " p2"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Turns Graph errors into graceful, actionable messages for the Activity tab.
/// Every variant maps to an `activity_unavailable` message so the tab degrades
/// rather than failing the surrounding detail pane — and so a raw Graph error
/// body is never surfaced verbatim to the user. Transient classes stay
/// `retryable` so a Refresh is the obvious next step.
fn map_activity_err(err: GraphError) -> UiError {
    let msg = |retryable: bool, message: &str| UiError {
        code: "activity_unavailable".to_string(),
        message: message.to_string(),
        retryable,
    };
    match &err {
        GraphError::Forbidden(body) => {
            if looks_like_missing_license(body) {
                msg(false, "The activity log requires an Entra ID P1 or P2 license, which this tenant doesn't appear to have.")
            } else {
                msg(false, "The activity log requires admin consent for AuditLog.Read.All. Ask a Global Administrator to grant it, then reopen this tab.")
            }
        }
        GraphError::Token(_) => msg(
            false,
            "Couldn't acquire AuditLog.Read.All consent for the activity log. It needs admin consent (and Entra ID P1/P2); the rest of the app is unaffected.",
        ),
        GraphError::Unauthorized => {
            msg(false, "Your session expired. Sign in again to view the activity log.")
        }
        GraphError::Throttled { .. } | GraphError::Server { .. } | GraphError::Network(_) => msg(
            true,
            "Couldn't reach the activity log just now. Try Refresh in a moment.",
        ),
        // NotFound / Api / Deserialize / Protocol / Url: don't leak the raw
        // Graph body; surface a generic, non-retryable unavailable message.
        _ => msg(false, "The activity log is unavailable for this app right now."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::{
        AuditActivityInitiator, AuditAppIdentity, AuditLogTargetResource, AuditModifiedProperty,
        AuditUserIdentity, SignInActivity,
    };

    fn log_with(initiator: Option<AuditActivityInitiator>) -> DirectoryAuditLog {
        DirectoryAuditLog {
            id: Some("id-1".into()),
            activity_display_name: Some("Update application".into()),
            initiated_by: initiator,
            target_resources: vec![AuditLogTargetResource {
                id: Some("obj-1".into()),
                display_name: Some("My App".into()),
                modified_properties: vec![AuditModifiedProperty {
                    display_name: Some("KeyDescription".into()),
                    old_value: Some("[]".into()),
                    new_value: Some("[\"secret\"]".into()),
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn initiated_by_prefers_user_upn_then_app_then_system() {
        let by_user = to_item(log_with(Some(AuditActivityInitiator {
            user: Some(AuditUserIdentity {
                user_principal_name: Some("admin@contoso.com".into()),
                display_name: Some("Admin".into()),
                ..Default::default()
            }),
            app: None,
        })));
        assert_eq!(by_user.initiated_by, "admin@contoso.com");

        let by_app = to_item(log_with(Some(AuditActivityInitiator {
            user: None,
            app: Some(AuditAppIdentity {
                display_name: Some("Provisioning Service".into()),
                ..Default::default()
            }),
        })));
        assert_eq!(by_app.initiated_by, "Provisioning Service");

        let by_system = to_item(log_with(None));
        assert_eq!(by_system.initiated_by, "system");
    }

    #[test]
    fn flattens_targets_and_modified_properties() {
        let item = to_item(log_with(None));
        assert_eq!(item.target_summary, "My App");
        assert_eq!(item.modified_properties.len(), 1);
        assert_eq!(item.modified_properties[0].name, "KeyDescription");
        assert_eq!(item.activity, "Update application");
    }

    #[test]
    fn empty_targets_render_em_dash() {
        let item = to_item(DirectoryAuditLog::default());
        assert_eq!(item.target_summary, "—");
        assert_eq!(item.activity, "(activity)");
        assert_eq!(item.initiated_by, "system");
    }

    #[test]
    fn forbidden_license_vs_consent_messages_differ() {
        // Real Graph license rejection: structured JSON code + message.
        let license = map_activity_err(GraphError::Forbidden(
            "{\"error\":{\"code\":\"Authentication_RequestFromNonPremiumTenantOrB2CTenant\",\"message\":\"Neither tenant is B2C or tenant doesn't have premium license\"}}".into(),
        ));
        assert_eq!(license.code, "activity_unavailable");
        assert!(license.message.contains("license"));
        assert!(!license.retryable);

        let consent = map_activity_err(GraphError::Forbidden("Insufficient privileges".into()));
        assert_eq!(consent.code, "activity_unavailable");
        assert!(consent.message.contains("consent"));

        let token = map_activity_err(GraphError::Token("user declined".into()));
        assert_eq!(token.code, "activity_unavailable");
    }

    #[test]
    fn transient_errors_are_retryable_and_dont_leak_bodies() {
        for err in [
            GraphError::Server {
                status: 503,
                body: "secret-internal-detail".into(),
            },
            GraphError::Throttled {
                retry_after_secs: Some(5),
            },
            GraphError::Network("connection reset to 10.0.0.1".into()),
        ] {
            let ui = map_activity_err(err);
            assert_eq!(ui.code, "activity_unavailable");
            assert!(ui.retryable);
            // The raw Graph body must never reach the user.
            assert!(!ui.message.contains("secret-internal-detail"));
            assert!(!ui.message.contains("10.0.0.1"));
        }
    }

    #[test]
    fn opaque_errors_degrade_without_leaking_body() {
        let ui = map_activity_err(GraphError::Api {
            status: 500,
            body: "raw graph internals".into(),
        });
        assert_eq!(ui.code, "activity_unavailable");
        assert!(!ui.retryable);
        assert!(!ui.message.contains("raw graph internals"));
    }

    fn sp_activity(app_id: &str, date: Option<&str>) -> ServicePrincipalSignInActivity {
        ServicePrincipalSignInActivity {
            app_id: Some(app_id.into()),
            last_sign_in_activity: Some(SignInActivity {
                last_sign_in_date_time: date.map(|d| {
                    chrono::DateTime::parse_from_rfc3339(d)
                        .unwrap()
                        .with_timezone(&chrono::Utc)
                }),
            }),
        }
    }

    #[test]
    fn pick_last_sign_in_matches_app_id_or_returns_none() {
        let items = vec![
            sp_activity("other", Some("2024-01-01T00:00:00Z")),
            sp_activity("target", Some("2024-05-05T12:00:00Z")),
        ];
        let hit = pick_last_sign_in(items.clone(), "target").unwrap();
        assert_eq!(hit.to_rfc3339(), "2024-05-05T12:00:00+00:00");
        // App absent from the report ⇒ no sign-in observed.
        assert!(pick_last_sign_in(items, "missing").is_none());
        // App present but with a null last-sign-in ⇒ None, not a panic.
        assert!(pick_last_sign_in(vec![sp_activity("target", None)], "target").is_none());
    }

    #[test]
    fn sign_in_err_license_vs_consent_and_no_body_leak() {
        let license = map_sign_in_err(GraphError::Forbidden(
            "{\"error\":{\"code\":\"Authentication_RequestFromNonPremiumTenantOrB2CTenant\"}}"
                .into(),
        ));
        assert!(!license.available);
        assert!(!license.consent_required);
        assert!(license.message.unwrap().contains("license"));

        let consent = map_sign_in_err(GraphError::Forbidden("Insufficient privileges".into()));
        assert!(consent.message.unwrap().contains("consent"));

        // Transient / opaque errors degrade without leaking the raw body.
        let transient = map_sign_in_err(GraphError::Server {
            status: 503,
            body: "secret-internal-detail".into(),
        });
        assert!(!transient.available);
        assert!(!transient
            .message
            .unwrap()
            .contains("secret-internal-detail"));
    }
}
