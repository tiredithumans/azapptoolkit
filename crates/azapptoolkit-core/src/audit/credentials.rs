//! Credential summarization and the sign-in/unused-app helpers shared by
//! the audit scorer, the credential-expiry dashboard, and the removal
//! sweeps.

use chrono::{DateTime, Duration, Utc};

use crate::models::Application;

use super::*;

/// Flattens an application's client secrets and certificates into
/// `(secrets, certs)` summaries with per-credential days-to-expiry and status.
/// Public so the credential-expiry dashboard can reuse the same expiry logic
/// the audit scorer uses, keeping the two views consistent.
pub fn summarize_credentials(
    app: &Application,
    now: DateTime<Utc>,
) -> (Vec<CredentialSummary>, Vec<CredentialSummary>) {
    let secrets = app
        .password_credentials
        .iter()
        .map(|p| {
            let end = p.end_date_time;
            let days_to_expiry = end.map(|e| (e - now).num_days());
            CredentialSummary {
                name: p.display_name.clone().unwrap_or_else(|| "—".to_string()),
                kind: CredentialKind::Secret,
                start_date_time: p.start_date_time,
                end_date_time: end,
                days_to_expiry,
                status: credential_status(days_to_expiry),
            }
        })
        .collect();
    let certs = app
        .key_credentials
        .iter()
        .map(|k| {
            let end = k.end_date_time;
            let days_to_expiry = end.map(|e| (e - now).num_days());
            CredentialSummary {
                name: k.display_name.clone().unwrap_or_else(|| "—".to_string()),
                kind: CredentialKind::Certificate,
                start_date_time: k.start_date_time,
                end_date_time: end,
                days_to_expiry,
                status: credential_status(days_to_expiry),
            }
        })
        .collect();
    (secrets, certs)
}

/// Whether a credential's end date is past by at least one whole day — the
/// single "expired" rule shared by the audit scorer ([`credential_status`]),
/// the one-click remediation, the per-app expired-secret removal, and the bulk
/// sweep. `num_days()` truncates toward zero, so a credential that lapsed
/// under 24h ago is still *expiring soon* everywhere: the audit offers no Fix
/// for it, and no removal path deletes it until it crosses a full day.
pub fn is_expired(end: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    end.is_some_and(|e| (e - now).num_days() < 0)
}

fn credential_status(days: Option<i64>) -> CredentialStatus {
    match days {
        None => CredentialStatus::Unknown,
        Some(d) if d < 0 => CredentialStatus::Expired,
        Some(d) if d <= EXPIRY_WARNING_DAYS => CredentialStatus::ExpiringSoon,
        Some(_) => CredentialStatus::Active,
    }
}

pub(super) fn overall_credential_status(all: &[&CredentialSummary]) -> CredentialStatus {
    if all.is_empty() {
        return CredentialStatus::Unknown;
    }
    if all.iter().any(|c| c.status == CredentialStatus::Expired) {
        CredentialStatus::Expired
    } else if all
        .iter()
        .any(|c| c.status == CredentialStatus::ExpiringSoon)
    {
        CredentialStatus::ExpiringSoon
    } else if all.iter().all(|c| c.status == CredentialStatus::Unknown) {
        CredentialStatus::Unknown
    } else {
        CredentialStatus::Active
    }
}

pub(super) fn is_long_lived(c: &CredentialSummary) -> bool {
    match (c.start_date_time, c.end_date_time) {
        (Some(start), Some(end)) => (end - start) > Duration::days(LONG_LIVED_SECRET_DAYS),
        _ => false,
    }
}

/// Encodes the three states of sign-in activity report data for unused-app
/// detection.  Replaces `Option<Option<DateTime<Utc>>>` with a named,
/// self-documenting type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInStatus {
    /// The sign-in report was unavailable (no `AuditLog.Read.All` / no Entra ID
    /// P1-P2 / call failed). Never flag without data.
    Unavailable,
    /// Report available but no sign-in recorded.
    NoneRecorded,
    /// Last observed sign-in timestamp.
    LastSeen(DateTime<Utc>),
}

/// Advisory (issue, recommendation) when an app appears unused per the sign-in
/// activity report. Net-new (no PowerShell origin); kept out of
/// [`score_application`] because the sign-in data is fetched separately and is
/// optional. Adds no risk score.
pub fn unused_app_advisory(
    sign_in_status: SignInStatus,
    created: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<(String, String)> {
    let rec = "Confirm the application is still needed; disable or delete it if not".to_string();
    match sign_in_status {
        SignInStatus::Unavailable => None,
        SignInStatus::LastSeen(dt) => {
            let days = (now - dt).num_days();
            (days > UNUSED_APP_DAYS).then(|| {
                (
                    format!("No sign-in for {days} days — application may be unused"),
                    rec,
                )
            })
        }
        SignInStatus::NoneRecorded => {
            let old_enough = created
                .map(|c| (now - c).num_days() > UNUSED_APP_DAYS)
                .unwrap_or(false);
            old_enough.then(|| {
                (
                    "No sign-in activity recorded — application may be unused".to_string(),
                    rec,
                )
            })
        }
    }
}

/// Convert `Option<Option<DateTime<Utc>>>` into [`SignInStatus`] for callers
/// that still receive the double-Option from DTOs.
impl From<Option<Option<DateTime<Utc>>>> for SignInStatus {
    fn from(value: Option<Option<DateTime<Utc>>>) -> Self {
        match value {
            None => SignInStatus::Unavailable,
            Some(None) => SignInStatus::NoneRecorded,
            Some(Some(dt)) => SignInStatus::LastSeen(dt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 22, 12, 0, 0).unwrap()
    }

    #[test]
    fn is_expired_agrees_with_credential_status_at_the_day_boundary() {
        // The shared removal predicate and the scorer's status must call the
        // same set "expired" — a sub-day lapse is ExpiringSoon to both, so no
        // removal path deletes a credential the audit never flagged.
        let now = now();
        let cases = [
            (None, false),
            (Some(now + Duration::days(30)), false),
            (Some(now - Duration::hours(12)), false), // lapsed <24h: still "expiring soon"
            (Some(now - Duration::days(1)), true),
        ];
        for (end, expired) in cases {
            assert_eq!(is_expired(end, now), expired, "is_expired({end:?})");
            let status = credential_status(end.map(|e| (e - now).num_days()));
            assert_eq!(
                status == CredentialStatus::Expired,
                expired,
                "credential_status({end:?}) = {status:?}"
            );
        }
    }

    #[test]
    fn unused_app_advisory_degrades_and_flags_correctly() {
        let created_old = Some(now() - Duration::days(200));
        let created_new = Some(now() - Duration::days(10));
        // Report unavailable → never flag, regardless of age.
        assert!(unused_app_advisory(SignInStatus::Unavailable, created_old, now()).is_none());
        // Recent sign-in → not flagged.
        assert!(
            unused_app_advisory(
                SignInStatus::LastSeen(now() - Duration::days(10)),
                created_old,
                now()
            )
            .is_none()
        );
        // Old sign-in → flagged.
        let flagged = unused_app_advisory(
            SignInStatus::LastSeen(now() - Duration::days(200)),
            created_old,
            now(),
        );
        assert!(flagged.is_some_and(|(i, _)| i.starts_with("No sign-in for")));
        // No sign-in recorded + old app → flagged.
        assert!(
            unused_app_advisory(SignInStatus::NoneRecorded, created_old, now())
                .is_some_and(|(i, _)| i.starts_with("No sign-in activity recorded"))
        );
        // No sign-in recorded + new app → not flagged (avoid flagging brand-new).
        assert!(unused_app_advisory(SignInStatus::NoneRecorded, created_new, now()).is_none());
    }

    #[test]
    fn sign_in_status_from_double_option() {
        assert_eq!(SignInStatus::from(None), SignInStatus::Unavailable);
        assert_eq!(SignInStatus::from(Some(None)), SignInStatus::NoneRecorded);
        let dt = now() - Duration::days(10);
        assert_eq!(
            SignInStatus::from(Some(Some(dt))),
            SignInStatus::LastSeen(dt)
        );
    }
}
