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
                status: CredentialStatus::from_days_to_expiry(days_to_expiry),
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
                status: CredentialStatus::from_days_to_expiry(days_to_expiry),
            }
        })
        .collect();
    (secrets, certs)
}

/// Whether a credential's end date is past by at least one whole day — the
/// single "expired" rule shared by the audit scorer
/// ([`CredentialStatus::from_days_to_expiry`]), the one-click remediation, the
/// per-app expired-secret removal, and the bulk sweep. `num_days()` truncates toward zero, so a credential that lapsed
/// under 24h ago is still *expiring soon* everywhere: the audit offers no Fix
/// for it, and no removal path deletes it until it crosses a full day.
pub fn is_expired(end: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    end.is_some_and(|e| (e - now).num_days() < 0)
}

/// keyIds of the app's expired client secrets, by the shared whole-day
/// [`is_expired`] rule — the *exact* set the audit flags, so no removal path
/// (the one-click fix, the per-app expired-secret removal, or the bulk sweep)
/// can ever delete a credential the audit never flagged. Single-sourced here
/// because two byte-identical copies had grown in the command layer.
pub fn expired_password_key_ids(app: &Application, now: DateTime<Utc>) -> Vec<String> {
    app.password_credentials
        .iter()
        .filter(|c| is_expired(c.end_date_time, now))
        .map(|c| c.key_id.clone())
        .collect()
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

/// Tri-state per-credential last-used signal for the beta
/// `appCredentialSignInActivities` report. Mirrors [`SignInStatus`] but is
/// stricter on the third state: the report is preview data and its coverage
/// of never-used credentials is not contractual, so a credential ABSENT from
/// the report is `Unknown` — never evidence of non-use. Only a present row
/// (with or without a date) says something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialActivity {
    /// The report was unavailable, or this credential has no row in it.
    /// Never a finding (a live credential could simply be uncovered).
    Unknown,
    /// The report tracks this credential but observed no use.
    Never,
    /// Last observed use of the credential (across all flows).
    LastSeen(DateTime<Utc>),
}

/// Aggregated "credential unused for over {n} days" advisory for one app —
/// one issue line naming up to three stale credentials, never one per
/// credential (the mixed-credential-status line set that precedent). Net-new
/// (no PowerShell origin); fires only on positive report evidence: a `Never`
/// credential older than the window, or a still-valid one last used beyond
/// it. Already-expired credentials are the caller's to filter out (the
/// expired-credential finding covers them). Adds no risk score: last-used is
/// operator context on top of the expiry signals, not a new severity, and
/// removal stays an admin-judged act, so the finding carries no Fix.
pub fn unused_credential_advisory(
    creds: &[(&str, CredentialActivity, Option<DateTime<Utc>>)],
    now: DateTime<Utc>,
) -> Option<(String, String)> {
    let mut stale: Vec<String> = Vec::new();
    for (label, activity, start) in creds {
        // The unused-app rule's "avoid flagging brand-new" guard, per
        // credential: no-use evidence only reads as stale once the credential
        // is older than the window itself.
        let old_enough = start
            .map(|s| (now - s).num_days() > UNUSED_CREDENTIAL_DAYS)
            .unwrap_or(false);
        if !old_enough {
            continue;
        }
        match activity {
            CredentialActivity::Unknown => {}
            CredentialActivity::Never => stale.push(format!("{label} (no use recorded)")),
            CredentialActivity::LastSeen(dt) => {
                let days = (now - dt).num_days();
                if days > UNUSED_CREDENTIAL_DAYS {
                    stale.push(format!("{label} (last used {days} days ago)"));
                }
            }
        }
    }
    if stale.is_empty() {
        return None;
    }
    let shown = if stale.len() > 3 {
        format!("{} and {} more", stale[..3].join(", "), stale.len() - 3)
    } else {
        stale.join(", ")
    };
    Some((
        format!(
            "{} {shown} — no sign-in activity for over {UNUSED_CREDENTIAL_DAYS} days",
            issue::UNUSED_CREDENTIAL
        ),
        "Confirm each is still needed; remove or rotate the unused ones".to_string(),
    ))
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
    fn is_expired_agrees_with_from_days_to_expiry_at_the_day_boundary() {
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
            let status = CredentialStatus::from_days_to_expiry(end.map(|e| (e - now).num_days()));
            assert_eq!(
                status == CredentialStatus::Expired,
                expired,
                "from_days_to_expiry({end:?}) = {status:?}"
            );
        }
    }

    #[test]
    fn expired_password_key_ids_selects_exactly_the_flagged_set() {
        use crate::models::PasswordCredential;
        let now = now();
        let cred = |key: &str, end: DateTime<Utc>| PasswordCredential {
            key_id: key.to_string(),
            end_date_time: Some(end),
            ..Default::default()
        };
        let app = Application {
            password_credentials: vec![
                cred("active", now + Duration::days(30)),
                // Lapsed under a whole day: ExpiringSoon to the audit, so the
                // removal predicate must NOT select it either.
                cred("sub-day", now - Duration::hours(12)),
                cred("day-old", now - Duration::days(1)),
            ],
            ..Default::default()
        };
        assert_eq!(expired_password_key_ids(&app, now), vec!["day-old"]);
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
    fn unused_credential_advisory_never_flags_unknown() {
        // Absence from the report is `Unknown`, not "unused" — flagging on it
        // would strip live credentials whose use the preview report simply
        // doesn't surface. This is the never-false-positive contract.
        let old = Some(now() - Duration::days(200));
        let creds = [("secret \"a\"", CredentialActivity::Unknown, old)];
        assert!(unused_credential_advisory(&creds, now()).is_none());
    }

    #[test]
    fn unused_credential_advisory_flags_only_stale_evidence() {
        let old = Some(now() - Duration::days(200));
        let young = Some(now() - Duration::days(10));
        // Recent use → not flagged, even for an old credential.
        let recent = [(
            "secret \"a\"",
            CredentialActivity::LastSeen(now() - Duration::days(10)),
            old,
        )];
        assert!(unused_credential_advisory(&recent, now()).is_none());
        // Stale use → flagged, with the day count named.
        let stale = [(
            "cert \"b\"",
            CredentialActivity::LastSeen(now() - Duration::days(150)),
            old,
        )];
        let (issue_text, rec) = unused_credential_advisory(&stale, now()).expect("stale flags");
        assert!(issue_text.starts_with(issue::UNUSED_CREDENTIAL));
        assert!(issue_text.contains("cert \"b\" (last used 150 days ago)"));
        assert!(!rec.is_empty());
        // Never-used + old → flagged; young → not (brand-new guard).
        let never_old = [("secret \"c\"", CredentialActivity::Never, old)];
        assert!(
            unused_credential_advisory(&never_old, now())
                .is_some_and(|(i, _)| i.contains("secret \"c\" (no use recorded)"))
        );
        let never_young = [("secret \"c\"", CredentialActivity::Never, young)];
        assert!(unused_credential_advisory(&never_young, now()).is_none());
        // No age info at all → conservative, no flag.
        let unknown_age = [("secret \"d\"", CredentialActivity::Never, None)];
        assert!(unused_credential_advisory(&unknown_age, now()).is_none());
    }

    #[test]
    fn unused_credential_advisory_is_aggregated_and_capped() {
        // One line, first three named — never one issue per credential.
        let old = Some(now() - Duration::days(200));
        let labels = ["s1", "s2", "s3", "s4", "s5"];
        let creds: Vec<(&str, CredentialActivity, Option<DateTime<Utc>>)> =
            labels.map(|l| (l, CredentialActivity::Never, old)).to_vec();
        let (issue_text, _) = unused_credential_advisory(&creds, now()).expect("flags");
        assert!(
            issue_text.contains(
                "s1 (no use recorded), s2 (no use recorded), s3 (no use recorded) and 2 more"
            ) && !issue_text.contains("s4"),
            "{issue_text}"
        );
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
