//! Credential summarization and the sign-in/unused-app helpers shared by
//! the audit scorer, the credential-expiry dashboard, and the removal
//! sweeps.

use chrono::{DateTime, Duration, Utc};

use crate::models::{
    AppManagementPolicy, Application, CredentialRestrictionConfiguration, TenantAppManagementPolicy,
};

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

/// Parse an ISO 8601 duration (Graph's `maxLifetime` wire format, e.g. `P90D`
/// or `P4DT12H30M5S`) into whole days, truncating the time part. Years and
/// months are calendar-relative, so any duration that needs them reads as
/// unknown (`None`) — the never-flag-on-unknown contract, matching how
/// credential activity absence is treated. A sub-day cap likewise reads
/// unknown: there is no whole-day comparison to make.
pub fn iso_duration_days(s: &str) -> Option<i64> {
    let rest = s.trim().strip_prefix('P')?;
    if rest.is_empty() {
        return None;
    }
    let (date_part, _time_part) = match rest.split_once('T') {
        Some((d, t)) => (d, t),
        None => (rest, ""),
    };
    // Collect (amount, unit) pairs; digits must always precede a unit.
    let mut pairs: Vec<(i64, char)> = Vec::new();
    let mut digits = String::new();
    for c in date_part.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            let n: i64 = digits.parse().ok()?;
            pairs.push((n, c));
            digits.clear();
        }
    }
    if !digits.is_empty() {
        return None;
    }
    let mut days: i64 = 0;
    for (n, unit) in pairs {
        match unit {
            'Y' | 'M' => return None,
            'W' => days += n.checked_mul(7)?,
            'D' => days += n,
            _ => return None,
        }
    }
    (days > 0).then_some(days)
}

/// Whether one restriction entry enforces a secret lifetime for an app created
/// at `created`. `Unknown` means the entry IS an enforced password-lifetime
/// restriction whose cap cannot be resolved (unparseable `maxLifetime`, or a
/// date gate whose coverage depends on an unknown creation date) — the caller
/// must treat that as "no verdict", never as "compliant".
enum EntryCap {
    Irrelevant,
    Unknown,
    Cap(i64),
}

fn entry_cap(e: &CredentialRestrictionConfiguration, created: Option<DateTime<Utc>>) -> EntryCap {
    if e.state.as_deref() != Some("enabled")
        || e.restriction_type.as_deref() != Some("passwordLifetime")
    {
        return EntryCap::Irrelevant;
    }
    let Some(cap) = e.max_lifetime.as_deref().and_then(iso_duration_days) else {
        return EntryCap::Unknown;
    };
    match e.restrict_for_apps_created_after_date_time {
        // No gate date = retroactive: covers every app, whenever created.
        None => EntryCap::Cap(cap),
        Some(gate) => match created {
            Some(created) if created > gate => EntryCap::Cap(cap),
            Some(_) => EntryCap::Irrelevant,
            None => EntryCap::Unknown,
        },
    }
}

fn min_cap<'a>(
    entries: impl Iterator<Item = &'a CredentialRestrictionConfiguration>,
    created: Option<DateTime<Utc>>,
) -> Option<i64> {
    let mut caps: Vec<i64> = Vec::new();
    for e in entries {
        match entry_cap(e, created) {
            EntryCap::Irrelevant => {}
            EntryCap::Unknown => return None,
            EntryCap::Cap(c) => caps.push(c),
        }
    }
    caps.into_iter().min()
}

/// The policy-enforced maximum secret lifetime (days) for ONE application, or
/// `None` when no cap is knowable for it. Call sites must never flag on
/// `None` — it means unknown or unenforced, not compliant.
///
/// A per-app `custom` policy, when one is assigned, REPLACES the tenant
/// default ("the application adopts this policy over the tenant-wide
/// setting") — including when it is disabled or carries no lifetime rule, so
/// the default's cap must not be applied to that app either. `None` custom =
/// no override assigned.
pub fn enforced_secret_max_days(
    custom: Option<&AppManagementPolicy>,
    default: Option<&TenantAppManagementPolicy>,
    created: Option<DateTime<Utc>>,
) -> Option<i64> {
    let (enabled, restrictions) = match (custom, default) {
        (Some(c), _) => (c.is_enabled, c.restrictions.as_ref()),
        (None, Some(d)) => (d.is_enabled, d.application_restrictions.as_ref()),
        (None, None) => return None,
    };
    if !enabled {
        return None;
    }
    min_cap(restrictions?.password_entries(), created)
}

/// The tenant-wide view of the default policy's secret-lifetime cap for the
/// Home posture line: the smallest enforced `passwordLifetime` in the default
/// policy, IGNORING per-app date gates — the "what does this tenant cap
/// secrets at" number. `None` = unknown or no cap enforced. Per-app coverage
/// (and the never-flag-on-unknown rule) stays with
/// [`enforced_secret_max_days`].
pub fn tenant_secret_max_days(default: Option<&TenantAppManagementPolicy>) -> Option<i64> {
    let default = default.filter(|d| d.is_enabled)?;
    // Gate-ignoring lens: only an unparseable `maxLifetime` on an enforced
    // password-lifetime entry makes the tenant cap unknowable.
    let entries = default
        .application_restrictions
        .as_ref()?
        .password_entries();
    let mut caps: Vec<i64> = Vec::new();
    for e in entries {
        if e.state.as_deref() != Some("enabled")
            || e.restriction_type.as_deref() != Some("passwordLifetime")
        {
            continue;
        }
        caps.push(e.max_lifetime.as_deref().and_then(iso_duration_days)?);
    }
    caps.into_iter().min()
}

/// True when a credential provably exceeds a `cap_days` lifetime: no expiry
/// is over any cap; a dated lifetime counts only when BOTH dates are known
/// (a credential whose lifetime cannot be computed is never flagged — the
/// never-flag-on-unknown contract the unused-credential rule follows too).
/// Expiry state is NOT checked here; callers gate on [`is_expired`] first so
/// an expired credential keeps its single "Expired" signal instead of stacking
/// a second marker. The Credentials tab marks its rows with this predicate and
/// [`secret_lifetime_advisory`] aggregates with it — the one definition that
/// keeps the audit's advisory and the tab's markers unable to disagree.
pub fn credential_over_cap(
    end: Option<DateTime<Utc>>,
    start: Option<DateTime<Utc>>,
    cap_days: i64,
) -> bool {
    match (end, start) {
        (None, _) => true,
        (Some(end), Some(start)) => (end - start).num_days() > cap_days,
        (Some(_), None) => false,
    }
}

/// One credential's lifetime facts: `(label, end_date_time,
/// start_or_fallback)` — the shape [`secret_lifetime_advisory`] judges.
pub type CredentialLifetime<'a> = (&'a str, Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// Aggregated "secret runs past the policy cap" advisory for one app — one
/// recommendation line naming up to three over-long secrets, following
/// [`unused_credential_advisory`]'s aggregate-and-cap style.
///
/// Recommendation-only: it adds no issue marker, no finding key and no risk
/// score. The cap is operator context — whether a secret is legal-but-long is
/// not a finding, and a tenant that enforces no cap must hear nothing at all.
/// `creds` are [`CredentialLifetime`] for the caller's
/// still-valid secrets only (expired ones belong to the expired-credential
/// finding). A secret with no end date exceeds any finite cap; one whose
/// lifetime cannot be derived (start unknown) gets no verdict — the
/// never-flag-on-unknown contract.
pub fn secret_lifetime_advisory(creds: &[CredentialLifetime<'_>], cap_days: i64) -> Option<String> {
    let mut over: Vec<String> = Vec::new();
    for (label, end, start) in creds {
        if !credential_over_cap(*end, *start, cap_days) {
            continue;
        }
        match (end, start) {
            (None, _) => over.push(format!("{label} (no expiry)")),
            (Some(end), Some(start)) => {
                let days = (*end - *start).num_days();
                over.push(format!("{label} ({days}-day lifetime)"));
            }
            (Some(_), None) => {}
        }
    }
    if over.is_empty() {
        return None;
    }
    let shown = if over.len() > 3 {
        format!("{} and {} more", over[..3].join(", "), over.len() - 3)
    } else {
        over.join(", ")
    };
    Some(format!(
        "Policy caps secret lifetimes at {cap_days} days; shorten or rotate: {shown}"
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
    use crate::models::AppManagementConfiguration;
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
    fn secret_lifetime_advisory_never_flags_unknown_and_caps_names() {
        // No expiry = infinite lifetime, so it exceeds any finite cap…
        let never = [("secret \"a\"", None, Some(now()))];
        let rec = secret_lifetime_advisory(&never, 90).expect("no-expiry is over any cap");
        assert!(rec.contains("90 days"), "{rec}");
        assert!(rec.contains("secret \"a\" (no expiry)"), "{rec}");
        // In-scope lifetimes get no verdict…
        let ok = [(
            "secret \"b\"",
            Some(now() + Duration::days(30)),
            Some(now() - Duration::days(30)),
        )];
        assert!(secret_lifetime_advisory(&ok, 90).is_none());
        // …neither does an unknown lifetime (no start to measure from)…
        let unknown = [("secret \"c\"", Some(now() + Duration::days(400)), None)];
        assert!(
            secret_lifetime_advisory(&unknown, 90).is_none(),
            "unknown lifetime is not evidence of an over-long secret"
        );
        // …and exactly-at-cap is at cap, not past it.
        let at_cap = [(
            "secret \"d\"",
            Some(now() + Duration::days(30)),
            Some(now() - Duration::days(60)),
        )];
        assert!(secret_lifetime_advisory(&at_cap, 90).is_none());
        // Over-cap is flagged with the day count; more than three aggregates.
        let over: Vec<CredentialLifetime> = ["s1", "s2", "s3", "s4"]
            .map(|l| {
                (
                    l,
                    Some(now() + Duration::days(400)),
                    Some(now() - Duration::days(30)),
                )
            })
            .to_vec();
        let rec = secret_lifetime_advisory(&over, 90).expect("flags");
        assert!(rec.contains("430-day lifetime"), "{rec}");
        assert!(
            rec.contains("s1") && rec.contains("s3") && !rec.contains("s4"),
            "{rec}"
        );
        assert!(rec.contains("and 1 more"), "{rec}");
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

    fn entry(
        restriction_type: Option<&str>,
        state: Option<&str>,
        max_lifetime: Option<&str>,
        gate: Option<DateTime<Utc>>,
    ) -> CredentialRestrictionConfiguration {
        CredentialRestrictionConfiguration {
            restriction_type: restriction_type.map(str::to_string),
            state: state.map(str::to_string),
            max_lifetime: max_lifetime.map(str::to_string),
            restrict_for_apps_created_after_date_time: gate,
        }
    }

    fn lifetime(max: &str, gate: Option<DateTime<Utc>>) -> CredentialRestrictionConfiguration {
        entry(Some("passwordLifetime"), Some("enabled"), Some(max), gate)
    }

    #[test]
    fn iso_duration_days_parses_whole_days_and_refuses_calendar_units() {
        let cases = [
            ("P90D", Some(90)),
            ("P2W", Some(14)),
            ("P4DT12H30M5S", Some(4)), // time part truncates into day granularity
            ("P1Y", None),             // calendar-relative → unknown, never guessed
            ("P3M", None),
            ("PT12H", None), // sub-day cap has no whole-day comparison
            ("P", None),
            ("", None),
            ("P90", None),         // digits without a unit
            ("ninety days", None), // not a duration at all
            ("P-5D", None),
        ];
        for (input, expected) in cases {
            assert_eq!(iso_duration_days(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn enforced_secret_max_days_never_guesses_unknown_caps() {
        let old = now() - Duration::days(200);
        // Unenforced or irrelevant entries give no verdict…
        assert!(
            enforced_secret_max_days(None, None, Some(old)).is_none(),
            "no policy at all"
        );
        let tenant = |enabled: bool, entries: Vec<CredentialRestrictionConfiguration>| {
            TenantAppManagementPolicy {
                is_enabled: enabled,
                application_restrictions: Some(AppManagementConfiguration {
                    password_credentials: entries,
                    ..Default::default()
                }),
                ..Default::default()
            }
        };
        let disabled = tenant(false, vec![lifetime("P90D", None)]);
        assert!(
            enforced_secret_max_days(None, Some(&disabled), Some(old)).is_none(),
            "disabled restriction is documented, not enforced"
        );
        // …and an enforced-but-unparseable cap must NOT fall back to "fine".
        let garbage = tenant(true, vec![lifetime("banana", None)]);
        assert!(
            enforced_secret_max_days(None, Some(&garbage), Some(old)).is_none(),
            "unparseable maxLifetime is an unknown cap"
        );
        // Retroactive (null gate) applies to every app…
        let retro = tenant(true, vec![lifetime("P90D", None)]);
        assert_eq!(
            enforced_secret_max_days(None, Some(&retro), Some(old)),
            Some(90)
        );
        // …a date gate covers only apps created after it…
        let gate = now() - Duration::days(30);
        let gated = tenant(true, vec![lifetime("P180D", Some(gate))]);
        assert_eq!(
            enforced_secret_max_days(None, Some(&gated), Some(now())),
            Some(180)
        );
        assert!(
            enforced_secret_max_days(None, Some(&gated), Some(old)).is_none(),
            "app older than the gate is grandfathered"
        );
        // …and unknown creation date is unknown coverage, never a flag.
        assert!(enforced_secret_max_days(None, Some(&gated), None).is_none());
        // Multiple caps: the strictest wins.
        let both = tenant(
            true,
            vec![lifetime("P365D", None), lifetime("P60D", Some(gate))],
        );
        assert_eq!(
            enforced_secret_max_days(None, Some(&both), Some(now())),
            Some(60),
            "strictest applicable cap wins"
        );
    }

    #[test]
    fn assigned_custom_policy_replaces_the_tenant_default() {
        let old = now() - Duration::days(200);
        let tenant = TenantAppManagementPolicy {
            is_enabled: true,
            application_restrictions: Some(AppManagementConfiguration {
                password_credentials: vec![lifetime("P90D", None)],
                ..Default::default()
            }),
            ..Default::default()
        };
        // A per-app override replaces the default even when it carries no
        // lifetime rule of its own — the default must not be applied to an
        // overridden app.
        let custom_bare = AppManagementPolicy {
            is_enabled: true,
            restrictions: Some(AppManagementConfiguration::default()),
            ..Default::default()
        };
        assert!(enforced_secret_max_days(Some(&custom_bare), Some(&tenant), Some(old)).is_none());
        // A DISABLED override still occupies the slot: combination semantics
        // are not knowable from directory data → no verdict, ever.
        let custom_disabled = AppManagementPolicy {
            is_enabled: false,
            restrictions: Some(AppManagementConfiguration {
                password_credentials: vec![lifetime("P30D", None)],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            enforced_secret_max_days(Some(&custom_disabled), Some(&tenant), Some(old)).is_none()
        );
        // An enabled override's own cap is the effective one.
        let custom = AppManagementPolicy {
            is_enabled: true,
            restrictions: Some(AppManagementConfiguration {
                password_credentials: vec![lifetime("P30D", None)],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            enforced_secret_max_days(Some(&custom), Some(&tenant), Some(old)),
            Some(30),
            "override outranks the default"
        );
    }

    #[test]
    fn custom_restrictions_read_from_either_shape_layer() {
        // The per-app `customAppManagementConfiguration` has shipped the
        // password array at the top level AND nested under
        // `applicationRestrictions`; resolution merges both.
        let nested = AppManagementPolicy {
            is_enabled: true,
            restrictions: Some(AppManagementConfiguration {
                password_credentials: vec![],
                application_restrictions: Some(Box::new(AppManagementConfiguration {
                    password_credentials: vec![lifetime("P45D", None)],
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            enforced_secret_max_days(Some(&nested), None, None),
            Some(45),
            "nested passwordCredentials must be read too"
        );
    }

    #[test]
    fn tenant_secret_max_days_ignores_gates_but_not_unknowns() {
        assert!(tenant_secret_max_days(None).is_none());
        let off = TenantAppManagementPolicy {
            is_enabled: false,
            application_restrictions: Some(AppManagementConfiguration {
                password_credentials: vec![lifetime("P90D", None)],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(tenant_secret_max_days(Some(&off)).is_none());
        let gate = now() - Duration::days(30);
        let tenant = TenantAppManagementPolicy {
            is_enabled: true,
            application_restrictions: Some(AppManagementConfiguration {
                password_credentials: vec![lifetime("P90D", Some(gate)), lifetime("P180D", None)],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(tenant_secret_max_days(Some(&tenant)), Some(90));
        let broken = TenantAppManagementPolicy {
            is_enabled: true,
            application_restrictions: Some(AppManagementConfiguration {
                password_credentials: vec![lifetime("nope", None)],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(tenant_secret_max_days(Some(&broken)).is_none());
    }
}
