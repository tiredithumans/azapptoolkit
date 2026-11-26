//! The "No built-in scoping" finding's per-row checklist (audit Rule 24).
//!
//! One line per held permission Microsoft offers no way to narrow, with its
//! Conditional Access network-lock verdict, then the row's other safeguards.
//! Wording rule: a safeguard limits where a stolen credential works, never
//! what the app can read — no line says "scoped", "confined" or "limited to".

use azapptoolkit_core::audit::{
    AuditItem, AuditPrincipalKind, GrantUsage, UsageUnknownReason, expiry_has_passed, issue,
};
use azapptoolkit_core::conditional_access::{LockIneligible, NetworkLock};
use leptos::prelude::*;

use crate::components::ui::Badge;
use crate::state::use_session;
use crate::util::fmt_day;
use crate::views::tabs::app_tab::AppTab;

use super::{last_sign_in_cell, risk_tone};

/// `(mark, text)` for one grant's network-lock verdict: ✓ in place, ✗ missing,
/// · neither (report-only, may-apply, not possible, unknown).
pub(super) fn network_lock_line(lock: &NetworkLock) -> (&'static str, String) {
    let not_possible = |who: &str| format!("not possible — Conditional Access can't target {who}");
    match lock {
        NetworkLock::Enforced { .. } => (
            "✓",
            "Conditional Access blocks sign-in from outside named locations".to_string(),
        ),
        NetworkLock::ReportOnly => (
            "·",
            "Conditional Access policy is report-only — it doesn't block yet".to_string(),
        ),
        NetworkLock::MayApply => (
            "·",
            "a Conditional Access policy may cover this app (filter or app group)".to_string(),
        ),
        // Where to set one up depends on the row: see `UnscopableChecklist`.
        NetworkLock::None => (
            "✗",
            "no Conditional Access policy locks this app to named locations".to_string(),
        ),
        NetworkLock::NotPossible { reason } => (
            "·",
            not_possible(match reason {
                LockIneligible::OtherTenant => "an app owned by another tenant",
                LockIneligible::MultiTenantApp => "a multi-tenant app",
                LockIneligible::ManagedIdentity => "a managed identity",
                LockIneligible::NoServicePrincipal => "an app with no service principal",
            }),
        ),
        NetworkLock::Unknown => (
            "·",
            "unknown — couldn't read Conditional Access (needs Policy.Read.All consent, an Entra ID P1/P2 license and a role such as Security Reader)"
                .to_string(),
        ),
    }
}

/// `(mark, text)` for one grant's observed Graph usage. A call in the
/// permission's family is one it COULD have authorized, so only "no call" is
/// worded as evidence about the grant — and only over enough days of logs to
/// advise removal (`not_seen_is_conclusive`).
pub(super) fn usage_line(usage: &GrantUsage, now: jiff::Timestamp) -> (&'static str, String) {
    match usage {
        GrantUsage::NotSeen { since }
            if !azapptoolkit_core::audit::not_seen_is_conclusive(*since, now) =>
        {
            let days = now.duration_since(*since).as_hours() / 24;
            (
                "·",
                format!(
                    "No call it could authorize since {} — only {days} day{} of logs so far, too few to judge",
                    fmt_day(*since),
                    if days == 1 { "" } else { "s" }
                ),
            )
        }
        GrantUsage::Seen { at } => (
            "·",
            format!("Last call it could authorize: {}", fmt_day(*at)),
        ),
        GrantUsage::NotSeen { since } => (
            "✗",
            format!(
                "No call it could authorize since {} — consider removing it",
                fmt_day(*since)
            ),
        ),
        GrantUsage::NotTracked => ("·", "Usage not tracked for this permission".to_string()),
        GrantUsage::Unknown { reason } => (
            "·",
            match reason {
                UsageUnknownReason::NoWorkspace => {
                    "Usage unknown — no Log Analytics workspace with Microsoft Graph activity logs"
                }
                UsageUnknownReason::NoConsent => {
                    "Usage unknown — grant the Log Analytics and Azure Resource Manager consents on the Observed Graph activity panel"
                }
                UsageUnknownReason::TimedOut => {
                    "Usage unknown — the Graph activity query took too long; re-run the audit"
                }
                UsageUnknownReason::NoLogs => {
                    "Usage unknown — the workspace has no Microsoft Graph activity logs from the last 90 days"
                }
                UsageUnknownReason::Stale => {
                    "Usage unknown — Microsoft Graph activity logs stopped arriving; check the Entra diagnostic setting"
                }
                UsageUnknownReason::NotChecked => "Usage not checked in this run",
                UsageUnknownReason::Failed => {
                    "Usage unknown — couldn't read Microsoft Graph activity logs"
                }
            }
            .to_string(),
        ),
    }
}

/// `(mark, text)` for a grant's expiry (Rule 25's tag), `None` when none is
/// set. A grant expires at the end of its day (UTC). `listed`: the run's
/// "Grants past their expiry" holds it — a run computed before UTC midnight
/// doesn't yet, so the line says to re-run rather than point at a group that
/// lacks it.
pub(super) fn expiry_line(
    expires_on: Option<jiff::civil::Date>,
    now: jiff::Timestamp,
    listed: bool,
) -> Option<(&'static str, String)> {
    let date = expires_on?;
    Some(if expiry_has_passed(date, now) {
        (
            "✗",
            if listed {
                format!("Expired {date} — revoke it from Grants past their expiry")
            } else {
                format!(
                    "Expired {date} — re-run the audit to list it under Grants past their expiry"
                )
            },
        )
    } else {
        ("·", format!("Expires {date}"))
    })
}

/// Whether the run's "Grants past their expiry" lists `g`. The run dated `g`
/// from the same tag it listed, so the resource and the date identify it.
pub(super) fn is_listed(
    expired: &[azapptoolkit_core::audit::ExpiredGrant],
    g: &azapptoolkit_core::audit::UnscopableGrant,
) -> bool {
    let resource = g
        .permission
        .resource_app_id
        .as_deref()
        .unwrap_or(azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID);
    expired.iter().any(|e| {
        e.resource_app_id.eq_ignore_ascii_case(resource) && Some(e.expires_on) == g.expires_on
    })
}

/// `(mark, text)` for an app registration's credentials.
fn credentials_line(item: &AuditItem) -> (&'static str, &'static str) {
    match (item.certificates.is_empty(), item.secrets.is_empty()) {
        (_, false) => ("✗", "uses a client secret"),
        (false, true) => ("✓", "certificate only"),
        (true, true) => ("·", "none"),
    }
}

/// `(mark, text)` for an app registration's owners, from the Rule 14 markers
/// (the audit reads owners on every run; no marker means two or more).
fn owners_line(item: &AuditItem) -> (&'static str, &'static str) {
    if item.issues.iter().any(|i| i.starts_with(issue::NO_OWNERS)) {
        ("✗", "none")
    } else if item
        .issues
        .iter()
        .any(|i| i.starts_with(issue::SINGLE_OWNER))
    {
        ("·", "one")
    } else {
        ("✓", "two or more")
    }
}

/// `(mark, text)` for an app registration's instance property lock, from the
/// Rule 15 marker (it fires whenever an app holding permissions has the lock
/// off — always the case for a row in this group).
fn instance_lock_line(item: &AuditItem) -> (&'static str, &'static str) {
    if item
        .issues
        .iter()
        .any(|i| i.starts_with(issue::INSTANCE_LOCK_DISABLED))
    {
        ("✗", "not fully enabled")
    } else {
        ("✓", "on")
    }
}

/// The Detail cell of a "No built-in scoping" row. App-registration rows add
/// credentials and owners; an SP-only row's live in its home tenant.
#[component]
pub(super) fn UnscopableChecklist(item: AuditItem) -> impl IntoView {
    let session = use_session();
    let is_app = item.principal_kind == AuditPrincipalKind::Application;
    let object_id = item.object_id.clone();
    let grants = item
        .unscopable_grants
        .iter()
        .map(|g| {
            let (mark, lock) = network_lock_line(&g.network_lock);
            // A missing lock: an app registration's is set up on its
            // Conditional Access tab (one click away); the enterprise pane
            // has no lock section.
            let lock_tail = (g.network_lock == NetworkLock::None).then(|| {
                if is_app {
                    let oid = object_id.clone();
                    view! {
                        " — set one up on "
                        <button
                            type="button"
                            class="link-btn"
                            on:click=move |_| {
                                session.open_app_on_tab(oid.clone(), AppTab::ConditionalAccess.value())
                            }
                        >
                            "the app's Conditional Access tab"
                        </button>
                    }
                        .into_any()
                } else {
                    " — set one up in the Microsoft Entra admin center".into_any()
                }
            });
            let (umark, used) = usage_line(&g.last_used, jiff::Timestamp::now());
            let expiry = expiry_line(
                g.expires_on,
                jiff::Timestamp::now(),
                is_listed(&item.expired_grants, g),
            )
                .map(|(m, t)| view! { <div>{format!("{m} {t}")}</div> });
            let mechanism = g.microsoft_mechanism.map(|m| match m {
                // C3: the toolkit writes the PowerShell (Teams has no API).
                azapptoolkit_core::audit::UnmanagedMechanism::TeamsMeetingAccessPolicy => format!(
                    "Microsoft can narrow this with {}: Meeting policy… on the app's Permissions tab writes the PowerShell.",
                    m.label()
                ),
                _ => format!(
                    "Microsoft can narrow this with {}; this toolkit doesn't manage it yet.",
                    m.label()
                ),
            });
            view! {
                <li>
                    <span class="mono">{g.permission.value.clone()}</span>
                    " "
                    <Badge label=g.risk.as_str() tone=risk_tone(&g.risk) />
                    <div>{format!("{mark} Network lock: {lock}")} {lock_tail}</div>
                    <div>{format!("{umark} {used}")}</div>
                    {expiry}
                    {mechanism.map(|m| view! { <div class="muted">{m}</div> })}
                </li>
            }
        })
        .collect_view();
    let app_lines = is_app.then(|| {
        let (cm, ct) = credentials_line(&item);
        let (om, ot) = owners_line(&item);
        let (lm, lt) = instance_lock_line(&item);
        view! {
            <li>{format!("{cm} Credentials: {ct}")}</li>
            <li>{format!("{om} Owners: {ot}")}</li>
            <li>{format!("{lm} Instance property lock: {lt}")}</li>
        }
    });
    let sign_in = last_sign_in_cell(&item);
    view! {
        <ul class="issues">
            {grants}
            {app_lines}
            <li>"· Last sign-in: " {sign_in}</li>
        </ul>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::conditional_access::{LockIneligible, NetworkLock};

    #[test]
    fn network_lock_lines() {
        use LockIneligible::*;
        let cases = [
            (
                NetworkLock::Enforced {
                    policy_ids: vec!["p".into()],
                },
                "✓",
                "Conditional Access blocks sign-in from outside named locations",
            ),
            (
                NetworkLock::ReportOnly,
                "·",
                "Conditional Access policy is report-only — it doesn't block yet",
            ),
            (
                NetworkLock::MayApply,
                "·",
                "a Conditional Access policy may cover this app (filter or app group)",
            ),
            (
                // Where to set one up is the row's to say (a link, B2e).
                NetworkLock::None,
                "✗",
                "no Conditional Access policy locks this app to named locations",
            ),
            (
                NetworkLock::NotPossible {
                    reason: OtherTenant,
                },
                "·",
                "not possible — Conditional Access can't target an app owned by another tenant",
            ),
            (
                NetworkLock::NotPossible {
                    reason: MultiTenantApp,
                },
                "·",
                "not possible — Conditional Access can't target a multi-tenant app",
            ),
            (
                NetworkLock::NotPossible {
                    reason: ManagedIdentity,
                },
                "·",
                "not possible — Conditional Access can't target a managed identity",
            ),
            (
                NetworkLock::NotPossible {
                    reason: NoServicePrincipal,
                },
                "·",
                "not possible — Conditional Access can't target an app with no service principal",
            ),
            (
                NetworkLock::Unknown,
                "·",
                "unknown — couldn't read Conditional Access (needs Policy.Read.All consent, an Entra ID P1/P2 license and a role such as Security Reader)",
            ),
        ];
        for (lock, mark, text) in cases {
            let (m, t) = network_lock_line(&lock);
            assert_eq!((m, t.as_str()), (mark, text), "{lock:?}");
            // A lock limits where a token works, never what it reads.
            for banned in ["scoped", "confined", "limited to"] {
                assert!(!t.contains(banned), "{t:?} says {banned:?}");
            }
        }
    }

    #[test]
    fn instance_lock_line_reads_the_rule_15_marker() {
        let on = azapptoolkit_core::audit::score_application(
            &azapptoolkit_core::models::Application::default(),
            None,
            &azapptoolkit_core::audit::AppPermissions::default(),
            jiff::Timestamp::UNIX_EPOCH,
        );
        assert_eq!(instance_lock_line(&on), ("✓", "on"));
        let mut off = on.clone();
        off.issues.push(format!(
            "{} — credentials could be added",
            issue::INSTANCE_LOCK_DISABLED
        ));
        assert_eq!(instance_lock_line(&off), ("✗", "not fully enabled"));
    }

    #[test]
    fn usage_lines() {
        use azapptoolkit_core::audit::{GrantUsage, UsageUnknownReason as R};
        let at: jiff::Timestamp = "2026-11-20T10:00:00Z".parse().unwrap();
        let since: jiff::Timestamp = "2026-08-27T00:00:00Z".parse().unwrap();
        let now: jiff::Timestamp = "2026-11-25T00:00:00Z".parse().unwrap();
        let recent: jiff::Timestamp = "2026-11-22T00:00:00Z".parse().unwrap();
        let cases = [
            (GrantUsage::Seen { at }, "·", "Last call it could authorize: 2026-11-20".to_string()),
            (
                GrantUsage::NotSeen { since },
                "✗",
                "No call it could authorize since 2026-08-27 — consider removing it".to_string(),
            ),
            // Logs only just started: too little to advise removal (B1b).
            (
                GrantUsage::NotSeen { since: recent },
                "·",
                "No call it could authorize since 2026-11-22 — only 3 days of logs so far, too few to judge".to_string(),
            ),
            (GrantUsage::NotTracked, "·", "Usage not tracked for this permission".to_string()),
            (
                GrantUsage::Unknown { reason: R::NoWorkspace },
                "·",
                "Usage unknown — no Log Analytics workspace with Microsoft Graph activity logs".to_string(),
            ),
            (
                GrantUsage::Unknown { reason: R::NoConsent },
                "·",
                "Usage unknown — grant the Log Analytics and Azure Resource Manager consents on the Observed Graph activity panel".to_string(),
            ),
            (
                GrantUsage::Unknown { reason: R::TimedOut },
                "·",
                "Usage unknown — the Graph activity query took too long; re-run the audit".to_string(),
            ),
            (
                GrantUsage::Unknown { reason: R::Failed },
                "·",
                "Usage unknown — couldn't read Microsoft Graph activity logs".to_string(),
            ),
            (
                GrantUsage::Unknown { reason: R::NotChecked },
                "·",
                "Usage not checked in this run".to_string(),
            ),
            (
                GrantUsage::Unknown { reason: R::NoLogs },
                "·",
                "Usage unknown — the workspace has no Microsoft Graph activity logs from the last 90 days".to_string(),
            ),
            (
                GrantUsage::Unknown { reason: R::Stale },
                "·",
                "Usage unknown — Microsoft Graph activity logs stopped arriving; check the Entra diagnostic setting".to_string(),
            ),
        ];
        for (usage, mark, text) in cases {
            let (m, t) = usage_line(&usage, now);
            assert_eq!((m, t.as_str()), (mark, text.as_str()), "{usage:?}");
            for banned in ["used it", "scoped", "confined"] {
                assert!(!t.contains(banned), "{t:?} says {banned:?}");
            }
        }
    }

    #[test]
    fn a_grant_is_listed_by_resource_and_date() {
        use azapptoolkit_core::audit::{
            ExpiredGrant, ResourcePermission, RiskLevel, UnscopableGrant,
        };
        let day = |d: &str| d.parse::<jiff::civil::Date>().unwrap();
        let grant = |resource: Option<&str>, date: &str| UnscopableGrant {
            permission: ResourcePermission {
                resource_app_id: resource.map(str::to_string),
                ..ResourcePermission::graph("CallRecords.Read.All")
            },
            risk: RiskLevel::Medium,
            microsoft_mechanism: None,
            network_lock: NetworkLock::default(),
            last_used: Default::default(),
            expires_on: Some(day(date)),
        };
        let listed = vec![ExpiredGrant {
            resource_app_id: azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID.into(),
            app_role_id: "role".into(),
            name: "CallRecords.Read.All".into(),
            expires_on: day("2026-11-24"),
        }];
        assert!(
            is_listed(&listed, &grant(None, "2026-11-24")),
            "no resource = Graph"
        );
        assert!(is_listed(
            &listed,
            &grant(Some("00000003-0000-0000-C000-000000000000"), "2026-11-24")
        ));
        assert!(
            !is_listed(&listed, &grant(None, "2026-11-25")),
            "another date"
        );
        assert!(
            !is_listed(&[], &grant(None, "2026-11-24")),
            "a run before midnight"
        );
        assert!(!is_listed(
            &listed,
            &grant(Some("00000002-0000-0ff1-ce00-000000000000"), "2026-11-24")
        ));
    }

    #[test]
    fn expiry_lines() {
        let now: jiff::Timestamp = "2026-11-25T12:00:00Z".parse().unwrap();
        let day = |d: &str| Some(d.parse::<jiff::civil::Date>().unwrap());
        assert_eq!(expiry_line(None, now, false), None);
        assert_eq!(
            expiry_line(day("2026-12-24"), now, false),
            Some(("·", "Expires 2026-12-24".to_string()))
        );
        assert_eq!(
            expiry_line(day("2026-11-25"), now, false),
            Some(("·", "Expires 2026-11-25".to_string())),
            "a grant expires at the end of its day"
        );
        assert_eq!(
            expiry_line(day("2026-11-24"), now, true),
            Some((
                "✗",
                "Expired 2026-11-24 — revoke it from Grants past their expiry".to_string()
            ))
        );
        // A run computed before UTC midnight doesn't list it yet (B3g).
        assert_eq!(
            expiry_line(day("2026-11-24"), now, false),
            Some((
                "✗",
                "Expired 2026-11-24 — re-run the audit to list it under Grants past their expiry"
                    .to_string()
            ))
        );
    }
}
