//! The "No built-in scoping" finding's per-row checklist (audit Rule 24).
//!
//! One line per held permission Microsoft offers no way to narrow, with its
//! Conditional Access network-lock verdict, then the row's other safeguards.
//! Wording rule: a safeguard limits where a stolen credential works, never
//! what the app can read — no line says "scoped", "confined" or "limited to".

use azapptoolkit_core::audit::{
    AuditItem, AuditPrincipalKind, GrantUsage, UsageUnknownReason, issue,
};
use azapptoolkit_core::conditional_access::{LockIneligible, NetworkLock};
use leptos::prelude::*;

use crate::components::ui::Badge;
use crate::util::fmt_day;

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
        NetworkLock::None => (
            "✗",
            "no Conditional Access policy locks this app to named locations — set one up on the app's Conditional Access tab"
                .to_string(),
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
/// worded as evidence about the grant.
pub(super) fn usage_line(usage: &GrantUsage) -> (&'static str, String) {
    match usage {
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
                    "Usage unknown — grant the Log Analytics consent on the Observed Graph activity panel"
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
    let is_app = item.principal_kind == AuditPrincipalKind::Application;
    let grants = item
        .unscopable_grants
        .iter()
        .map(|g| {
            let (mark, lock) = network_lock_line(&g.network_lock);
            let (umark, used) = usage_line(&g.last_used);
            let mechanism = g.microsoft_mechanism.map(|m| {
                format!(
                    "Microsoft can narrow this with {}; this toolkit doesn't manage it yet.",
                    m.label()
                )
            });
            view! {
                <li>
                    <span class="mono">{g.permission.value.clone()}</span>
                    " "
                    <Badge label=g.risk.as_str() tone=risk_tone(&g.risk) />
                    <div>{format!("{mark} Network lock: {lock}")}</div>
                    <div>{format!("{umark} {used}")}</div>
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
                NetworkLock::None,
                "✗",
                "no Conditional Access policy locks this app to named locations — set one up on the app's Conditional Access tab",
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
        let cases = [
            (GrantUsage::Seen { at }, "·", "Last call it could authorize: 2026-11-20".to_string()),
            (
                GrantUsage::NotSeen { since },
                "✗",
                "No call it could authorize since 2026-08-27 — consider removing it".to_string(),
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
                "Usage unknown — grant the Log Analytics consent on the Observed Graph activity panel".to_string(),
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
            let (m, t) = usage_line(&usage);
            assert_eq!((m, t.as_str()), (mark, text.as_str()), "{usage:?}");
            for banned in ["used it", "scoped", "confined"] {
                assert!(!t.contains(banned), "{t:?} says {banned:?}");
            }
        }
    }
}
