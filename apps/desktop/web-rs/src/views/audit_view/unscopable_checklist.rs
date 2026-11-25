//! The "No built-in scoping" finding's per-row checklist (audit Rule 24).
//!
//! One line per held permission Microsoft offers no way to narrow, with its
//! Conditional Access network-lock verdict, then the row's other safeguards.
//! Wording rule: a safeguard limits where a stolen credential works, never
//! what the app can read — no line says "scoped", "confined" or "limited to".

use azapptoolkit_core::audit::{AuditItem, AuditPrincipalKind, issue};
use azapptoolkit_core::conditional_access::{LockIneligible, NetworkLock};
use leptos::prelude::*;

use crate::components::ui::Badge;

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
            "unknown — couldn't read Conditional Access (needs Security Reader or similar)"
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
                    {mechanism.map(|m| view! { <div class="muted">{m}</div> })}
                </li>
            }
        })
        .collect_view();
    let app_lines = is_app.then(|| {
        let (cm, ct) = credentials_line(&item);
        let (om, ot) = owners_line(&item);
        view! {
            <li>{format!("{cm} Credentials: {ct}")}</li>
            <li>{format!("{om} Owners: {ot}")}</li>
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
                "unknown — couldn't read Conditional Access (needs Security Reader or similar)",
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
}
