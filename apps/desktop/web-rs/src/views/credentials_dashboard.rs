//! Credential-expiry dashboard.
//!
//! Tenant-wide view of every app-registration client secret and certificate,
//! sorted soonest-to-expire first, with status filters, an "expiring soon"
//! banner, CSV export (OS save dialog), and a one-click deep-link into each
//! app's Credentials tab to rotate. Data is fetched fresh on open (no cache) so
//! a just-rotated credential is never shown as still-expiring. The scaffold
//! (fetch, filters, export, keyboard-navigable table) lives in
//! [`AuditDashboard`]; this view supplies the credential-specific bits.

use azapptoolkit_core::audit::CredentialStatus;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::credentials::{self, CredentialRowDto};
use crate::components::audit_dashboard::AuditDashboard;
use crate::state::use_session;

const CRITICAL_DAYS: i64 = 7;
const WARNING_DAYS: i64 = 30;

#[component]
pub fn CredentialsDashboard() -> impl IntoView {
    let session = use_session();

    // Bound to `let` rather than inline: the `view!` macro can't parse an
    // `async move {}` block as an attribute value.
    let fetch =
        move |tid: String| async move { credentials::list_credential_expirations(&tid).await };
    let export = move |data: Vec<CredentialRowDto>| async move {
        credentials::save_credentials_to_file(&data, "csv").await
    };

    view! {
        <AuditDashboard
            title="Credential expiry"
            crumb="Secrets & certificates across the tenant"
            search_placeholder="Filter by app name or appId…"
            view_key="credentials"
            noun="credential(s)"
            empty_message="No credentials match this filter."
            facets=vec![
                ("all", "All"),
                ("expired", "Expired"),
                ("7", "≤ 7 days"),
                ("30", "≤ 30 days"),
            ]
            // Lifted to the session so the Home Credential Health metrics can
            // deep-link straight to e.g. the Expired or ≤7-day rows.
            facet=session.credentials_facet
            headers=vec!["Application", "Type", "Credential", "Expires", "Status", ""]
            fetch=fetch
            export=export
            banner=move |all: &[CredentialRowDto]| {
                let expired = all
                    .iter()
                    .filter(|r| matches!(r.status, CredentialStatus::Expired))
                    .count();
                let soon = all
                    .iter()
                    .filter(|r| {
                        matches!(r.days_to_expiry, Some(d) if (0..=CRITICAL_DAYS).contains(&d))
                    })
                    .count();
                (expired + soon > 0)
                    .then(|| {
                        view! {
                            <div class="alert alert--warn">
                                {format!(
                                    "{expired} credential(s) already expired; {soon} expire within {CRITICAL_DAYS} days.",
                                )}
                            </div>
                        }
                            .into_any()
                    })
            }
            matches=move |r: &CredentialRowDto, facet: &str, q: &str| {
                matches_facet(r, facet)
                    && (q.is_empty() || r.app_display_name.to_lowercase().contains(q)
                        || r.app_id.to_lowercase().contains(q))
            }
            row=move |r: CredentialRowDto| credential_row(session, r).into_any()
        />
    }
}

fn credential_row(session: crate::state::Session, r: CredentialRowDto) -> impl IntoView {
    let (status_label, badge_class) = status_badge(r.status, r.days_to_expiry);
    let expires = r
        .end_date_time
        .map(|d| d.date_naive().to_string())
        .unwrap_or_else(|| "—".into());
    let object_id = r.app_object_id.clone();
    view! {
        <tr>
            <td>
                <div class="permissions-cell__primary">{r.app_display_name.clone()}</div>
                <div class="permissions-cell__secondary mono">{r.app_id.clone()}</div>
            </td>
            <td>{r.kind.as_str()}</td>
            <td>{r.credential_name.clone()}</td>
            <td>{expires}</td>
            <td>
                <span class=format!("badge {badge_class}")>{status_label}</span>
            </td>
            <td>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    on_click=Box::new(move |_| {
                        session.open_app_on_tab(object_id.clone(), "credentials")
                    })
                >
                    "Open"
                </Button>
            </td>
        </tr>
    }
}

fn matches_facet(r: &CredentialRowDto, facet: &str) -> bool {
    match facet {
        "all" => true,
        "expired" => matches!(r.status, CredentialStatus::Expired),
        "7" => matches!(r.days_to_expiry, Some(d) if (0..=CRITICAL_DAYS).contains(&d)),
        "30" => matches!(r.days_to_expiry, Some(d) if (0..=WARNING_DAYS).contains(&d)),
        _ => true,
    }
}

/// Maps a credential's status + days-left to a label and badge class. Reuses
/// the same `badge--*` classes as the per-app Credentials tab.
fn status_badge(status: CredentialStatus, days: Option<i64>) -> (String, &'static str) {
    match status {
        CredentialStatus::Expired => ("Expired".to_string(), "badge--danger"),
        CredentialStatus::ExpiringSoon => {
            let cls = match days {
                Some(d) if d <= CRITICAL_DAYS => "badge--danger",
                _ => "badge--warning",
            };
            let label = days
                .map(|d| format!("{d}d left"))
                .unwrap_or_else(|| "Expiring".to_string());
            (label, cls)
        }
        CredentialStatus::Active => {
            let label = days
                .map(|d| format!("{d}d left"))
                .unwrap_or_else(|| "Active".to_string());
            (label, "badge--ok")
        }
        CredentialStatus::Unknown => ("No expiry".to_string(), "badge--unknown"),
    }
}
