//! Credential-expiry dashboard.
//!
//! Tenant-wide view of every app-registration client secret and certificate,
//! sorted soonest-to-expire first, with status filters, an "expiring soon"
//! banner, CSV export (OS save dialog), and a one-click deep-link into each
//! app's Credentials tab to rotate. The list is read through the backend's
//! `{tenant}|credential_expirations` cache (`CacheKind::Lists`), which
//! `invalidate_app_credentials` (rotate/remove) and `invalidate_app_lists`
//! (create/delete) bust on `Ok`, so a just-rotated credential is never shown as
//! still-expiring. The scaffold
//! (fetch, filters, export, keyboard-navigable table) lives in
//! [`AuditDashboard`]; this view supplies the credential-specific bits.

use azapptoolkit_core::audit::EXPIRY_WARNING_DAYS as WARNING_DAYS;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::credentials::{self, CredentialHealthCounts, CredentialRowDto};
use crate::components::audit_dashboard::AuditDashboard;
use crate::components::ui::{Badge, Callout, CopyableId};
use crate::state::use_session;
use crate::util::{
    EXPIRY_CRITICAL_DAYS as CRITICAL_DAYS, contains_ignore_case, count_noun,
    credential_status_badge, fmt_date,
};

#[component]
pub fn CredentialsDashboard() -> impl IntoView {
    let session = use_session();

    // Bound to `let` rather than inline: the `view!` macro can't parse an
    // `async move {}` block as an attribute value.
    let fetch =
        move |tid: String| async move { credentials::list_credential_expirations(&tid).await };
    let export = move |data: Vec<CredentialRowDto>, format: &'static str| async move {
        credentials::save_credentials_to_file(&data, format).await
    };

    view! {
        <AuditDashboard
            title="Credential expiry"
            crumb="Secrets & certificates across the tenant"
            search_placeholder="Filter by app name or appId…"
            refresh_label="Refresh credential expiry"
            view_key="credentials"
            noun="credentials"
            empty_message="No credentials match this filter."
            facets=vec![
                ("all", "All"),
                ("expired", "Expired"),
                ("7", "≤ 7 days"),
                ("30", "≤ 30 days"),
            ]
            // Lifted to the session so the Home Credential Health metrics can
            // deep-link straight to e.g. the Expired or ≤7-day rows.
            facet=session.tenant_ui.credentials_facet
            headers=vec!["Application", "Type", "Credential", "Expires", "Status", ""]
            fetch=fetch
            export=export
            banner=move |all: &[CredentialRowDto]| {
                // The same predicates the chips and the Home counts use.
                let counts = CredentialHealthCounts::of(all);
                let (expired, soon) = (counts.expired, counts.within_critical);
                (expired + soon > 0)
                    .then(|| {
                        view! {
                            <Callout tone="warn">
                                {format!(
                                    "{} already expired; {soon} expire within {CRITICAL_DAYS} days.",
                                    count_noun(expired, "credential", "credentials"),
                                )}
                            </Callout>
                        }
                            .into_any()
                    })
            }
            matches=move |r: &CredentialRowDto, facet: &str, q: &str| {
                // `contains_ignore_case` is true for an empty query, and
                // allocates nothing per row for an ASCII name.
                matches_facet(r, facet)
                    && (contains_ignore_case(&r.app_display_name, q)
                        || contains_ignore_case(&r.app_id, q))
            }
            row=move |r: CredentialRowDto| credential_row(session, r).into_any()
        />
    }
}

fn credential_row(session: crate::state::Session, r: CredentialRowDto) -> impl IntoView {
    // "No expiry": a credential's Unknown is one with no end date.
    let (status_label, status_tone) =
        credential_status_badge(r.status, r.days_to_expiry, "No expiry");
    let expires = fmt_date(r.end_date_time);
    let object_id = r.app_object_id.clone();
    view! {
        <tr>
            <td>
                <div class="permissions-cell__primary">{r.app_display_name.clone()}</div>
                <div class="permissions-cell__secondary">
                    <CopyableId value=r.app_id.clone() label="app id" />
                </div>
            </td>
            <td>{r.kind.as_str()}</td>
            <td>{r.credential_name.clone()}</td>
            <td>{expires}</td>
            <td>
                <Badge label=status_label tone=status_tone />
            </td>
            <td class="cell-mid">
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

/// The facet predicates are the dto's own, the ones Home's Credential Health
/// counts are reduced with in the backend, so a count and the rows its chip
/// opens cannot disagree.
fn matches_facet(r: &CredentialRowDto, facet: &str) -> bool {
    match facet {
        "all" => true,
        "expired" => r.is_expired(),
        "7" => r.expires_within(CRITICAL_DAYS),
        "30" => r.expires_within(WARNING_DAYS),
        _ => true,
    }
}
