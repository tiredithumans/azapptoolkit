//! SAML signing-certificate expiry dashboard.
//!
//! Tenant-wide view of every SAML app's token-signing certificate, soonest to
//! expire first. The sibling of the credential-expiry dashboard, and built on
//! the same [`AuditDashboard`] scaffold — but about a different failure: an
//! expired client secret stops one integration authenticating, while an expired
//! signing certificate stops **everyone** signing in to that application.
//!
//! Two columns carry the signal the raw expiry date doesn't. **Replacement**
//! says whether a certificate is already staged, which is the difference
//! between "click activate" and "start a rollover"; **Notify** says whether
//! anyone is on Entra's 60/30/7-day warnings, and a "nobody" there is how these
//! turn into outages — Entra seeds only the admin who added the app, whose
//! mailbox may be long gone.

use std::collections::HashMap;
use std::sync::Arc;

use azapptoolkit_core::audit::CredentialStatus;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::sso::{self, RolloverPhase, SsoCertificateRowDto};
use crate::components::audit_dashboard::AuditDashboard;
use crate::components::bulk_action_bar::{BulkAction, BulkActionBar};
use crate::components::ui::{Callout, CopyableId};
use crate::state::use_session;

const CRITICAL_DAYS: i64 = 7;
const WARNING_DAYS: i64 = 30;

#[component]
pub fn SsoCertificatesDashboard() -> impl IntoView {
    let session = use_session();
    // Service-principal ids, tenant-scoped (reset on switch by structure).
    let selection = session.tenant_ui.selected_sso_cert_ids;
    // Lifted out of the scaffold so the bulk bar can refetch after staging —
    // the board must not keep claiming "no replacement staged" for apps it just
    // staged one on.
    let reload = RwSignal::new(0_u32);
    let on_done = Callback::new(move |()| reload.update(|n| *n = n.wrapping_add(1)));

    // Row-derived state the bulk bar needs, owned HERE rather than read out of
    // the banner slot.
    //
    // The bar used to be rendered from the banner (the one place the scaffold
    // hands a caller its rows) — which quietly broke the thing the bar exists to
    // show: a successful run bumps `reload`, the dashboard refetches, the banner
    // re-renders, and the bar is REMOUNTED with a fresh (empty) summary. The
    // operator never saw what the run did, or which apps failed. Populating
    // these in `fetch` instead is a plain async write, outside any render, and
    // lets the bar sit outside the reloading subtree.
    let names: RwSignal<Arc<HashMap<String, String>>> = RwSignal::new(Arc::new(HashMap::new()));
    let queue_ids: RwSignal<Vec<String>> = RwSignal::new(Vec::new());

    // Bound to `let` rather than inline: the `view!` macro can't parse an
    // `async move {}` block as an attribute value.
    let fetch = move |tid: String| async move {
        let rows = sso::list_sso_certificate_expirations(&tid).await;
        if let Ok(rows) = &rows {
            names.set(Arc::new(
                rows.iter()
                    .map(|r| (r.service_principal_id.clone(), r.display_name.clone()))
                    .collect(),
            ));
            // The work queue: due within the warning window with nothing
            // prepared. Same predicate as the `unprepared` facet, so the
            // shortcut and the filter can't disagree about what needs doing.
            queue_ids.set(
                rows.iter()
                    .filter(|r| {
                        !r.has_staged_replacement
                            && matches!(r.days_to_expiry, Some(d) if d <= WARNING_DAYS)
                    })
                    .map(|r| r.service_principal_id.clone())
                    .collect(),
            );
        }
        rows
    };
    let export = move |data: Vec<SsoCertificateRowDto>, format: &'static str| async move {
        sso::save_sso_certificates_to_file(&data, format).await
    };

    view! {
        <div class="sso-cert-board">
            // Outside the dashboard on purpose: a successful run reloads it, and
            // anything rendered inside would be remounted — taking the run's
            // summary and failure list with it.
            {move || {
                let ids = queue_ids.get();
                let queue = ids.len();
                (queue > 0)
                    .then(|| {
                        view! {
                            <Button
                                class="sso-cert-queue-select"
                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                on_click=Box::new(move |_| {
                                    selection.set(ids.iter().cloned().collect())
                                })
                            >
                                {format!("Select the {queue} needing a replacement")}
                            </Button>
                        }
                    })
            }}
            <BulkActionBar
                selection=selection
                actions=Signal::derive(|| vec![BulkAction::StageSsoCertificate])
                on_done=on_done
                names=Signal::derive(move || names.get())
            />
            <AuditDashboard
            title="SSO certificate expiry"
            crumb="SAML token-signing certificates across the tenant"
            search_placeholder="Filter by app name or appId…"
            refresh_label="Refresh SSO certificate expiry"
            view_key="sso-certificates"
            noun="SAML app(s)"
            empty_message="No SAML applications match this filter."
            reload=reload
            facets=vec![
                ("all", "All"),
                ("expired", "Expired"),
                ("7", "≤ 7 days"),
                ("30", "≤ 30 days"),
                ("unprepared", "No replacement staged"),
            ]
            headers=vec![
                "",
                "Application",
                "Thumbprint",
                "Expires",
                "Status",
                "Replacement",
                "Notify",
                "",
            ]
            fetch=fetch
            export=export
            banner=move |all: &[SsoCertificateRowDto]| {
                let expired = all
                    .iter()
                    .filter(|r| matches!(r.status, CredentialStatus::Expired))
                    .count();
                // The actionable count is not "expiring" but "expiring with
                // nothing staged" — an app with a replacement ready is a click,
                // not a project.
                let unprepared = all
                    .iter()
                    .filter(|r| {
                        !r.has_staged_replacement
                            && matches!(r.days_to_expiry, Some(d) if d <= WARNING_DAYS)
                    })
                    .count();
                (expired + unprepared > 0)
                    .then(|| {
                        view! {
                            <Callout tone="warn">
                                {format!(
                                    "{expired} signing certificate(s) already expired; {unprepared} expire within {WARNING_DAYS} days with no replacement staged.",
                                )}
                            </Callout>
                        }
                            .into_any()
                    })
            }
            matches=move |r: &SsoCertificateRowDto, facet: &str, q: &str| {
                matches_facet(r, facet)
                    && (q.is_empty() || r.display_name.to_lowercase().contains(q)
                        || r.app_id.to_lowercase().contains(q))
            }
                row=move |r: SsoCertificateRowDto| sso_cert_row(session, selection, r).into_any()
            />
        </div>
    }
}

fn sso_cert_row(
    session: crate::state::Session,
    selection: RwSignal<std::collections::HashSet<String>>,
    r: SsoCertificateRowDto,
) -> impl IntoView {
    let (status_label, badge_class) = status_badge(r.status, r.days_to_expiry);
    // The payload carries RFC3339; the board only ever shows the date.
    let expires = r
        .end_date_time
        .as_deref()
        .and_then(|d| d.split('T').next())
        .unwrap_or("—")
        .to_string();
    let thumbprint = r
        .thumbprint
        .clone()
        .unwrap_or_else(|| "none nominated".to_string());
    let sp_id = r.service_principal_id.clone();

    // An expired *active* certificate with a valid replacement staged is the
    // case where Entra has already promoted on its own — call that out rather
    // than showing a bare "Staged", which reads as "nothing has happened yet".
    let (replacement_label, replacement_class) = match (r.has_staged_replacement, r.status) {
        (true, CredentialStatus::Expired) => ("Auto-promoted", "badge--warning"),
        (true, _) => ("Staged", "badge--ok"),
        (false, _) if matches!(r.phase, RolloverPhase::Unconfigured) => ("None", "badge--danger"),
        (false, _) => ("None", "badge--unknown"),
    };

    let checkbox_id = r.service_principal_id.clone();
    let checked = {
        let id = r.service_principal_id.clone();
        Signal::derive(move || selection.with(|s| s.contains(&id)))
    };
    let label = format!("Select {}", r.display_name);

    view! {
        <tr>
            <td>
                <input
                    type="checkbox"
                    class="row-select"
                    aria-label=label
                    prop:checked=checked
                    on:change=move |_| {
                        selection
                            .update(|s| {
                                if !s.remove(&checkbox_id) {
                                    s.insert(checkbox_id.clone());
                                }
                            })
                    }
                />
            </td>
            <td>
                <div class="permissions-cell__primary">{r.display_name.clone()}</div>
                <div class="permissions-cell__secondary">
                    <CopyableId value=r.app_id.clone() label="app id" />
                </div>
            </td>
            <td>
                <code class="sso-cert-thumbprint">{thumbprint}</code>
            </td>
            <td>{expires}</td>
            <td>
                <span class=format!("badge {badge_class}")>{status_label}</span>
            </td>
            <td>
                <span class=format!(
                    "badge {replacement_class}",
                )>{replacement_label.to_string()}</span>
            </td>
            <td>
                {if r.notification_emails_configured {
                    view! { <span class="badge badge--ok">"Set"</span> }
                } else {
                    view! { <span class="badge badge--warning">"Nobody"</span> }
                }}
            </td>
            <td>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    on_click=Box::new(move |_| {
                        session.open_enterprise_on_tab(sp_id.clone(), "sso")
                    })
                >
                    "Open"
                </Button>
            </td>
        </tr>
    }
}

fn matches_facet(r: &SsoCertificateRowDto, facet: &str) -> bool {
    match facet {
        "all" => true,
        "expired" => matches!(r.status, CredentialStatus::Expired),
        "7" => matches!(r.days_to_expiry, Some(d) if (0..=CRITICAL_DAYS).contains(&d)),
        "30" => matches!(r.days_to_expiry, Some(d) if (0..=WARNING_DAYS).contains(&d)),
        // The work queue: due within the warning window and nothing prepared.
        // Deliberately includes already-expired rows — those are the most
        // unprepared of all.
        "unprepared" => {
            !r.has_staged_replacement && matches!(r.days_to_expiry, Some(d) if d <= WARNING_DAYS)
        }
        _ => true,
    }
}

/// Maps a signing certificate's status + days-left to a label and badge class.
/// Same `badge--*` classes and thresholds as the credential-expiry board, so the
/// two read identically at a glance.
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
        // Never "Active": an expiry we couldn't read is not evidence of health.
        CredentialStatus::Unknown => ("Unknown".to_string(), "badge--unknown"),
    }
}
