//! Application-permission audit.
//!
//! Tenant-wide view of the **application** permissions apps hold on the
//! high-value resource APIs (Microsoft Graph, Exchange, SharePoint) — the
//! app-only access that runs without a user and is the most dangerous to
//! over-grant. Risk-classified, filterable, CSV-exportable, with a deep-link
//! into each holder's Enterprise Application detail. Complements the delegated
//! Consent grants view. The scaffold lives in [`AuditDashboard`]; this view
//! supplies the permission-specific bits.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::consent::{self, AppPermissionGrantDto};
use crate::components::audit_dashboard::AuditDashboard;
use crate::state::use_session;

#[component]
pub fn AppPermissionsView() -> impl IntoView {
    let session = use_session();

    // Bound to `let` rather than inline: the `view!` macro can't parse an
    // `async move {}` block as an attribute value.
    let fetch = move |tid: String| async move { consent::list_app_permission_grants(&tid).await };
    let export = move |data: Vec<AppPermissionGrantDto>| async move {
        consent::save_app_permission_grants_to_file(&data, "csv").await
    };

    view! {
        <AuditDashboard
            title="App permissions"
            crumb="Application permissions held across Graph, Exchange & SharePoint"
            search_placeholder="Filter by application name…"
            view_key="app_permissions"
            noun="grant(s)"
            empty_message="No application permissions match this filter."
            facets=vec![("all", "All"), ("high", "High-risk")]
            headers=vec!["Application", "Permission", "Resource", "Risk"]
            fetch=fetch
            export=export
            banner=move |all: &[AppPermissionGrantDto]| {
                let high = all.iter().filter(|r| r.risk == "high").count();
                (high > 0)
                    .then(|| {
                        view! {
                            <div class="alert alert--warn">
                                {format!(
                                    "{high} high-risk application permission grant(s) — these run app-only, without a user.",
                                )}
                            </div>
                        }
                            .into_any()
                    })
            }
            matches=move |r: &AppPermissionGrantDto, facet: &str, q: &str| {
                matches_facet(r, facet)
                    && (q.is_empty() || r.client_display_name.to_lowercase().contains(q))
            }
            row=move |r: AppPermissionGrantDto| grant_row(session, r).into_any()
        />
    }
}

fn grant_row(session: crate::state::Session, r: AppPermissionGrantDto) -> impl IntoView {
    let (risk_label, risk_class) = match r.risk.as_str() {
        "high" => ("High", "badge badge--danger"),
        "medium" => ("Medium", "badge badge--warning"),
        _ => ("Low", "badge"),
    };
    let sp_id = r.client_sp_id.clone();
    view! {
        <tr>
            <td>{r.client_display_name.clone()}</td>
            <td class="mono">{r.permission.clone()}</td>
            <td>{r.resource_display_name.clone()}</td>
            <td>
                <span class=risk_class>{risk_label}</span>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    on_click=Box::new(move |_| {
                        // Land on Permissions, where this grant can be revoked.
                        session.open_enterprise_on_tab(sp_id.clone(), "permissions");
                    })
                >
                    "Open"
                </Button>
            </td>
        </tr>
    }
}

fn matches_facet(r: &AppPermissionGrantDto, facet: &str) -> bool {
    match facet {
        "all" => true,
        "high" => r.risk == "high",
        _ => true,
    }
}
