//! Consent / OAuth2 grant audit.
//!
//! Tenant-wide view of every delegated (OAuth2) permission grant, risk-classified
//! and sorted risky-first, with filters, a high-risk banner, CSV export, and a
//! deep-link from each grant's client into its Enterprise Application detail
//! (where the grant can be revoked). Fetched fresh on open. The scaffold lives
//! in [`AuditDashboard`]; this view supplies the grant-specific bits.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::consent::{self, OAuth2GrantDto};
use crate::components::audit_dashboard::AuditDashboard;
use crate::state::use_session;

#[component]
pub fn ConsentGrantsView() -> impl IntoView {
    let session = use_session();

    // Bound to `let` rather than inline: the `view!` macro can't parse an
    // `async move {}` block as an attribute value.
    let fetch = move |tid: String| async move { consent::list_oauth2_grants_audit(&tid).await };
    let export = move |data: Vec<OAuth2GrantDto>| async move {
        consent::save_oauth2_grants_to_file(&data, "csv").await
    };

    view! {
        <AuditDashboard
            title="Consent grants"
            crumb="Delegated (OAuth2) permission grants"
            search_placeholder="Filter by client name…"
            view_key="consent"
            noun="grant(s)"
            empty_message="No grants match this filter."
            facets=vec![("all", "All"), ("risky", "High-risk"), ("admin", "Admin consent")]
            headers=vec!["Client", "Resource", "Consent", "Scopes", ""]
            fetch=fetch
            export=export
            banner=move |all: &[OAuth2GrantDto]| {
                let risky = all.iter().filter(|r| !r.risky_scopes.is_empty()).count();
                let admin_risky = all
                    .iter()
                    .filter(|r| !r.risky_scopes.is_empty() && r.consent_type == "AllPrincipals")
                    .count();
                (risky > 0)
                    .then(|| {
                        view! {
                            <div class="alert alert--warn">
                                {format!(
                                    "{risky} grant(s) include high-risk scopes ({admin_risky} admin-consented for all users).",
                                )}
                            </div>
                        }
                            .into_any()
                    })
            }
            matches=move |r: &OAuth2GrantDto, facet: &str, q: &str| {
                matches_facet(r, facet)
                    && (q.is_empty() || r.client_display_name.to_lowercase().contains(q))
            }
            row=move |r: OAuth2GrantDto| grant_row(session, r).into_any()
        />
    }
}

fn grant_row(session: crate::state::Session, r: OAuth2GrantDto) -> impl IntoView {
    let (consent_label, consent_class) = if r.consent_type == "AllPrincipals" {
        ("Admin (all users)", "badge badge--warning")
    } else {
        ("User", "badge")
    };
    let risky: std::collections::HashSet<String> = r.risky_scopes.iter().cloned().collect();
    let scope_chips = r
        .scopes
        .iter()
        .map(|s| {
            let cls = if risky.contains(s) {
                "badge badge--danger"
            } else {
                "badge"
            };
            view! { <span class=cls>{s.clone()}</span> }
        })
        .collect_view();
    let client_app_id = r.client_app_id.clone().unwrap_or_default();
    let sp_id = r.client_sp_id.clone();
    view! {
        <tr>
            <td>
                <div class="permissions-cell__primary">{r.client_display_name.clone()}</div>
                <div class="permissions-cell__secondary mono">{client_app_id}</div>
            </td>
            <td>{r.resource_display_name.clone()}</td>
            <td>
                <span class=consent_class>{consent_label}</span>
            </td>
            <td>
                <div class="scope-chips">{scope_chips}</div>
            </td>
            <td>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    on_click=Box::new(move |_| {
                        // Land on Permissions, where this consent can be revoked.
                        session.open_enterprise_on_tab(sp_id.clone(), "permissions");
                    })
                >
                    "Open"
                </Button>
            </td>
        </tr>
    }
}

fn matches_facet(r: &OAuth2GrantDto, facet: &str) -> bool {
    match facet {
        "all" => true,
        "risky" => !r.risky_scopes.is_empty(),
        "admin" => r.consent_type == "AllPrincipals",
        _ => true,
    }
}
