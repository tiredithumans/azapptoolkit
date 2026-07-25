//! Application-permission grant audit.
//!
//! Tenant-wide view of every **application** permission (`appRoleAssignment`)
//! apps hold on the high-value resource APIs — Microsoft Graph, Exchange,
//! SharePoint — risk-classified, with filters, a high-risk banner, CSV/JSON
//! export, and a deep-link from each holder into its Enterprise Application
//! detail (where the grant can be revoked). Fetched fresh on open.
//!
//! The delegated counterpart is [`super::consent_grants_view`]: that one covers
//! consent granted *on behalf of a signed-in user*, this one covers permissions
//! an app holds *as itself*, with no user in the loop — the grants that keep
//! working after every user is gone, which is why they carry the higher risk.
//! The shared scaffold lives in [`AuditDashboard`].

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::consent::{self, AppPermissionGrantDto};
use crate::components::audit_dashboard::AuditDashboard;
use crate::components::ui::Callout;
use crate::state::use_session;
use crate::util::contains_ignore_case;

#[component]
pub fn AppPermissionGrantsView() -> impl IntoView {
    let session = use_session();

    // Bound to `let` rather than inline: the `view!` macro can't parse an
    // `async move {}` block as an attribute value.
    let fetch = move |tid: String| async move { consent::list_app_permission_grants(&tid).await };
    let export = move |data: Vec<AppPermissionGrantDto>, format: &'static str| async move {
        consent::save_app_permission_grants_to_file(&data, format).await
    };

    view! {
        <AuditDashboard
            title="Application permissions"
            crumb="App-only permissions held across the tenant"
            search_placeholder="Filter by app, permission, or resource…"
            refresh_label="Refresh application permissions"
            view_key="app-permissions"
            noun="permission(s)"
            empty_message="No application permissions match this filter."
            facets=vec![("all", "All"), ("high", "High-risk"), ("medium", "Medium-risk")]
            headers=vec!["Application", "Permission", "Resource", "Risk", ""]
            fetch=fetch
            export=export
            banner=move |all: &[AppPermissionGrantDto]| {
                let high = all.iter().filter(|r| r.risk == "high").count();
                let apps: std::collections::HashSet<&str> = all
                    .iter()
                    .filter(|r| r.risk == "high")
                    .map(|r| r.client_sp_id.as_str())
                    .collect();
                (high > 0)
                    .then(|| {
                        view! {
                            <Callout tone="warn">
                                {format!(
                                    "{high} high-risk application permission(s) held by {} app(s). These grant tenant-wide access with no signed-in user.",
                                    apps.len(),
                                )}
                            </Callout>
                        }
                            .into_any()
                    })
            }
            matches=move |r: &AppPermissionGrantDto, facet: &str, q: &str| {
                matches_facet(r, facet)
                    && (q.is_empty() || matches_query(r, q))
            }
            row=move |r: AppPermissionGrantDto| grant_row(session, r).into_any()
        />
    }
}

fn grant_row(session: crate::state::Session, r: AppPermissionGrantDto) -> impl IntoView {
    let risk_class = match r.risk.as_str() {
        "high" => "badge badge--danger",
        "medium" => "badge badge--warning",
        _ => "badge",
    };
    let risk_label = match r.risk.as_str() {
        "high" => "High",
        "medium" => "Medium",
        _ => "Low",
    };
    let sp_id = r.client_sp_id.clone();
    view! {
        <tr>
            <td>
                <div class="permissions-cell__primary">{r.client_display_name.clone()}</div>
            </td>
            <td>
                <span class="mono">{r.permission.clone()}</span>
            </td>
            <td>{r.resource_display_name.clone()}</td>
            <td>
                <span class=risk_class>{risk_label}</span>
            </td>
            <td>
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
        "medium" => r.risk == "medium",
        _ => true,
    }
}

/// Search spans all three identifying columns — an operator hunting a grant
/// knows it by the app, the permission value, or the resource API, and which
/// one they remember varies by task.
fn matches_query(r: &AppPermissionGrantDto, q: &str) -> bool {
    contains_ignore_case(&r.client_display_name, q)
        || contains_ignore_case(&r.permission, q)
        || contains_ignore_case(&r.resource_display_name, q)
}
