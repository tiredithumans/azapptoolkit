//! Conditional Access tab — which CA policies apply to this app, and what they
//! enforce. Read-only; degrades gracefully when Policy.Read.All is un-consented
//! or the tenant lacks an Entra ID P1/P2 license.

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::bindings::applications::ApplicationDetail;
use crate::bindings::conditional_access::{self, ConditionalAccessPolicyDto};
use crate::components::requires_role::RequiresRole;
use crate::components::ui::DataTable;
use crate::state::use_session;

use crate::util::no_tenant;

/// App-registration Conditional Access tab (keys on the app's appId).
#[component]
pub fn ConditionalAccessTab(#[prop(into)] detail: Signal<Arc<ApplicationDetail>>) -> impl IntoView {
    let app_id = Signal::derive(move || detail.with(|d| d.application.app_id.clone()));
    view! { <ConditionalAccessPanel app_id=app_id /> }
}

/// Core CA panel for an appId. Shared by the app-registration and
/// enterprise-application detail panes.
#[component]
pub fn ConditionalAccessPanel(#[prop(into)] app_id: Signal<String>) -> impl IntoView {
    let session = use_session();
    let reload = RwSignal::new(0_u32);

    let policies = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let app_id = app_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            conditional_access::list_conditional_access_for_app(&t.tenant_id, &app_id).await
        }
    });

    view! {
        <div class="conditional-access-tab">
            <header class="row-between">
                <div class="row">
                    <strong>"Conditional Access"</strong>
                    <RequiresRole capability_key="conditional_access" />
                </div>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| reload.update(|n| *n += 1))
                >
                    "Refresh"
                </Button>
            </header>
            <Body1>
                "Conditional Access policies that target this application (directly, or via an \"All apps\" / grouping include). Requires Policy.Read.All consent and an Entra ID P1/P2 license."
            </Body1>

            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" /> }
            }>
                {move || Suspend::new(async move {
                    match policies.await {
                        Ok(list) => ca_table(list).into_any(),
                        Err(e) if e.code == "ca_unavailable" => {
                            view! { <div class="alert alert--warn">{e.message}</div> }.into_any()
                        }
                        Err(e) => view! { <Body1 class="form-error">{e.message}</Body1> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

fn ca_table(list: Vec<ConditionalAccessPolicyDto>) -> impl IntoView {
    view! {
        <DataTable
            headers=vec!["Policy", "State", "Applies", "Controls"]
            rows=list
            empty_message="No Conditional Access policies target this app."
            row=|p| ca_row(p).into_any()
        />
    }
}

fn ca_row(p: ConditionalAccessPolicyDto) -> impl IntoView {
    let (state_label, state_class) = state_badge(&p.state);
    let applies = applies_label(&p.applies_reason);
    let controls = if p.grant_controls.is_empty() {
        "—".to_string()
    } else {
        let joined = p
            .grant_controls
            .iter()
            .map(|c| control_label(c))
            .collect::<Vec<_>>()
            .join(if p.grant_operator.as_deref() == Some("OR") {
                " or "
            } else {
                " and "
            });
        joined
    };
    view! {
        <tr>
            <td>{p.display_name}</td>
            <td>
                <span class=state_class>{state_label}</span>
            </td>
            <td>{applies}</td>
            <td>{controls}</td>
        </tr>
    }
}

fn state_badge(state: &str) -> (&'static str, &'static str) {
    match state {
        "enabled" => ("Enabled", "badge badge--ok"),
        "enabledForReportingButNotEnforced" => ("Report-only", "badge badge--warning"),
        "disabled" => ("Disabled", "badge"),
        _ => ("Unknown", "badge"),
    }
}

fn applies_label(reason: &str) -> &'static str {
    match reason {
        "appId" => "This app",
        "all" => "All apps",
        "office365" => "Office 365 (may apply)",
        "adminPortals" => "Admin portals (may apply)",
        "filter" => "App filter (may apply)",
        "filterExclude" => "App filter (applies unless excluded)",
        _ => "May apply",
    }
}

/// Friendly label for a known grant control, or the raw Graph name for any
/// control we don't have a translation for (so it still renders meaningfully).
fn control_label(control: &str) -> String {
    match control {
        "mfa" => "MFA",
        "block" => "Block access",
        "compliantDevice" => "Compliant device",
        "domainJoinedDevice" => "Hybrid-joined device",
        "approvedApplication" => "Approved app",
        "compliantApplication" => "App protection policy",
        "passwordChange" => "Password change",
        other => return other.to_string(),
    }
    .to_string()
}
