//! Conditional Access tab — which CA policies apply to this app, and what they
//! enforce. Read-only; degrades gracefully when Policy.Read.All is un-consented
//! or the tenant lacks an Entra ID P1/P2 license.

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::applications::ApplicationDetail;
use crate::bindings::conditional_access::{self, ConditionalAccessPolicyDto};
use crate::components::requires_role::RequiresRole;
use crate::components::ui::{Badge, BadgeTone, Callout, DataTable, DetailLoadError, SkeletonList};
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
                "Conditional Access policies that target this application — as a resource (directly, or via an \"All apps\" / grouping include) or as a client (its service principal / workload-identity clients). Requires Policy.Read.All consent and an Entra ID P1/P2 license."
            </Body1>

            <Suspense fallback=move || view! { <SkeletonList rows=4 /> }>
                {move || Suspend::new(async move {
                    match policies.await {
                        Ok(list) => ca_table(list).into_any(),
                        Err(e) if e.code == "ca_unavailable" => {
                            view! { <Callout tone="warn">{e.message}</Callout> }.into_any()
                        }
                        // A real failure (429, network, …) — offer a way out.
                        Err(e) => {
                            view! {
                                <DetailLoadError
                                    error=e
                                    on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                />
                            }
                                .into_any()
                        }
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
    let (state_label, state_tone) = state_badge(&p.state);
    let applies = applies_label(&p.applies_reason, p.workload_clients);
    let controls = if p.grant_controls.is_empty() {
        "—".to_string()
    } else {
        p.grant_controls
            .iter()
            .map(|c| control_label(c))
            .collect::<Vec<_>>()
            .join(if p.grant_operator.as_deref() == Some("OR") {
                " or "
            } else {
                " and "
            })
    };
    view! {
        <tr>
            <td>{p.display_name}</td>
            <td>
                <Badge label=state_label tone=state_tone />
            </td>
            <td>{applies}</td>
            <td>{controls}</td>
        </tr>
    }
}

fn state_badge(state: &str) -> (&'static str, BadgeTone) {
    match state {
        "enabled" => ("Enabled", BadgeTone::Ok),
        "enabledForReportingButNotEnforced" => ("Report-only", BadgeTone::Warning),
        "disabled" => ("Disabled", BadgeTone::Neutral),
        _ => ("Unknown", BadgeTone::Neutral),
    }
}

/// Renders the `Applies` cell. Resource-axis codes say which *resource* set
/// the policy targets; a set `workload_clients` flag narrows it to policies
/// whose client axis names this app's service principal (or workload
/// identities generally), so the suffix keeps "All apps" honest when only
/// workload clients are gated. The `sp`/`allWorkload`/`clientFilter*` codes
/// are client-only policies — they gate this app signing in *elsewhere*
/// with its credentials, which the resource-only view used to drop.
fn applies_label(reason: &str, workload_clients: bool) -> String {
    let base = match reason {
        "appId" => "This app",
        "all" => "All apps",
        "office365" => "Office 365 (may apply)",
        "adminPortals" => "Admin portals (may apply)",
        "filter" => "App filter (may apply)",
        "filterExclude" => "App filter (applies unless excluded)",
        "sp" => "This app's service principal (as a client)",
        "allWorkload" => "All workload identities (as clients)",
        "clientFilter" => "Client filter (may apply)",
        "clientFilterExclude" => "Client filter (applies unless excluded)",
        _ => "May apply",
    };
    let narrowed = matches!(
        reason,
        "appId" | "all" | "office365" | "adminPortals" | "filter" | "filterExclude"
    ) && workload_clients;
    if narrowed {
        format!("{base} — workload-identity clients only")
    } else {
        base.to_string()
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
