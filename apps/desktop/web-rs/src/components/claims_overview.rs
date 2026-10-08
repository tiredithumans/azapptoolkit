//! Read-only "Attributes & claims" overview for a SAML app, laid out like the
//! Entra admin center's page: where the claims come from, the required Name ID
//! claim, then every additional claim. The backend reads whichever policy is in
//! effect (`commands::sso::claims_view`); this only renders it.

use leptos::prelude::*;
use thaw::Body1;

use crate::bindings::sso::{ClaimRowDto, ClaimsSource, ClaimsViewDto};
use crate::components::ui::{Callout, DataTable};

/// One-line statement of where the claims below come from.
fn source_line(view: &ClaimsViewDto) -> String {
    let mut line = source_only(view);
    if view.portal_policy_unreadable {
        line.push_str(
            " This cloud can't read claims configured in the Entra admin center, so any set there aren't shown.",
        );
    }
    line
}

fn source_only(view: &ClaimsViewDto) -> String {
    match view.source {
        // Without the admin center read, "not customized" is a claim the view
        // can't make: only that no mapping policy is assigned.
        ClaimsSource::Default if view.portal_policy_unreadable => {
            "No claims mapping policy is assigned, so these are Microsoft Entra's default claims."
                .into()
        }
        ClaimsSource::Default => "Not customized: Microsoft Entra's default claims.".into(),
        ClaimsSource::PortalPolicy => "Configured in the Microsoft Entra admin center.".into(),
        ClaimsSource::MappingPolicy => {
            let name = view
                .mapping_policy_name
                .clone()
                .unwrap_or_else(|| "unnamed".into());
            let mut line = format!(
                "Set by the claims mapping policy “{name}”. While it is assigned, the admin center can't edit these claims."
            );
            if view.portal_policy_overridden {
                line.push_str(" It overrides the claims configured in the admin center.");
            }
            line
        }
    }
}

fn claim_row(row: ClaimRowDto) -> AnyView {
    view! {
        <tr>
            <td class="permission-cell mono">{row.name}</td>
            <td class="cell-mid">{row.token_types.join(", ")}</td>
            <td class="permission-cell">
                <div class="mono">{row.value}</div>
                {row.detail.map(|d| view! { <div class="muted">{d}</div> })}
            </td>
        </tr>
    }
    .into_any()
}

#[component]
pub fn ClaimsOverview(view: ClaimsViewDto) -> impl IntoView {
    let source = source_line(&view);
    view! {
        <div class="claims-overview">
            <Callout tone="info">{source}</Callout>
            <strong>"Required claim"</strong>
            <DataTable
                headers=vec!["Claim name", "Type", "Value"]
                rows=vec![view.required]
                empty_message=""
                row=claim_row
            />
            <strong>"Additional claims"</strong>
            <DataTable
                headers=vec!["Claim name", "Type", "Value"]
                rows=view.additional
                empty_message="No additional claims."
                row=claim_row
            />
            <Body1 class="hint">
                "Read from the claims policy that is in effect, as the admin center shows it."
            </Body1>
        </div>
    }
}
