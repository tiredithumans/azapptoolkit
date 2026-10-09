//! Consent / OAuth2 grant audit.
//!
//! Tenant-wide view of every delegated (OAuth2) permission grant, risk-classified
//! and sorted risky-first, with filters, a high-risk banner, CSV export, and a
//! deep-link from each grant's client into its Enterprise Application detail
//! (where the grant can be revoked). Fetched fresh on open. The scaffold lives
//! in [`AuditDashboard`]; this view supplies the grant-specific bits.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::consent::{self, OAuth2GrantDto, TenantConsentPostureDto};
use crate::components::audit_dashboard::AuditDashboard;
use crate::components::ui::{Badge, BadgeTone, Callout, CopyableId};
use crate::state::use_session;
use crate::util::{contains_ignore_case, count_noun};

#[component]
pub fn ConsentGrantsView() -> impl IntoView {
    let session = use_session();

    // Bound to `let` rather than inline: the `view!` macro can't parse an
    // `async move {}` block as an attribute value.
    let fetch = move |tid: String| async move { consent::list_oauth2_grants_audit(&tid).await };
    let export = move |data: Vec<OAuth2GrantDto>, format: &'static str| async move {
        consent::save_oauth2_grants_to_file(&data, format).await
    };

    // Tenant consent posture (F274): the config that *produced* the grants
    // below. Shares the `reload` counter with the row fetch — Refresh pulls
    // both — and is deliberately independent of it: a failed posture read or an
    // `available: false` answer renders nothing (unknown is never a verdict).
    let reload = RwSignal::new(0_u32);
    let posture = RwSignal::new(TenantConsentPostureDto::default());
    Effect::new(move |_| {
        let Some(t) = session.active_tenant.get() else {
            return;
        };
        let _ = reload.get();
        posture.set(TenantConsentPostureDto::default());
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            if let Ok(p) = consent::get_tenant_consent_posture(&tenant_id).await {
                let still_active = session
                    .active_tenant
                    .get_untracked()
                    .map(|t| t.tenant_id == tenant_id)
                    .unwrap_or(false);
                if still_active {
                    posture.set(p);
                }
            }
        });
    });
    let header_note = Signal::derive(move || {
        let p = posture.get();
        let names = p.default_user_role_consent_policies.unwrap_or_default();
        if names.is_empty() {
            return None;
        }
        let mut text = format!(
            "Users in this tenant can approve apps' access to their own data without an admin \
             (consent policy: {}). Any 'User' grant below may have been granted this way, not by \
             an admin.",
            names.join(", ")
        );
        if p.risky_app_user_consent == Some(true) {
            text.push_str(" Users can also approve apps Microsoft flags as risky.");
        }
        Some(("warn".to_string(), text))
    });

    view! {
        <AuditDashboard
            title="Consent grants"
            crumb="Delegated (OAuth2) permission grants"
            search_placeholder="Filter by client name…"
            refresh_label="Refresh consent grants"
            view_key="consent"
            noun="grants"
            empty_message="No grants match this filter."
            reload=reload
            header_note=header_note
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
                            <Callout tone="warn">
                                {format!(
                                    "{} high-risk scopes ({admin_risky} admin-consented for all users).",
                                    count_noun(risky, "grant includes", "grants include"),
                                )}
                            </Callout>
                        }
                            .into_any()
                    })
            }
            matches=move |r: &OAuth2GrantDto, facet: &str, q: &str| {
                matches_facet(r, facet)
                    && (q.is_empty() || contains_ignore_case(&r.client_display_name, q))
            }
            row=move |r: OAuth2GrantDto| grant_row(session, r).into_any()
        />
    }
}

fn grant_row(session: crate::state::Session, r: OAuth2GrantDto) -> impl IntoView {
    let (consent_label, consent_tone) = if r.consent_type == "AllPrincipals" {
        ("Admin (all users)", BadgeTone::Warning)
    } else {
        ("User", BadgeTone::Neutral)
    };
    let risky: std::collections::HashSet<String> = r.risky_scopes.iter().cloned().collect();
    let scope_chips = r
        .scopes
        .iter()
        .map(|s| {
            let tone = if risky.contains(s) {
                BadgeTone::Danger
            } else {
                BadgeTone::Neutral
            };
            view! { <Badge label=s.clone() tone=tone /> }
        })
        .collect_view();
    let client_app_id = r.client_app_id.clone().unwrap_or_default();
    let sp_id = r.client_sp_id.clone();
    view! {
        <tr>
            <td>
                <div class="permissions-cell__primary">{r.client_display_name.clone()}</div>
                <div class="permissions-cell__secondary">
                    <CopyableId value=client_app_id label="client app id" />
                </div>
            </td>
            <td>{r.resource_display_name.clone()}</td>
            <td>
                <Badge label=consent_label tone=consent_tone />
            </td>
            <td>
                <div class="scope-chips">{scope_chips}</div>
            </td>
            <td class="cell-mid">
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
