//! Home dashboard — the post-sign-in landing surface. A tenant inventory
//! (App Registrations, Enterprise apps, Managed identities) plus tenant health
//! at a glance (credential expiry + security posture). Each card loads
//! independently so the page renders immediately.

use azapptoolkit_core::audit::CredentialStatus;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::managed_identity::MiSubtype;
use crate::bindings::{applications, audit, credentials, enterprise_application, managed_identity};
use crate::components::icon::{Icon, IconName};
use crate::components::ui::{DetailLoadError, SectionHeader, Skeleton};
use crate::state::{ActiveView, use_session};
use crate::views::audit_view::posture::posture_counts;

#[component]
pub fn HomeDashboard() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // Shared retry trigger for the inventory cards: a failed card keeps its
    // error (not a silent empty card) and renders a Retry button that bumps
    // this to refetch all four.
    let reload = RwSignal::new(0u32);

    let apps = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => Some(applications::list_applications_with_pairing(&t.tenant_id).await),
                None => None,
            }
        }
    });

    let enterprise = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => {
                    Some(enterprise_application::list_enterprise_applications(&t.tenant_id).await)
                }
                None => None,
            }
        }
    });

    let managed = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => Some(managed_identity::list_managed_identities(&t.tenant_id).await),
                None => None,
            }
        }
    });

    let creds = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => Some(credentials::list_credential_expirations(&t.tenant_id).await),
                None => None,
            }
        }
    });

    let cached_audit = LocalResource::new(move || {
        let tenant = tenant.get();
        // Refetch after an audit run: this dashboard stays mounted across view
        // switches (keep-alive panes), so without tracking this bump the tile
        // would keep its first value (e.g. "No audit has been run yet").
        let _ = session.audit_reload.get();
        async move {
            match tenant {
                Some(t) => audit::get_cached_audit(&t.tenant_id).await,
                None => None,
            }
        }
    });

    view! {
        <main class="dashboard">
            <SectionHeader title="Overview".to_string() crumb="Home".to_string() />
            <div class="dash-grid">
                <section class="dash-card">
                    <h3 class="dash-card__title">
                        <Icon name=IconName::AppWindow size=18 />
                        "App Registrations"
                    </h3>
                    <Suspense fallback=card_skeleton>
                        {move || Suspend::new(async move {
                            match apps.await {
                                Some(Ok(rows)) => {
                                    let total = rows.len();
                                    let with_secrets = rows
                                        .iter()
                                        .filter(|r| r.password_credential_count > 0)
                                        .count();
                                    let with_certs = rows
                                        .iter()
                                        .filter(|r| r.key_credential_count > 0)
                                        .count();
                                    view! {
                                        <span class="dash-card__count">{total}</span>
                                        <div class="dash-metrics">
                                            {metric(with_secrets, "With secrets", "warning")}
                                            {metric(with_certs, "With certs", "warning")}
                                        </div>
                                        <div class="dash-card__actions">
                                            <Button
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Secondary
                                                })
                                                on_click=Box::new(move |_| {
                                                    session.set_view(ActiveView::Apps)
                                                })
                                            >
                                                "View all"
                                            </Button>
                                            <Button
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Primary
                                                })
                                                on_click=Box::new(move |_| {
                                                    session.set_view(ActiveView::Apps);
                                                    session.open_create_app();
                                                })
                                            >
                                                "+ New app registration"
                                            </Button>
                                        </div>
                                    }
                                        .into_any()
                                }
                                Some(Err(e)) => {
                                    view! {
                                        <DetailLoadError
                                            error=e
                                            on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                        />
                                    }
                                        .into_any()
                                }
                                None => {
                                    view! {
                                        <Body1>"Couldn't load app registrations for this tenant."</Body1>
                                    }
                                        .into_any()
                                }
                            }
                        })}
                    </Suspense>
                </section>

                <section class="dash-card">
                    <h3 class="dash-card__title">
                        <Icon name=IconName::Building size=18 />
                        "Enterprise Applications"
                    </h3>
                    <Suspense fallback=card_skeleton>
                        {move || Suspend::new(async move {
                            match enterprise.await {
                                Some(Ok(items)) => {
                                    let total = items.len();
                                    let disabled = items
                                        .iter()
                                        .filter(|i| i.account_enabled == Some(false))
                                        .count();
                                    let foreign = items
                                        .iter()
                                        .filter(|i| i.is_foreign_tenant)
                                        .count();
                                    view! {
                                        <span class="dash-card__count">{total}</span>
                                        <div class="dash-metrics">
                                            {metric_link(
                                                disabled,
                                                "Disabled",
                                                "warning",
                                                move || session.open_enterprise_with_facet("disabled"),
                                            )}
                                            {metric_link(
                                                foreign,
                                                "Foreign tenant",
                                                "warning",
                                                move || session.open_enterprise_with_facet("foreign"),
                                            )}
                                        </div>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| {
                                                session.set_view(ActiveView::EnterpriseApps)
                                            })
                                        >
                                            "View enterprise apps"
                                        </Button>
                                    }
                                        .into_any()
                                }
                                Some(Err(e)) => {
                                    view! {
                                        <DetailLoadError
                                            error=e
                                            on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                        />
                                    }
                                        .into_any()
                                }
                                None => {
                                    view! {
                                        <Body1>"Couldn't load enterprise applications for this tenant."</Body1>
                                    }
                                        .into_any()
                                }
                            }
                        })}
                    </Suspense>
                </section>

                <section class="dash-card">
                    <h3 class="dash-card__title">
                        <Icon name=IconName::Server size=18 />
                        "Managed Identities"
                    </h3>
                    <Suspense fallback=card_skeleton>
                        {move || Suspend::new(async move {
                            match managed.await {
                                Some(Ok(items)) => {
                                    let total = items.len();
                                    let system = items
                                        .iter()
                                        .filter(|i| i.mi_subtype == MiSubtype::SystemAssigned)
                                        .count();
                                    let user = items
                                        .iter()
                                        .filter(|i| i.mi_subtype == MiSubtype::UserAssigned)
                                        .count();
                                    view! {
                                        <span class="dash-card__count">{total}</span>
                                        <div class="dash-metrics">
                                            {metric_link(
                                                system,
                                                "System-assigned",
                                                "neutral",
                                                move || {
                                                    session.open_managed_identities_with_facet("system")
                                                },
                                            )}
                                            {metric_link(
                                                user,
                                                "User-assigned",
                                                "neutral",
                                                move || {
                                                    session.open_managed_identities_with_facet("user")
                                                },
                                            )}
                                        </div>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| {
                                                session.set_view(ActiveView::ManagedIdentities)
                                            })
                                        >
                                            "View managed identities"
                                        </Button>
                                    }
                                        .into_any()
                                }
                                Some(Err(e)) => {
                                    view! {
                                        <DetailLoadError
                                            error=e
                                            on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                        />
                                    }
                                        .into_any()
                                }
                                None => {
                                    view! {
                                        <Body1>"Couldn't load managed identities for this tenant."</Body1>
                                    }
                                        .into_any()
                                }
                            }
                        })}
                    </Suspense>
                </section>

                <section class="dash-card">
                    <h3 class="dash-card__title">"Credential Health"</h3>
                    <Suspense fallback=card_skeleton>
                        {move || Suspend::new(async move {
                            match creds.await {
                                Some(Ok(rows)) => {
                                    let expired = rows
                                        .iter()
                                        .filter(|r| matches!(r.status, CredentialStatus::Expired))
                                        .count();
                                    let soon = rows
                                        .iter()
                                        .filter(|r| {
                                            matches!(r.days_to_expiry, Some(d) if (0..=7).contains(&d))
                                        })
                                        .count();
                                    let m30 = rows
                                        .iter()
                                        .filter(|r| {
                                            matches!(r.days_to_expiry, Some(d) if (0..=30).contains(&d))
                                        })
                                        .count();
                                    view! {
                                        <div class="dash-metrics">
                                            {metric_link(
                                                expired,
                                                "Expired",
                                                "danger",
                                                move || session.open_credentials_with_facet("expired"),
                                            )}
                                            {metric_link(
                                                soon,
                                                "≤ 7 days",
                                                "danger",
                                                move || session.open_credentials_with_facet("7"),
                                            )}
                                            {metric_link(
                                                m30,
                                                "≤ 30 days",
                                                "warning",
                                                move || session.open_credentials_with_facet("30"),
                                            )}
                                        </div>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| {
                                                session.open_security("credentials")
                                            })
                                        >
                                            "View credentials"
                                        </Button>
                                    }
                                        .into_any()
                                }
                                Some(Err(e)) => {
                                    view! {
                                        <DetailLoadError
                                            error=e
                                            on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                        />
                                    }
                                        .into_any()
                                }
                                None => {
                                    view! {
                                        <Body1>"Couldn't load credential data for this tenant."</Body1>
                                    }
                                        .into_any()
                                }
                            }
                        })}
                    </Suspense>
                </section>

                <section class="dash-card">
                    <h3 class="dash-card__title">"Security Posture"</h3>
                    <Suspense fallback=card_skeleton>
                        {move || Suspend::new(async move {
                            match cached_audit.await {
                                Some(r) => {
                                    // One shared count source with the Security
                                    // workbench's posture strip — the numbers
                                    // here and there can never disagree.
                                    let c = posture_counts(&r.items);
                                    let (crit, high, medium) = (c.critical, c.high, c.medium);
                                    let expired = c.expired;
                                    let over_privileged = c.over_privileged;
                                    let orgwide_mailbox = c.orgwide_mailbox;
                                    let orgwide_sharepoint = c.orgwide_sharepoint;
                                    let ownership = c.unowned;
                                    let unused = c.unused;
                                    view! {
                                        <div class="dash-metrics">
                                            {metric_link(
                                                crit,
                                                "Critical",
                                                "danger",
                                                move || session.open_posture_with_facet("critical"),
                                            )}
                                            {metric_link(
                                                high,
                                                "High",
                                                "danger",
                                                move || session.open_posture_with_facet("high"),
                                            )}
                                            {metric_link(
                                                medium,
                                                "Medium",
                                                "warning",
                                                move || session.open_posture_with_facet("medium"),
                                            )}
                                            {metric_link(
                                                expired,
                                                "Expired",
                                                "warning",
                                                move || session.open_posture_with_facet("expired"),
                                            )}
                                            {metric_link(
                                                over_privileged,
                                                "Over-privileged",
                                                "danger",
                                                move || session.open_posture_with_facet("high_risk_perms"),
                                            )}
                                            {metric_link(
                                                orgwide_mailbox,
                                                "Org-wide mailbox",
                                                "warning",
                                                move || {
                                                    session.open_posture_with_facet("orgwide_mailbox")
                                                },
                                            )}
                                            {metric_link(
                                                orgwide_sharepoint,
                                                "Org-wide SharePoint",
                                                "warning",
                                                move || {
                                                    session
                                                        .open_posture_with_facet("orgwide_sharepoint")
                                                },
                                            )}
                                            {metric_link(
                                                ownership,
                                                "Unowned",
                                                "warning",
                                                move || session.open_posture_with_facet("ownership"),
                                            )}
                                            {metric_link(
                                                unused,
                                                "Unused",
                                                "warning",
                                                move || session.open_posture_with_facet("unused"),
                                            )}
                                        </div>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| session.open_security("findings"))
                                        >
                                            "Open security audit"
                                        </Button>
                                    }
                                        .into_any()
                                }
                                None => {
                                    view! {
                                        <Body1>"No audit has been run yet."</Body1>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                                            on_click=Box::new(move |_| session.open_security("findings"))
                                        >
                                            "Run a security audit"
                                        </Button>
                                    }
                                        .into_any()
                                }
                            }
                        })}
                    </Suspense>
                </section>
            </div>
        </main>
    }
}

/// Loading placeholder for a dashboard card — a big count block plus two metric
/// lines, matching the card's loaded geometry (skeletons for content regions;
/// spinners are reserved for in-button busy affordances).
fn card_skeleton() -> impl IntoView {
    view! {
        <div style="display:flex;flex-direction:column;gap:10px;" aria-busy="true">
            <Skeleton width="64px".to_string() height="30px".to_string() />
            <Skeleton width="80%".to_string() height="12px".to_string() />
            <Skeleton width="60%".to_string() height="12px".to_string() />
        </div>
    }
}

fn metric(n: usize, label: &'static str, tone: &'static str) -> impl IntoView {
    // Zero counts are muted; non-zero use the tone colour.
    let num_class = if n == 0 {
        "dash-metric__num".to_string()
    } else {
        format!("dash-metric__num dash-metric__num--{tone}")
    };
    view! {
        <div class="dash-metric">
            <span class=num_class>{n}</span>
            <span class="dash-metric__label">{label}</span>
        </div>
    }
}

/// A clickable metric that drills into the matching pre-filtered list/facet
/// (`on_click` sets the destination facet + navigates). A zero count degrades to
/// a muted, non-interactive box — there's nothing to drill into — but keeps the
/// same geometry so it lines up with its clickable siblings in the row. Mirrors
/// the audit view's posture cards (`.audit-card`).
fn metric_link(
    n: usize,
    label: &'static str,
    tone: &'static str,
    on_click: impl Fn() + 'static,
) -> impl IntoView {
    if n == 0 {
        return view! {
            <div class="dash-metric dash-metric--box">
                <span class="dash-metric__num">{n}</span>
                <span class="dash-metric__label">{label}</span>
            </div>
        }
        .into_any();
    }
    let num_class = format!("dash-metric__num dash-metric__num--{tone}");
    view! {
        <button
            type="button"
            class="dash-metric dash-metric--link"
            title=format!("Show {label}")
            on:click=move |_| on_click()
        >
            <span class=num_class>{n}</span>
            <span class="dash-metric__label">{label}</span>
        </button>
    }
    .into_any()
}
