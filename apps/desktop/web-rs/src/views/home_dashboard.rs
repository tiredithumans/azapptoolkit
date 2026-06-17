//! Home dashboard — the post-sign-in landing surface. A tenant inventory
//! (App Registrations, Enterprise apps, Managed identities) plus tenant health
//! at a glance (credential expiry + security posture). Each card loads
//! independently so the page renders immediately.

use azapptoolkit_core::audit::{issue, CredentialStatus, RiskLevel};
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::bindings::managed_identity::MiSubtype;
use crate::bindings::{applications, audit, credentials, enterprise_application, managed_identity};
use crate::components::icon::{Icon, IconName};
use crate::components::ui::SectionHeader;
use crate::state::{use_session, ActiveView};

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
            <SectionHeader
                title="Overview".to_string()
                crumb="Tenant inventory and health at a glance".to_string()
            />
            <div class="dash-grid">
                <section class="dash-card">
                    <h3 class="dash-card__title">
                        <Icon name=IconName::AppWindow size=18 />
                        "App Registrations"
                    </h3>
                    <Suspense fallback=card_spinner>
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
                                Some(Err(e)) => card_error(e.message, reload).into_any(),
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
                    <Suspense fallback=card_spinner>
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
                                            {metric(disabled, "Disabled", "warning")}
                                            {metric(foreign, "Foreign tenant", "warning")}
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
                                Some(Err(e)) => card_error(e.message, reload).into_any(),
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
                    <Suspense fallback=card_spinner>
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
                                            {metric(system, "System-assigned", "neutral")}
                                            {metric(user, "User-assigned", "neutral")}
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
                                Some(Err(e)) => card_error(e.message, reload).into_any(),
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
                    <Suspense fallback=card_spinner>
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
                                            {metric(expired, "Expired", "danger")}
                                            {metric(soon, "≤ 7 days", "danger")}
                                            {metric(m30, "≤ 30 days", "warning")}
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
                                Some(Err(e)) => card_error(e.message, reload).into_any(),
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
                    <Suspense fallback=card_spinner>
                        {move || Suspend::new(async move {
                            match cached_audit.await {
                                Some(r) => {
                                    let crit = count_level(&r.items, RiskLevel::Critical);
                                    let high = count_level(&r.items, RiskLevel::High);
                                    let ownerless = count_issue(&r.items, issue::NO_OWNERS);
                                    // Structured flag set by the audit runner from the
                                    // sign-in activity report — matches the audit view's
                                    // "Unused" facet (no issue-text parsing).
                                    let unused = r.items.iter().filter(|i| i.unused).count();
                                    view! {
                                        <div class="dash-metrics">
                                            {metric(crit, "Critical", "danger")}
                                            {metric(high, "High", "warning")}
                                            {metric(ownerless, "Ownerless", "warning")}
                                            {metric(unused, "Unused", "warning")}
                                        </div>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| session.open_security("posture"))
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
                                            on_click=Box::new(move |_| session.open_security("posture"))
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

fn card_error(message: String, reload: RwSignal<u32>) -> impl IntoView {
    view! {
        <Body1 class="form-error">{message}</Body1>
        <Button
            appearance=Signal::derive(|| ButtonAppearance::Secondary)
            on_click=Box::new(move |_| reload.update(|n| *n += 1))
        >
            "Retry"
        </Button>
    }
}

fn card_spinner() -> impl IntoView {
    view! {
        <div class="centered-pad">
            <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" />
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

fn count_level(items: &[azapptoolkit_core::audit::AuditItem], level: RiskLevel) -> usize {
    items.iter().filter(|i| i.risk_level == level).count()
}

fn count_issue(items: &[azapptoolkit_core::audit::AuditItem], prefix: &str) -> usize {
    items
        .iter()
        .filter(|i| i.issues.iter().any(|x| x.starts_with(prefix)))
        .count()
}
