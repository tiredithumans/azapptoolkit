//! Home dashboard — the post-sign-in landing surface. A tenant inventory
//! (App Registrations, Enterprise apps, Managed identities) plus tenant health
//! at a glance (credential expiry + security posture). Each card loads
//! independently so the page renders immediately.

use azapptoolkit_core::audit::CredentialStatus;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::consent::TenantConsentPostureDto;
use crate::bindings::managed_identity::MiSubtype;
use crate::bindings::{
    applications, audit, consent, credentials, enterprise_application, managed_identity,
};
use crate::components::icon::{Icon, IconName};
use crate::components::ui::{BadgeTone, Callout, DetailLoadError, SectionHeader, SkeletonCard};
use crate::state::{ActiveView, Session, use_session};
use crate::util::{TimeAgo, time_ago};
use crate::views::audit_view::ranked_actionable_findings;

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
        // Same keep-alive reasoning as `cached_audit` below: the dashboard stays
        // mounted, so without this bump a bulk delete/create elsewhere leaves
        // the inventory count showing its pre-mutation value.
        let _ = session.apps_reload.get();
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
        let _ = session.enterprise_apps_reload.get();
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
        // Credential expirations are derived from the app registrations, and the
        // backend busts them transitively via `invalidate_app_lists` — so this
        // card follows the same bump as `apps`.
        let _ = session.apps_reload.get();
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
        // The counts-only summary, never the run: the card shows a dozen
        // numbers, and the run is up to 10k scored principals the Security
        // view already holds its own copy of.
        let _ = session.audit_reload.get();
        async move {
            match tenant {
                // A failed read renders as "no audit yet", as before the
                // command became fallible, but says so in the console.
                Some(t) => match audit::get_cached_audit_summary(&t.tenant_id).await {
                    Ok(summary) => summary,
                    Err(err) => {
                        leptos::logging::warn!(
                            "get_cached_audit_summary failed ({}): {}",
                            err.code,
                            err.message
                        );
                        None
                    }
                },
                None => None,
            }
        }
    });

    // Tenant consent posture (F274): mount-time tenant config, deliberately NOT
    // riding `audit_reload` — it is not run-derived — and served by its own
    // Suspense so the posture counts never wait on a live Graph read. A failed
    // read is `None` and renders nothing (the command never errors); unknown
    // fields render nothing too.
    let consent_posture = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => consent::get_tenant_consent_posture(&t.tenant_id).await.ok(),
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
                                    let with_secrets =
                                        rows.iter().filter(|r| r.has_secrets()).count();
                                    let with_certs =
                                        rows.iter().filter(|r| r.has_certs()).count();
                                    view! {
                                        <span class="dash-card__count">{total}</span>
                                        <div class="dash-metrics">
                                            // Drill into the App Registrations
                                            // chip of the same name.
                                            {metric_link(
                                                with_secrets,
                                                "With secrets",
                                                "warning",
                                                move || session.open_apps_with_facet("secrets"),
                                            )}
                                            {metric_link(
                                                with_certs,
                                                "With certs",
                                                "warning",
                                                move || session.open_apps_with_facet("certs"),
                                            )}
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
                                                "View app registrations"
                                            </Button>
                                            <Button
                                                class="btn-icon-label"
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Primary
                                                })
                                                on_click=Box::new(move |_| {
                                                    session.set_view(ActiveView::Apps);
                                                    session.open_create_app();
                                                })
                                            >
                                                <Icon name=IconName::Plus size=16 />
                                                "New app registration"
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
                                        <div class="dash-card__actions">
                                            <Button
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Secondary
                                                })
                                                on_click=Box::new(move |_| {
                                                    session.set_view(ActiveView::EnterpriseApps)
                                                })
                                            >
                                                "View enterprise apps"
                                            </Button>
                                            <Button
                                                class="btn-icon-label"
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Primary
                                                })
                                                on_click=Box::new(move |_| {
                                                    session.set_view(ActiveView::EnterpriseApps);
                                                    session.open_new_app_chooser();
                                                })
                                            >
                                                <Icon name=IconName::Plus size=16 />
                                                "New application"
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
                                        <div class="dash-card__actions">
                                            <Button
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Secondary
                                                })
                                                on_click=Box::new(move |_| {
                                                    session.set_view(ActiveView::ManagedIdentities)
                                                })
                                            >
                                                "View managed identities"
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
                                        <div class="dash-card__actions">
                                            <Button
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Secondary
                                                })
                                                on_click=Box::new(move |_| {
                                                    session.open_security("credentials")
                                                })
                                            >
                                                "View credentials"
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
                    // The consent-posture note sits ABOVE the run-derived counts
                    // and outside their Suspense: it answers "how did this tenant
                    // get these grants" (tenant config, live read at mount), not
                    // "what did the scan find". An unreachable Graph must not
                    // delay or alter the counts.
                    <Suspense fallback=move || view! { <></> }>
                        {move || Suspend::new(async move {
                            match consent_posture.await {
                                Some(p) if p.available => {
                                    consent_posture_note(&p).into_any()
                                }
                                _ => ().into_any(),
                            }
                        })}
                    </Suspense>
                    <Suspense fallback=card_skeleton>
                        {move || Suspend::new(async move {
                            match cached_audit.await {
                                Some(r) => {
                                    // Counted by the backend with core's
                                    // `posture_counts` — the function the
                                    // Security workbench's posture strip runs
                                    // over its own copy — so the numbers here
                                    // and there can never disagree.
                                    let c = r.posture;
                                    // Ranked with the workbench Findings pane's
                                    // own ordering (imported, not re-hardcoded)
                                    // so the card rhymes with what it opens.
                                    // Only the findings the card drills into;
                                    // zero-count ones are dropped.
                                    let findings: Vec<_> = ranked_actionable_findings(|key| {
                                            card_lists(key).then(|| r.finding_tally(key)).flatten()
                                        })
                                        .into_iter()
                                        .map(|(key, title, tone, n)| {
                                            finding_row(n, title, tone, key, session)
                                        })
                                        .collect();
                                    let clean = findings.is_empty();
                                    view! {
                                        // Severity row up top — large, box geometry,
                                        // still clickable drills.
                                        <div class="dash-metrics posture-severities">
                                            {metric_link(
                                                c.critical,
                                                "Critical",
                                                "danger",
                                                move || session.open_posture_with_facet("critical"),
                                            )}
                                            {metric_link(
                                                c.high,
                                                "High",
                                                "danger",
                                                move || session.open_posture_with_facet("high"),
                                            )}
                                            {metric_link(
                                                c.medium,
                                                "Medium",
                                                "warning",
                                                move || session.open_posture_with_facet("medium"),
                                            )}
                                        </div>
                                        // Directly under the counts, because it
                                        // qualifies them: the run cache is
                                        // in-process with a 60-minute TTL, so
                                        // this card presented an hour-old scan
                                        // exactly like one that just finished
                                        // while every number on it is something
                                        // an operator acts on. The exact stamp
                                        // hangs off the title for a change
                                        // ticket that has to cite it.
                                        {r
                                            .completed_at
                                            .as_deref()
                                            .and_then(time_ago)
                                            .map(|TimeAgo { relative, exact }| {
                                                view! {
                                                    <p class="muted" title=exact>
                                                        {format!("Scanned {relative}")}
                                                    </p>
                                                }
                                            })}
                                        {
                                            // Tenant credential-lifetime posture (F260/F270),
                                            // riding the cached run: this card and the audit's
                                            // per-app advice read the SAME pair decided at run
                                            // time, so they cannot disagree after an hour-old
                                            // cache serves both. Rendered only when the policy
                                            // is knowable — `credential_policy_available` is
                                            // false when Policy.Read.All was absent, and
                                            // available-but-capless renders nothing either:
                                            // neither unknown nor "no cap enforced" belongs on
                                            // the posture strip, which qualifies findings.
                                            r
                                                .credential_policy_available
                                                .then_some(r.credential_policy_max_days)
                                                .flatten()
                                                .map(|cap| {
                                                    view! {
                                                        <p class="muted">
                                                            {format!(
                                                                "Tenant policy caps secret lifetimes at {cap} days."
                                                            )}
                                                        </p>
                                                    }
                                                })
                                        }
                                        // Ranked "Top findings" list below.
                                        {clean
                                            .then(|| {
                                                view! {
                                                    <p class="muted">
                                                        "No priority findings — the tenant looks healthy."
                                                    </p>
                                                }
                                            })}
                                        <div class="posture-findings">{findings}</div>
                                        <div class="dash-card__actions">
                                            <Button
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Secondary
                                                })
                                                on_click=Box::new(move |_| {
                                                    session.open_security("findings")
                                                })
                                            >
                                                "Open security audit"
                                            </Button>
                                        </div>
                                    }
                                        .into_any()
                                }
                                None => {
                                    view! {
                                        // NOT "no audit has been run yet": the
                                        // run cache is in-process with a 60-minute
                                        // TTL, so this is what an operator sees
                                        // after every relaunch and after any
                                        // hour-long gap — a tenant audited daily
                                        // for a year lands here every morning.
                                        <Body1>"No audit run in this session."</Body1>
                                        <div class="dash-card__actions">
                                            <Button
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Primary
                                                })
                                                on_click=Box::new(move |_| {
                                                    // One click, not two: trip the
                                                    // one-shot flag the audit
                                                    // controller consumes on
                                                    // arrival so the scan starts
                                                    // itself. Navigating alone
                                                    // left the operator to find
                                                    // and press "Run audit" again.
                                                    session.tenant_ui.pending_audit_run.set(true);
                                                    session.open_security("findings");
                                                })
                                            >
                                                "Run a security audit"
                                            </Button>
                                        </div>
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
    view! { <SkeletonCard /> }
}

/// Whether the card lists a finding — `false` for the ones it doesn't drill
/// into (redundant / delegated / external exposure / no-local-app), so they're
/// dropped from the ranked list. The two unconfinable-reach groups are listed:
/// an app that reaches every mailbox or site must not leave the card reading
/// "the tenant looks healthy" — and neither may the org-wide Files finding,
/// which describes the same kind of blind tenant-wide reach. The counts
/// themselves come from the summary's `PostureCounts`, the one shared source,
/// so the card and the Security workbench can't disagree.
fn card_lists(key: &str) -> bool {
    matches!(
        key,
        "expired"
            | "orgwide_mailbox"
            | "legacy_mailbox_scope"
            | "unscopable_legacy_mailbox"
            | "unconfinable_orgwide"
            | "orgwide_sharepoint"
            | "orgwide_files"
            | "high_risk_perms"
            | "ownership"
            | "unused"
    )
}

/// The consent-posture note (F274) for one posture read. Mirrors the grants
/// view's header Callout but sized for the card. Whole-DTO contract: an absent
/// `default_user_role_consent_policies` is UNKNOWN — neither "consent is
/// restricted" nor "all clear" — so it renders nothing, exactly like the
/// credential-lifetime line's policy-unavailable case below it. The
/// recommended setup (user consent off, admin consent workflow on) also
/// renders nothing; only a confirmed-off workflow gets a muted line.
fn consent_posture_note(p: &TenantConsentPostureDto) -> impl IntoView {
    let Some(names) = p.default_user_role_consent_policies.as_ref() else {
        return ().into_any();
    };
    if !names.is_empty() {
        let mut text = format!(
            "Users in this tenant can approve apps' access to their own data without an admin \
             (consent policy: {}). Any per-user permission in the audit may have been granted \
             this way, not by an admin.",
            names.join(", ")
        );
        if p.risky_app_user_consent == Some(true) {
            text.push_str(" Users can also approve apps Microsoft flags as risky.");
        }
        return view! { <Callout tone="warn">{text}</Callout> }.into_any();
    }
    // User consent is off. With the admin consent workflow on, that is the
    // recommended setup and the card says nothing; an unknown workflow state
    // says nothing either. Only a confirmed-off workflow earns a line, as a
    // suggestion rather than a warning.
    if p.admin_consent_workflow_enabled != Some(false) {
        return ().into_any();
    }
    view! {
        <p class="muted">
            "Users can't approve apps on their own, and they can't ask an admin for approval \
             either: the admin consent workflow is off."
        </p>
    }
    .into_any()
}

/// One ranked "Top findings" line: tone dot · title · count · chevron, drilling
/// into the matching pre-filtered Security workbench pane. Rhymes with the
/// pane's finding-group header (reuses its `finding-group__tone--*` dot classes).
fn finding_row(
    n: usize,
    title: &'static str,
    tone: BadgeTone,
    key: &'static str,
    session: Session,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class="posture-finding"
            title=format!("Show {title}")
            on:click=move |_| session.open_posture_with_facet(key)
        >
            <span class=format!("finding-group__tone finding-group__tone--{tone}")></span>
            <span class="posture-finding__title">{title}</span>
            <span class=format!(
                "posture-finding__count posture-finding__count--{tone}",
            )>{n}</span>
            <Icon name=IconName::ChevronRight size=16 class="posture-finding__chevron" />
        </button>
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
