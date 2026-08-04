//! "Sites this app can reach" — the per-principal view of the tenant site-
//! permission index, answering which SharePoint sites a `Sites.Selected` app is
//! scoped to and with what roles, **without the operator knowing a site URL**.
//!
//! Why it needs an index at all: Microsoft Graph exposes site permissions only
//! per site (`/sites/{id}/permissions`) and offers **no reverse
//! `appId → sites` lookup**, so the only way to answer this question is to read
//! every enumerable site once. That sweep is tenant-wide, cached (60-minute
//! audit TTL) and shared with Resource Access → Sites, so the common case here
//! is a free cache read; running one from this panel warms it for every other
//! app's panel too.
//!
//! Coverage is stated, never implied. The sweep can't see personal OneDrive
//! sites, a site whose permission read failed contributes no rows, and a
//! cancelled sweep is a prefix of the tenant — so an empty list only means "no
//! grants" when the underlying sweep was complete (`AppSiteAccessDto::is_complete`).

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, ProgressBar, Spinner, SpinnerSize};

use crate::bindings::events;
use crate::bindings::sharepoint::{self, AppSiteAccessDto, SiteSweepProgress};
use crate::components::ui::DataTable;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::use_session;

#[component]
pub fn AppSiteAccessPanel(
    /// appId (client id) — what a site grant's `grantedToIdentities` carries.
    #[prop(into)]
    app_id: Signal<String>,
    /// Fired with a site URL when the operator picks a row, so the host can load
    /// it into its per-site manage flow (grant / list / revoke) — the reason
    /// this panel doesn't duplicate those mutations. `None` on a surface with no
    /// such flow (the managed-identity pane, which is read-only here): the row
    /// then renders without an action rather than a button that goes nowhere.
    #[prop(optional)]
    on_pick: Option<Callback<String>>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let access: RwSignal<Option<AppSiteAccessDto>> = RwSignal::new(None);
    // Distinguishes "haven't looked yet" from "looked, and no sweep is cached"
    // — the second is what offers the scan, the first must not flash it.
    let checked = RwSignal::new(false);
    let scanning = RwSignal::new(false);
    let progress: RwSignal<Option<SiteSweepProgress>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let consent_required = RwSignal::new(false);

    use_progress_stream(progress, events::site_sweep_progress);

    // Cached read, re-run on tenant/app change. Stale state is cleared
    // synchronously, and the async write is guarded against a switch that
    // happened while it was in flight.
    //
    // No disclosure gate needed: the host section renders its body only while
    // expanded, so this component doesn't exist — and costs no IPC — until the
    // operator opens it.
    Effect::new(move |_| {
        let t = tenant.get();
        let app = app_id.get();
        access.set(None);
        checked.set(false);
        error.set(None);
        let Some(t) = t else { return };
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let found = sharepoint::get_app_site_access(&tenant_id, &app)
                .await
                .ok()
                .flatten();
            let still_active = tenant
                .get_untracked()
                .map(|t| t.tenant_id == tenant_id)
                .unwrap_or(false)
                && app_id.get_untracked() == app;
            if still_active {
                access.set(found);
                checked.set(true);
            }
        });
    });

    // Runs the tenant-wide sweep, then projects this app's slice out of it.
    // Projected client-side here rather than re-reading the cache: a partial or
    // cancelled sweep is deliberately never cached, and dropping its result
    // would throw away the scan the operator just waited for.
    let do_scan = move || {
        if scanning.get_untracked() {
            return;
        }
        let Some(t) = tenant.get_untracked() else {
            return;
        };
        let app = app_id.get_untracked();
        scanning.set(true);
        error.set(None);
        consent_required.set(false);
        progress.set(Some(SiteSweepProgress {
            done: 0,
            total: 0,
            current_site: None,
            cancelled: false,
        }));
        leptos::task::spawn_local(async move {
            match sharepoint::sweep_site_permissions(&t.tenant_id).await {
                Ok(sweep) => {
                    access.set(Some(AppSiteAccessDto::from_sweep(&sweep, &app)));
                    checked.set(true);
                }
                Err(e) => {
                    consent_required.set(e.code == "consent_required");
                    error.set(Some(e.message));
                }
            }
            scanning.set(false);
            progress.set(None);
        });
    };

    let grant_consent = move |_| {
        let Some(t) = tenant.get_untracked() else {
            return;
        };
        error.set(None);
        leptos::task::spawn_local(async move {
            match auth_consent(&t.tenant_id).await {
                Ok(()) => do_scan(),
                Err(msg) => error.set(Some(msg)),
            }
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            let _ = sharepoint::cancel_resource_sweep().await;
        });
    };

    view! {
        <header class="row-between">
            <strong>"Sites this app can reach"</strong>
            {move || {
                if scanning.get() {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(cancel)
                        >
                            "Cancel scan"
                        </Button>
                    }
                        .into_any()
                } else {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| do_scan())
                        >
                            {move || {
                                if access.with(|a| a.is_some()) { "Re-scan sites" } else { "Scan sites" }
                            }}
                        </Button>
                    }
                        .into_any()
                }
            }}
        </header>
        <Body1 class="hint">
            "Microsoft Graph has no reverse app-to-sites lookup, so this reads every enumerable site's permissions once. The scan is tenant-wide and shared with Resource Access → Sites (and cached for an hour), so it also answers this question for every other app."
        </Body1>

        {move || {
            progress
                .get()
                .filter(|_| scanning.get())
                .map(|p| {
                    let pct = if p.total == 0 { 0.0 } else { p.done as f64 / p.total as f64 };
                    view! {
                        <div class="audit-progress">
                            <ProgressBar value=Signal::derive(move || pct) />
                            <Body1>
                                {format!(
                                    "{} / {} sites{}{}",
                                    p.done,
                                    p.total,
                                    p.current_site.as_deref().map(|s| format!(" — {s}")).unwrap_or_default(),
                                    if p.cancelled { " (cancelling…)" } else { "" },
                                )}
                            </Body1>
                        </div>
                    }
                })
        }}
        {move || {
            error
                .get()
                .map(|e| {
                    view! {
                        <div class="alert alert--warn">
                            <Body1>{e}</Body1>
                            {consent_required
                                .get()
                                .then(|| {
                                    view! {
                                        <div class="actions-row">
                                            <Button
                                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                on_click=Box::new(grant_consent)
                                            >
                                                "Grant consent & retry"
                                            </Button>
                                        </div>
                                    }
                                })}
                        </div>
                    }
                })
        }}
        {move || {
            if scanning.get() {
                return ().into_any();
            }
            match access.get() {
                // Looked, nothing cached: say what a scan costs before running it.
                None if checked.get() => {
                    view! {
                        <Body1>
                            "No site scan has run for this tenant yet, so this app's per-site grants are unknown. Scanning reads every site with your SharePoint admin rights — it can take a while on large tenants and can be cancelled anytime."
                        </Body1>
                    }
                        .into_any()
                }
                None => {
                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" /> }
                        .into_any()
                }
                Some(a) => {
                    let summary = coverage_summary(&a);
                    let complete = a.is_complete();
                    let sites = a.sites.clone();
                    view! {
                        <Body1 class="page__summary">{summary}</Body1>
                        <DataTable
                            headers=vec!["Site", "Roles", ""]
                            rows=sites
                            empty_message=if complete {
                                "No per-site grants. This app reaches no site through the Sites.Selected model — if it holds an org-wide Sites.* permission it reaches every site without appearing here."
                            } else {
                                "No per-site grants found in the sites that could be read — coverage was partial, so this is not proof the app has none."
                            }
                            row=move |r: sharepoint::SiteAppGrantRow| {
                                let name = r
                                    .site_display_name
                                    .clone()
                                    .or_else(|| r.site_url.clone())
                                    .unwrap_or_else(|| r.site_id.clone());
                                let url = r.site_url.clone().unwrap_or_default();
                                let pick = url.clone();
                                view! {
                                    <tr>
                                        <td class="permission-cell">
                                            <div class="permissions-cell__primary">{name}</div>
                                            <div class="permissions-cell__secondary mono">
                                                {url.clone()}
                                            </div>
                                        </td>
                                        <td class="cell-mid">{r.roles.join(", ")}</td>
                                        <td>
                                            {on_pick
                                                .filter(|_| !pick.is_empty())
                                                .map(|on_pick| {
                                                    view! {
                                                        <Button
                                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                            on_click=Box::new(move |_| on_pick.run(pick.clone()))
                                                        >
                                                            "Manage"
                                                        </Button>
                                                    }
                                                })}
                                        </td>
                                    </tr>
                                }
                                    .into_any()
                            }
                        />
                    }
                        .into_any()
                }
            }
        }}
    }
}

/// One line qualifying the list: how many sites the answer is drawn from, and
/// whether anything was missed. Never claims full coverage it doesn't have.
fn coverage_summary(access: &AppSiteAccessDto) -> String {
    let n = access.sites.len();
    let mut out = format!(
        "{n} site{} — from {} of {} scanned site{}",
        if n == 1 { "" } else { "s" },
        access.sites_scanned,
        access.total_sites,
        if access.total_sites == 1 { "" } else { "s" },
    );
    if access.sites_failed > 0 {
        out.push_str(&format!(
            " ({} failed to read — coverage is partial)",
            access.sites_failed
        ));
    }
    if access.cancelled {
        out.push_str(" — the scan was cancelled early");
    }
    out.push_str(". Personal OneDrive sites aren't enumerable.");
    out
}

/// Interactive consent for the SharePoint admin scope, flattened to a message
/// so the caller's error signal stays a plain `String`.
async fn auth_consent(tenant_id: &str) -> Result<(), String> {
    crate::bindings::auth::request_scope_consent(tenant_id, "sharepoint")
        .await
        .map_err(|e| e.message)
}
