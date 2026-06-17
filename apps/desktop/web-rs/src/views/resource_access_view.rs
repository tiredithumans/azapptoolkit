//! Resource Access — the resource → identities reverse lookups Graph doesn't
//! offer, one tab per resource plane:
//!
//! - **Mailboxes** (first tab): every candidate principal — mail-scopable
//!   Graph application permission holders plus Exchange-registered SPs —
//!   probed against one target mailbox (`find_mailbox_reachers`, the
//!   Entra ∪ Exchange-RBAC union) — "which apps can read this mailbox?".
//! - **Sites**: a tenant-wide sweep of every enumerable site's application
//!   permissions (`sweep_site_permissions`, progress-streamed, backend-cached).
//!   Filtering by app answers "which sites can this app reach?" — the
//!   `Sites.Selected` blind spot — and filtering by site answers "which apps
//!   can touch this site?".
//!
//! Both panels stay mounted across tab switches (display toggle) so an
//! expensive sweep/probe result survives flipping between them.

use crate::hooks::use_progress_stream::use_progress_stream;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, ProgressBar, Tab, TabList};

use crate::bindings::auth;
use crate::bindings::events;
use crate::bindings::permission_tester::{
    self, MailboxProbeProgress, MailboxReacherRow, MailboxReachersResult,
};
use crate::bindings::sharepoint::{self, SiteAppGrantRow, SiteSweepProgress, SiteSweepResult};
use crate::components::ui::{SearchInput, SectionHeader};
use crate::hooks::use_debounced::{use_debounced, LIST_FILTER_DEBOUNCE_MS};
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::state::use_session;

/// Rows drawn per page in the sweep/probe result tables. The tables window to
/// this many at a time with a "Show more" control, so a large sweep (≤5k site
/// grants) or mailbox probe keeps the DOM bounded — same pattern as the audit
/// table.
const RENDER_PAGE: usize = 200;

#[component]
pub fn ResourceAccessView() -> impl IntoView {
    let tab = RwSignal::new(String::from("mailboxes"));
    view! {
        <div class="page">
            <SectionHeader title="Resource Access" />
            <Body1>
                "Reverse lookups: pick a resource plane and see which applications can reach what. (Key Vault / Azure RBAC lookups live on each managed identity's detail for now.)"
            </Body1>
            <TabList selected_value=tab>
                <Tab value="mailboxes">"Mailboxes"</Tab>
                <Tab value="sites">"Sites"</Tab>
            </TabList>
            <div style:display=move || {
                if tab.get() == "mailboxes" { "contents" } else { "none" }
            }>
                <MailboxesPanel />
            </div>
            <div style:display=move || {
                if tab.get() == "sites" { "contents" } else { "none" }
            }>
                <SitesPanel />
            </div>
        </div>
    }
}

/// Lowercased haystack of a row's site + app facets, newline-joined so one
/// search box serves both lookup directions without cross-field false matches.
/// Built once per sweep result (see `corpus`), never per keystroke.
fn row_haystack(row: &SiteAppGrantRow) -> String {
    let mut hay = String::new();
    for field in [
        &row.site_display_name,
        &row.site_url,
        &row.app_display_name,
        &row.app_id,
    ] {
        if let Some(v) = field.as_deref() {
            hay.push_str(&v.to_lowercase());
            hay.push('\n');
        }
    }
    hay
}

#[component]
fn SitesPanel() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<SiteSweepResult>> = RwSignal::new(None);
    let scanning = RwSignal::new(false);
    let progress: RwSignal<Option<SiteSweepProgress>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let consent_required = RwSignal::new(false);
    let search = RwSignal::new(String::new());

    // Filtered rows + summary derived with `.with()` over the debounced query
    // — previously every keystroke deep-cloned the whole SiteSweepResult
    // (≤5k rows) and rebuilt the entire table.
    let search_debounced = use_debounced(search.into(), LIST_FILTER_DEBOUNCE_MS);
    // Lowercased search haystack per row, rebuilt once per sweep result (it reads
    // `result`, not the query) so filtering is allocation-free. Previously the
    // filter lowercased all four fields of every row (≤5k) on each settled
    // keystroke (~20k allocations); now a keystroke just runs `contains` over the
    // prebuilt corpus. Indices align with `result.rows` (both derive from `result`).
    let corpus: Memo<Vec<String>> = Memo::new(move |_| {
        result.with(|r| {
            r.as_ref()
                .map(|r| r.rows.iter().map(row_haystack).collect::<Vec<_>>())
                .unwrap_or_default()
        })
    });
    let filtered_rows = Memo::new(move |_| {
        let needle = search_debounced.get().trim().to_lowercase();
        result.with(|r| {
            r.as_ref()
                .map(|r| {
                    if needle.is_empty() {
                        return r.rows.clone();
                    }
                    corpus.with(|hays| {
                        r.rows
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| hays.get(*i).is_some_and(|h| h.contains(&needle)))
                            .map(|(_, row)| row.clone())
                            .collect::<Vec<_>>()
                    })
                })
                .unwrap_or_default()
        })
    });
    // Render window — draw the first page and grow on demand so a ≤5k-row sweep
    // doesn't build every <tr> at once. Reset when the filter or scan changes.
    let render_limit = RwSignal::new(RENDER_PAGE);
    Effect::new(move |prev: Option<()>| {
        search_debounced.track();
        let _ = filtered_rows.with(|r| r.len());
        if prev.is_some() {
            render_limit.set(RENDER_PAGE);
        }
    });
    // Roving-tabindex keyboard nav over the result rows (matches the audit table).
    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    let on_grid_key = use_grid_keynav(tbody_ref, move || {
        let _ = render_limit.get();
        let _ = filtered_rows.with(|r| r.len());
    });
    let summary = Memo::new(move |_| {
        result.with(|r| {
            r.as_ref().map(|r| {
                filtered_rows.with(|rows| {
                    let distinct_sites = {
                        let mut ids: Vec<&str> = rows.iter().map(|x| x.site_id.as_str()).collect();
                        ids.sort_unstable();
                        ids.dedup();
                        ids.len()
                    };
                    format!(
                        "{} app grant{} across {} site{} — scanned {} of {} sites{}{}",
                        rows.len(),
                        if rows.len() == 1 { "" } else { "s" },
                        distinct_sites,
                        if distinct_sites == 1 { "" } else { "s" },
                        r.sites_scanned,
                        r.total_sites,
                        if r.sites_failed > 0 {
                            format!(" ({} failed — coverage is partial)", r.sites_failed)
                        } else {
                            String::new()
                        },
                        if r.cancelled {
                            " — scan was cancelled early"
                        } else {
                            ""
                        },
                    )
                })
            })
        })
    });

    // Subscribe to sweep progress for this view's lifetime; abort on unmount so
    // the stream task doesn't leak or race a remount's task (audit pattern).
    use_progress_stream(progress, events::site_sweep_progress);

    // Hydrate from the backend cache on tenant change, clearing stale state
    // synchronously and guarding the async write against a tenant switch.
    Effect::new(move |_| {
        let t = tenant.get();
        result.set(None);
        error.set(None);
        progress.set(None);
        consent_required.set(false);
        let Some(t) = t else { return };
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let cached = sharepoint::get_cached_site_sweep(&tenant_id)
                .await
                .ok()
                .flatten();
            let still_active = tenant
                .get_untracked()
                .map(|t| t.tenant_id == tenant_id)
                .unwrap_or(false);
            if still_active {
                result.set(cached);
            }
        });
    });

    // Zero-arg so the Scan button and the post-consent retry share it.
    let do_run = move || {
        if scanning.get() {
            return;
        }
        scanning.set(true);
        error.set(None);
        consent_required.set(false);
        progress.set(Some(SiteSweepProgress {
            done: 0,
            total: 0,
            current_site: None,
            cancelled: false,
        }));
        let t = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                scanning.set(false);
                return;
            };
            match sharepoint::sweep_site_permissions(&t.tenant_id).await {
                Ok(r) => result.set(Some(r)),
                Err(e) => {
                    consent_required.set(e.code == "consent_required");
                    error.set(Some(e.message));
                }
            }
            scanning.set(false);
            progress.set(None);
        });
    };

    // Interactive consent for the SharePoint scope, then re-run the sweep.
    let grant_consent = move |_| {
        if scanning.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        error.set(None);
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&t.tenant_id, "sharepoint").await {
                Ok(()) => do_run(),
                Err(e) => error.set(Some(e.message)),
            }
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            let _ = sharepoint::cancel_resource_sweep().await;
        });
    };

    view! {
        <Body1>
            "Scans every enumerable site's application permissions; search by app to see its granted sites (Sites.Selected), or by site to see who can touch it."
        </Body1>
        <div class="actions-row">
            {move || {
                if scanning.get() {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(cancel)
                        >
                            "Cancel"
                        </Button>
                    }
                        .into_any()
                } else {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| do_run())
                        >
                            {if result.with(|r| r.is_some()) {
                                "Re-scan sites"
                            } else {
                                "Scan sites"
                            }}
                        </Button>
                    }
                        .into_any()
                }
            }}
            <div class="page__search">
                <SearchInput value=search placeholder="Filter by site, app name, or app id…" />
            </div>
        </div>
        {move || {
            progress
                .get()
                .filter(|_| scanning.get())
                .map(|p| {
                    let pct = if p.total == 0 {
                        0.0
                    } else {
                        p.done as f64 / p.total as f64
                    };
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
            if result.with(|r| r.is_none()) {
                return (!scanning.get())
                    .then(|| {
                        view! {
                            <Body1>
                                "No scan yet for this tenant. Scanning reads every site's application permissions with the signed-in user's SharePoint admin rights — it can take a while on large tenants and can be cancelled anytime."
                            </Body1>
                        }
                            .into_any()
                    })
                    .unwrap_or_else(|| ().into_any());
            }
            // The shell renders once per sweep; the summary line and the keyed
            // <For> react to search changes on their own, so a keystroke diffs
            // rows instead of tearing down the whole table.
            // Clone the keynav handler into the nested <Show> body so this outer
            // reactive closure stays `Fn` (only borrows the captured handler).
            let on_grid_key = on_grid_key.clone();
            view! {
                <Body1 class="page__summary">{move || summary.get().unwrap_or_default()}</Body1>
                <Show
                    when=move || filtered_rows.with(|r| !r.is_empty())
                    fallback=|| {
                        view! {
                            <Body1>
                                "No application grants match. Sites without app permissions don't produce rows — only the Sites.Selected model creates per-site grants (org-wide Sites.* holders reach every site without appearing here; see the Security audit for those)."
                            </Body1>
                        }
                    }
                >
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>"Site"</th>
                                <th>"Application"</th>
                                <th>"Roles"</th>
                            </tr>
                        </thead>
                        <tbody node_ref=tbody_ref on:keydown=on_grid_key.clone()>
                            <For
                                each=move || {
                                    let limit = render_limit.get();
                                    filtered_rows
                                        .with(|r| r.iter().take(limit).cloned().collect::<Vec<_>>())
                                }
                                key=|row| (row.site_id.clone(), row.permission_id.clone())
                                children=move |row| {
                                    let site_primary = row
                                        .site_display_name
                                        .clone()
                                        .or_else(|| row.site_url.clone())
                                        .unwrap_or_else(|| row.site_id.clone());
                                    let site_secondary = row.site_url.clone().unwrap_or_default();
                                    let app_primary = row
                                        .app_display_name
                                        .clone()
                                        .or_else(|| row.app_id.clone())
                                        .unwrap_or_else(|| "(unknown app)".into());
                                    let app_secondary = row.app_id.clone().unwrap_or_default();
                                    view! {
                                        <tr>
                                            <td class="permission-cell">
                                                <div class="permissions-cell__primary">{site_primary}</div>
                                                <div class="permissions-cell__secondary mono">{site_secondary}</div>
                                            </td>
                                            <td class="permission-cell">
                                                <div class="permissions-cell__primary">{app_primary}</div>
                                                <div class="permissions-cell__secondary mono">{app_secondary}</div>
                                            </td>
                                            <td class="cell-mid">{row.roles.join(", ")}</td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                    {move || {
                        let total = filtered_rows.with(|r| r.len());
                        let limit = render_limit.get();
                        (total > limit)
                            .then(|| {
                                let remaining = total - limit;
                                let next = RENDER_PAGE.min(remaining);
                                view! {
                                    <div class="audit-show-more">
                                        <Body1>
                                            {format!("Showing {limit} of {total} matching rows")}
                                        </Body1>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| {
                                                render_limit.update(|n| *n += RENDER_PAGE)
                                            })
                                        >
                                            {format!("Show {next} more")}
                                        </Button>
                                    </div>
                                }
                            })
                    }}
                </Show>
            }
                .into_any()
        }}
    }
}

/// Verdict badge class — org-wide reach reads as a warning, confined access as
/// ok, everything else neutral.
fn verdict_badge(verdict: &str) -> (&'static str, &'static str) {
    match verdict {
        "org_wide" => ("badge badge--warning", "Org-wide"),
        "scoped" => ("badge badge--ok", "Scoped"),
        "no_access" => ("badge", "No access"),
        _ => ("badge", "Unknown"),
    }
}

#[component]
fn MailboxesPanel() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<MailboxReachersResult>> = RwSignal::new(None);
    let probing = RwSignal::new(false);
    let progress: RwSignal<Option<MailboxProbeProgress>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let mailbox = RwSignal::new(String::new());
    // Render window for the reachers table — bounded DOM on a large result.
    let render_limit = RwSignal::new(RENDER_PAGE);
    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    let on_grid_key = use_grid_keynav(tbody_ref, move || {
        let _ = render_limit.get();
        let _ = result.with(|r| r.as_ref().map(|x| x.rows.len()));
    });
    Effect::new(move |prev: Option<()>| {
        result.track();
        if prev.is_some() {
            render_limit.set(RENDER_PAGE);
        }
    });

    use_progress_stream(progress, events::mailbox_probe_progress);

    // A probe result is mailbox- and tenant-specific: clear it on tenant switch
    // so another tenant's verdicts can never linger (cross-tenant leakage).
    Effect::new(move |_| {
        let _ = tenant.get();
        result.set(None);
        error.set(None);
        progress.set(None);
        mailbox.set(String::new());
    });

    let do_probe = move || {
        if probing.get() {
            return;
        }
        let mb = mailbox.get().trim().to_string();
        if mb.is_empty() {
            error.set(Some(
                "Enter a mailbox address (e.g. shared@contoso.com).".into(),
            ));
            return;
        }
        probing.set(true);
        error.set(None);
        progress.set(Some(MailboxProbeProgress {
            done: 0,
            total: 0,
            current_app: None,
            cancelled: false,
        }));
        let t = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                probing.set(false);
                return;
            };
            match permission_tester::find_mailbox_reachers(&t.tenant_id, &mb).await {
                Ok(r) => result.set(Some(r)),
                Err(e) => error.set(Some(e.message)),
            }
            probing.set(false);
            progress.set(None);
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            let _ = sharepoint::cancel_resource_sweep().await;
        });
    };

    view! {
        <Body1>
            "Lists every application holding a mail-scopable Graph permission and tests each against one mailbox via Exchange's authoritative authorization check — \"who can read this mailbox?\"."
        </Body1>
        <div class="actions-row">
            <div class="page__search">
                <Input value=mailbox placeholder="Mailbox address (e.g. shared@contoso.com)…" />
            </div>
            {move || {
                if probing.get() {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(cancel)
                        >
                            "Cancel"
                        </Button>
                    }
                        .into_any()
                } else {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| do_probe())
                        >
                            "Check mailbox"
                        </Button>
                    }
                        .into_any()
                }
            }}
        </div>
        {move || {
            progress
                .get()
                .filter(|_| probing.get())
                .map(|p| {
                    let pct = if p.total == 0 {
                        0.0
                    } else {
                        p.done as f64 / p.total as f64
                    };
                    view! {
                        <div class="audit-progress">
                            <ProgressBar value=Signal::derive(move || pct) />
                            <Body1>
                                {format!(
                                    "{} / {} candidate apps{}{}",
                                    p.done,
                                    p.total,
                                    p.current_app.as_deref().map(|s| format!(" — {s}")).unwrap_or_default(),
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
                .map(|e| view! { <div class="alert alert--warn"><Body1>{e}</Body1></div> })
        }}
        {move || {
            let Some(r) = result.get() else {
                return ().into_any();
            };
            let reachers = r
                .rows
                .iter()
                .filter(|x| x.verdict == "org_wide" || x.verdict == "scoped")
                .count();
            let summary = format!(
                "{} of {} candidate app{} can reach “{}”{}{}",
                reachers,
                r.total_candidates,
                if r.total_candidates == 1 { "" } else { "s" },
                r.mailbox,
                if r.exchange_available {
                    ""
                } else {
                    " — Exchange was unavailable, so verdicts derive from the Entra grants alone (org-wide unless scoped; never under-reported)"
                },
                if r.cancelled { " — probe was cancelled early" } else { "" },
            );
            view! {
                <Body1 class="page__summary">{summary}</Body1>
                {if r.rows.is_empty() {
                    view! {
                        <Body1>
                            "No application in this tenant holds a mail-scopable Graph application permission or an Exchange RBAC-for-Applications registration — nothing can read mailboxes app-only via Graph."
                        </Body1>
                    }
                        .into_any()
                } else {
                    let total = r.rows.len();
                    let limit = render_limit.get();
                    let rows: Vec<MailboxReacherRow> =
                        r.rows.iter().take(limit).cloned().collect();
                    view! {
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>"Application"</th>
                                    <th>"Holds"</th>
                                    <th>"Verdict"</th>
                                    <th>"Detail"</th>
                                </tr>
                            </thead>
                            <tbody node_ref=tbody_ref on:keydown=on_grid_key.clone()>
                                {rows
                                    .into_iter()
                                    .map(|row| {
                                        let (badge_class, badge_label) = verdict_badge(&row.verdict);
                                        let app_primary = row
                                            .display_name
                                            .clone()
                                            .unwrap_or_else(|| row.app_id.clone());
                                        let roles = if row.roles.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" — via {}", row.roles.join(", "))
                                        };
                                        view! {
                                            <tr>
                                                <td class="permission-cell">
                                                    <div class="permissions-cell__primary">{app_primary}</div>
                                                    <div class="permissions-cell__secondary mono">{row.app_id}</div>
                                                </td>
                                                <td class="cell-mid">{row.held_permissions.join(", ")}</td>
                                                <td class="cell-mid">
                                                    <span class=badge_class>{badge_label}</span>
                                                </td>
                                                <td>{format!("{}{roles}", row.detail.unwrap_or_default())}</td>
                                            </tr>
                                        }
                                    })
                                    .collect_view()}
                            </tbody>
                        </table>
                        {(total > limit)
                            .then(|| {
                                let remaining = total - limit;
                                let next = RENDER_PAGE.min(remaining);
                                view! {
                                    <div class="audit-show-more">
                                        <Body1>
                                            {format!("Showing {limit} of {total} apps")}
                                        </Body1>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| {
                                                render_limit.update(|n| *n += RENDER_PAGE)
                                            })
                                        >
                                            {format!("Show {next} more")}
                                        </Button>
                                    </div>
                                }
                            })}
                    }
                        .into_any()
                }}
            }
                .into_any()
        }}
    }
}
