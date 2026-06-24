//! Security audit dashboard.
//! CSV export goes through the OS save dialog (backend `tauri-plugin-dialog`)
//! rather than the React-side `Blob`/`URL.createObjectURL` path.

mod filter;
mod row;
mod sort;

use crate::hooks::use_progress_stream::use_progress_stream;
use azapptoolkit_core::audit::{AuditItem, RiskLevel, issue};
use leptos::prelude::*;
use thaw::{
    Body1, Button, ButtonAppearance, Menu, MenuItem, MenuPosition, MenuTrigger, ProgressBar,
    Spinner, SpinnerSize,
};

use crate::bindings::audit::{self, AuditProgress, AuditRunResult};
use crate::bindings::auth;
use crate::bindings::events;
use crate::components::bulk_action_bar::BulkActionBar;
use crate::components::filter_chip::FilterChip;
use crate::components::filter_toggle::FilterToggle;
use crate::components::saved_views::SavedViews;
use crate::components::select_all_bar::SelectAllBar;
use crate::components::ui::{SearchInput, SectionHeader, TabBar, TabBarItem};
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::state::use_session;

use filter::filter_indices;
use row::AuditRowActions;
use sort::SortCol;

#[component]
pub fn AuditView() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<AuditRunResult>> = RwSignal::new(None);
    // When a row's remediation succeeds, drop that item's remediations so the
    // "Fix" button is gone for good (the audit cache is already busted
    // server-side; scores refresh on the next manual re-run).
    let on_remediated = Callback::new(move |object_id: String| {
        result.update(|opt| {
            if let Some(r) = opt.as_mut()
                && let Some(item) = r.items.iter_mut().find(|i| i.object_id == object_id)
            {
                item.remediations.clear();
            }
        });
    });
    // After a successful inline bulk run, refetch the App Registrations list
    // (a delete / remove-expired sweep busts its backend cache). The audit's own
    // scan is a point-in-time snapshot — the bar clears the audit selection on
    // delete; deleted rows linger until the next manual re-run, matching how the
    // audit cache already works.
    let on_bulk_done = Callback::new(move |_| session.bump_apps_reload());
    let scanning = RwSignal::new(false);
    let progress: RwSignal<Option<AuditProgress>> = RwSignal::new(None);
    // High-water concurrency cap. When the live cap later drops below this peak,
    // Graph is throttling and the scan is backing off — surfaced below so a slow
    // audit reads as expected, not stalled (mirrors the DR backup view).
    // Monotonic within a run; reset when a new run clears `progress`.
    let peak_cap = RwSignal::new(0usize);
    Effect::new(move |_| match progress.get() {
        Some(p) => peak_cap.update(|peak| *peak = (*peak).max(p.in_flight_cap)),
        None => peak_cap.set(0),
    });
    let scan_error: RwSignal<Option<String>> = RwSignal::new(None);
    // Two INDEPENDENT, intersecting filter dimensions, both lifted to the session
    // so the Home "Security Posture" metrics can deep-link straight to a subset
    // (e.g. Critical rows, or Unused) and reset on tenant switch. The severity
    // TabBar + the Risk scorecard cards drive `severity`; the finding FilterChip
    // drawer + the Findings cards drive `finding`. Filter = severity AND finding.
    let severity = session.audit_severity;
    let finding = session.audit_finding;
    // The audit table's own multi-select set (separate from the App
    // Registrations list's `selected_app_ids`), feeding the inline bulk bar.
    let selection = session.selected_audit_ids;
    let search = RwSignal::new(String::new());
    // Collapsible drawer for the secondary "finding" chips, so the default view
    // is just the severity tabs + search. Badged when a finding filter is active
    // but hidden behind the collapsed drawer.
    let filters_open = RwSignal::new(false);
    let active_filters = Signal::derive(move || finding.with(|f| (f != "all") as usize));
    // Column sort: `None` keeps the backend's risk-ranked order. `Some((col,
    // desc))` sorts the filtered indices by that column.
    let sort: RwSignal<Option<(SortCol, bool)>> = RwSignal::new(None);
    let exporting = RwSignal::new(false);
    let export_msg: RwSignal<Option<String>> = RwSignal::new(None);

    // Derived views of the result, computed with `.with()` so the multi-MB
    // `AuditRunResult` is never cloned wholesale — previously every keystroke
    // deep-cloned it for the table, and the posture/consent closures cloned it
    // again for a handful of integers.
    let search_debounced = use_debounced(search.into(), LIST_FILTER_DEBOUNCE_MS);
    // Per-bucket counts driving both the scorecard cards and the finding chip
    // badges. Depends only on `result`, so it's computed once per scan (not per
    // keystroke) and never clones the multi-MB run. Finding counts are
    // tenant-wide totals (not intersected with the active severity) — they match
    // the scorecard numbers and the chips' zero-count muting.
    let posture_counts = Memo::new(move |_| {
        result.with(|r| {
            r.as_ref().map(|r| {
                let items = &r.items;
                PostureCounts {
                    critical: count_level(items, RiskLevel::Critical),
                    high: count_level(items, RiskLevel::High),
                    medium: count_level(items, RiskLevel::Medium),
                    low: count_level(items, RiskLevel::Low),
                    expiring: count_expiring(items),
                    unused: items.iter().filter(|i| i.unused).count(),
                    over_privileged: count_issue_prefix(items, issue::HIGH_RISK_APP_PERMS),
                    high_risk_delegated: count_issue_prefix(
                        items,
                        issue::HIGH_RISK_DELEGATED_PERMS,
                    ),
                    orgwide_mailbox: count_issue_prefix(items, issue::ORG_WIDE_MAILBOX),
                    scoped_mailbox: items
                        .iter()
                        .filter(|i| i.issues.iter().any(|x| x.contains(issue::SCOPED_VIA_RBAC)))
                        .count(),
                    orgwide_sharepoint: count_issue_prefix(items, issue::ORG_WIDE_SHAREPOINT),
                    scoped_sites: count_issue_prefix(items, issue::SCOPED_SHAREPOINT),
                    unowned: items
                        .iter()
                        .filter(|i| {
                            i.issues.iter().any(|x| {
                                x.starts_with(issue::NO_OWNERS)
                                    || x.starts_with(issue::SINGLE_OWNER)
                            })
                        })
                        .count(),
                }
            })
        })
    });
    let consent_needed =
        Memo::new(move |_| result.with(|r| r.as_ref().is_some_and(|r| r.sign_in_consent_required)));
    let total_items = Memo::new(move |_| result.with(|r| r.as_ref().map(|r| r.items.len())));
    let report_available =
        Memo::new(move |_| result.with(|r| r.as_ref().is_some_and(|r| r.sign_in_report_available)));
    // Filter to row INDICES, not cloned items: a keystroke/facet click rescans
    // to a `Vec<usize>` (no `AuditItem` clones), and the renderer below clones
    // only the rows it actually draws. Previously this memo deep-cloned every
    // matching item, and the `<For>` cloned the whole `Vec` again — twice the
    // multi-MB set per keystroke on a large tenant.
    let filtered = Memo::new(move |_| {
        let sev = severity.get();
        let fnd = finding.get();
        let q = search_debounced.get().to_lowercase();
        let srt = sort.get();
        result.with(|r| {
            r.as_ref()
                .map(|r| {
                    let mut idx = filter_indices(&r.items, &sev, &fnd, &q);
                    if let Some((col, desc)) = srt {
                        // Stable sort over indices — reads the column value from
                        // the items by index, never cloning a row.
                        idx.sort_by(|&a, &b| {
                            let (ia, ib) = (&r.items[a], &r.items[b]);
                            let ord = match col {
                                SortCol::Name => ia
                                    .application_name
                                    .to_lowercase()
                                    .cmp(&ib.application_name.to_lowercase()),
                                SortCol::Score => ia.risk_score.cmp(&ib.risk_score),
                                SortCol::LastSignIn => ia.last_sign_in.cmp(&ib.last_sign_in),
                            };
                            if desc { ord.reverse() } else { ord }
                        });
                    }
                    idx
                })
                .unwrap_or_default()
        })
    });

    // Click a sortable header: cycle default-direction → reverse → unsorted.
    let toggle_sort = move |col: SortCol| {
        sort.update(|s| {
            *s = match *s {
                Some((c, desc)) if c == col => {
                    if desc == col.default_desc() {
                        Some((col, !desc))
                    } else {
                        None
                    }
                }
                _ => Some((col, col.default_desc())),
            };
        });
    };
    // Sort-direction glyph for a header (empty when that column isn't the sort).
    let sort_glyph = move |col: SortCol| -> &'static str {
        match sort.get() {
            Some((c, desc)) if c == col => {
                if desc {
                    " ↓"
                } else {
                    " ↑"
                }
            }
            _ => "",
        }
    };

    // Render window. The audit table is the one view guaranteed to hold every
    // app in the tenant; rendering all matched rows at once builds ~15 nodes ×
    // 10k rows = a multi-second main-thread stall. Draw the first page and grow
    // on demand, keeping the DOM bounded and the keyed table/keyboard-nav intact.
    let render_limit = RwSignal::new(RENDER_PAGE);
    // Reset the window to the first page whenever the filter changes or a new
    // scan lands a different item set. Tracks facet/search/total — an in-place
    // remediation changes none of those, so an expanded window survives a Fix.
    Effect::new(move |prev: Option<()>| {
        severity.track();
        finding.track();
        search_debounced.track();
        total_items.track();
        sort.track();
        if prev.is_some() {
            render_limit.set(RENDER_PAGE);
        }
    });

    // Roving-tabindex keyboard navigation for the results table — Arrow/Home/End
    // move between rows and Enter activates the row's first button (its "Open"
    // deep-link), matching the lens tables (which get it via AuditDashboard).
    // Reseeded whenever the filtered row set changes (covers facet, search, and
    // scan-result changes).
    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    let on_grid_key = use_grid_keynav(tbody_ref, move || {
        // Reseed on the rendered row set: filter changes AND window growth
        // (Show more) both add/remove navigable rows.
        let _ = filtered.with(|f| f.len());
        let _ = render_limit.get();
    });

    // Subscribe to audit-progress events for this view's lifetime, and abort
    // the stream task on unmount so it doesn't leak or race a remount's task.
    use_progress_stream(progress, events::audit_progress);

    // Hydrate from cache when tenant changes. Clear stale state synchronously so
    // the previous tenant's table never lingers, then guard the async write
    // against a tenant-changed race: if the user switches tenants (or two cache
    // loads resolve out of order) while `get_cached_audit` is in flight, drop
    // the late result instead of clobbering the now-active tenant's view.
    Effect::new(move |_| {
        let t = tenant.get();
        // Reset transient per-tenant state up front (tracked read above, plain
        // writes here — Effect re-runs only on `tenant` changing).
        result.set(None);
        scan_error.set(None);
        progress.set(None);
        let Some(t) = t else { return };
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let cached = audit::get_cached_audit(&tenant_id).await;
            // Only apply if this tenant is still the active one.
            let still_active = tenant
                .get_untracked()
                .map(|t| t.tenant_id == tenant_id)
                .unwrap_or(false);
            if still_active {
                result.set(cached);
            }
        });
    });

    // Zero-arg so it drives both the "Run audit" button and the post-consent
    // re-run (after enabling the sign-in report) without the event arg leaking.
    let do_run = move || {
        if scanning.get() {
            return;
        }
        scanning.set(true);
        scan_error.set(None);
        progress.set(Some(AuditProgress {
            done: 0,
            total: 0,
            current_app: None,
            in_flight_cap: 8,
            cancelled: false,
        }));
        let t = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                scanning.set(false);
                return;
            };
            match audit::run_audit(&t.tenant_id).await {
                Ok(r) => {
                    result.set(Some(r));
                    // Refresh the Home dashboard's "Security Posture" tile: it
                    // keeps its cached-audit resource alive across view switches
                    // (keep-alive panes), so it only refetches when this bumps.
                    session.bump_audit_reload();
                }
                Err(e) => scan_error.set(Some(e.message)),
            }
            scanning.set(false);
            progress.set(None);
        });
    };

    // Grants AuditLog.Read.All (the sign-in activity report behind the Unused
    // tab), then re-runs the audit so unused apps populate.
    let grant_reports_consent = move |_| {
        if scanning.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        scan_error.set(None);
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&t.tenant_id, "audit_log").await {
                Ok(()) => do_run(),
                Err(e) => scan_error.set(Some(e.message)),
            }
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            audit::cancel_audit().await;
        });
    };

    let export = move |format: &'static str| {
        if exporting.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        // Export by reference: the backend serves its own cached run, so the
        // item vector doesn't round-trip the IPC bridge. Only a CANCELLED run
        // (never cached backend-side) ships its items along.
        let (empty, cancelled_items) = result.with(|r| match r.as_ref() {
            Some(r) => (r.items.is_empty(), r.cancelled.then(|| r.items.clone())),
            None => (true, None),
        });
        if empty {
            return;
        }
        exporting.set(true);
        export_msg.set(None);
        leptos::task::spawn_local(async move {
            match audit::save_audit_to_file(&t.tenant_id, cancelled_items.as_deref(), format).await
            {
                Ok(Some(path)) => export_msg.set(Some(format!("Saved to {path}"))),
                Ok(None) => {} // user cancelled
                Err(e) => export_msg.set(Some(format!("Export failed: {}", e.message))),
            }
            exporting.set(false);
        });
    };

    view! {
        <main class="audit-view">
            <SectionHeader title="Security audit".to_string() crumb="Tenant health".to_string()>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| do_run())
                    disabled=Signal::derive(move || scanning.get())
                >
                    {move || {
                        if scanning.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                .into_any()
                        } else {
                            view! { "Run audit" }.into_any()
                        }
                    }}
                </Button>
                <Show when=move || scanning.get() fallback=|| view! { <></> }>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(cancel)
                    >
                        "Cancel"
                    </Button>
                </Show>
                <Menu
                    position=MenuPosition::BottomEnd
                    on_select=move |fmt: String| {
                        match fmt.as_str() {
                            "csv" => export("csv"),
                            "json" => export("json"),
                            "html" => export("html"),
                            _ => {}
                        }
                    }
                >
                    <MenuTrigger slot>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                            disabled=Signal::derive(move || {
                                exporting.get() || result.with(|r| r.is_none())
                            })
                        >
                            "Export ▾"
                        </Button>
                    </MenuTrigger>
                    <MenuItem value="csv".to_string()>"Export as CSV…"</MenuItem>
                    <MenuItem value="json".to_string()>"Export as JSON…"</MenuItem>
                    <MenuItem value="html".to_string()>"Export as HTML…"</MenuItem>
                </Menu>
            </SectionHeader>
            {move || {
                progress
                    .get()
                    .map(|p| {
                        let pct = if p.total > 0 {
                            (p.done as f64) / (p.total as f64)
                        } else {
                            0.0
                        };
                        let cap = p.in_flight_cap;
                        view! {
                            <div class="audit-progress">
                                <ProgressBar value=Signal::derive(move || pct) />
                                <Body1>
                                    {format!(
                                        "{} / {} apps  (cap: {}{})",
                                        p.done,
                                        p.total,
                                        cap,
                                        if p.cancelled { ", cancelled" } else { "" },
                                    )}
                                </Body1>
                                {p.current_app.map(|n| view! { <Body1>{n}</Body1> })}
                                <Show when=move || cap < peak_cap.get()>
                                    <p class="audit-progress__notice" role="status">
                                        "Microsoft Graph is rate-limiting this scan, so it's automatically slowing down to recover. It will still complete — large tenants just take longer."
                                    </p>
                                </Show>
                            </div>
                        }
                    })
            }}
            {move || {
                scan_error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
            }}
            {move || {
                export_msg.get().map(|m| view! { <div class="alert alert--ok">{m}</div> })
            }}
            // Primary filter dimension: risk severity, always visible.
            <TabBar
                selected=severity
                items=vec![
                    TabBarItem { value: "all", label: "All" },
                    TabBarItem { value: "critical", label: "Critical" },
                    TabBarItem { value: "high", label: "High" },
                    TabBarItem { value: "medium", label: "Medium" },
                    TabBarItem { value: "low", label: "Low" },
                ]
            />
            <SearchInput value=search placeholder="Filter by name or appId…" />
            // Secondary filter dimension: finding type, behind a collapsible
            // drawer so the default view stays the severity tabs + search. The
            // chips intersect with the active severity (filter = severity AND
            // finding); counts are tenant-wide totals matching the scorecard.
            <FilterToggle open=filters_open active_count=active_filters />
            <Show when=move || filters_open.get()>
                <SavedViews view_key="audit" facet=severity search=search />
                {move || {
                    posture_counts
                        .get()
                        .map(|c| {
                            view! {
                                <div class="filter-chips">
                                    <FilterChip
                                        label="All"
                                        value="all"
                                        count=total_items.get().unwrap_or(0)
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="Expiring"
                                        value="expiring"
                                        count=c.expiring
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="Unused"
                                        value="unused"
                                        count=c.unused
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="Over-privileged"
                                        value="high_risk_perms"
                                        count=c.over_privileged
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="High-risk delegated"
                                        value="high_risk_delegated"
                                        count=c.high_risk_delegated
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="Org-wide mailbox"
                                        value="orgwide_mailbox"
                                        count=c.orgwide_mailbox
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="Scoped mailbox"
                                        value="scoped_mailbox"
                                        count=c.scoped_mailbox
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="Org-wide SharePoint"
                                        value="orgwide_sharepoint"
                                        count=c.orgwide_sharepoint
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="Scoped sites"
                                        value="scoped_sites"
                                        count=c.scoped_sites
                                        facet=finding
                                    />
                                    <FilterChip
                                        label="Unowned"
                                        value="ownership"
                                        count=c.unowned
                                        facet=finding
                                    />
                                </div>
                            }
                        })
                }}
            </Show>
            // Posture scorecard — clickable summary counts grouped by Risk
            // (seed `severity`) and Findings (seed `finding`). Each card sets its
            // own dimension and leaves the sibling untouched, so a Risk card and a
            // Findings card compose (e.g. Critical + Over-privileged). Shown once
            // an audit has populated `result`.
            {move || {
                posture_counts
                    .get()
                    .map(|c| {
                        view! {
                            <div class="audit-scorecard">
                                <div class="audit-scorecard__group">
                                    <span class="audit-scorecard__label">"Risk"</span>
                                    <div class="dash-metrics audit-cards">
                                        {posture_card("Critical", c.critical, "danger", "critical", severity)}
                                        {posture_card("High", c.high, "danger", "high", severity)}
                                        {posture_card("Medium", c.medium, "warning", "medium", severity)}
                                        {posture_card("Low", c.low, "muted", "low", severity)}
                                    </div>
                                </div>
                                <div class="audit-scorecard__group">
                                    <span class="audit-scorecard__label">"Findings"</span>
                                    <div class="dash-metrics audit-cards">
                                        {posture_card("Expiring", c.expiring, "warning", "expiring", finding)}
                                        {posture_card("Unused", c.unused, "warning", "unused", finding)}
                                        {posture_card(
                                            "Over-privileged",
                                            c.over_privileged,
                                            "danger",
                                            "high_risk_perms",
                                            finding,
                                        )}
                                        {posture_card(
                                            "High-risk delegated",
                                            c.high_risk_delegated,
                                            "warning",
                                            "high_risk_delegated",
                                            finding,
                                        )}
                                        {posture_card(
                                            "Org-wide mailbox",
                                            c.orgwide_mailbox,
                                            "warning",
                                            "orgwide_mailbox",
                                            finding,
                                        )}
                                        {posture_card(
                                            "Org-wide SharePoint",
                                            c.orgwide_sharepoint,
                                            "warning",
                                            "orgwide_sharepoint",
                                            finding,
                                        )}
                                        {posture_card("Unowned", c.unowned, "warning", "ownership", finding)}
                                    </div>
                                </div>
                            </div>
                        }
                    })
            }}
            // AuditLog.Read.All consent prompt — the sign-in activity report
            // (behind the Unused tab) needs it. Offered when the last run found it
            // un-consented; granting re-runs the audit.
            {move || {
                consent_needed
                    .get()
                    .then(|| {
                        view! {
                            <div class="alert alert--warn">
                                "Unused-app detection needs the AuditLog.Read.All permission (it reads each app's last sign-in). Grant consent to enable it — requires a Global Reader / Security Reader / Reports Reader role and Entra ID P1 or P2."
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(grant_reports_consent)
                                        disabled=Signal::derive(move || scanning.get())
                                    >
                                        "Grant consent & re-run"
                                    </Button>
                                </div>
                            </div>
                        }
                    })
            }}
            {move || {
                if total_items.get().is_none() {
                    return view! { <Body1>"Run an audit to populate this view."</Body1> }
                        .into_any();
                }
                // The table shell renders once per scan; the count line and the
                // keyed <For> below react to filter changes on their own, so a
                // facet click or keystroke diffs rows by key instead of tearing
                // down the whole <tbody>.
                view! {
                    <div>
                        // Inline bulk-action bar — self-gating: visible once ≥1
                        // row is checked, and stays to show the result summary
                        // after a run clears the selection.
                        <BulkActionBar selection=selection on_done=on_bulk_done />
                        // Tri-state select-all + result count. `visible_ids` is the
                        // object_ids of every row matching the active filters (not
                        // just the rendered window), so "select all visible" covers
                        // the whole filtered set. Rebuilt when the filter changes.
                        {move || {
                            let (count_label, visible_ids) = filtered
                                .with(|idx| {
                                    let label = format!(
                                        "{} of {} apps match",
                                        idx.len(),
                                        total_items.get().unwrap_or(0),
                                    );
                                    let ids = result
                                        .with(|r| {
                                            r.as_ref()
                                                .map(|r| {
                                                    idx.iter()
                                                        .filter_map(|&i| {
                                                            r.items.get(i).map(|it| it.object_id.clone())
                                                        })
                                                        .collect::<Vec<_>>()
                                                })
                                                .unwrap_or_default()
                                        });
                                    (label, ids)
                                });
                            view! {
                                <SelectAllBar
                                    count_label=count_label
                                    visible_ids=visible_ids
                                    selected=selection
                                />
                            }
                        }}
                        {move || {
                            filtered
                                .with(|f| f.is_empty())
                                .then(|| {
                                    let msg = empty_facet_message(
                                        &finding.get(),
                                        report_available.get(),
                                    );
                                    view! { <div class="alert">{msg}</div> }
                                })
                        }}
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th class="data-table__check" aria-label="Select"></th>
                                    <th>
                                        <button
                                            class="th-sort"
                                            type="button"
                                            on:click=move |_| toggle_sort(SortCol::Name)
                                        >
                                            "Application"
                                            {move || sort_glyph(SortCol::Name)}
                                        </button>
                                    </th>
                                    <th>"AppId"</th>
                                    <th>
                                        <button
                                            class="th-sort"
                                            type="button"
                                            title="Sort by risk score"
                                            on:click=move |_| toggle_sort(SortCol::Score)
                                        >
                                            "Risk"
                                        </button>
                                    </th>
                                    <th>
                                        <button
                                            class="th-sort"
                                            type="button"
                                            on:click=move |_| toggle_sort(SortCol::Score)
                                        >
                                            "Score"
                                            {move || sort_glyph(SortCol::Score)}
                                        </button>
                                    </th>
                                    <th>"Status"</th>
                                    <th>
                                        <button
                                            class="th-sort"
                                            type="button"
                                            on:click=move |_| toggle_sort(SortCol::LastSignIn)
                                        >
                                            "Last sign-in"
                                            {move || sort_glyph(SortCol::LastSignIn)}
                                        </button>
                                    </th>
                                    <th>"Issues"</th>
                                    <th>"Actions"</th>
                                </tr>
                            </thead>
                            <tbody node_ref=tbody_ref on:keydown=on_grid_key.clone()>
                                // Window over filtered INDICES: clone only the
                                // rows actually drawn (the first `render_limit`
                                // matches), not the whole matched set. Key carries
                                // the remediation count so a keyed row re-renders
                                // only when its key changes — the one in-place
                                // mutation this view performs is `on_remediated`
                                // clearing an item's remediations (Fix must vanish).
                                <For
                                    each=move || {
                                        let limit = render_limit.get();
                                        filtered.with(|idx| {
                                            result
                                                .with(|r| {
                                                    r.as_ref()
                                                        .map(|r| {
                                                            idx.iter()
                                                                .take(limit)
                                                                .filter_map(|&i| {
                                                                    r.items.get(i).map(|it| (i, it.clone()))
                                                                })
                                                                .collect::<Vec<_>>()
                                                        })
                                                        .unwrap_or_default()
                                                })
                                        })
                                    }
                                    key=|(_, i)| (i.object_id.clone(), i.remediations.len())
                                    children=move |(_, i)| {
                                        let oid = i.object_id.clone();
                                        let oid_change = oid.clone();
                                        let check_label = format!(
                                            "Select {} for bulk actions",
                                            i.application_name,
                                        );
                                        view! {
                                            <tr>
                                                <td class="data-table__check">
                                                    <input
                                                        type="checkbox"
                                                        aria-label=check_label
                                                        prop:checked=move || session.is_audit_selected(&oid)
                                                        on:change=move |_| {
                                                            session.toggle_audit_selected(oid_change.clone())
                                                        }
                                                    />
                                                </td>
                                                <td>{i.application_name.clone()}</td>
                                                <td class="mono">{i.app_id.clone()}</td>
                                                <td>
                                                    <span class=format!(
                                                        "badge {}",
                                                        risk_class(&i.risk_level),
                                                    )>{i.risk_level.as_str()}</span>
                                                </td>
                                                <td>{i.risk_score}</td>
                                                <td>{i.credential_status.as_str()}</td>
                                                <td>{last_sign_in_cell(&i)}</td>
                                                <td>
                                                    <ul class="issues">
                                                        {i.issues
                                                            .iter()
                                                            .take(ISSUES_INLINE)
                                                            .map(|issue| view! { <li>{issue.clone()}</li> })
                                                            .collect_view()}
                                                        {(i.issues.len() > ISSUES_INLINE)
                                                            .then(|| {
                                                                let more = i.issues.len() - ISSUES_INLINE;
                                                                view! {
                                                                    <li class="issues__more">
                                                                        {format!("+{more} more — open to see all")}
                                                                    </li>
                                                                }
                                                            })}
                                                    </ul>
                                                </td>
                                                <td>
                                                    <AuditRowActions item=i.clone() on_done=on_remediated />
                                                </td>
                                            </tr>
                                        }
                                    }
                                />
                            </tbody>
                        </table>
                        // "Show more" grows the render window a page at a time.
                        // Shown only when matches exceed what's drawn.
                        {move || {
                            let matched = filtered.with(|f| f.len());
                            let limit = render_limit.get();
                            (matched > limit)
                                .then(|| {
                                    let remaining = matched - limit;
                                    let next = RENDER_PAGE.min(remaining);
                                    view! {
                                        <div class="audit-show-more">
                                            <Body1>
                                                {format!("Showing {limit} of {matched} matching rows")}
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
                    </div>
                }
                    .into_any()
            }}
        </main>
    }
}

fn risk_class(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "badge--critical",
        RiskLevel::High => "badge--danger",
        RiskLevel::Medium => "badge--warning",
        RiskLevel::Low => "badge--ok",
    }
}

/// Per-bucket counts for the posture scorecard and the finding chips, computed
/// once per scan from the audit run (never per keystroke). Finding counts are
/// tenant-wide totals — not intersected with the active severity.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PostureCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    expiring: usize,
    unused: usize,
    over_privileged: usize,
    high_risk_delegated: usize,
    orgwide_mailbox: usize,
    scoped_mailbox: usize,
    orgwide_sharepoint: usize,
    scoped_sites: usize,
    unowned: usize,
}

fn count_level(items: &[AuditItem], level: RiskLevel) -> usize {
    items.iter().filter(|i| i.risk_level == level).count()
}

fn count_expiring(items: &[AuditItem]) -> usize {
    use azapptoolkit_core::audit::CredentialStatus;
    items
        .iter()
        .filter(|i| {
            matches!(
                i.credential_status,
                CredentialStatus::ExpiringSoon | CredentialStatus::Expired
            )
        })
        .count()
}

fn count_issue_prefix(items: &[AuditItem], prefix: &str) -> usize {
    items
        .iter()
        .filter(|i| i.issues.iter().any(|x| x.starts_with(prefix)))
        .count()
}

/// One clickable posture card. Zero counts render muted; non-zero use the tone
/// colour. Clicking seeds the given filter dimension (`dim`) with `target` and
/// leaves the other dimension untouched, so a Risk card and a Findings card
/// compose.
fn posture_card(
    label: &'static str,
    n: usize,
    tone: &'static str,
    target: &'static str,
    dim: RwSignal<String>,
) -> impl IntoView {
    let num_class = if n == 0 {
        "dash-metric__num".to_string()
    } else {
        format!("dash-metric__num dash-metric__num--{tone}")
    };
    view! {
        <button
            class="dash-metric audit-card"
            type="button"
            on:click=move |_| dim.set(target.to_string())
        >
            <span class=num_class>{n}</span>
            <span class="dash-metric__label">{label}</span>
        </button>
    }
}

/// "Last sign-in" cell. Distinguishes never-signed-in from an unavailable report
/// (no `AuditLog.Read.All` / no Entra ID P1-P2) so an empty value isn't read as
/// "never used".
fn last_sign_in_cell(i: &AuditItem) -> AnyView {
    if !i.sign_in_report_available {
        return view! { <span class="muted" title="Sign-in report unavailable">"—"</span> }
            .into_any();
    }
    match i.last_sign_in {
        Some(dt) => view! { <span>{dt.format("%Y-%m-%d").to_string()}</span> }.into_any(),
        None => view! { <span class="muted">"Never"</span> }.into_any(),
    }
}

/// Contextual message when a filter yields no rows — most importantly explaining
/// why the Unused finding is empty when the sign-in report wasn't available.
fn empty_facet_message(finding: &str, sign_in_report_available: bool) -> &'static str {
    if finding == "unused" && !sign_in_report_available {
        "No unused apps to show: the sign-in activity report wasn't available. It needs the AuditLog.Read.All permission and Entra ID P1 or P2 — grant consent above and re-run to enable unused-app detection."
    } else {
        "No applications match this filter."
    }
}
