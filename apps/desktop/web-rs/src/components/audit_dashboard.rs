//! Shared tenant-wide audit dashboard.
//!
//! The credential-expiry, consent-grant, and application-permission views are
//! thin wrappers over this component — they share an identical scaffold
//! (fetch-on-tenant with a tenant-changed race guard, facet tabs, a search box,
//! saved views, CSV export, a caller-supplied risk banner, and a
//! keyboard-navigable `data-table`) and differ only in the row type, the
//! fetch/export IPC bindings, the facets, the columns, the banner, the filter
//! predicate, and the per-row markup. Those differences are the props.

use std::future::Future;

use azapptoolkit_dto::UiError;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Tab, TabList};

use crate::components::export_menu::ExportMenu;
use crate::components::icon::IconName;
use crate::components::saved_views::SavedViews;
use crate::components::ui::{
    DetailLoadError, EmptyState, IconButton, SearchInput, SectionHeader, SkeletonList,
};
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::state::use_session;

/// A generic tenant-wide audit table. See the module docs for the split between
/// the shared scaffold (here) and the per-view props.
#[component]
pub fn AuditDashboard<T, Fetch, FetchFut, Export, ExportFut, Banner, Matches, Row>(
    #[prop(into)] title: String,
    #[prop(into)] crumb: String,
    #[prop(into)] search_placeholder: String,
    /// Accessible name for the refresh control, e.g. `"Refresh credential
    /// expiry"` — an icon button needs a view-specific label, not "Refresh".
    #[prop(into)]
    refresh_label: String,
    /// Namespaces saved views in `localStorage` (e.g. `"credentials"`).
    view_key: &'static str,
    /// Plural-aware noun for the count line, e.g. `"credential(s)"`.
    #[prop(into)]
    noun: String,
    /// Shown when the filter matches nothing.
    #[prop(into)]
    empty_message: String,
    /// `(value, label)` facet tabs; the first should be the catch-all `"all"`.
    facets: Vec<(&'static str, &'static str)>,
    /// Optional external facet signal (lifted to `Session`) so a caller can seed
    /// the active facet from outside — e.g. the Home dashboard drilling into a
    /// specific Credential-expiry filter. Omitted → a fresh local `"all"` signal.
    #[prop(optional)]
    facet: Option<RwSignal<String>>,
    /// Column header labels (use `""` for an action column with no heading).
    headers: Vec<&'static str>,
    /// Fetches the rows for a tenant id.
    fetch: Fetch,
    /// Writes the rows to a user-chosen file in the given format (`"csv"` /
    /// `"json"`); `Ok(None)` = cancelled.
    export: Export,
    /// Optional alert banner derived from all rows (e.g. "N high-risk …").
    banner: Banner,
    /// Filter predicate: `(row, facet, lowercased_query) -> keep`.
    matches: Matches,
    /// Renders one `<tr>` for a row.
    row: Row,
) -> impl IntoView
where
    T: Clone + 'static,
    Fetch: Fn(String) -> FetchFut + 'static,
    FetchFut: Future<Output = Result<Vec<T>, UiError>> + 'static,
    Export: Fn(Vec<T>, &'static str) -> ExportFut + 'static,
    ExportFut: Future<Output = Result<Option<String>, UiError>> + 'static,
    Banner: Fn(&[T]) -> Option<AnyView> + 'static,
    Matches: Fn(&T, &str, &str) -> bool + 'static,
    Row: Fn(T) -> AnyView + 'static,
{
    let session = use_session();
    let tenant = session.active_tenant;

    let rows = RwSignal::new_local(Vec::<T>::new());
    let loading = RwSignal::new(false);
    // Keep the whole `UiError` (not a pre-formatted string) so the failure can
    // render through the shared `DetailLoadError`, which shows the code too.
    let error: RwSignal<Option<UiError>> = RwSignal::new(None);
    let reload = RwSignal::new(0_u32);
    // Use the caller-supplied (session-lifted) facet if given, else a local one.
    let facet = facet.unwrap_or_else(|| RwSignal::new(String::from("all")));
    let search = RwSignal::new(String::new());
    let exporting = RwSignal::new(false);

    // Non-`Send` closures live in single-threaded (CSR) storage, mirroring
    // `VirtualList`'s `render_row` handling.
    let fetch = StoredValue::new_local(fetch);
    let export = StoredValue::new_local(export);
    let banner = StoredValue::new_local(banner);
    let matches = StoredValue::new_local(matches);
    let row = StoredValue::new_local(row);
    // The owned `String`/`Vec` props are read inside the reactive render
    // closure; `view!` wraps each `{…}` text node in its own `move ||`, which
    // would move these out and make the render closure `FnOnce`. Holding them
    // as `Copy` `StoredValue` handles keeps it `Fn`.
    let noun = StoredValue::new_local(noun);
    let empty_message = StoredValue::new_local(empty_message);
    let headers = StoredValue::new_local(headers);

    // Fetch on tenant change / explicit reload. The async write is guarded
    // against a tenant-changed race so a late response can't clobber the active
    // tenant's view (the audit/credentials hydrate pattern).
    Effect::new(move |_| {
        let t = tenant.get();
        let _ = reload.get();
        rows.set(Vec::new());
        error.set(None);
        let Some(t) = t else { return };
        loading.set(true);
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let result = fetch.with_value(|f| f(tenant_id.clone())).await;
            let still_active = tenant
                .get_untracked()
                .map(|t| t.tenant_id == tenant_id)
                .unwrap_or(false);
            if still_active {
                match result {
                    Ok(r) => rows.set(r),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            }
        });
    });

    let on_export = move |format: &'static str| {
        if exporting.get() {
            return;
        }
        let data = rows.get();
        if data.is_empty() {
            return;
        }
        exporting.set(true);
        leptos::task::spawn_local(async move {
            match export.with_value(|f| f(data, format)).await {
                // Surface through the shared bottom-right toasts (like the
                // list-view exports), not a persistent inline banner.
                Ok(Some(path)) => {
                    session.toast_success(format!("Saved to {path}"));
                }
                Ok(None) => {} // user cancelled
                Err(e) => session.report_command_error(&e),
            }
            exporting.set(false);
        });
    };

    // Debounce the filter so a keystroke doesn't re-filter + re-render the whole
    // tenant-scale row set synchronously (these lenses hold thousands of rows).
    let search_debounced = use_debounced(search.into(), 200);
    // Render window — draw the first page, grow on demand, reset on filter change
    // or a new fetch (an in-place row mutation keeps the count, so the window
    // survives it). Mirrors the audit table.
    let render_limit = RwSignal::new(RENDER_PAGE);
    Effect::new(move |prev: Option<()>| {
        facet.track();
        search_debounced.track();
        let _ = rows.with(Vec::len);
        if prev.is_some() {
            render_limit.set(RENDER_PAGE);
        }
    });

    // Filter to INDICES in a MEMO, not inline in the render closure. Growing the
    // render window (or any unrelated reactive tick) must not re-run the
    // predicate over every row: at tenant scale these lenses hold thousands, and
    // "Show more" previously re-filtered the whole set before rebuilding the
    // table. Indices (not rows) keep this O(matched) `usize`s rather than a deep
    // clone of every match.
    let matched: Memo<Vec<usize>> = Memo::new(move |_| {
        let q = search_debounced.get().to_lowercase();
        let f = facet.get();
        rows.with(|all| {
            matches.with_value(|m| {
                all.iter()
                    .enumerate()
                    .filter(|(_, r)| m(r, &f, &q))
                    .map(|(i, _)| i)
                    .collect()
            })
        })
    });

    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    let on_grid_key = use_grid_keynav(tbody_ref, move || {
        // Reapply the roving tabindex whenever the rendered row set changes
        // (filter change AND window growth both add/remove navigable rows).
        let _ = facet.get();
        let _ = search_debounced.get();
        let _ = render_limit.get();
        let _ = rows.with(Vec::len);
    });

    view! {
        <main class="audit-view">
            <SectionHeader title=title crumb=crumb>
                <ExportMenu
                    disabled=Signal::derive(move || {
                        exporting.get() || rows.with(Vec::is_empty)
                    })
                    on_select=Callback::new(on_export)
                    options=vec![("csv", "Export as CSV…"), ("json", "Export as JSON…")]
                />
                <IconButton
                    icon=IconName::Refresh
                    aria_label=refresh_label.clone()
                    title="Refresh".to_string()
                    on_click=Callback::new(move |_| reload.update(|n| *n += 1))
                    busy=Signal::derive(move || loading.get())
                />
            </SectionHeader>

            {move || {
                error
                    .get()
                    .map(|e| {
                        view! {
                            <DetailLoadError
                                error=e
                                on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                class="app-list__error"
                            />
                        }
                    })
            }}
            {move || banner.with_value(|b| rows.with(|all| b(all.as_slice())))}

            <TabList selected_value=facet>
                {facets
                    .into_iter()
                    .map(|(value, label)| view! { <Tab value=value>{label}</Tab> })
                    .collect_view()}
            </TabList>
            <SearchInput value=search placeholder=search_placeholder />
            <SavedViews view_key=view_key facet=facet search=search />

            {move || {
                if loading.get() && rows.with(Vec::is_empty) {
                    return view! { <SkeletonList rows=6 /> }.into_any();
                }
                if matched.with(Vec::is_empty) {
                    return view! {
                        <EmptyState
                            icon=IconName::Search
                            title="No matches".to_string()
                            body=empty_message.get_value()
                        />
                    }
                        .into_any();
                }
                let total = rows.with(Vec::len);
                let shown = matched.with(Vec::len);
                let header_cells = headers
                    .with_value(|h| h.iter().map(|c| view! { <th>{*c}</th> }).collect_view());
                let count_line = format!("{shown} of {total} {} match", noun.get_value());
                view! {
                    <div>
                        <Body1>{count_line}</Body1>
                        <table class="data-table">
                            <thead>
                                <tr>{header_cells}</tr>
                            </thead>
                            <tbody node_ref=tbody_ref on:keydown=on_grid_key.clone()>
                                // Keyed by row index so growing the window (or a
                                // filter change that keeps rows) patches the
                                // affected `<tr>`s instead of tearing down and
                                // rebuilding the entire table.
                                <For
                                    each=move || {
                                        matched
                                            .get()
                                            .into_iter()
                                            .take(render_limit.get())
                                            .collect::<Vec<_>>()
                                    }
                                    key=|i| *i
                                    let:i
                                >
                                    {rows
                                        .with(|all| {
                                            all.get(i)
                                                .cloned()
                                                .map(|r| row.with_value(|f| f(r)))
                                        })}
                                </For>
                            </tbody>
                        </table>
                        {move || {
                            let shown = matched.with(Vec::len);
                            let limit = render_limit.get();
                            (shown > limit)
                                .then(|| {
                                    let next = RENDER_PAGE.min(shown - limit);
                                    view! {
                                        <div class="audit-show-more">
                                            <Body1>
                                                {format!("Showing {limit} of {shown} matching rows")}
                                            </Body1>
                                            <Button
                                                appearance=Signal::derive(|| {
                                                    ButtonAppearance::Secondary
                                                })
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
