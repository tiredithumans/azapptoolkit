use leptos::prelude::*;
use thaw::Body1;

use crate::hooks::use_grid_keynav::use_grid_keynav;

/// A `data-table` with built-in keyboard navigation (the WAI-ARIA roving-tabindex
/// grid pattern: Arrow Up/Down + Home/End move between rows, Enter activates a
/// row's first button) and an empty state — so tables get accessible keyboard
/// nav for free instead of hand-rolling `<table class="data-table">` + wiring
/// `use_grid_keynav` each time.
///
/// The caller supplies the column `headers` (use `""` for an action column with
/// no label) and a `row` closure that renders one `<tr>` per item. `rows` is
/// taken by value — the rows at render time: reactive callers place this inside
/// their own `move ||` so a fresh table builds when the row set changes; static
/// callers (e.g. a post-await list) build it once.
#[component]
pub fn DataTable<T, RowFn>(
    headers: Vec<&'static str>,
    rows: Vec<T>,
    /// Shown (as muted body text) when there are no rows.
    #[prop(into)]
    empty_message: String,
    /// Renders one `<tr>` for a row.
    row: RowFn,
) -> impl IntoView
where
    T: 'static,
    RowFn: Fn(T) -> AnyView + 'static,
{
    if rows.is_empty() {
        return view! { <Body1 class="data-table__empty">{empty_message}</Body1> }.into_any();
    }
    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    // Rows are fixed for this table instance, so the roving tabindex is seeded
    // once on mount (no rerender trigger needed).
    let on_grid_key = use_grid_keynav(tbody_ref, || {});
    let header_cells = headers
        .into_iter()
        .map(|h| view! { <th>{h}</th> })
        .collect_view();
    let body_rows = rows.into_iter().map(row).collect_view();
    view! {
        <table class="data-table">
            <thead>
                <tr>{header_cells}</tr>
            </thead>
            <tbody node_ref=tbody_ref on:keydown=on_grid_key>
                {body_rows}
            </tbody>
        </table>
    }
    .into_any()
}
