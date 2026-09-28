use leptos::prelude::*;
use thaw::Body1;

use crate::hooks::use_grid_keynav::use_grid_keynav;

/// A `data-table` with built-in keyboard navigation (the WAI-ARIA roving-tabindex
/// grid pattern: Arrow Up/Down + Home/End move between rows, Enter activates a
/// row's first button) and an empty state — so tables get accessible keyboard
/// nav for free instead of hand-rolling `<table class="data-table">` + wiring
/// `use_grid_keynav` each time.
///
/// The caller supplies the column `headers` (use `""` for an action column: it
/// renders a visually-hidden "Actions" header, so the row buttons get a column
/// name from a screen reader instead of "column 6") and a `row` closure that renders one `<tr>` per item. `rows` is
/// taken by value — the rows at render time: reactive callers place this inside
/// their own `move ||` so a fresh table builds when the row set changes; static
/// callers (e.g. a post-await list) build it once.
///
/// **Intentionally uncapped** (no render-limit / "Show more"): every caller —
/// a principal's held grants, an app's published scopes, an SP's assignees — is
/// admin-bounded data that realistically numbers in the handful, so a cap would
/// never engage. The large, genuinely-unbounded lists (App Registrations,
/// Enterprise Apps) use the windowed `VirtualList` instead. Add a cap here only
/// if a real tenant is shown to stall on one of these tables.
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
        .map(|h| {
            if h.is_empty() {
                view! {
                    <th>
                        <span class="visually-hidden">"Actions"</span>
                    </th>
                }
                .into_any()
            } else {
                view! { <th>{h}</th> }.into_any()
            }
        })
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

#[cfg(test)]
mod tests {
    /// The stylesheet, as shipped. The browser GUI tests mount views without
    /// it, so they would pass even if `visually-hidden` named no rule at all.
    const STYLES: &str = include_str!("../../../styles.css");

    /// The declarations of the top-level rule `selector { … }`, or `None` when
    /// the stylesheet has no such rule.
    fn rule_body(selector: &str) -> Option<&'static str> {
        let open = STYLES.find(&format!("\n{selector} {{"))?;
        let body = &STYLES[open..];
        let close = body.find('}')?;
        Some(&body[..close])
    }

    /// An empty action header renders "Actions" inside `.visually-hidden`:
    /// without the rule that word would paint in every action column.
    #[test]
    fn visually_hidden_utility_hides_without_removing_from_the_a11y_tree() {
        let body = rule_body(".visually-hidden")
            .expect("styles.css has no top-level `.visually-hidden {` rule");
        for decl in [
            "position: absolute",
            "clip: rect(0, 0, 0, 0)",
            "overflow: hidden",
        ] {
            assert!(
                body.contains(decl),
                "`.visually-hidden` lacks `{decl}`: {body}"
            );
        }
        for hides_from_at in ["display: none", "visibility: hidden"] {
            assert!(
                !body.contains(hides_from_at),
                "`.visually-hidden` must stay in the accessibility tree, not `{hides_from_at}`"
            );
        }
    }
}
