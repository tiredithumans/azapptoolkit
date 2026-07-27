//! Header control bar for the App Registrations / Enterprise Applications
//! lists: a tri-state "select all visible" checkbox alongside the result count,
//! plus a Clear action. Operates directly on a `RwSignal<HashSet<String>>`
//! selection set so the same component drives both lists.

use std::collections::HashSet;
use std::sync::Arc;

use leptos::prelude::*;

#[component]
pub fn SelectAllBar(
    /// Result count line, e.g. `"42 of 100 app registrations"`.
    #[prop(into)]
    count_label: Signal<String>,
    /// Object ids of the currently-filtered (visible) rows — the "current view".
    ///
    /// A **shared** handle, not an owned `Vec`: the caller derives this from its
    /// filtered row set, which changes on every keystroke and facet click, and
    /// at the 10 000-app list ceiling materializing one `String` per visible row
    /// each time was the list's dominant per-keystroke cost. Taking a `Signal`
    /// over an `Arc` makes a re-render a refcount clone.
    #[prop(into)]
    visible_ids: Signal<Arc<Vec<String>>>,
    /// The bulk-selection set this bar toggles (a superset of the visible ids,
    /// since rows hidden by the active filter can still be selected).
    selected: RwSignal<HashSet<String>>,
) -> impl IntoView {
    let visible_count = move || visible_ids.with(|ids| ids.len());

    // `(all visible selected, any visible selected)` in one memoized pass per
    // selection change, shared by the checkbox's `checked` and `indeterminate`.
    // Membership is an O(1) HashSet lookup now (the store is a set), so this is
    // O(visible), not O(visible × selected). `all` is false when nothing is visible.
    let sel_state = Memo::new(move |_| {
        selected.with(|sel| {
            visible_ids.with(|ids| {
                let on = ids.iter().filter(|id| sel.contains(id.as_str())).count();
                (!ids.is_empty() && on == ids.len(), on > 0)
            })
        })
    });
    let all_selected = move || sel_state.get().0;
    let indeterminate = move || {
        let (all, any) = sel_state.get();
        !all && any
    };

    let toggle = move |_| {
        if all_selected() {
            // Deselect every visible id, leaving any off-screen selections intact.
            selected.update(|sel| {
                visible_ids.with(|ids| {
                    for id in ids.iter() {
                        sel.remove(id);
                    }
                })
            });
        } else {
            selected.update(|sel| visible_ids.with(|ids| sel.extend(ids.iter().cloned())));
        }
    };

    let clear = move |_| selected.update(HashSet::clear);

    view! {
        <div class="app-list__selectbar">
            <label class="app-list__selectall">
                <input
                    type="checkbox"
                    class="app-list__check"
                    aria-label=move || format!("Select all {} visible", visible_count())
                    prop:checked=all_selected
                    prop:indeterminate=indeterminate
                    on:change=toggle
                />
                <span class="app-list__count">{move || count_label.get()}</span>
            </label>
            {move || {
                let n = selected.with(HashSet::len);
                (n > 0)
                    .then(|| {
                        view! {
                            <button type="button" class="link-btn" on:click=clear>
                                {format!("Clear ({n})")}
                            </button>
                        }
                    })
            }}
        </div>
    }
}
