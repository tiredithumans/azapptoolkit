//! Header control bar for the App Registrations / Enterprise Applications
//! lists: a tri-state "select all visible" checkbox alongside the result count,
//! plus a Clear action. Operates directly on a `RwSignal<HashSet<String>>`
//! selection set so the same component drives both lists.

use std::collections::HashSet;

use leptos::prelude::*;

#[component]
pub fn SelectAllBar(
    /// Result count line, e.g. `"42 of 100 app registrations"`.
    count_label: String,
    /// Object ids of the currently-filtered (visible) rows — the "current view".
    visible_ids: Vec<String>,
    /// The bulk-selection set this bar toggles (a superset of the visible ids,
    /// since rows hidden by the active filter can still be selected).
    selected: RwSignal<HashSet<String>>,
) -> impl IntoView {
    let visible = StoredValue::new(visible_ids);
    let visible_count = visible.with_value(Vec::len);

    // `(all visible selected, any visible selected)` in one memoized pass per
    // selection change, shared by the checkbox's `checked` and `indeterminate`.
    // Membership is an O(1) HashSet lookup now (the store is a set), so this is
    // O(visible), not O(visible × selected). `all` is false when nothing is visible.
    let sel_state = Memo::new(move |_| {
        selected.with(|sel| {
            visible.with_value(|ids| {
                let on = ids.iter().filter(|id| sel.contains(id.as_str())).count();
                (visible_count > 0 && on == ids.len(), on > 0)
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
                visible.with_value(|ids| {
                    for id in ids {
                        sel.remove(id);
                    }
                })
            });
        } else {
            selected.update(|sel| visible.with_value(|ids| sel.extend(ids.iter().cloned())));
        }
    };

    let clear = move |_| selected.update(HashSet::clear);

    view! {
        <div class="app-list__selectbar">
            <label class="app-list__selectall">
                <input
                    type="checkbox"
                    class="app-list__check"
                    aria-label=format!("Select all {visible_count} visible")
                    prop:checked=all_selected
                    prop:indeterminate=indeterminate
                    on:change=toggle
                />
                <span class="app-list__count">{count_label}</span>
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
