//! Saved filter views — let admins pin a facet + search combination (e.g.
//! "Expiring ≤7d", "High-risk") and reapply it in one click. Persisted to
//! `localStorage`, scoped per tenant + view so they don't cross-contaminate.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

use crate::state::use_session;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedView {
    name: String,
    facet: String,
    search: String,
}

fn ls_get(key: &str) -> Option<String> {
    let storage = web_sys::window()?.local_storage().ok().flatten()?;
    storage.get_item(key).ok().flatten()
}

fn ls_set(key: &str, value: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(key, value);
    }
}

/// A row of saved-view chips plus a save-current control. `facet`/`search` are
/// the host view's filter signals — clicking a chip writes them, and "Save
/// view" snapshots them. `view_key` namespaces storage so each view keeps its
/// own set.
#[component]
pub fn SavedViews(
    view_key: &'static str,
    facet: RwSignal<String>,
    search: RwSignal<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let views: RwSignal<Vec<SavedView>> = RwSignal::new(Vec::new());
    let naming = RwSignal::new(false);
    let name_input = RwSignal::new(String::new());

    let storage_key = move || {
        let t = tenant.get().map(|t| t.tenant_id).unwrap_or_default();
        format!("azapptoolkit:savedviews:{t}:{view_key}")
    };

    // (Re)load whenever the tenant changes.
    Effect::new(move |_| {
        let loaded = ls_get(&storage_key())
            .and_then(|s| serde_json::from_str::<Vec<SavedView>>(&s).ok())
            .unwrap_or_default();
        views.set(loaded);
    });

    let persist = move || {
        if let Ok(s) = serde_json::to_string(&views.get_untracked()) {
            ls_set(&storage_key(), &s);
        }
    };

    let save_current = move || {
        let name = name_input.get_untracked().trim().to_string();
        if name.is_empty() {
            return;
        }
        let sv = SavedView {
            name,
            facet: facet.get_untracked(),
            search: search.get_untracked(),
        };
        views.update(|v| {
            v.retain(|x| x.name != sv.name);
            v.push(sv);
        });
        persist();
        name_input.set(String::new());
        naming.set(false);
    };

    view! {
        <div class="saved-views">
            {move || {
                views
                    .get()
                    .into_iter()
                    .map(|sv| {
                        let applied = sv.clone();
                        let removed = sv.name.clone();
                        view! {
                            <span class="saved-view-chip">
                                <button
                                    type="button"
                                    class="saved-view-chip__apply"
                                    on:click=move |_| {
                                        facet.set(applied.facet.clone());
                                        search.set(applied.search.clone());
                                    }
                                >
                                    {sv.name.clone()}
                                </button>
                                <button
                                    type="button"
                                    class="saved-view-chip__remove"
                                    title="Remove saved view"
                                    on:click=move |_| {
                                        views.update(|v| v.retain(|x| x.name != removed));
                                        persist();
                                    }
                                >
                                    "×"
                                </button>
                            </span>
                        }
                    })
                    .collect_view()
            }}
            {move || {
                if naming.get() {
                    view! {
                        <span class="saved-views__naming">
                            <input
                                class="saved-views__input"
                                placeholder="View name"
                                prop:value=move || name_input.get()
                                on:input=move |ev| name_input.set(event_target_value(&ev))
                                on:keydown=move |ev| {
                                    if ev.key() == "Enter" {
                                        save_current();
                                    }
                                }
                            />
                            <button type="button" on:click=move |_| save_current()>
                                "Save"
                            </button>
                            <button type="button" on:click=move |_| naming.set(false)>
                                "Cancel"
                            </button>
                        </span>
                    }
                        .into_any()
                } else {
                    view! {
                        <button
                            type="button"
                            class="saved-views__add"
                            on:click=move |_| naming.set(true)
                        >
                            "+ Save view"
                        </button>
                    }
                        .into_any()
                }
            }}
        </div>
    }
}
