//! Saved filter views — let admins pin a facet + search combination (e.g.
//! "Expiring ≤7d", "High-risk") and reapply it in one click. Persisted to
//! `localStorage`, scoped per tenant + view so they don't cross-contaminate.

use chrono::NaiveDate;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

use crate::state::use_session;
use crate::util::{ls_get, ls_set};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedView {
    name: String,
    facet: String,
    search: String,
    /// The drawer's "created on" window when the view was saved, kept in the
    /// ISO form the native date inputs use (F369). Serde-defaulted because
    /// localStorage still holds views saved before this field existed.
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    before: Option<String>,
}

/// Same format `DateRangeFilter`'s native date inputs read and write.
const ISO: &str = "%Y-%m-%d";

fn iso_of(d: Option<NaiveDate>) -> Option<String> {
    d.map(|d| d.format(ISO).to_string())
}

fn parse_iso(s: Option<&String>) -> Option<NaiveDate> {
    s.and_then(|s| NaiveDate::parse_from_str(s, ISO).ok())
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
    /// The host's "created on" window, saved and applied with the facet +
    /// search (F369). Lists without a date filter omit them.
    #[prop(optional_no_strip)]
    after: Option<RwSignal<Option<NaiveDate>>>,
    #[prop(optional_no_strip)] before: Option<RwSignal<Option<NaiveDate>>>,
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
            after: after.and_then(|s| iso_of(s.get_untracked())),
            before: before.and_then(|s| iso_of(s.get_untracked())),
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
                        let remove_label = format!("Remove saved view {}", sv.name);
                        // Range text so the chip's tooltip says which window it
                        // will restore (the visible label is just the name).
                        let title = match (sv.after.as_deref(), sv.before.as_deref()) {
                            (None, None) => sv.name.clone(),
                            (Some(f), Some(t)) => {
                                format!("{} · created {f}…{t}", sv.name)
                            }
                            (Some(f), None) => format!("{} · created from {f}", sv.name),
                            (None, Some(t)) => format!("{} · created until {t}", sv.name),
                        };
                        let apply_label = format!("Apply saved view {}", sv.name);
                        let (after_sig, before_sig) = (after, before);
                        view! {
                            <span class="saved-view-chip">
                                <button
                                    type="button"
                                    class="saved-view-chip__apply"
                                    title=title
                                    aria-label=apply_label
                                    on:click=move |_| {
                                        facet.set(applied.facet.clone());
                                        search.set(applied.search.clone());
                                        // Apply *includes* clearing (F369): a
                                        // view without a range resets the
                                        // drawer's, or applying it would
                                        // silently keep the old window and
                                        // show fewer rows than it promises.
                                        if let Some(a) = after_sig {
                                            a.set(parse_iso(applied.after.as_ref()));
                                        }
                                        if let Some(b) = before_sig {
                                            b.set(parse_iso(applied.before.as_ref()));
                                        }
                                    }
                                >
                                    {sv.name.clone()}
                                </button>
                                <button
                                    type="button"
                                    class="saved-view-chip__remove button--danger"
                                    title="Remove saved view"
                                    aria-label=remove_label
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
                                aria-label="View name"
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
