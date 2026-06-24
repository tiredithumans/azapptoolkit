//! Top-bar command bar. One launcher for the whole app: a debounced query hits
//! the `global_search` Tauri command for directory record hits (App
//! Registrations / Enterprise Applications / Managed Identities, each tagged
//! with a [`TypeChip`]) and, above them, the nav/tool **commands** fuzzy-matched
//! from [`action_list`]. Clicking a record navigates + selects it; running a
//! command performs its side effect.
//!
//! This replaces the separate Cmd/Ctrl-K modal palette: the hotkey now focuses
//! this always-visible bar, and Arrow Up/Down + Enter navigate and run the
//! matched commands (the palette's keyboard flow, moved onto the bar). Records
//! stay click-to-open.

use leptos::ev;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::HtmlInputElement;

use crate::bindings::search::{self, GlobalSearchResults, SearchHit};
use crate::components::icon::{Icon, IconName};
use crate::components::type_chip::{AppKind, TypeChip};
use crate::hooks::use_debounced::use_debounced;
use crate::state::{ActiveView, Session, use_session};

/// One command-bar entry: a label, extra search keywords, and the side effect.
/// `run` is a plain `fn` pointer (non-capturing) so the list is trivially `Copy`.
#[derive(Clone, Copy)]
struct PaletteAction {
    label: &'static str,
    keywords: &'static str,
    run: fn(Session),
}

fn action_list() -> Vec<PaletteAction> {
    vec![
        PaletteAction {
            label: "Go to App Registrations",
            keywords: "apps registrations home",
            run: |s| s.set_view(ActiveView::Apps),
        },
        PaletteAction {
            label: "Go to Enterprise Applications",
            keywords: "enterprise sso service principals",
            run: |s| s.set_view(ActiveView::EnterpriseApps),
        },
        PaletteAction {
            label: "Go to Managed Identities",
            keywords: "mi managed identity",
            run: |s| s.set_view(ActiveView::ManagedIdentities),
        },
        PaletteAction {
            label: "Go to Security audit",
            keywords: "risk audit health posture security",
            run: |s| s.open_security("posture"),
        },
        PaletteAction {
            label: "Go to Credential expiry",
            keywords: "secrets certificates expiry rotate security",
            run: |s| s.open_security("credentials"),
        },
        PaletteAction {
            label: "Go to Delegated grants",
            keywords: "oauth permissions consent delegated security",
            run: |s| s.open_security("grants"),
        },
        PaletteAction {
            label: "New app registration",
            keywords: "create add register",
            run: |s| {
                s.set_view(ActiveView::Apps);
                s.open_create_app();
            },
        },
        PaletteAction {
            label: "Open Bulk Actions",
            keywords: "tools batch",
            run: |s| s.set_view(ActiveView::BulkActions),
        },
        PaletteAction {
            label: "Open Key Vault",
            keywords: "tools secrets vault",
            run: |s| s.set_view(ActiveView::KeyVault),
        },
        PaletteAction {
            label: "Open Cache",
            keywords: "tools debug cache diagnostics",
            run: |s| s.cache_open.set(true),
        },
        PaletteAction {
            label: "Sign Out",
            keywords: "logout exit",
            run: sign_out_action,
        },
    ]
}

fn sign_out_action(session: Session) {
    if let Some(t) = session.active_tenant.get_untracked() {
        leptos::task::spawn_local(async move {
            let _ = crate::bindings::auth::sign_out(&t).await;
            session.set_active_tenant(None);
        });
    } else {
        session.set_active_tenant(None);
    }
}

/// Case-insensitive subsequence match: every char of `needle` appears in
/// `haystack` in order. Empty needle matches everything.
fn fuzzy_matches(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let hay = haystack.to_lowercase();
    let mut chars = hay.chars();
    needle
        .to_lowercase()
        .chars()
        .all(|nc| chars.any(|hc| hc == nc))
}

#[component]
pub fn GlobalSearch() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 250);
    let focused = RwSignal::new(false);
    // Keyboard selection over the matched commands (Arrow/Enter). Records stay
    // click-only, so the selection only indexes into the command matches.
    let selected = RwSignal::new(0usize);
    let input_ref = NodeRef::<leptos::html::Input>::new();

    // Commands matching the current query (un-debounced, synchronous).
    let command_matches = Signal::derive(move || {
        let q = raw_query.get();
        let q = q.trim().to_string();
        if q.is_empty() {
            return Vec::new();
        }
        action_list()
            .into_iter()
            .filter(|a| fuzzy_matches(&format!("{} {}", a.label, a.keywords), &q))
            .collect::<Vec<_>>()
    });

    // Reset the highlight whenever the query changes.
    Effect::new(move |_| {
        raw_query.track();
        selected.set(0);
    });

    // Window-level Cmd/Ctrl-K focuses the bar (the palette's old hotkey).
    let handle = window_event_listener(ev::keydown, move |evt| {
        if (evt.meta_key() || evt.ctrl_key()) && evt.key().eq_ignore_ascii_case("k") {
            evt.prevent_default();
            if let Some(el) = input_ref.get() {
                let _ = el.focus();
            }
        }
    });
    on_cleanup(move || handle.remove());

    let results: LocalResource<Option<Result<GlobalSearchResults, String>>> =
        LocalResource::new(move || {
            let tenant = tenant.get();
            let q = query.get();
            async move {
                let trimmed = q.trim();
                if trimmed.is_empty() {
                    return None;
                }
                let t = tenant?;
                Some(
                    search::global_search(&t.tenant_id, trimmed)
                        .await
                        .map_err(|e| e.message),
                )
            }
        });

    // Flattened record hits (apps → enterprise → managed identities, matching
    // render order) for the keyboard roving selection — read synchronously by the
    // keydown handler. Derived from the async `results` resource (no separate
    // signal write) so it can never drift out of sync with what's rendered.
    // Mirror the resolved record hits into a plain signal via an Effect (rather
    // than a derive the keydown handler reads) so the handler always sees the
    // current list synchronously. `record_hits` is not a dependency of the
    // `results` resource, so setting it can't re-trigger the search.
    let record_hits: RwSignal<Vec<(SelectionKind, SearchHit)>> = RwSignal::new(Vec::new());
    Effect::new(move |_| record_hits.set(flatten_hits(results.get())));

    let on_input = move |ev: ev::Event| {
        if let Some(target) = ev.target()
            && let Ok(input) = target.dyn_into::<HtmlInputElement>()
        {
            raw_query.set(input.value());
        }
    };

    let clear = move || raw_query.set(String::new());
    let blur = move || {
        if let Some(el) = input_ref.get() {
            let _ = el.blur();
        }
    };

    // The roving selection spans the command matches first, then the record hits
    // (Arrow cycles the combined list; Enter activates whichever is highlighted),
    // so a keyboard-only user can reach searched records, not just commands.
    let on_keydown = move |evt: ev::KeyboardEvent| match evt.key().as_str() {
        "ArrowDown" => {
            evt.prevent_default();
            let total = command_matches.with(Vec::len) + record_hits.with(Vec::len);
            if total > 0 {
                selected.update(|i| *i = (*i + 1) % total);
            }
        }
        "ArrowUp" => {
            evt.prevent_default();
            let total = command_matches.with(Vec::len) + record_hits.with(Vec::len);
            if total > 0 {
                selected.update(|i| *i = if *i == 0 { total - 1 } else { *i - 1 });
            }
        }
        "Enter" => {
            let cmd_count = command_matches.with(Vec::len);
            let sel = selected.get_untracked();
            if sel < cmd_count {
                if let Some(action) = command_matches.with(|m| m.get(sel).copied()) {
                    evt.prevent_default();
                    (action.run)(session);
                    clear();
                    blur();
                }
            } else if let Some((kind, hit)) = record_hits.with(|r| r.get(sel - cmd_count).cloned())
            {
                evt.prevent_default();
                pick_hit(session, &hit, kind, raw_query);
                blur();
            }
        }
        "Escape" => {
            evt.prevent_default();
            clear();
            blur();
        }
        _ => {}
    };

    let dropdown_visible = Memo::new(move |_| !raw_query.get().trim().is_empty() && focused.get());

    view! {
        <div class="global-search">
            <label class="global-search__input">
                <span class="global-search__icon">
                    <Icon name=IconName::Search size=14 />
                </span>
                <input
                    node_ref=input_ref
                    type="text"
                    class="global-search__field"
                    role="combobox"
                    aria-autocomplete="list"
                    aria-controls="global-search-listbox"
                    aria-expanded=move || dropdown_visible.get().to_string()
                    aria-activedescendant=move || {
                        // The active row is a command while `selected` is within the
                        // command count, otherwise a record hit (offset past commands).
                        let cmd_count = command_matches.with(Vec::len);
                        let sel = selected.get();
                        if sel < cmd_count {
                            format!("gs-cmd-{sel}")
                        } else if record_hits.with(Vec::len) > 0 {
                            format!("gs-rec-{}", sel - cmd_count)
                        } else {
                            String::new()
                        }
                    }
                    placeholder="Search or run a command (⌘K) — apps, GUIDs, audit, key vault…"
                    prop:value=move || raw_query.get()
                    on:input=on_input
                    on:focus=move |_| focused.set(true)
                    on:blur=move |_| {
                        let win = web_sys::window();
                        if let Some(w) = win {
                            let cb = wasm_bindgen::closure::Closure::once_into_js(move || {
                                focused.set(false);
                            });
                            let _ = w
                                .set_timeout_with_callback_and_timeout_and_arguments_0(
                                    cb.unchecked_ref::<js_sys::Function>(),
                                    150,
                                );
                        }
                    }
                    on:keydown=on_keydown
                />
                // Clear (×) — shown only when the field has text. `mousedown` +
                // `prevent_default` so the click doesn't blur the input (which
                // would close the dropdown before the clear lands).
                {move || {
                    (!raw_query.get().is_empty())
                        .then(|| {
                            view! {
                                <button
                                    class="global-search__clear"
                                    type="button"
                                    tabindex="-1"
                                    aria-label="Clear search"
                                    title="Clear search"
                                    on:mousedown=move |ev| {
                                        ev.prevent_default();
                                        clear();
                                    }
                                >
                                    <Icon name=IconName::Close size=14 />
                                </button>
                            }
                        })
                }}
            </label>
            {move || {
                if !dropdown_visible.get() {
                    return ().into_any();
                }
                view! {
                    <div class="global-search__results" role="listbox" id="global-search-listbox">
                        // Commands group — nav/tool actions fuzzy-matched against
                        // the query, keyboard-navigable (Arrow/Enter). Rendered
                        // synchronously above the async record hits.
                        {move || {
                            let matches = command_matches.get();
                            if matches.is_empty() {
                                return ().into_any();
                            }
                            let sel = selected.get();
                            view! {
                                <div class="global-search__group-label">"Commands"</div>
                                {matches
                                    .into_iter()
                                    .enumerate()
                                    .map(move |(i, a)| {
                                        let run = a.run;
                                        let mut class = String::from("global-search__row");
                                        if i == sel {
                                            class.push_str(" global-search__row--active");
                                        }
                                        view! {
                                            <button
                                                class=class
                                                type="button"
                                                id=format!("gs-cmd-{i}")
                                                role="option"
                                                aria-selected=move || (i == sel).to_string()
                                                on:mousedown=move |_| {
                                                    run(session);
                                                    raw_query.set(String::new());
                                                }
                                                on:mouseenter=move |_| selected.set(i)
                                            >
                                                <span class="global-search__row-title">{a.label}</span>
                                            </button>
                                        }
                                    })
                                    .collect_view()}
                            }
                                .into_any()
                        }}
                        <Suspense fallback=move || {
                            view! { <div class="global-search__empty">"Searching…"</div> }
                        }>
                            {move || Suspend::new(async move {
                                match results.await {
                                    None => view! {
                                        <div class="global-search__empty">
                                            "Type a name or GUID."
                                        </div>
                                    }
                                        .into_any(),
                                    Some(Err(msg)) => view! {
                                        <div class="global-search__empty">
                                            {format!("Search failed: {msg}")}
                                        </div>
                                    }
                                        .into_any(),
                                    Some(Ok(r)) => {
                                        // Records are keyboard-selectable after the
                                        // commands, so their roving indices start at
                                        // the current command count (untracked — the
                                        // count is stable for a resolved query, and
                                        // `selected` resets on every query change).
                                        let cmd_count = command_matches.with_untracked(Vec::len);
                                        view_results(r, session, raw_query, selected, cmd_count)
                                    }
                                }
                            })}
                        </Suspense>
                    </div>
                }
                    .into_any()
            }}
        </div>
    }
}

fn view_results(
    results: GlobalSearchResults,
    session: crate::state::Session,
    raw_query: RwSignal<String>,
    selected: RwSignal<usize>,
    cmd_count: usize,
) -> leptos::prelude::AnyView {
    let empty = results.app_registrations.is_empty()
        && results.enterprise_apps.is_empty()
        && results.managed_identities.is_empty();
    if empty {
        return view! {
            <div class="global-search__empty">"No matches."</div>
        }
        .into_any();
    }

    // Roving indices continue past the commands: apps, then enterprise, then MIs.
    let apps_n = results.app_registrations.len();
    let ent_n = results.enterprise_apps.len();
    view! {
        {render_group(
            "App Registrations",
            AppKind::AppRegistration,
            results.app_registrations,
            session,
            raw_query,
            SelectionKind::AppReg,
            selected,
            cmd_count,
        )}
        {render_group(
            "Enterprise Applications",
            AppKind::EnterpriseApp,
            results.enterprise_apps,
            session,
            raw_query,
            SelectionKind::EntApp,
            selected,
            cmd_count + apps_n,
        )}
        {render_group(
            "Managed Identities",
            AppKind::ManagedIdentityUnknown,
            results.managed_identities,
            session,
            raw_query,
            SelectionKind::Mi,
            selected,
            cmd_count + apps_n + ent_n,
        )}
    }
    .into_any()
}

#[derive(Clone, Copy)]
enum SelectionKind {
    AppReg,
    EntApp,
    Mi,
}

#[allow(clippy::too_many_arguments)]
fn render_group(
    label: &'static str,
    chip_kind: AppKind,
    hits: Vec<SearchHit>,
    session: crate::state::Session,
    raw_query: RwSignal<String>,
    selection: SelectionKind,
    selected: RwSignal<usize>,
    base: usize,
) -> impl IntoView {
    if hits.is_empty() {
        return ().into_any();
    }
    view! {
        <div class="global-search__group-label">{label}</div>
        {hits
            .into_iter()
            .enumerate()
            .map(move |(i, hit)| {
                // Combined roving index: commands occupy 0..cmd_count, then this
                // group starts at `base`. The active class + aria-selected react to
                // `selected` so Arrow keys highlight the row without rebuilding it.
                let idx = base + i;
                let app_id = hit.app_id.clone();
                let display = hit.display_name.clone();
                let hit_for_pick = hit.clone();
                view! {
                    <button
                        class="global-search__row"
                        class:global-search__row--active=move || selected.get() == idx
                        type="button"
                        id=format!("gs-rec-{idx}")
                        role="option"
                        aria-selected=move || (selected.get() == idx).to_string()
                        on:mousedown=move |_| pick_hit(session, &hit_for_pick, selection, raw_query)
                        on:mouseenter=move |_| selected.set(idx)
                    >
                        <TypeChip kind=chip_kind compact=true />
                        <span class="global-search__row-title">{display}</span>
                        <span class="global-search__row-appid">
                            {app_id.unwrap_or_default()}
                        </span>
                    </button>
                }
            })
            .collect_view()}
    }
    .into_any()
}

/// Flattens the async search results into one ordered list — apps, then
/// enterprise apps, then managed identities (matching render order) — for the
/// keyboard roving selection.
fn flatten_hits(
    results: Option<Option<Result<GlobalSearchResults, String>>>,
) -> Vec<(SelectionKind, SearchHit)> {
    let Some(Some(Ok(r))) = results else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(
        r.app_registrations.len() + r.enterprise_apps.len() + r.managed_identities.len(),
    );
    out.extend(
        r.app_registrations
            .into_iter()
            .map(|h| (SelectionKind::AppReg, h)),
    );
    out.extend(
        r.enterprise_apps
            .into_iter()
            .map(|h| (SelectionKind::EntApp, h)),
    );
    out.extend(
        r.managed_identities
            .into_iter()
            .map(|h| (SelectionKind::Mi, h)),
    );
    out
}

/// Opens a picked record: switches to its list view, selects it, and seeds that
/// list's filter with its name (the search↔filter bridge). Shared by the row
/// mouse handler and the keyboard Enter dispatch so both behave identically.
fn pick_hit(
    session: crate::state::Session,
    hit: &SearchHit,
    selection: SelectionKind,
    raw_query: RwSignal<String>,
) {
    let id = hit.id.clone();
    let name = hit.display_name.clone();
    match selection {
        SelectionKind::AppReg => {
            session.set_view(ActiveView::Apps);
            session.set_selected_app(Some(id));
            session.apps_search.set(name);
        }
        SelectionKind::EntApp => {
            session.set_view(ActiveView::EnterpriseApps);
            session.set_selected_enterprise_app(Some(id));
            session.enterprise_search.set(name);
        }
        SelectionKind::Mi => {
            session.set_view(ActiveView::ManagedIdentities);
            session.set_selected_managed_identity(Some(id));
            session.mi_search.set(name);
        }
    }
    raw_query.set(String::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_matches_accepts_in_order_subsequence_case_insensitive() {
        assert!(fuzzy_matches("Go to App Registrations", "app"));
        assert!(fuzzy_matches("abcdef", "adf")); // non-contiguous subsequence
        assert!(fuzzy_matches("ABC", "abc")); // case-insensitive
        assert!(fuzzy_matches("anything", "")); // empty needle matches all
    }

    #[test]
    fn fuzzy_matches_rejects_absent_or_out_of_order() {
        assert!(!fuzzy_matches("Go to App Registrations", "zxq"));
        assert!(!fuzzy_matches("abcdef", "xyz"));
        assert!(!fuzzy_matches("abc", "cba")); // right chars, wrong order
    }

    fn hit(name: &str) -> SearchHit {
        SearchHit {
            id: name.into(),
            app_id: None,
            display_name: name.into(),
        }
    }

    #[test]
    fn flatten_hits_orders_apps_then_enterprise_then_mi() {
        let results = Some(Some(Ok(GlobalSearchResults {
            query: String::new(),
            looked_up_as_guid: false,
            app_registrations: vec![hit("a-app")],
            enterprise_apps: vec![hit("b-ent")],
            managed_identities: vec![hit("c-mi")],
        })));
        let flat = flatten_hits(results);
        // Render order = roving order: apps, then enterprise, then managed identities.
        let names: Vec<&str> = flat.iter().map(|(_, h)| h.display_name.as_str()).collect();
        assert_eq!(names, ["a-app", "b-ent", "c-mi"]);
        assert!(matches!(flat[0].0, SelectionKind::AppReg));
        assert!(matches!(flat[1].0, SelectionKind::EntApp));
        assert!(matches!(flat[2].0, SelectionKind::Mi));
    }

    #[test]
    fn flatten_hits_empty_for_loading_and_error_states() {
        assert!(flatten_hits(None).is_empty()); // resource still loading
        assert!(flatten_hits(Some(None)).is_empty()); // empty query
        assert!(flatten_hits(Some(Some(Err("boom".into())))).is_empty()); // search failed
    }
}
