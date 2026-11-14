//! Tab bookkeeping shared by the two detail panes (app registration and
//! enterprise application): which tab is on screen, which have been mounted,
//! which hold unsaved edits, and what a reload does to each.
//!
//! **Why it exists.** A pane used to render its tabs inside the `Suspense` of
//! its detail resource, so every reload — a tab's own `on_changed` after a
//! mutation, or the header's Refresh — swapped the whole pane for a skeleton
//! and rebuilt every tab. Editing Overview and then adding an owner on the
//! Owners tab threw the Overview form away without asking. The panes now keep
//! the last loaded detail in a signal and stay mounted across a reload
//! (`views::application_detail_pane`), and this type decides, per tab, what the
//! fresh data does:
//!
//! - a tab with **unsaved edits** that did not ask for the reload is kept as it
//!   is (its reactive reads follow the new detail; its form is untouched);
//! - the tab **on screen** is otherwise rebuilt in place, as before;
//! - every other mounted tab is dropped and mounts fresh when next opened — the
//!   old pane did the same, so a reload re-runs one tab's reads, not ten.
//!
//! "Unsaved edits" is whatever the tab reports through
//! [`use_unsaved_marker`](crate::hooks::use_unsaved_marker), which finds its tab
//! through the [`TabKey`] / [`PaneDirtyTabs`] contexts each slot provides.

use std::collections::{HashMap, HashSet};

use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// The tab a component is mounted in — provided by [`PaneTabs::slot`].
#[derive(Debug, Clone, Copy)]
pub struct TabKey(pub &'static str);

/// The pane's `(tab, marker)` set of unsaved-edit reports — provided by
/// [`PaneTabs::slot`], written by `use_unsaved_marker`.
#[derive(Debug, Clone, Copy)]
pub struct PaneDirtyTabs(pub RwSignal<HashSet<(&'static str, u64)>>);

/// What a reload should do to tabs that hold unsaved edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reload {
    /// A tab's own mutation asked for it: that tab is rebuilt, other tabs keep
    /// their unsaved edits.
    From(&'static str),
    /// The operator chose to discard (a confirmed Refresh, a different object):
    /// every tab is rebuilt.
    DiscardAll,
}

#[derive(Clone, Copy)]
pub struct PaneTabs {
    /// The tab on screen (`TabBar`'s two-way `selected`).
    pub active: RwSignal<String>,
    /// Insert-only latch of mounted tabs — a tab mounts on first visit and then
    /// stays in the DOM, hidden, so its reads and UI state survive a switch.
    visited: RwSignal<HashSet<String>>,
    dirty: RwSignal<HashSet<(&'static str, u64)>>,
    /// One counter per tab; bumping it rebuilds that tab's body in place.
    generations: StoredValue<HashMap<&'static str, RwSignal<u32>>>,
    /// Reload requests not yet landed (see [`Self::request`]).
    pending: StoredValue<Pending>,
}

/// The reload requests waiting on a fetch. Requests can overlap (two tabs'
/// mutations landing close together), so they merge rather than overwrite.
#[derive(Default, Clone)]
struct Pending {
    discard_all: bool,
    from: HashSet<&'static str>,
}

impl PaneTabs {
    /// `initial` is the tab to open on; `all` every tab value the pane has.
    pub fn new(initial: String, all: impl IntoIterator<Item = &'static str>) -> Self {
        let active = RwSignal::new(initial.clone());
        let visited = RwSignal::new(HashSet::from([initial]));
        Effect::new(move |_| {
            let tab = active.get();
            visited.update(|set| {
                set.insert(tab);
            });
        });
        let dirty: RwSignal<HashSet<(&'static str, u64)>> = RwSignal::new(HashSet::new());
        // The open item is dirty while any tab is: one report for the pane, so
        // closing its chip (or Cmd/Ctrl-W, or the dock cap) asks first. A no-op
        // for a pane mounted on its own, as the GUI tests do.
        if let Some(crate::hooks::OpenItemId(id)) = use_context::<crate::hooks::OpenItemId>() {
            let session = crate::state::use_session();
            Effect::new(move |_| session.set_item_dirty(id, dirty.with(|d| !d.is_empty())));
            on_cleanup(move || session.set_item_dirty(id, false));
        }
        Self {
            active,
            visited,
            dirty,
            generations: StoredValue::new(
                all.into_iter()
                    .map(|tab| (tab, RwSignal::new(0_u32)))
                    .collect(),
            ),
            pending: StoredValue::new(Pending::default()),
        }
    }

    /// Whether any tab reports unsaved edits (tracked).
    pub fn any_dirty(&self) -> bool {
        self.dirty.with(|d| !d.is_empty())
    }

    fn is_dirty_untracked(&self, tab: &str) -> bool {
        self.dirty
            .with_untracked(|d| d.iter().any(|(t, _)| *t == tab))
    }

    /// Record a reload request. The caller then triggers its fetch; the request
    /// is consumed by [`Self::land`] when the fresh detail arrives.
    pub fn request(&self, reload: Reload) {
        self.pending.update_value(|p| match reload {
            Reload::DiscardAll => p.discard_all = true,
            Reload::From(tab) => {
                p.from.insert(tab);
            }
        });
    }

    /// Apply the pending reload requests to the mounted tabs, now that the
    /// fresh detail is in the pane's signal. `scope` is the pane's root, used
    /// to give up focus inside a tab about to be disposed
    /// (`util::blur_focus_within`).
    pub fn land(&self, scope: Option<&web_sys::Element>) {
        let pending = self.pending.get_value();
        self.pending.set_value(Pending::default());
        let active = self.active.get_untracked();
        let keep = |tab: &str| {
            !pending.discard_all && !pending.from.contains(tab) && self.is_dirty_untracked(tab)
        };
        let disposing: Vec<String> = self
            .visited
            .with_untracked(|v| v.iter().filter(|tab| !keep(tab)).cloned().collect());
        if disposing.is_empty() {
            return;
        }
        blur_focus_in_tabs(scope, &disposing);
        // Hidden tabs are dropped (they mount fresh, with their own reads, when
        // next opened); the tab on screen is rebuilt in place below.
        self.visited
            .update(|set| set.retain(|tab| *tab == active || keep(tab)));
        if !keep(&active)
            && let Some(generation) = self
                .generations
                .with_value(|g| g.get(active.as_str()).copied())
        {
            generation.update(|n| *n = n.wrapping_add(1));
        }
    }

    /// One tab's slot: mounted on first visit, hidden (not unmounted) when
    /// another tab is selected, rebuilt when [`Self::land`] bumps it.
    ///
    /// The body is erased to `AnyView` here for the reason `util::keep_alive`
    /// documents — ten concretely-typed tabs crash the wasm linker.
    pub fn slot<F, V>(&self, tab: &'static str, body: F) -> impl IntoView + use<F, V>
    where
        F: Fn() -> V + Send + Sync + 'static,
        V: IntoView + 'static,
    {
        let this = *self;
        let generation = self
            .generations
            .with_value(|g| g.get(tab).copied())
            .unwrap_or_else(|| RwSignal::new(0));
        let body = StoredValue::new(body);
        view! {
            <Show when=move || this.visited.with(|set| set.contains(tab)) fallback=|| ()>
                <div
                    data-tab=tab
                    style:display=move || {
                        if this.active.with(|a| a == tab) { "contents" } else { "none" }
                    }
                >
                    {move || {
                        generation.track();
                        provide_context(TabKey(tab));
                        provide_context(PaneDirtyTabs(this.dirty));
                        body.with_value(|body| body().into_any())
                    }}
                </div>
            </Show>
        }
    }
}

/// Blur the focused element when it sits inside one of `tabs`' slots under
/// `scope`. Focus in a tab that is being kept is left alone — the operator may
/// be typing there while another tab's mutation lands.
fn blur_focus_in_tabs(scope: Option<&web_sys::Element>, tabs: &[String]) {
    let Some(active) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element())
    else {
        return;
    };
    if scope.is_some_and(|scope| !scope.contains(Some(&active))) {
        return;
    }
    let Some(slot) = active.closest("[data-tab]").ok().flatten() else {
        return;
    };
    let in_disposed_tab = slot
        .get_attribute("data-tab")
        .is_some_and(|tab| tabs.contains(&tab));
    if in_disposed_tab && let Ok(el) = active.dyn_into::<web_sys::HtmlElement>() {
        let _ = el.blur();
    }
}
