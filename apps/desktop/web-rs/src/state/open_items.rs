//! The cross-entity open-items working set.
//!
//! One shared set of chips, deduped by `(kind, entity_id)`, capped and 1-up (or
//! 2-up when split). There is no side detail pane and no `selected_*_id`
//! signal — this IS the selection model.
//!
//! The set is parked in `localStorage` between launches, under a **tenant-keyed**
//! key. That keying is not a nicety: an unkeyed snapshot restored into the next
//! tenant would reintroduce exactly the cross-tenant leak `set_active_tenant`'s
//! clear exists to prevent — the repo's #1 documented footgun. Every write to
//! `open_items` therefore goes through [`Session::update_open_items`], so the
//! snapshot cannot drift from the signal, and the only read is
//! [`Session::restore_open_items`], called from `set_active_tenant` *after* the
//! clear.

use super::*;

/// How many items the dock holds before the least recently focused is evicted.
const MAX_OPEN_ITEMS: usize = 8;

/// The snapshot store behind [`Session::restore_open_items`].
///
/// In the browser it is `localStorage`, via the shared [`crate::util`] helpers.
/// On the host target — where `just web-test` runs these unit tests —
/// `web_sys::window()` *panics*, so the store is a plain in-memory map. A
/// no-op stub would have been shorter and would have left the one invariant
/// worth pinning here (a restore never crosses tenants) untestable.
#[cfg(target_arch = "wasm32")]
mod store {
    pub(super) fn load(key: &str) -> Option<String> {
        crate::util::ls_get(key)
    }
    pub(super) fn save(key: &str, value: &str) {
        crate::util::ls_set(key, value);
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod store {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        // Per-thread, so tests running in parallel can't see each other's
        // snapshots — the same isolation each test's own `Owner` gives.
        static MEM: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    }

    pub(super) fn load(key: &str) -> Option<String> {
        MEM.with_borrow(|m| m.get(key).cloned())
    }
    pub(super) fn save(key: &str, value: &str) {
        MEM.with_borrow_mut(|m| m.insert(key.to_string(), value.to_string()));
    }
}

impl Session {
    /// Open `entity_id` into the shared working set and focus it (1-up).
    /// Deduped by `(kind, entity_id)`: re-opening an already-open item just
    /// re-focuses it (and refreshes its chip title) instead of stacking a
    /// duplicate. Returns the `OpenItem.id` (existing or freshly minted).
    pub fn open_item(
        &self,
        kind: OpenItemKind,
        entity_id: impl Into<String>,
        title: impl Into<String>,
    ) -> u64 {
        let entity_id = entity_id.into();
        let title = title.into();
        if let Some(existing) = self.is_open(kind, &entity_id) {
            self.set_open_item_title(existing, title);
            self.focus_item(existing, false);
            return existing;
        }
        let id = self.tick();
        // Cap the working set so it can't grow unbounded. Exactly one item is
        // pushed, so at most one can be over the cap.
        let mut evicted: Option<OpenItem> = None;
        self.update_open_items(|list| {
            list.push(OpenItem {
                id,
                kind,
                entity_id,
                title,
                focused_at: id,
            });
            if list.len() > MAX_OPEN_ITEMS
                && let Some(pos) = list
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, it)| it.focused_at)
                    .map(|(pos, _)| pos)
            {
                evicted = Some(list.remove(pos));
            }
        });
        if let Some(item) = evicted {
            self.shown_items
                .update(|shown| shown.retain(|s| *s != item.id));
            // Dropping the operator's parked reference app with no toast, no
            // cue and no way back is the whole of the complaint — so name what
            // left and offer it straight back. `Info`, not an error: the cap
            // did its job.
            let session = *self;
            let OpenItem {
                kind,
                entity_id,
                title,
                ..
            } = item;
            let message = format!("Open dock is full ({MAX_OPEN_ITEMS}) — closed \"{title}\".");
            self.push_toast(
                ToastKind::Info,
                message,
                Some("Reopen".to_string()),
                Some(std::rc::Rc::new(move || {
                    session.open_item(kind, entity_id.clone(), title.clone());
                })),
            );
        }
        self.focus_item(id, false);
        id
    }

    /// Show `id` in the workspace. `split = false` replaces the shown set (1-up);
    /// `split = true` pins it alongside the current pane for side-by-side
    /// compare, capped at two (drops the oldest pane on overflow).
    ///
    /// Also stamps the item as most-recently-focused, which is what the cap's
    /// eviction reads — and what makes `shown_items.last()` the pane the
    /// operator is reading, for Cmd/Ctrl-W and the dock's `[`/`]` stepping.
    pub fn focus_item(&self, id: u64, split: bool) {
        const MAX_SHOWN: usize = 2;
        // Skip the stamp when `id` is already the most recently focused — the
        // same no-op rule `set_open_item_title` follows, and for the same
        // reason: re-clicking the active chip is routine, and `open_items` is
        // read by every visible list row's "open" highlight.
        let stale = self.open_items.with_untracked(|list| {
            list.iter().max_by_key(|it| it.focused_at).map(|it| it.id) != Some(id)
        });
        if stale {
            let now = self.tick();
            self.update_open_items(|list| {
                if let Some(it) = list.iter_mut().find(|it| it.id == id) {
                    it.focused_at = now;
                }
            });
        }
        self.shown_items.update(|shown| {
            if split {
                if !shown.contains(&id) {
                    shown.push(id);
                }
                while shown.len() > MAX_SHOWN {
                    shown.remove(0);
                }
            } else {
                shown.clear();
                shown.push(id);
            }
        });
    }

    /// Close one open item (and drop it from the shown set if present).
    pub fn close_item(&self, id: u64) {
        self.update_open_items(|list| list.retain(|it| it.id != id));
        self.shown_items.update(|shown| shown.retain(|s| *s != id));
    }

    /// Close the entire working set — empties the dock and the workspace. (Tenant
    /// switch does the same via `set_active_tenant`; this is the explicit, in-
    /// tenant "Close all".)
    pub fn close_all_items(&self) {
        self.update_open_items(|list| list.clear());
        self.shown_items.set(Vec::new());
    }

    /// Close the open item identified by `(kind, entity_id)` — for detail-pane
    /// delete handlers, which know the entity id but not the synthetic open id.
    pub fn close_item_by_entity(&self, kind: OpenItemKind, entity_id: &str) {
        if let Some(id) = self.is_open(kind, entity_id) {
            self.close_item(id);
        }
    }

    /// Refresh an open item's chip label once its detail resolves (no-op if it
    /// was closed meanwhile, or the title is unchanged — so it doesn't needlessly
    /// re-render the dock).
    pub fn set_open_item_title(&self, id: u64, title: String) {
        let changed = self
            .open_items
            .with_untracked(|list| list.iter().any(|it| it.id == id && it.title != title));
        if changed {
            self.update_open_items(|list| {
                if let Some(it) = list.iter_mut().find(|it| it.id == id) {
                    it.title = title;
                }
            });
        }
    }

    /// The open-item id for `(kind, entity_id)` if it's in the working set —
    /// drives the list-row "open" highlight and `open_item` dedupe.
    pub fn is_open(&self, kind: OpenItemKind, entity_id: &str) -> Option<u64> {
        self.open_items.with(|list| {
            list.iter()
                .find(|it| it.kind == kind && it.entity_id == entity_id)
                .map(|it| it.id)
        })
    }

    /// Restore this tenant's parked working set. Called by `set_active_tenant`
    /// **after** it clears the previous tenant's, so the two halves of the
    /// footgun sit together: clear unconditionally, then read back only what
    /// this tenant id stored.
    ///
    /// `shown_items` is deliberately left empty — the dock comes back, the
    /// overlay does not. Launching straight into a detail pane over a list the
    /// operator has not seen yet contradicts the Home landing `set_active_tenant`
    /// just chose.
    pub(super) fn restore_open_items(&self) {
        let Some(key) = self.workspace_key() else {
            return;
        };
        let Some(restored) = store::load(&key)
            .and_then(|raw| serde_json::from_str::<Vec<OpenItem>>(&raw).ok())
            .filter(|list| !list.is_empty())
        else {
            return;
        };
        // The ids and stamps in a snapshot came from the *previous* launch's
        // `open_seq`, which restarts at 0 — advance the clock past them so a
        // freshly opened item can't mint an id a restored chip already holds
        // (two `<For>` rows with one key, and `close_item` hitting both).
        let high = restored.iter().map(|it| it.focused_at.max(it.id)).max();
        if let Some(high) = high {
            self.open_seq
                .update(|seq| *seq = (*seq).max(high.wrapping_add(1)));
        }
        self.open_items.set(restored);
    }

    /// Next tick of the working set's monotonic clock. One sequence mints ids
    /// *and* stamps focus, so "smallest stamp = least recently touched" holds
    /// across both without a second counter to keep in step.
    fn tick(&self) -> u64 {
        let n = self.open_seq.get_untracked();
        self.open_seq.set(n.wrapping_add(1));
        n
    }

    /// The one write path into `open_items`, so the parked snapshot can't drift
    /// from the signal — the same "make it structural, not vigilant" trade as
    /// `TenantScopedUi::reset`.
    fn update_open_items(&self, f: impl FnOnce(&mut Vec<OpenItem>)) {
        self.open_items.update(f);
        if let Some(key) = self.workspace_key()
            && let Ok(raw) = serde_json::to_string(&self.open_items.get_untracked())
        {
            store::save(&key, &raw);
        }
    }

    /// `localStorage` key for the active tenant's parked working set, or `None`
    /// when signed out (nothing to park, and nothing to read back into).
    /// **Tenant-scoped by construction** — see the module doc.
    fn workspace_key(&self) -> Option<String> {
        self.active_tenant.with_untracked(|t| {
            t.as_ref()
                .map(|t| format!("azapptoolkit:workspace:{}", t.tenant_id))
        })
    }
}
