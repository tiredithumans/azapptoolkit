//! The cross-entity open-items working set.
//!
//! One shared set of chips, deduped by `(kind, entity_id)`, capped and 1-up (or
//! 2-up when split). There is no side detail pane and no `selected_*_id`
//! signal — this IS the selection model.

use super::*;

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
        let id = self.open_seq.get_untracked();
        self.open_seq.set(id.wrapping_add(1));
        // Cap the working set so it can't grow unbounded — drop the oldest.
        const MAX_OPEN_ITEMS: usize = 8;
        let mut dropped: Vec<u64> = Vec::new();
        self.open_items.update(|list| {
            list.push(OpenItem {
                id,
                kind,
                entity_id,
                title,
            });
            let overflow = list.len().saturating_sub(MAX_OPEN_ITEMS);
            if overflow > 0 {
                dropped = list.drain(0..overflow).map(|it| it.id).collect();
            }
        });
        if !dropped.is_empty() {
            self.shown_items
                .update(|shown| shown.retain(|s| !dropped.contains(s)));
        }
        self.focus_item(id, false);
        id
    }

    /// Show `id` in the workspace. `split = false` replaces the shown set (1-up);
    /// `split = true` pins it alongside the current pane for side-by-side
    /// compare, capped at two (drops the oldest pane on overflow).
    pub fn focus_item(&self, id: u64, split: bool) {
        const MAX_SHOWN: usize = 2;
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
        self.open_items.update(|list| list.retain(|it| it.id != id));
        self.shown_items.update(|shown| shown.retain(|s| *s != id));
    }

    /// Close the entire working set — empties the dock and the workspace. (Tenant
    /// switch does the same via `set_active_tenant`; this is the explicit, in-
    /// tenant "Close all".)
    pub fn close_all_items(&self) {
        self.open_items.set(Vec::new());
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
            self.open_items.update(|list| {
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
}
