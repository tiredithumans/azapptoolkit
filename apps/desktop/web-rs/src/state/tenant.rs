//! Tenant lifecycle, bulk selection and reload counters.
//!
//! The tenant-switch reset is the repo's #1 documented footgun: `open_items` and
//! `shown_items` MUST be cleared here or a stale item leaks the previous
//! tenant's data into the next tenant's workspace. `tenant_switch_resets_every_tenant_scoped_field`
//! pins it.

use super::*;

impl Session {
    /// Switching tenant resets selections and view, mirroring the
    /// `setActiveTenant` reducer in `apps/desktop/web/src/store.ts`.
    pub fn set_active_tenant(&self, tenant: Option<TenantContext>) {
        self.active_tenant.set(tenant);
        // Clear the cross-entity working set — a previous tenant's open items are
        // stale and would leak its data into the next tenant's workspace (the
        // repo's #1 footgun). `open_seq` stays monotonic, like `toast_seq`.
        self.open_items.set(Vec::new());
        self.shown_items.set(Vec::new());
        // Every lifted search/facet/selection/dialog signal resets structurally
        // — membership and sentinels live on `TenantScopedUi` itself.
        self.tenant_ui.reset();
        self.view.set(ActiveView::Home);
    }

    /// Toggle an application object id in the bulk-selection set.
    pub fn toggle_app_selected(&self, id: String) {
        toggle_in(self.tenant_ui.selected_app_ids, id);
    }

    /// True if `id` is in the bulk-selection set — O(1) (a per-row checkbox
    /// re-evaluates this on every selection change).
    pub fn is_app_selected(&self, id: &str) -> bool {
        self.tenant_ui.selected_app_ids.with(|ids| ids.contains(id))
    }

    /// Clear the bulk-selection set.
    pub fn clear_app_selection(&self) {
        self.tenant_ui.selected_app_ids.update(HashSet::clear);
    }

    /// Toggle an application object id in the audit-table selection set (the
    /// audit's inline bulk bar operates on this, kept separate from
    /// `selected_app_ids`).
    pub fn toggle_audit_selected(&self, id: String) {
        toggle_in(self.tenant_ui.selected_audit_ids, id);
    }

    /// True if `id` is in the audit-table selection set — O(1).
    pub fn is_audit_selected(&self, id: &str) -> bool {
        self.tenant_ui
            .selected_audit_ids
            .with(|ids| ids.contains(id))
    }

    /// Clear the audit-table selection set.
    pub fn clear_audit_selection(&self) {
        self.tenant_ui.selected_audit_ids.update(HashSet::clear);
    }

    /// Force the app-registrations list to refetch.
    pub fn bump_apps_reload(&self) {
        self.apps_reload.update(|n| *n = n.wrapping_add(1));
    }

    /// Signal that a fresh audit was cached, so audit-derived surfaces outside
    /// the audit view (the Home posture tile) refetch.
    pub fn bump_audit_reload(&self) {
        self.audit_reload.update(|n| *n = n.wrapping_add(1));
    }

    /// Force the Access Readiness checklist to re-run — called after a token
    /// refresh re-applies roles, so the checklist reflects newly-active access.
    pub fn bump_readiness_reload(&self) {
        self.readiness_reload.update(|n| *n = n.wrapping_add(1));
    }
}

/// Add `id` if absent, remove it if present.
///
/// The two selection sets (app-registrations list, audit table) are
/// deliberately separate — they are different working sets — but their toggle
/// was written out twice, character for character. One helper, two call sites:
/// a change to the toggle semantics (say, capping a selection) now has one home.
fn toggle_in(set: RwSignal<HashSet<String>>, id: String) {
    set.update(|ids| {
        if !ids.remove(&id) {
            ids.insert(id);
        }
    });
}
