//! Tenant lifecycle, bulk selection and reload counters.
//!
//! The tenant-switch reset is the repo's #1 documented footgun: `open_items` and
//! `shown_items` MUST be cleared here or a stale item leaks the previous
//! tenant's data into the next tenant's workspace. `tenant_switch_resets_every_tenant_scoped_field`
//! pins it.
//!
//! The parked-workspace restore that follows the clear is the same footgun read
//! backwards, which is why its `localStorage` key carries the tenant id — an
//! unkeyed snapshot would hand the arriving tenant the departing one's items.
//! `restore_open_items_never_crosses_tenants` pins that.

use super::*;

impl Session {
    /// Switching tenant resets selections and view.
    pub fn set_active_tenant(&self, tenant: Option<TenantContext>) {
        self.active_tenant.set(tenant);
        // Clear the cross-entity working set — a previous tenant's open items are
        // stale and would leak its data into the next tenant's workspace (the
        // repo's #1 footgun). `open_seq` stays monotonic, like `toast_seq`.
        //
        // Deliberately the raw `set`, not `Session::update_open_items`: that one
        // also writes the parked snapshot, and by this line `active_tenant` is
        // already the NEW tenant — so persisting the clear would wipe the very
        // working set the restore below is about to read back.
        self.open_items.set(Vec::new());
        self.shown_items.set(Vec::new());
        // Every lifted search/facet/selection/dialog signal resets structurally
        // — membership and sentinels live on `TenantScopedUi` itself.
        self.tenant_ui.reset();
        self.view.set(ActiveView::Home);
        // Only now — after the unconditional clear — read back what THIS tenant
        // parked. The snapshot is keyed by tenant id, so a restore can only ever
        // return the arriving tenant's own items; signed out (`None`), it
        // returns nothing at all.
        self.restore_open_items();
    }

    /// Toggle an application object id in the bulk-selection set.
    /// Whether `tenant_id` is still the active tenant — the post-await check
    /// for a command that started for it. Sign-out clears the tenant, so a
    /// result that lands after it fails this too, and must not report into
    /// the next sign-in. Untracked and disposal-safe (`false` if the session
    /// itself is gone).
    pub fn is_active_tenant(&self, tenant_id: &str) -> bool {
        self.active_tenant
            .try_with_untracked(|t| t.as_ref().map(|t| t.tenant_id.as_str()) == Some(tenant_id))
            .unwrap_or(false)
    }

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

    /// Force the enterprise-applications list to refetch.
    pub fn bump_enterprise_apps_reload(&self) {
        self.enterprise_apps_reload
            .update(|n| *n = n.wrapping_add(1));
    }

    /// Both entity lists refetch: for a write that adds or removes an app
    /// registration together with its paired service principal. The backend
    /// patches its caches for these writes, so both refetches are cache hits.
    pub fn bump_app_and_enterprise_reload(&self) {
        self.bump_apps_reload();
        self.bump_enterprise_apps_reload();
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
