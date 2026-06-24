//! Application-wide reactive state. Replaces the React-side Zustand store
//! with Leptos `RwSignal`s provided through context. Components consume
//! state via `use_session()` and call setter helpers that preserve the
//! original cross-field semantics (e.g. switching tenant clears the selected
//! app and resets the view).

use std::collections::HashSet;

use leptos::prelude::*;

use crate::bindings::TenantContext;
use crate::components::toast::{Toast, ToastAction, ToastKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActiveView {
    Home,
    Apps,
    EnterpriseApps,
    ManagedIdentities,
    /// Unified tenant-wide security surface: the security audit (hero) plus the
    /// Credential-expiry and Delegated-grants inventory lenses, switched by an
    /// internal sub-tab (`security_tab`). Replaces sibling nav destinations.
    Security,
    PermissionTester,
    /// Tenant-wide resource → identities reverse lookups, one tab per plane:
    /// Sites (sweep every site's app permissions — "which sites can this app
    /// reach?" / "which apps can touch this site?") and Mailboxes (probe every
    /// mail-permission holder against one mailbox — "who can read it?").
    ResourceAccess,
    /// Bulk actions over the app-registration multi-selection (a page, not a
    /// modal — the modal used to cover the very list selection it operates on).
    BulkActions,
    /// Key Vault secret browser (a page). A revealed secret lives only while
    /// this is the active view; a view-watch wipes it on navigate-away.
    KeyVault,
    /// Live role/scope readiness checklist for the signed-in user — what they
    /// currently hold vs. what each feature needs, across the three auth planes.
    Readiness,
    /// Disaster-recovery backup & restore: export a portable manifest of the
    /// tenant's app estate (and, in later slices, restore it into a new tenant).
    DisasterRecovery,
}

#[derive(Clone, Copy)]
pub struct Session {
    pub active_tenant: RwSignal<Option<TenantContext>>,
    pub selected_app_object_id: RwSignal<Option<String>>,
    pub selected_enterprise_app_id: RwSignal<Option<String>>,
    pub selected_managed_identity_id: RwSignal<Option<String>>,
    // Per-list "Filter this list" query. Lifted to the session (rather than a
    // local view signal) for two reasons: (1) the top-bar Global Search seeds it
    // when a record is picked, so jumping to a record lands the user on a
    // visibly-filtered list with that record's detail open; (2) it MUST be reset
    // on tenant switch (see `set_active_tenant`) — a leftover filter from another
    // tenant silently narrowing this tenant's list would be cross-tenant leakage.
    pub apps_search: RwSignal<String>,
    pub enterprise_search: RwSignal<String>,
    pub mi_search: RwSignal<String>,
    // Facet selection for each surface the Home dashboard drills INTO, lifted to
    // the session for the same two reasons as the searches above: (1) a metric
    // click seeds it via `open_*_with_facet` so the destination lands pre-filtered
    // to that subset; (2) it MUST reset on tenant switch (see `set_active_tenant`)
    // — a leftover facet silently narrowing the next tenant's list would be
    // cross-tenant leakage. Defaults are each surface's "show all" sentinel
    // ("all"). The App Registrations list keeps a local facet — no metric drills
    // into it (its card's secret/cert counts have no matching facet).
    pub enterprise_facet: RwSignal<String>,
    pub mi_facet: RwSignal<String>,
    // The security audit's filter is two INDEPENDENT, intersecting dimensions
    // (filter = severity AND finding), so the single old `audit_facet` is split
    // in two. Both are lifted + reset on tenant switch for the same
    // cross-tenant-leakage reason as the other facets; `open_posture_with_facet`
    // routes a Home-dashboard metric to whichever dimension it belongs to.
    pub audit_severity: RwSignal<String>,
    pub audit_finding: RwSignal<String>,
    pub credentials_facet: RwSignal<String>,
    // One-shot "open the filter drawer on arrival" flag. The Enterprise list's
    // facet chips live in a drawer collapsed by default, so a drill would land
    // filtered with the active chip hidden; `open_enterprise_with_facet` sets this
    // and the list consumes it once to expand the drawer (MI shows its chips
    // unconditionally and the audit/credentials surfaces show tabs, so neither
    // needs this). Reset on tenant switch with the facets.
    pub pending_open_filters: RwSignal<bool>,
    pub view: RwSignal<ActiveView>,
    // Multi-select set of application object ids, distinct from the
    // single-select `selected_app_object_id` (which drives the detail pane).
    // This set is what the bulk-actions dialog operates on.
    pub selected_app_ids: RwSignal<HashSet<String>>,
    // Separate multi-select set for the Security Audit table's inline bulk bar.
    // Kept distinct from `selected_app_ids` so checking rows in the audit doesn't
    // surface a stale selection in the App Registrations list (and vice versa) —
    // both hold app-registration object ids but they're independent working sets.
    // Reset on tenant switch alongside `selected_app_ids`.
    pub selected_audit_ids: RwSignal<HashSet<String>>,
    // Bumped to force the app-registrations list to refetch — e.g. after a
    // bulk delete / remove-expired sweep invalidates the backend cache.
    pub apps_reload: RwSignal<u32>,
    // Enterprise-app reload bump (analogous to `apps_reload`).
    pub enterprise_apps_reload: RwSignal<u32>,
    // Bumped when a security audit completes, so surfaces that cache the audit
    // result independently of the audit view — chiefly the Home dashboard's
    // "Security Posture" tile, which stays mounted (keep-alive) across view
    // switches — refetch the freshly cached run instead of showing stale state.
    pub audit_reload: RwSignal<u32>,
    // Shell-owned tool dialog flag. Lifted here so the dialog can be mounted by
    // the persistent shell and triggered from the nav rail no matter which view
    // is on screen. (Key Vault and Bulk actions are now pages — ActiveView
    // variants — not modals; only Cache diagnostics remains a modal.)
    pub cache_open: RwSignal<bool>,
    // Create-app dialog open flag (also lifted to shell so it survives view
    // switches — the old approach re-mounted the dialog and lost state).
    pub create_open: RwSignal<bool>,
    // "New SSO application" wizard open flag. Lifted to the shell (like
    // `create_open`) so it survives view switches and is triggered from the
    // Enterprise Apps view header.
    pub sso_wizard_open: RwSignal<bool>,
    // Deep-link target tab for the app detail pane. Set by `open_app_on_tab`
    // (e.g. the credential dashboard's "Open" action) and consumed once by the
    // detail pane on mount so it opens directly on that tab instead of Overview.
    pub pending_app_tab: RwSignal<Option<String>>,
    // Same deep-link mechanism for the enterprise-app detail pane (e.g. a
    // consent-grant "Open" jumping straight to its Permissions tab). Consumed
    // once by the enterprise pane on mount.
    pub pending_enterprise_tab: RwSignal<Option<String>>,
    // Last-viewed detail tab per resource type, so switching between items keeps
    // the admin's working tab (e.g. stay on Permissions across apps) instead of
    // snapping back to Overview. A deep-link via `pending_app_tab` overrides it.
    pub last_app_tab: RwSignal<String>,
    pub last_enterprise_tab: RwSignal<String>,
    pub last_mi_tab: RwSignal<String>,
    // Active sub-tab of the unified Security surface ("posture" | "credentials"
    // | "grants"). Lifted to the session so the Home cards and command palette
    // can deep-link straight to a sub-tab, and so the choice survives navigating
    // away and back.
    pub security_tab: RwSignal<String>,
    // In-app toast stack + a monotonic id source. Rendered once by
    // `ToastHost` near the shell root; pushed via the helpers below.
    // `LocalStorage`-backed because `Toast` carries a non-`Send` `Rc<dyn Fn()>`
    // retry action — fine for this CSR-only (single-threaded wasm) frontend.
    pub toasts: RwSignal<Vec<Toast>, LocalStorage>,
    pub toast_seq: RwSignal<u64>,
}

impl Session {
    /// Switching tenant resets selections and view, mirroring the
    /// `setActiveTenant` reducer in `apps/desktop/web/src/store.ts`.
    pub fn set_active_tenant(&self, tenant: Option<TenantContext>) {
        self.active_tenant.set(tenant);
        self.selected_app_object_id.set(None);
        self.selected_enterprise_app_id.set(None);
        self.selected_managed_identity_id.set(None);
        self.selected_app_ids.update(HashSet::clear);
        self.selected_audit_ids.update(HashSet::clear);
        // Clear per-list filters so a previous tenant's query never narrows the
        // next tenant's list (cross-tenant leakage is this repo's #1 footgun).
        self.apps_search.set(String::new());
        self.enterprise_search.set(String::new());
        self.mi_search.set(String::new());
        // Reset the lifted facets to their "show all" sentinel for the same
        // cross-tenant-leakage reason as the searches above (the App Registrations
        // facet is local, so it rides its own view's lifecycle).
        self.enterprise_facet.set(String::from("all"));
        self.mi_facet.set(String::from("all"));
        self.audit_severity.set(String::from("all"));
        self.audit_finding.set(String::from("all"));
        self.credentials_facet.set(String::from("all"));
        self.pending_open_filters.set(false);
        self.view.set(ActiveView::Home);
        self.cache_open.set(false);
        self.pending_app_tab.set(None);
        self.pending_enterprise_tab.set(None);
    }

    pub fn set_selected_app(&self, id: Option<String>) {
        self.selected_app_object_id.set(id);
    }

    /// Toggle an application object id in the bulk-selection set.
    pub fn toggle_app_selected(&self, id: String) {
        self.selected_app_ids.update(|ids| {
            if !ids.remove(&id) {
                ids.insert(id);
            }
        });
    }

    /// True if `id` is in the bulk-selection set — O(1) (a per-row checkbox
    /// re-evaluates this on every selection change).
    pub fn is_app_selected(&self, id: &str) -> bool {
        self.selected_app_ids.with(|ids| ids.contains(id))
    }

    /// Clear the bulk-selection set.
    pub fn clear_app_selection(&self) {
        self.selected_app_ids.update(HashSet::clear);
    }

    /// Toggle an application object id in the audit-table selection set (the
    /// audit's inline bulk bar operates on this, kept separate from
    /// `selected_app_ids`).
    pub fn toggle_audit_selected(&self, id: String) {
        self.selected_audit_ids.update(|ids| {
            if !ids.remove(&id) {
                ids.insert(id);
            }
        });
    }

    /// True if `id` is in the audit-table selection set — O(1).
    pub fn is_audit_selected(&self, id: &str) -> bool {
        self.selected_audit_ids.with(|ids| ids.contains(id))
    }

    /// Clear the audit-table selection set.
    pub fn clear_audit_selection(&self) {
        self.selected_audit_ids.update(HashSet::clear);
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

    pub fn set_selected_enterprise_app(&self, id: Option<String>) {
        self.selected_enterprise_app_id.set(id);
    }

    pub fn set_selected_managed_identity(&self, id: Option<String>) {
        self.selected_managed_identity_id.set(id);
    }

    pub fn set_view(&self, view: ActiveView) {
        self.view.set(view);
    }

    /// Navigate to the unified Security surface on a specific sub-tab
    /// (`"posture"` | `"credentials"` | `"grants"`). Used by the Home cards and
    /// command palette to deep-link past the default Posture tab.
    pub fn open_security(&self, tab: &str) {
        self.security_tab.set(tab.to_string());
        self.view.set(ActiveView::Security);
    }

    /// Open the Create-app dialog. (Lifted to the shell so it survives view
    /// switches.)
    pub fn open_create_app(&self) {
        self.create_open.set(true);
    }

    /// Navigate to an app registration's detail pane opened on a specific tab
    /// (e.g. `"credentials"`). Used to deep-link from the credential-expiry
    /// dashboard straight into the rotation workflow. The detail pane consumes
    /// `pending_app_tab` once on mount.
    pub fn open_app_on_tab(&self, object_id: String, tab: &str) {
        self.pending_app_tab.set(Some(tab.to_string()));
        self.selected_app_object_id.set(Some(object_id));
        self.view.set(ActiveView::Apps);
    }

    /// Navigate to an enterprise application's detail pane opened on a specific
    /// tab (e.g. `"permissions"`). Used to deep-link from a risky consent grant
    /// or delegated-permission finding straight to where it can be revoked. The
    /// enterprise pane consumes `pending_enterprise_tab` once on mount.
    pub fn open_enterprise_on_tab(&self, sp_object_id: String, tab: &str) {
        self.pending_enterprise_tab.set(Some(tab.to_string()));
        self.selected_enterprise_app_id.set(Some(sp_object_id));
        self.view.set(ActiveView::EnterpriseApps);
    }

    /// Navigate to the Enterprise Applications list pre-filtered to a facet
    /// (`"disabled"` | `"foreign"` | `"enabled"`). Used by the Home dashboard's
    /// Enterprise metrics. Clears any lingering per-list search so the drilled
    /// list matches the clicked metric, and trips `pending_open_filters` so the
    /// list expands its (collapsed-by-default) drawer to show the active chip.
    pub fn open_enterprise_with_facet(&self, facet: &str) {
        self.enterprise_facet.set(facet.to_string());
        self.enterprise_search.set(String::new());
        self.pending_open_filters.set(true);
        self.view.set(ActiveView::EnterpriseApps);
    }

    /// Navigate to the Managed Identities list pre-filtered to a facet
    /// (`"system"` | `"user"` | `"enabled"` | `"disabled"`). Used by the Home
    /// dashboard's Managed Identities metrics. (MI chips are always visible, so
    /// no drawer needs expanding.)
    pub fn open_managed_identities_with_facet(&self, facet: &str) {
        self.mi_facet.set(facet.to_string());
        self.mi_search.set(String::new());
        self.view.set(ActiveView::ManagedIdentities);
    }

    /// Navigate to the Security surface's Posture (audit) sub-tab pre-filtered to
    /// an audit facet (`"critical"` | `"high"` | `"ownership"` | `"unused"` | …).
    /// Used by the Home dashboard's Security Posture metrics. The audit view
    /// loads the cached run on mount, so the drilled facet lands on populated
    /// data without re-running the scan.
    ///
    /// The audit filter is now two intersecting dimensions (severity + finding),
    /// so route the single metric string to whichever dimension it names and
    /// reset the other to "all" — a Home metric seeds exactly its own subset.
    pub fn open_posture_with_facet(&self, facet: &str) {
        match facet {
            "critical" | "high" | "medium" | "low" => {
                self.audit_severity.set(facet.to_string());
                self.audit_finding.set(String::from("all"));
            }
            "all" => {
                self.audit_severity.set(String::from("all"));
                self.audit_finding.set(String::from("all"));
            }
            // Any other value is a finding-dimension facet (expiring, unused,
            // ownership, orgwide_mailbox, …).
            _ => {
                self.audit_finding.set(facet.to_string());
                self.audit_severity.set(String::from("all"));
            }
        }
        self.open_security("posture");
    }

    /// Navigate to the Security surface's Credential-expiry sub-tab pre-filtered
    /// to a facet (`"expired"` | `"7"` | `"30"`). Used by the Home dashboard's
    /// Credential Health metrics — that surface is per-credential (one row per
    /// secret/cert), so the drilled count matches the clicked metric, unlike the
    /// per-app App Registrations credential facet.
    pub fn open_credentials_with_facet(&self, facet: &str) {
        self.credentials_facet.set(facet.to_string());
        self.open_security("credentials");
    }

    /// Push a toast and return its id. `action_label` + `action` render an
    /// inline button (used for Retry on retryable errors). The id lets a
    /// caller dismiss the toast later.
    pub fn push_toast(
        &self,
        kind: ToastKind,
        message: impl Into<String>,
        action_label: Option<String>,
        action: Option<ToastAction>,
    ) -> u64 {
        let id = self.toast_seq.get_untracked();
        self.toast_seq.set(id.wrapping_add(1));
        self.toasts.update(|list| {
            list.push(Toast {
                id,
                kind,
                message: message.into(),
                action_label,
                action,
            });
            // Cap the visible stack so a burst of failures (e.g. a tight
            // mutation loop) can't paper the screen — drop the oldest.
            const MAX_TOASTS: usize = 5;
            let overflow = list.len().saturating_sub(MAX_TOASTS);
            if overflow > 0 {
                list.drain(0..overflow);
            }
        });
        id
    }

    /// Convenience: a success toast (auto-dismisses).
    pub fn toast_success(&self, message: impl Into<String>) -> u64 {
        self.push_toast(ToastKind::Success, message, None, None)
    }

    /// Convenience: an error toast. With `retry: Some(..)` the toast gains a
    /// "Retry" button and stays until acted on / dismissed.
    pub fn toast_error(&self, message: impl Into<String>, retry: Option<ToastAction>) -> u64 {
        let label = retry.as_ref().map(|_| "Retry".to_string());
        self.push_toast(ToastKind::Error, message, label, retry)
    }

    /// Remove the toast with `id` (no-op if already gone).
    pub fn dismiss_toast(&self, id: u64) {
        self.toasts.update(|list| list.retain(|t| t.id != id));
    }
}

/// Provide a fresh `Session` into the current Leptos context. Call once at
/// the root.
pub fn provide_session() {
    let session = Session {
        active_tenant: RwSignal::new(None),
        selected_app_object_id: RwSignal::new(None),
        selected_enterprise_app_id: RwSignal::new(None),
        selected_managed_identity_id: RwSignal::new(None),
        apps_search: RwSignal::new(String::new()),
        enterprise_search: RwSignal::new(String::new()),
        mi_search: RwSignal::new(String::new()),
        enterprise_facet: RwSignal::new(String::from("all")),
        mi_facet: RwSignal::new(String::from("all")),
        audit_severity: RwSignal::new(String::from("all")),
        audit_finding: RwSignal::new(String::from("all")),
        credentials_facet: RwSignal::new(String::from("all")),
        pending_open_filters: RwSignal::new(false),
        selected_app_ids: RwSignal::new(HashSet::new()),
        selected_audit_ids: RwSignal::new(HashSet::new()),
        apps_reload: RwSignal::new(0),
        view: RwSignal::new(ActiveView::Home),
        cache_open: RwSignal::new(false),
        create_open: RwSignal::new(false),
        sso_wizard_open: RwSignal::new(false),
        pending_app_tab: RwSignal::new(None),
        pending_enterprise_tab: RwSignal::new(None),
        last_app_tab: RwSignal::new(String::from("overview")),
        last_enterprise_tab: RwSignal::new(String::from("overview")),
        last_mi_tab: RwSignal::new(String::from("overview")),
        security_tab: RwSignal::new(String::from("posture")),
        enterprise_apps_reload: RwSignal::new(0),
        audit_reload: RwSignal::new(0),
        toasts: RwSignal::new_local(Vec::new()),
        toast_seq: RwSignal::new(0),
    };
    provide_context(session);
}

/// Pull the session out of context. Panics if `provide_session()` was not
/// called by an ancestor — same trade-off as React Context's mandatory
/// provider.
pub fn use_session() -> Session {
    use_context::<Session>().expect("Session not provided — wrap your tree in <App />")
}
