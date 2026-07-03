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

/// Which entity surface an [`OpenItem`] points at — the three list views whose
/// rows can be opened into the shared workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenItemKind {
    AppReg,
    Enterprise,
    ManagedIdentity,
}

/// One entry in the cross-entity "working set" — an item the admin has opened
/// into the workspace dock. Modeled on the toast stack: a `Vec` of these on
/// `Session` with a monotonic `open_seq` id source, capped + drain-oldest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenItem {
    /// Monotonic id from `open_seq` — the stable `<For>` key for this item's
    /// window, so closing/reordering siblings never remounts (and discards the
    /// live state of) another window.
    pub id: u64,
    pub kind: OpenItemKind,
    /// App object id / SP id / MI service-principal id, per `kind`.
    pub entity_id: String,
    /// Dock chip label. Best-effort at open time (the clicked row's name); the
    /// window calls [`Session::set_open_item_title`] once its detail resolves so
    /// deep-link / global-search opens that lacked a name self-correct.
    pub title: String,
}

/// Every lifted search / facet / selection / dialog signal that would leak one
/// tenant's context into the next if it survived a tenant switch — the
/// front-end mirror of the backend's tenant-scoped-cache footgun. Grouped so
/// the reset is structural: [`Self::reset`] lives DIRECTLY below the field
/// declarations, and **every field added here must be reset in `reset()` —
/// that adjacency is the point** (the old flat-on-`Session` shape relied on
/// remembering to extend `set_active_tenant`, and drifted twice).
///
/// All fields are `Copy` `RwSignal`s, so this struct (and `Session`) stay
/// `Copy`. Deliberately NOT here: state that must survive a tenant switch
/// (`last_*_tab`, `security_tab`, reload bumps, toasts, `open_seq`) and the
/// open-items working set (`open_items`/`shown_items` — reset in
/// `set_active_tenant` next to their own footgun comment, but owned by
/// `Session` because their helper API (`open_item`, `focus_item`, …) and the
/// monotonic `open_seq` form one model).
#[derive(Clone, Copy)]
pub struct TenantScopedUi {
    // Per-list "Filter this list" query. Lifted to the session (rather than a
    // local view signal) so the top-bar Global Search can seed it when a record
    // is picked — jumping to a record lands the user on a visibly-filtered list
    // with that record's detail open.
    pub apps_search: RwSignal<String>,
    pub enterprise_search: RwSignal<String>,
    pub mi_search: RwSignal<String>,
    // Facet selection for each surface the Home dashboard drills INTO: a metric
    // click seeds it via `open_*_with_facet` so the destination lands
    // pre-filtered to that subset. Defaults are each surface's "show all"
    // sentinel ("all"). The App Registrations list keeps a local facet — no
    // metric drills into it (its card's secret/cert counts have no matching
    // facet).
    pub enterprise_facet: RwSignal<String>,
    pub mi_facet: RwSignal<String>,
    // The All-apps audit pane's ONE filter dimension (risk severity); Home's
    // Critical/High/Medium drills seed it via `open_posture_with_facet`. (The
    // old second dimension, `audit_finding`, is gone — finding-shaped browsing
    // lives in the Findings pane's groups, driven by `audit_expanded_group`
    // below.)
    pub audit_severity: RwSignal<String>,
    // Which finding group the Findings pane has expanded (accordion — one at a
    // time; `None` = all collapsed). Holds a `groups::GROUP_CATALOG` key.
    // Lifted so Home's finding drills land with the right group open.
    pub audit_expanded_group: RwSignal<Option<String>>,
    pub credentials_facet: RwSignal<String>,
    // One-shot "open the filter drawer on arrival" flag. The Enterprise list's
    // facet chips live in a drawer collapsed by default, so a drill would land
    // filtered with the active chip hidden; `open_enterprise_with_facet` sets
    // this and the list consumes it once to expand the drawer (MI shows its
    // chips unconditionally and the audit/credentials surfaces show tabs, so
    // neither needs this).
    pub pending_open_filters: RwSignal<bool>,
    // Multi-select set of application object ids — distinct from the
    // workspace's open-items working set; this set is what the bulk-actions
    // dialog operates on.
    pub selected_app_ids: RwSignal<HashSet<String>>,
    // Separate multi-select set for the Security Audit table's inline bulk bar.
    // Kept distinct from `selected_app_ids` so checking rows in the audit
    // doesn't surface a stale selection in the App Registrations list (and vice
    // versa) — both hold app-registration object ids but they're independent
    // working sets.
    pub selected_audit_ids: RwSignal<HashSet<String>>,
    // Deep-link target tab for the app detail pane. Set by `open_app_on_tab`
    // (e.g. the credential dashboard's "Open" action) and consumed once by the
    // detail pane on mount so it opens directly on that tab instead of
    // Overview.
    pub pending_app_tab: RwSignal<Option<String>>,
    // Same deep-link mechanism for the enterprise-app detail pane (e.g. a
    // consent-grant "Open" jumping straight to its Permissions tab). Consumed
    // once by the enterprise pane on mount.
    pub pending_enterprise_tab: RwSignal<Option<String>>,
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
}

impl TenantScopedUi {
    fn new() -> Self {
        Self {
            apps_search: RwSignal::new(String::new()),
            enterprise_search: RwSignal::new(String::new()),
            mi_search: RwSignal::new(String::new()),
            enterprise_facet: RwSignal::new(String::from("all")),
            mi_facet: RwSignal::new(String::from("all")),
            audit_severity: RwSignal::new(String::from("all")),
            audit_expanded_group: RwSignal::new(None),
            credentials_facet: RwSignal::new(String::from("all")),
            pending_open_filters: RwSignal::new(false),
            selected_app_ids: RwSignal::new(HashSet::new()),
            selected_audit_ids: RwSignal::new(HashSet::new()),
            pending_app_tab: RwSignal::new(None),
            pending_enterprise_tab: RwSignal::new(None),
            cache_open: RwSignal::new(false),
            create_open: RwSignal::new(false),
            sso_wizard_open: RwSignal::new(false),
        }
    }

    /// Reset every field to its "show all"/empty/closed sentinel. Called by
    /// `Session::set_active_tenant` — a leftover search, facet, selection,
    /// pending deep-link, or open dialog from another tenant silently applied
    /// to the next tenant's data is cross-tenant leakage (this repo's #1
    /// footgun). Every field declared above MUST have a line here; the
    /// `tenant_switch_resets_every_tenant_scoped_field` test pins it.
    pub fn reset(&self) {
        self.apps_search.set(String::new());
        self.enterprise_search.set(String::new());
        self.mi_search.set(String::new());
        self.enterprise_facet.set(String::from("all"));
        self.mi_facet.set(String::from("all"));
        self.audit_severity.set(String::from("all"));
        self.audit_expanded_group.set(None);
        self.credentials_facet.set(String::from("all"));
        self.pending_open_filters.set(false);
        self.selected_app_ids.update(HashSet::clear);
        self.selected_audit_ids.update(HashSet::clear);
        self.pending_app_tab.set(None);
        self.pending_enterprise_tab.set(None);
        self.cache_open.set(false);
        self.create_open.set(false);
        self.sso_wizard_open.set(false);
    }
}

#[derive(Clone, Copy)]
pub struct Session {
    pub active_tenant: RwSignal<Option<TenantContext>>,
    // The shared, cross-entity "working set": every item the admin has opened
    // into the workspace dock, across all three list views. Modeled on the
    // toast stack below (`Vec` + a monotonic `open_seq` id source, capped +
    // drain-oldest). `shown_items` names the 1–2 currently displayed by id
    // (left, right). Plain `RwSignal` (not `LocalStorage`) — `OpenItem` is
    // `Send`, unlike `Toast`'s `Rc<dyn Fn()>` retry action. CROSS-TENANT
    // FOOTGUN: both `open_items` and `shown_items` MUST reset in
    // `set_active_tenant` (an open item from another tenant is stale + leaks).
    // They live on `Session` (not `TenantScopedUi`) because the working-set
    // helpers + monotonic `open_seq` form one model.
    pub open_items: RwSignal<Vec<OpenItem>>,
    pub open_seq: RwSignal<u64>,
    pub shown_items: RwSignal<Vec<u64>>,
    // Every tenant-scoped search/facet/selection/dialog signal, grouped so the
    // tenant-switch reset is structural — see the type's doc for the invariant.
    pub tenant_ui: TenantScopedUi,
    pub view: RwSignal<ActiveView>,
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
    // Last-viewed detail tab per resource type, so switching between items keeps
    // the admin's working tab (e.g. stay on Permissions across apps) instead of
    // snapping back to Overview. A deep-link via `pending_app_tab` overrides it.
    pub last_app_tab: RwSignal<String>,
    pub last_enterprise_tab: RwSignal<String>,
    pub last_mi_tab: RwSignal<String>,
    // Active sub-tab of the Security workbench ("findings" | "apps" |
    // "credentials" | "grants"). Lifted to the session so the Home cards and
    // command palette can deep-link straight to a sub-tab, and so the choice
    // survives navigating away and back.
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
        self.tenant_ui.selected_app_ids.update(|ids| {
            if !ids.remove(&id) {
                ids.insert(id);
            }
        });
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
        self.tenant_ui.selected_audit_ids.update(|ids| {
            if !ids.remove(&id) {
                ids.insert(id);
            }
        });
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

    /// Navigate to `view`. Collapses the open-items workspace overlay back to the
    /// dock — the open items stay as chips, only the on-top detail panes are
    /// dismissed — so the destination view is visible instead of hidden behind
    /// them. (The two callers that navigate *and* open a detail — pairing jumps
    /// and Global Search — call this first, then `open_item`, which re-shows.)
    pub fn set_view(&self, view: ActiveView) {
        self.shown_items.set(Vec::new());
        self.view.set(view);
    }

    /// Navigate to the Security workbench on a specific sub-tab (`"findings"`
    /// | `"apps"` | `"credentials"` | `"grants"`). Used by the Home cards and
    /// command palette to deep-link past the default Findings tab.
    pub fn open_security(&self, tab: &str) {
        self.security_tab.set(tab.to_string());
        self.view.set(ActiveView::Security);
    }

    /// Open the Create-app dialog. (Lifted to the shell so it survives view
    /// switches.)
    pub fn open_create_app(&self) {
        self.tenant_ui.create_open.set(true);
    }

    /// Open an app registration in the workspace on a specific tab (e.g.
    /// `"credentials"`). Used to deep-link from the credential-expiry dashboard
    /// straight into the rotation workflow. The detail pane consumes
    /// `pending_app_tab` once on mount; the chip starts labelled with the id and
    /// the pane corrects it to the real name once it loads.
    pub fn open_app_on_tab(&self, object_id: String, tab: &str) {
        self.tenant_ui.pending_app_tab.set(Some(tab.to_string()));
        self.view.set(ActiveView::Apps);
        self.open_item(OpenItemKind::AppReg, object_id.clone(), object_id);
    }

    /// Open an enterprise application in the workspace on a specific tab (e.g.
    /// `"permissions"`). Used to deep-link from a risky consent grant or
    /// delegated-permission finding straight to where it can be revoked. The
    /// enterprise pane consumes `pending_enterprise_tab` once on mount.
    pub fn open_enterprise_on_tab(&self, sp_object_id: String, tab: &str) {
        self.tenant_ui
            .pending_enterprise_tab
            .set(Some(tab.to_string()));
        self.view.set(ActiveView::EnterpriseApps);
        self.open_item(OpenItemKind::Enterprise, sp_object_id.clone(), sp_object_id);
    }

    /// Open a managed identity in the workspace on a specific tab (e.g.
    /// `"permissions"`). Used to deep-link from an SP-only audit finding. The MI
    /// pane has no pending-tab signal; it initializes from `last_mi_tab`, so
    /// setting that here lands a *newly mounted* window on the target tab (an
    /// already-open window keeps its live tab, same as the pending-tab panes).
    pub fn open_managed_identity_on_tab(&self, sp_object_id: String, tab: &str) {
        self.last_mi_tab.set(tab.to_string());
        self.view.set(ActiveView::ManagedIdentities);
        self.open_item(
            OpenItemKind::ManagedIdentity,
            sp_object_id.clone(),
            sp_object_id,
        );
    }

    /// Navigate to the Enterprise Applications list pre-filtered to a facet
    /// (`"disabled"` | `"foreign"` | `"enabled"`). Used by the Home dashboard's
    /// Enterprise metrics. Clears any lingering per-list search so the drilled
    /// list matches the clicked metric, and trips `pending_open_filters` so the
    /// list expands its (collapsed-by-default) drawer to show the active chip.
    pub fn open_enterprise_with_facet(&self, facet: &str) {
        self.tenant_ui.enterprise_facet.set(facet.to_string());
        self.tenant_ui.enterprise_search.set(String::new());
        self.tenant_ui.pending_open_filters.set(true);
        self.view.set(ActiveView::EnterpriseApps);
    }

    /// Navigate to the Managed Identities list pre-filtered to a facet
    /// (`"system"` | `"user"` | `"enabled"` | `"disabled"`). Used by the Home
    /// dashboard's Managed Identities metrics. (MI chips are always visible, so
    /// no drawer needs expanding.)
    pub fn open_managed_identities_with_facet(&self, facet: &str) {
        self.tenant_ui.mi_facet.set(facet.to_string());
        self.tenant_ui.mi_search.set(String::new());
        self.view.set(ActiveView::ManagedIdentities);
    }

    /// Drill from a Home "Security Posture" metric into the Security
    /// workbench. Severity metrics (`"critical"` | `"high"` | `"medium"` |
    /// `"low"`) land on the **All apps** pane with that severity filter set;
    /// finding metrics (`"expired"`, `"ownership"`, `"orgwide_mailbox"`, …)
    /// land on the **Findings** pane with that group expanded. The workbench
    /// hydrates the cached run on mount, so the drill lands on populated data
    /// without re-running the scan.
    pub fn open_posture_with_facet(&self, facet: &str) {
        match facet {
            "critical" | "high" | "medium" | "low" => {
                self.tenant_ui.audit_severity.set(facet.to_string());
                self.open_security("apps");
            }
            "all" => {
                self.tenant_ui.audit_expanded_group.set(None);
                self.open_security("findings");
            }
            // Any other value is a finding-group key (unused, ownership,
            // orgwide_mailbox, …).
            _ => {
                self.tenant_ui
                    .audit_expanded_group
                    .set(Some(facet.to_string()));
                self.open_security("findings");
            }
        }
    }

    /// Navigate to the Security surface's Credential-expiry sub-tab pre-filtered
    /// to a facet (`"expired"` | `"7"` | `"30"`). Used by the Home dashboard's
    /// Credential Health metrics — that surface is per-credential (one row per
    /// secret/cert), so the drilled count matches the clicked metric, unlike the
    /// per-app App Registrations credential facet.
    pub fn open_credentials_with_facet(&self, facet: &str) {
        self.tenant_ui.credentials_facet.set(facet.to_string());
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

    /// Interactively re-authenticate the signed-in account in place — one browser
    /// round trip — when the session has gone dead, so the user skips the manual
    /// Sign Out → Sign In (which would also wipe the cached lists + audit run).
    /// The tenant id is unchanged (the backend validates the returned identity
    /// matches), so this deliberately does **not** call `set_active_tenant`:
    /// re-setting it would needlessly reset the user's filters and selection.
    /// Used by the smart Refresh button's fallback and the
    /// [`Self::report_command_error`] "Re-authenticate" toast action.
    pub fn spawn_reauth(&self) {
        let session = *self;
        leptos::task::spawn_local(async move {
            let Some(tenant) = session.active_tenant.get_untracked() else {
                return;
            };
            match crate::bindings::auth::reauthenticate(&tenant).await {
                Ok(_) => {
                    session.toast_success("Re-authenticated — retry the action that failed.");
                }
                Err(e) => {
                    session.toast_error(format!("Couldn't re-authenticate: {}", e.message), None);
                }
            }
        });
    }

    /// When `e` means the **session is dead** — the refresh token
    /// expired/revoked (`refresh_missing`) or there's no session at all
    /// (`not_signed_in`) — show the persistent error toast whose action
    /// re-authenticates in place (see [`Self::spawn_reauth`]) and return
    /// `true`; otherwise show nothing and return `false`. Surfaces with their
    /// own error affordance (an inline banner, a contextual toast) call this
    /// first so a dead session still gets the recovery action instead of a
    /// dead-end message, without growing another copy of the code set.
    ///
    /// The two codes are the wire contract from `azapptoolkit_dto`'s
    /// `From<AuthError>`: `InvalidGrant`/`RefreshTokenMissing` → `refresh_missing`,
    /// `NotSignedIn` → `not_signed_in`.
    pub fn report_if_session_dead(&self, e: &azapptoolkit_dto::UiError) -> bool {
        if !matches!(e.code.as_str(), "refresh_missing" | "not_signed_in") {
            return false;
        }
        let session = *self;
        self.push_toast(
            ToastKind::Error,
            "Your session has expired — re-authenticate to continue.",
            Some("Re-authenticate".to_string()),
            Some(std::rc::Rc::new(move || session.spawn_reauth())),
        );
        true
    }

    /// Surface a failed command: the dead-session recovery toast when it
    /// applies (see [`Self::report_if_session_dead`]), else a plain
    /// `toast_error`. This is the central error sink `use_command` routes
    /// through.
    pub fn report_command_error(&self, e: &azapptoolkit_dto::UiError) {
        if !self.report_if_session_dead(e) {
            self.toast_error(e.message.clone(), None);
        }
    }
}

/// Provide a fresh `Session` into the current Leptos context. Call once at
/// the root.
pub fn provide_session() {
    let session = Session {
        active_tenant: RwSignal::new(None),
        open_items: RwSignal::new(Vec::new()),
        open_seq: RwSignal::new(0),
        shown_items: RwSignal::new(Vec::new()),
        tenant_ui: TenantScopedUi::new(),
        apps_reload: RwSignal::new(0),
        view: RwSignal::new(ActiveView::Home),
        last_app_tab: RwSignal::new(String::from("overview")),
        last_enterprise_tab: RwSignal::new(String::from("overview")),
        last_mi_tab: RwSignal::new(String::from("overview")),
        security_tab: RwSignal::new(String::from("findings")),
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

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_dto::UiError;

    // `Session` holds `RwSignal`s, so a reactive owner must be active.
    fn with_session<R>(f: impl FnOnce(Session) -> R) -> R {
        Owner::new().with(|| {
            provide_session();
            f(use_session())
        })
    }

    #[test]
    fn report_command_error_offers_reauth_on_dead_session() {
        // Both `refresh_missing` (expired/revoked or absent refresh token) and
        // `not_signed_in` are the wire codes that mean "interactive re-auth
        // required"; each must surface a "Re-authenticate" toast action.
        for code in ["refresh_missing", "not_signed_in"] {
            with_session(|session| {
                session.report_command_error(&UiError::new(code, "boom", false));
                session.toasts.with_untracked(|list| {
                    assert_eq!(list.len(), 1, "code {code}");
                    let t = &list[0];
                    assert!(matches!(t.kind, ToastKind::Error));
                    assert_eq!(t.action_label.as_deref(), Some("Re-authenticate"));
                    assert!(
                        t.action.is_some(),
                        "code {code} should carry a re-auth action"
                    );
                });
            });
        }
    }

    #[test]
    fn report_if_session_dead_ignores_ordinary_errors() {
        with_session(|session| {
            // An ordinary command failure is the caller's to surface (inline
            // banner / contextual toast) — no toast from the helper.
            assert!(!session.report_if_session_dead(&UiError::new("graph_error", "boom", true)));
            session
                .toasts
                .with_untracked(|list| assert!(list.is_empty()));
        });
    }

    #[test]
    fn tenant_switch_resets_every_tenant_scoped_field() {
        // Pins the `TenantScopedUi` invariant: every field must return to its
        // "show all"/empty/closed sentinel on tenant switch — a survivor is
        // cross-tenant leakage (a stale search/facet silently narrowing the
        // next tenant's list, a selection targeting the wrong tenant's apps, a
        // create-app form or SSO wizard floating over the new tenant's Home).
        // Adding a field to `TenantScopedUi` without a `reset()` line (and an
        // assertion here) is the drift this structure exists to prevent.
        with_session(|session| {
            let ui = session.tenant_ui;
            ui.apps_search.set("query".into());
            ui.enterprise_search.set("query".into());
            ui.mi_search.set("query".into());
            ui.enterprise_facet.set("disabled".into());
            ui.mi_facet.set("user".into());
            ui.audit_severity.set("critical".into());
            ui.audit_expanded_group.set(Some("ownership".into()));
            ui.credentials_facet.set("expired".into());
            ui.pending_open_filters.set(true);
            ui.selected_app_ids.update(|s| {
                s.insert("app-1".into());
            });
            ui.selected_audit_ids.update(|s| {
                s.insert("app-2".into());
            });
            ui.pending_app_tab.set(Some("credentials".into()));
            ui.pending_enterprise_tab.set(Some("permissions".into()));
            ui.cache_open.set(true);
            ui.create_open.set(true);
            ui.sso_wizard_open.set(true);

            session.set_active_tenant(None);

            assert_eq!(ui.apps_search.get_untracked(), "");
            assert_eq!(ui.enterprise_search.get_untracked(), "");
            assert_eq!(ui.mi_search.get_untracked(), "");
            assert_eq!(ui.enterprise_facet.get_untracked(), "all");
            assert_eq!(ui.mi_facet.get_untracked(), "all");
            assert_eq!(ui.audit_severity.get_untracked(), "all");
            assert_eq!(ui.audit_expanded_group.get_untracked(), None);
            assert_eq!(ui.credentials_facet.get_untracked(), "all");
            assert!(!ui.pending_open_filters.get_untracked());
            ui.selected_app_ids
                .with_untracked(|s| assert!(s.is_empty()));
            ui.selected_audit_ids
                .with_untracked(|s| assert!(s.is_empty()));
            assert_eq!(ui.pending_app_tab.get_untracked(), None);
            assert_eq!(ui.pending_enterprise_tab.get_untracked(), None);
            assert!(!ui.cache_open.get_untracked());
            assert!(!ui.create_open.get_untracked());
            assert!(!ui.sso_wizard_open.get_untracked());
            // And the Session-owned resets still happen alongside.
            assert_eq!(session.view.get_untracked(), ActiveView::Home);
        });
    }

    #[test]
    fn open_item_dedupes_and_refocuses() {
        with_session(|session| {
            let a = session.open_item(OpenItemKind::AppReg, "app-1", "Contoso");
            session.open_item(OpenItemKind::Enterprise, "sp-1", "Fabrikam");
            // Re-opening the same (kind, entity) returns the same id, no dup.
            let a2 = session.open_item(OpenItemKind::AppReg, "app-1", "Contoso (renamed)");
            assert_eq!(a, a2, "dedupe by (kind, entity_id)");
            session.open_items.with_untracked(|list| {
                assert_eq!(list.len(), 2);
                let item = list.iter().find(|it| it.id == a).unwrap();
                assert_eq!(
                    item.title, "Contoso (renamed)",
                    "title refreshed on re-open"
                );
            });
            // Re-opening focuses it (1-up).
            session
                .shown_items
                .with_untracked(|shown| assert_eq!(shown, &vec![a]));
        });
    }

    #[test]
    fn open_item_caps_and_drops_oldest() {
        with_session(|session| {
            for i in 0..10 {
                session.open_item(OpenItemKind::AppReg, format!("app-{i}"), format!("App {i}"));
            }
            session.open_items.with_untracked(|list| {
                assert_eq!(list.len(), 8, "capped at MAX_OPEN_ITEMS");
                // The two oldest were drained.
                assert!(list.iter().all(|it| it.entity_id != "app-0"));
                assert!(list.iter().all(|it| it.entity_id != "app-1"));
                assert_eq!(list.first().unwrap().entity_id, "app-2");
            });
        });
    }

    #[test]
    fn focus_item_split_caps_shown_at_two() {
        with_session(|session| {
            let a = session.open_item(OpenItemKind::AppReg, "app-1", "A");
            let b = session.open_item(OpenItemKind::AppReg, "app-2", "B");
            let c = session.open_item(OpenItemKind::AppReg, "app-3", "C");
            session.focus_item(a, false);
            session.focus_item(b, true);
            session
                .shown_items
                .with_untracked(|s| assert_eq!(s, &vec![a, b]));
            // A third pinned pane evicts the oldest shown (a).
            session.focus_item(c, true);
            session
                .shown_items
                .with_untracked(|s| assert_eq!(s, &vec![b, c]));
        });
    }

    #[test]
    fn close_item_clears_from_both_sets() {
        with_session(|session| {
            let a = session.open_item(OpenItemKind::AppReg, "app-1", "A");
            let b = session.open_item(OpenItemKind::AppReg, "app-2", "B");
            session.focus_item(a, false);
            session.focus_item(b, true);
            session.close_item(a);
            session.open_items.with_untracked(|list| {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].id, b);
            });
            session
                .shown_items
                .with_untracked(|s| assert_eq!(s, &vec![b]));
            // close_item_by_entity resolves the synthetic id from (kind, entity).
            session.close_item_by_entity(OpenItemKind::AppReg, "app-2");
            session
                .open_items
                .with_untracked(|list| assert!(list.is_empty()));
            session
                .shown_items
                .with_untracked(|s| assert!(s.is_empty()));
        });
    }

    #[test]
    fn close_all_items_empties_the_working_set() {
        with_session(|session| {
            let a = session.open_item(OpenItemKind::AppReg, "app-1", "A");
            let b = session.open_item(OpenItemKind::Enterprise, "sp-1", "B");
            session.focus_item(a, false);
            session.focus_item(b, true);
            session.close_all_items();
            session
                .open_items
                .with_untracked(|list| assert!(list.is_empty()));
            session
                .shown_items
                .with_untracked(|s| assert!(s.is_empty()));
        });
    }

    #[test]
    fn set_view_collapses_workspace_but_keeps_the_dock() {
        with_session(|session| {
            let a = session.open_item(OpenItemKind::AppReg, "app-1", "A");
            session.focus_item(a, false);
            session
                .shown_items
                .with_untracked(|s| assert_eq!(s, &vec![a]));
            // Navigating dismisses the overlay (shown cleared) but the item stays
            // in the dock and the view changes.
            session.set_view(ActiveView::ManagedIdentities);
            session
                .shown_items
                .with_untracked(|s| assert!(s.is_empty()));
            session
                .open_items
                .with_untracked(|list| assert_eq!(list.len(), 1));
            assert_eq!(session.view.get_untracked(), ActiveView::ManagedIdentities);
        });
    }

    #[test]
    fn set_active_tenant_clears_working_set() {
        with_session(|session| {
            session.open_item(OpenItemKind::AppReg, "app-1", "A");
            session.open_item(OpenItemKind::Enterprise, "sp-1", "B");
            session.set_active_tenant(None);
            session
                .open_items
                .with_untracked(|list| assert!(list.is_empty()));
            session
                .shown_items
                .with_untracked(|s| assert!(s.is_empty()));
        });
    }

    #[test]
    fn report_command_error_plain_toast_for_other_codes() {
        with_session(|session| {
            session.report_command_error(&UiError::new("network", "down", true));
            session.toasts.with_untracked(|list| {
                assert_eq!(list.len(), 1);
                let t = &list[0];
                assert!(matches!(t.kind, ToastKind::Error));
                assert_eq!(t.message, "down");
                assert!(t.action_label.is_none(), "non-auth error needs no action");
                assert!(t.action.is_none());
            });
        });
    }
}
