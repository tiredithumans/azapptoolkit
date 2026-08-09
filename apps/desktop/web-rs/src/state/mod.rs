//! Application-wide reactive state. Replaces the React-side Zustand store
//! with Leptos `RwSignal`s provided through context. Components consume
//! state via `use_session()` and call setter helpers that preserve the
//! original cross-field semantics (e.g. switching tenant clears the selected
//! app and resets the view).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use leptos::prelude::*;

use crate::bindings::TenantContext;
use crate::components::toast::{Toast, ToastAction, ToastKind};

// The `Session` impl is split by concern rather than living as one ~440-line
// block with 53 methods. It mixed tenant lifecycle, bulk selection, the
// open-items working set, navigation, toasts and error reporting — and the
// tenant-reset footgun (clear `open_items`/`shown_items` or leak the previous
// tenant's data) sat in the middle of it, where it is hardest to see.
//
// Rust allows several `impl Session` blocks in one crate, so this costs nothing
// at the type level: `Session` is still one struct with one API.
mod errors;
mod navigation;
mod open_items;
mod tenant;
mod toasts;

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
    /// Per-tenant operator defaults (default owners, SSO notification emails,
    /// scope-name pattern). An account-scoped page, not org data.
    Settings,
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
    // "New application" chooser (Browse the gallery / Create your own) open flag,
    // and the gallery-browse modal open flag it routes to. Both lifted to the
    // shell like the wizard so they survive view switches.
    pub new_app_chooser_open: RwSignal<bool>,
    pub gallery_open: RwSignal<bool>,
    // `object_id -> display name` for every app registration in the tenant,
    // published by the App Registrations list when it loads. The bulk commands
    // take object ids and their outcomes carry only ids, so without this a
    // failure list is a column of raw GUIDs. The list already had this map for
    // its own inline bar; lifting it here lets the standalone Bulk Actions page
    // — which owns no rows — label failures the same way. Tenant-scoped by
    // nature: these ids belong to one tenant's directory.
    pub app_names: RwSignal<Arc<HashMap<String, String>>>,
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
            new_app_chooser_open: RwSignal::new(false),
            gallery_open: RwSignal::new(false),
            app_names: RwSignal::new(Arc::new(HashMap::new())),
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
        self.new_app_chooser_open.set(false);
        self.gallery_open.set(false);
        self.app_names.set(Arc::new(HashMap::new()));
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
    // Bumped when the operator refreshes their token (re-applying roles activated
    // since sign-in), so a mounted Access Readiness checklist re-runs its check in
    // place. The Refresh-token control is the single "re-check my access" trigger —
    // there is no separate Re-check button.
    pub readiness_reload: RwSignal<u32>,
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
        readiness_reload: RwSignal::new(0),
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
            ui.new_app_chooser_open.set(true);
            ui.gallery_open.set(true);
            ui.app_names.set(Arc::new(HashMap::from([(
                "app-1".to_string(),
                "App One".to_string(),
            )])));

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
            assert!(!ui.new_app_chooser_open.get_untracked());
            assert!(!ui.gallery_open.get_untracked());
            ui.app_names.with_untracked(|m| assert!(m.is_empty()));
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
