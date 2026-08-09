//! View switching and the typed deep links into it.
//!
//! Every `open_*` helper is a named destination rather than a caller poking
//! `view` and a facet signal in the right order — the ordering matters
//! (`set_view` collapses the workspace, so it must come before `open_item`).

use leptos::prelude::*;

use super::*;

impl Session {
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

    /// Open the New-SSO-application wizard. (Lifted to the shell — mounted under
    /// the Enterprise Apps view — so callers off that view must switch to it too.)
    pub fn open_sso_wizard(&self) {
        self.tenant_ui.sso_wizard_open.set(true);
    }

    /// Open the "New application" chooser (Browse the gallery / Create your own).
    /// Like the wizard it's mounted under the Enterprise Apps view, so callers off
    /// that view switch to it first.
    pub fn open_new_app_chooser(&self) {
        self.tenant_ui.new_app_chooser_open.set(true);
    }

    /// Open the gallery-browse modal (reached from the chooser's "Browse the
    /// gallery" option).
    pub fn open_gallery(&self) {
        self.tenant_ui.gallery_open.set(true);
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
}
