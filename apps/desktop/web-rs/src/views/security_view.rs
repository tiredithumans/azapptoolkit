//! Unified Security surface.
//!
//! One nav destination that hosts the four tenant-wide security/inventory
//! lenses — Posture (the security audit), Credential expiry, Delegated grants,
//! and App permissions — behind an internal sub-tab bar, instead of four
//! sibling nav rows. Each lens is the **same** component as before; this view
//! only supplies the sub-navigation, so every behavior is preserved (the audit
//! scan/progress/cancel, fetch-fresh credentials, the AuditLog-gated Unused
//! facet, multi-format export, and the per-row "Open" deep-links).
//!
//! Sub-panes are **keep-alive** (mounted on first visit, then toggled by CSS
//! `display`) so switching sub-tabs never tears down the audit's scan result or
//! refetches a lens — mirroring the main shell's view keep-alive.

use std::collections::HashSet;

use leptos::prelude::*;

use crate::components::ui::{TabBar, TabBarItem};
use crate::state::use_session;
use crate::util::keep_alive;
use crate::views::app_permissions_view::AppPermissionsView;
use crate::views::audit_view::AuditView;
use crate::views::consent_grants_view::ConsentGrantsView;
use crate::views::credentials_dashboard::CredentialsDashboard;

#[component]
pub fn SecurityView() -> impl IntoView {
    let session = use_session();
    let sub = session.security_tab;

    // Insert-only latch of visited sub-tabs, seeded with the active one so the
    // first pane mounts immediately and is grown as the user switches tabs.
    let visited = RwSignal::new(HashSet::from([sub.get_untracked()]));
    Effect::new(move |_| {
        let v = sub.get();
        visited.update(|set| {
            set.insert(v);
        });
    });

    view! {
        <div class="security-view">
            <TabBar
                selected=sub
                items=vec![
                    TabBarItem { value: "posture", label: "Posture" },
                    TabBarItem { value: "credentials", label: "Credential expiry" },
                    TabBarItem { value: "grants", label: "Delegated grants" },
                    TabBarItem { value: "permissions", label: "App permissions" },
                ]
            />
            {keep_alive(sub, visited, "posture", || view! { <AuditView /> })}
            {keep_alive(sub, visited, "credentials", || view! { <CredentialsDashboard /> })}
            {keep_alive(sub, visited, "grants", || view! { <ConsentGrantsView /> })}
            {keep_alive(sub, visited, "permissions", || view! { <AppPermissionsView /> })}
        </div>
    }
}
