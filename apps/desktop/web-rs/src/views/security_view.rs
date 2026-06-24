//! Unified Security surface.
//!
//! The **security audit** is the hero of this nav destination; the three
//! tenant-wide inventory lenses — Credential expiry, Delegated grants, and App
//! permissions — are demoted to a subordinate "Detailed inventories" control
//! rather than four co-equal tabs. Selecting a lens swaps it in as the main
//! content (the deep-links from Home / Global Search still set `security_tab`
//! to a lens and expect it shown), but the audit is the default and the visibly
//! primary entry. Each lens is the **same** component as before; this view only
//! supplies the sub-navigation, so every behavior is preserved (the audit
//! scan/progress/cancel, fetch-fresh credentials, the AuditLog-gated Unused
//! finding, multi-format export, and the per-row "Open" deep-links).
//!
//! Sub-panes are **keep-alive** (mounted on first visit, then toggled by CSS
//! `display`) so switching never tears down the audit's scan result or refetches
//! a lens — mirroring the main shell's view keep-alive.

use std::collections::HashSet;

use leptos::prelude::*;

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

    // Insert-only latch of visited panes, seeded with the active one so the
    // first pane mounts immediately and is grown as the user switches.
    let visited = RwSignal::new(HashSet::from([sub.get_untracked()]));
    Effect::new(move |_| {
        let v = sub.get();
        visited.update(|set| {
            set.insert(v);
        });
    });

    view! {
        <div class="security-view">
            <div class="security-lenses">
                {lens_btn(sub, "posture", "Security audit", true)}
                <span class="security-lenses__label">"Detailed inventories"</span>
                {lens_btn(sub, "credentials", "Credential expiry", false)}
                {lens_btn(sub, "grants", "Delegated grants", false)}
                {lens_btn(sub, "permissions", "App permissions", false)}
            </div>
            {keep_alive(sub, visited, "posture", || view! { <AuditView /> })}
            {keep_alive(sub, visited, "credentials", || view! { <CredentialsDashboard /> })}
            {keep_alive(sub, visited, "grants", || view! { <ConsentGrantsView /> })}
            {keep_alive(sub, visited, "permissions", || view! { <AppPermissionsView /> })}
        </div>
    }
}

/// One entry in the Security surface's lens selector. `hero` styles the audit
/// as the primary entry; the rest render as subdued "detailed inventory" links.
fn lens_btn(
    sub: RwSignal<String>,
    value: &'static str,
    label: &'static str,
    hero: bool,
) -> impl IntoView {
    let class = move || {
        let mut c = String::from("security-lens");
        if hero {
            c.push_str(" security-lens--hero");
        }
        if sub.with(|s| s == value) {
            c.push_str(" security-lens--active");
        }
        c
    };
    view! {
        <button type="button" class=class on:click=move |_| sub.set(value.to_string())>
            {label}
        </button>
    }
}
