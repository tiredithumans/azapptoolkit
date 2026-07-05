//! Resource Access — the resource → identities reverse lookups Graph doesn't
//! offer, one tab per resource plane:
//!
//! - **Mailboxes** (first tab): every candidate principal — mail-scopable
//!   Graph application permission holders plus Exchange-registered SPs —
//!   probed against one target mailbox (`find_mailbox_reachers`, the
//!   Entra ∪ Exchange-RBAC union) — "which apps can read this mailbox?".
//! - **Sites**: a tenant-wide sweep of every enumerable site's application
//!   permissions (`sweep_site_permissions`, progress-streamed, backend-cached).
//!   Filtering by app answers "which sites can this app reach?" — the
//!   `Sites.Selected` blind spot — and filtering by site answers "which apps
//!   can touch this site?".
//! - **Key Vault**: a tenant-wide sweep of every reachable vault's direct Azure
//!   RBAC role assignments (`sweep_key_vault_access`, progress-streamed,
//!   backend-cached). Filtering by principal answers "which vaults can this app
//!   / managed identity reach?" and filtering by vault answers "who can touch
//!   this vault?".
//!
//! All panels stay mounted across tab switches (display toggle) so an
//! expensive sweep/probe result survives flipping between them.

use leptos::prelude::*;
use thaw::{Body1, Tab, TabList};

use crate::components::ui::SectionHeader;

mod keyvault;
mod mailboxes;
mod sites;

use keyvault::KeyVaultPanel;
use mailboxes::MailboxesPanel;
use sites::SitesPanel;

#[component]
pub fn ResourceAccessView() -> impl IntoView {
    let tab = RwSignal::new(String::from("mailboxes"));
    view! {
        <div class="page">
            <SectionHeader title="Resource Access" />
            <Body1>
                "Reverse lookups: pick a resource plane and see which applications and identities can reach what."
            </Body1>
            <TabList selected_value=tab>
                <Tab value="mailboxes">"Mailboxes"</Tab>
                <Tab value="sites">"Sites"</Tab>
                <Tab value="keyvault">"Key Vault"</Tab>
            </TabList>
            <div style:display=move || {
                if tab.get() == "mailboxes" { "contents" } else { "none" }
            }>
                <MailboxesPanel />
            </div>
            <div style:display=move || {
                if tab.get() == "sites" { "contents" } else { "none" }
            }>
                <SitesPanel />
            </div>
            <div style:display=move || {
                if tab.get() == "keyvault" { "contents" } else { "none" }
            }>
                <KeyVaultPanel />
            </div>
        </div>
    }
}

/// Verdict badge class — org-wide reach reads as a warning, confined access as
/// ok, everything else neutral.
pub(super) fn verdict_badge(verdict: &str) -> (&'static str, &'static str) {
    match verdict {
        "org_wide" => ("badge badge--warning", "Org-wide"),
        "scoped" => ("badge badge--ok", "Scoped"),
        "no_access" => ("badge", "No access"),
        _ => ("badge", "Unknown"),
    }
}
