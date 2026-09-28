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
//! - **Vault access**: a tenant-wide sweep of every reachable vault's Azure RBAC
//!   role assignments, direct and inherited (`sweep_key_vault_access`, progress-streamed,
//!   backend-cached). Filtering by principal answers "which vaults can this app
//!   / managed identity reach?" and filtering by vault answers "who can touch
//!   this vault?".
//!
//! All panels stay mounted across tab switches (display toggle) so an
//! expensive sweep/probe result survives flipping between them.

use leptos::prelude::*;
use thaw::Body1;

use crate::bindings::permission_tester::AccessVerdict;
use crate::components::ui::{SectionHeader, TabBar, TabBarItem};
use crate::state::use_session;

mod keyvault;
mod mailboxes;
mod sites;

use keyvault::KeyVaultPanel;
use mailboxes::MailboxesPanel;
use sites::SitesPanel;

#[component]
pub fn ResourceAccessView() -> impl IntoView {
    // Session-held rather than local: this view is keep-alive and its panels
    // stay mounted across tab switches, so a local signal could never be
    // addressed from outside — which is what Global Search's "Go to" group
    // (and any future deep link) needs to land on a named plane.
    let tab = use_session().resource_access_tab;
    view! {
        <div class="page">
            <SectionHeader title="Resource Access" />
            <Body1>
                "Reverse lookups: pick a resource plane and see which applications and identities can reach what."
            </Body1>
            <TabBar
                items=vec![
                    TabBarItem { value: "mailboxes", label: "Mailboxes" },
                    TabBarItem { value: "sites", label: "Sites" },
                    // "Vault access", not "Key Vault": the rail's Key Vault row
                    // is the secret *browser*, a different destination
                    // entirely, and two tabs sharing a name left the operator
                    // no way to tell which one answers "who can reach this
                    // vault?".
                    TabBarItem { value: "keyvault", label: "Vault access" },
                ]
                selected=tab
            />
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
/// ok, everything else neutral. Exhaustive on purpose (as is
/// [`verdict_tooltip`]): a new verdict must be given its own badge.
pub(super) fn verdict_badge(verdict: AccessVerdict) -> (&'static str, &'static str) {
    match verdict {
        AccessVerdict::OrgWide => ("badge badge--warning", "Org-wide"),
        AccessVerdict::Scoped => ("badge badge--ok", "Scoped"),
        AccessVerdict::NoAccess => ("badge", "No access"),
        AccessVerdict::Unknown => ("badge", "Unknown"),
    }
}

/// Hover tooltip for a verdict badge. `Unknown` is the load-bearing one: it means
/// a path (typically the Exchange RBAC check) couldn't be evaluated, so the badge
/// must read as "possible access, not yet verified" rather than contradicting a
/// "blocked" line in the detail column.
pub(super) fn verdict_tooltip(verdict: AccessVerdict) -> &'static str {
    match verdict {
        AccessVerdict::OrgWide => {
            "Reaches this mailbox — and every mailbox — via an org-wide grant."
        }
        AccessVerdict::Scoped => "Reaches this mailbox through a scoped grant.",
        AccessVerdict::NoAccess => "Confirmed: this principal cannot reach this mailbox.",
        AccessVerdict::Unknown => {
            "Access couldn’t be confirmed — an Exchange RBAC check needs Exchange administrator rights. Treat as possible access until verified."
        }
    }
}
