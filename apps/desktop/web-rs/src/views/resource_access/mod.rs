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
use crate::components::ui::{BadgeTone, SectionHeader, TabBar, TabBarItem};
use crate::constants::{LIST_FILTER_DEBOUNCE_MS, RENDER_PAGE};
use crate::hooks::use_debounced::use_debounced;
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

/// Verdict badge tone — org-wide reach reads as a warning, confined access as
/// ok, everything else neutral. Exhaustive on purpose (as is
/// [`verdict_tooltip`]): a new verdict must be given its own badge.
pub(super) fn verdict_badge(verdict: AccessVerdict) -> (BadgeTone, &'static str) {
    match verdict {
        AccessVerdict::OrgWide => (BadgeTone::Warning, "Org-wide"),
        AccessVerdict::Scoped => (BadgeTone::Ok, "Scoped"),
        AccessVerdict::NoAccess => (BadgeTone::Neutral, "No access"),
        AccessVerdict::Unknown => (BadgeTone::Neutral, "Unknown"),
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

/// The Sites and Vault-access sweep tables' shared filter scaffolding: the
/// debounced search, a lowercased haystack per row (rebuilt once per sweep
/// result, not per keystroke, so filtering a ≤5k-row sweep is just `contains`
/// over the prebuilt corpus), the filtered rows, and the render window — the
/// first page is drawn and grown on demand, and resets to one page whenever
/// the filter or the scan changes. One copy, so a fix lands in both panels.
///
/// `rows_of` projects the sweep result's rows; `haystack` builds one row's
/// lowercased search text. Summary, export and run/consent stay per panel —
/// they differ in DTO, command and consent feature.
pub(super) fn use_sweep_filter<Res, Row>(
    result: RwSignal<Option<Res>>,
    search: RwSignal<String>,
    rows_of: fn(&Res) -> &[Row],
    haystack: fn(&Row) -> String,
) -> (Memo<Vec<Row>>, RwSignal<usize>)
where
    Res: Send + Sync + 'static,
    Row: Clone + PartialEq + Send + Sync + 'static,
{
    let search_debounced = use_debounced(search.into(), LIST_FILTER_DEBOUNCE_MS);
    // Indices align with `rows_of(result)` — both derive from `result`.
    let corpus: Memo<Vec<String>> = Memo::new(move |_| {
        result.with(|r| {
            r.as_ref()
                .map(|r| rows_of(r).iter().map(haystack).collect::<Vec<_>>())
                .unwrap_or_default()
        })
    });
    let filtered_rows = Memo::new(move |_| {
        let needle = search_debounced.get().trim().to_lowercase();
        result.with(|r| {
            r.as_ref()
                .map(|r| {
                    let rows = rows_of(r);
                    if needle.is_empty() {
                        return rows.to_vec();
                    }
                    corpus.with(|hays| {
                        rows.iter()
                            .enumerate()
                            .filter(|(i, _)| hays.get(*i).is_some_and(|h| h.contains(&needle)))
                            .map(|(_, row)| row.clone())
                            .collect::<Vec<_>>()
                    })
                })
                .unwrap_or_default()
        })
    });
    let render_limit = RwSignal::new(RENDER_PAGE);
    Effect::new(move |prev: Option<()>| {
        search_debounced.track();
        let _ = filtered_rows.with(|r| r.len());
        if prev.is_some() {
            render_limit.set(RENDER_PAGE);
        }
    });
    (filtered_rows, render_limit)
}
