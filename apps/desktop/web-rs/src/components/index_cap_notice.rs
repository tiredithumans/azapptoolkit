//! Truncation notice for the surfaces built on the shared service-principal
//! index.
//!
//! The App Registrations list detects its own cap with `total >= APPS_MAX` (the
//! constant `azapptoolkit_dto` shares with the backend), because its rows *are*
//! the capped set. The SP index's cap still reaches it, through the pairing:
//! each row's "Jump to paired Enterprise Application" link and the export's
//! `PairedEnterpriseAppId` are joined from that index, so an app whose service
//! principal lies past the cap reads exactly like an app with none
//! ([`PairingCapNotice`], worded by [`pairing_cap_message`]). That notice reads
//! the index status from the cache alone: the rows joined the index on the scan
//! that produced them, so it is cached whenever the list loaded through it, and
//! a warm visit must not start an SP-index scan just to draw a notice. The
//! Enterprise Applications and Managed Identities lists
//! cannot: both are filtered subsets of the SP index
//! (one drops managed identities, the other keeps only them), so their row
//! counts sit below the cap even on a tenant whose index truncated — a
//! `len() >= cap` check there would never fire. They ask the backend instead.
//!
//! Without this, a tenant with >10 000 service principals (routine wherever
//! every Microsoft first-party and consented SaaS app has one) silently shows a
//! partial list: filtering for an app that exists returns "No matching
//! enterprise applications" and the operator concludes it isn't in the tenant.
//!
//! The wording lives in [`index_cap_message`] rather than in the component, so
//! every surface says the same thing rather than a second, subtly different
//! thing about the same cap — one wording per thing the cap hides: rows here,
//! pair links on the App Registrations list. The top-bar search dropdown filters a corpus built
//! from the *same* capped SP index **and** the app-registration index (capped at
//! the same number), so either cap can make it answer "No matches." for a record
//! that is genuinely present; its form, [`corpus_cap_message`], names both and
//! lives here beside the list form.

use leptos::prelude::*;

use crate::bindings::applications;
use crate::components::ui::Callout;
use crate::state::use_session;

/// The one wording for "this tenant's service-principal index truncated", shared
/// by every surface that has to admit it.
///
/// `noun` is the singular for whatever the surface is showing ("enterprise
/// application", "managed identity", "record") — the only part that varies.
/// Centralized because two surfaces telling an operator two different stories
/// about the same cap is exactly how "it must not be in the tenant" gets
/// believed.
pub fn index_cap_message(cap: usize, noun: &str) -> String {
    format!(
        "This tenant has more than {cap} service principals. Only the first {cap} are loaded, \
         so this list — and its search and filters — cover that subset. A {noun} outside it \
         will not appear."
    )
}

/// The search dropdown's form of [`index_cap_message`]. Its corpus is built from
/// BOTH tenant-wide indexes, so either cap can hide a record.
pub fn corpus_cap_message(cap: usize) -> String {
    format!(
        "This tenant has more than {cap} service principals or app registrations. Search \
         covers only the first {cap} of each, so a record outside them will not appear."
    )
}

/// The App Registrations list's form of [`index_cap_message`]. Its rows are
/// app registrations, capped separately at `APPS_MAX`, so the SP cap hides no
/// row there; it hides the *pairing*. An app whose service principal is past
/// the cap gets no pair link and an empty `PairedEnterpriseAppId` in the
/// export, the same thing an app with no enterprise application shows.
pub fn pairing_cap_message(cap: usize) -> String {
    format!(
        "This tenant has more than {cap} service principals. Pair links and the export's \
         PairedEnterpriseAppId cover only the first {cap} service principals, so an app whose \
         enterprise application is outside them shows no pair link."
    )
}

/// Renders nothing unless the shared SP index truncated for the active tenant.
/// The read is fallible and its failure is swallowed on purpose — losing the
/// notice is survivable, losing the list is not.
#[component]
pub fn IndexCapNotice(
    /// Plural noun for this surface's rows, e.g. "enterprise applications".
    #[prop(into)]
    noun: String,
) -> impl IntoView {
    // `Copy` handle: the Suspend closure must stay `FnMut`, and a captured
    // `String` would move out of it on first call.
    let noun = StoredValue::new(noun);
    sp_index_cap_callout(
        move |cap| index_cap_message(cap, &noun.get_value()),
        StatusRead::Fetch,
    )
}

/// The App Registrations list's notice: [`pairing_cap_message`] when the shared
/// SP index truncated, else nothing. Unlike [`IndexCapNotice`] it reads the
/// status from the cache alone (`get_cached_directory_index_status`): an index
/// that is not cached draws no notice rather than a directory scan.
#[component]
pub fn PairingCapNotice() -> impl IntoView {
    sp_index_cap_callout(pairing_cap_message, StatusRead::CachedOnly)
}

/// Where a notice reads the SP index's coverage from.
#[derive(Clone, Copy)]
enum StatusRead {
    /// `get_directory_index_status`: through the index, seeding it when cold.
    /// The SP-index lists need that index anyway.
    Fetch,
    /// `get_cached_directory_index_status`: the cache alone, `None` when cold.
    CachedOnly,
}

/// The one read-and-render behind both notices: a warn [`Callout`] worded by
/// `message(cap)` once the status `read` returns reports the SP index truncated
/// for the active tenant, nothing otherwise (or on any failure).
fn sp_index_cap_callout(
    message: impl Fn(usize) -> String + Copy + Send + Sync + 'static,
    read: StatusRead,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let status = LocalResource::new(move || {
        let tenant = tenant.get();
        async move {
            let t = tenant?;
            match read {
                StatusRead::Fetch => applications::get_directory_index_status(&t.tenant_id)
                    .await
                    .ok(),
                StatusRead::CachedOnly => {
                    applications::get_cached_directory_index_status(&t.tenant_id)
                        .await
                        .ok()
                        .flatten()
                }
            }
        }
    });

    view! {
        <Suspense fallback=|| ()>
            {move || Suspend::new(async move {
                status
                    .await
                    .filter(|s| s.sp_index_truncated)
                    .map(|s| {
                        view! {
                            <Callout tone="warn">{message(s.sp_index_cap)}</Callout>
                        }
                    })
            })}
        </Suspense>
    }
}
