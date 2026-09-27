//! Truncation notice for the surfaces built on the shared service-principal
//! index.
//!
//! The App Registrations list detects its own cap with `total >= APPS_MAX` (the
//! constant `azapptoolkit_dto` shares with the backend), because its rows *are*
//! the capped set. The Enterprise Applications and Managed Identities lists
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
//! thing about the same cap. The top-bar search dropdown filters a corpus built
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

/// Renders nothing unless the shared SP index truncated for the active tenant.
/// The read is fallible and its failure is swallowed on purpose — losing the
/// notice is survivable, losing the list is not.
#[component]
pub fn IndexCapNotice(
    /// Plural noun for this surface's rows, e.g. "enterprise applications".
    #[prop(into)]
    noun: String,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    // `Copy` handle: the Suspend closure must stay `FnMut`, and a captured
    // `String` would move out of it on first call.
    let noun = StoredValue::new(noun);

    let status = LocalResource::new(move || {
        let tenant = tenant.get();
        async move {
            match tenant {
                Some(t) => applications::get_directory_index_status(&t.tenant_id)
                    .await
                    .ok(),
                None => None,
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
                            <Callout tone="warn">
                                {index_cap_message(s.sp_index_cap, &noun.get_value())}
                            </Callout>
                        }
                    })
            })}
        </Suspense>
    }
}
