//! Truncation notice for the surfaces built on the shared service-principal
//! index.
//!
//! The App Registrations list detects its own cap with `total >= APPS_HARD_CAP`,
//! because its rows *are* the capped set. The Enterprise Applications and
//! Managed Identities lists cannot: both are filtered subsets of the SP index
//! (one drops managed identities, the other keeps only them), so their row
//! counts sit below the cap even on a tenant whose index truncated — a
//! `len() >= cap` check there would never fire. They ask the backend instead.
//!
//! Without this, a tenant with >10 000 service principals (routine wherever
//! every Microsoft first-party and consented SaaS app has one) silently shows a
//! partial list: filtering for an app that exists returns "No matching
//! enterprise applications" and the operator concludes it isn't in the tenant.

use leptos::prelude::*;

use crate::bindings::applications;
use crate::components::ui::Callout;
use crate::state::use_session;

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
                                {format!(
                                    "This tenant has more than {} service principals. Only the first {} are loaded, so this list — and its search and filters — cover that subset. A {} outside it will not appear.",
                                    s.sp_index_cap,
                                    s.sp_index_cap,
                                    noun.get_value(),
                                )}
                            </Callout>
                        }
                    })
            })}
        </Suspense>
    }
}
