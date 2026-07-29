//! Owner search-and-pick: a user-scoped [`DirectorySearch`] that emits the
//! chosen [`DirectoryObject`] via `on_pick`. Kept as a named wrapper so the
//! Settings default-owner editors read as what they are, and so their call
//! sites don't have to spell out the scope and copy every time.

use std::collections::HashSet;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;

use crate::components::directory_search::{DirectoryScope, DirectorySearch};

#[component]
pub fn OwnerPicker(
    /// Fired with the picked directory object when the user clicks "Add".
    on_pick: Callback<DirectoryObject>,
    /// Ids already selected — hidden from results so they can't be re-added.
    #[prop(into)]
    exclude: Signal<HashSet<String>>,
    #[prop(optional, into, default = String::from("Search by display name or UPN (2+ chars)"))]
    label: String,
) -> impl IntoView {
    view! {
        <DirectorySearch
            scope=Signal::derive(|| DirectoryScope::Users)
            on_pick=on_pick
            exclude=exclude
            label=label
            placeholder="alice@contoso.com"
            class="owner-picker"
        />
    }
}
