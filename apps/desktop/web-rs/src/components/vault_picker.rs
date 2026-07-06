//! Vault name picker: a free-text input (always type-able, and the source of
//! truth via `value`) plus a row of discovered-vault chips that fill it on click.
//! Discovery is best-effort ARM enumeration (`list_available_key_vaults`); if it
//! fails or returns nothing (e.g. no Azure consent), only the free-text input
//! shows — so an operator who knows the name can always proceed.

use leptos::prelude::*;
use thaw::Input;

use crate::bindings::keyvault;
use crate::state::use_session;

/// How many discovered vaults to show as chips before collapsing to a count.
const MAX_CHIPS: usize = 12;

#[component]
pub fn VaultPicker(
    /// The chosen/typed vault name — the source of truth.
    value: RwSignal<String>,
    #[prop(optional, into, default = String::from("myvault"))] placeholder: String,
) -> impl IntoView {
    let session = use_session();
    let vaults = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        async move {
            match tenant {
                // Degrade to free-text on any error (missing ARM consent, etc.).
                Some(t) => keyvault::list_available_key_vaults(&t.tenant_id)
                    .await
                    .unwrap_or_default(),
                None => Vec::new(),
            }
        }
    });

    view! {
        <Input value=value placeholder=placeholder />
        <Suspense fallback=|| ()>
            {move || Suspend::new(async move {
                let mut list = vaults.await;
                if list.is_empty() {
                    return ().into_any();
                }
                let overflow = list.len().saturating_sub(MAX_CHIPS);
                list.truncate(MAX_CHIPS);
                view! {
                    <div class="vault-picker__suggestions">
                        <span class="muted small">"Discovered vaults:"</span>
                        {list
                            .into_iter()
                            .map(|name| {
                                let pick = name.clone();
                                view! {
                                    <button
                                        type="button"
                                        class="vault-picker__chip"
                                        on:click=move |_| value.set(pick.clone())
                                    >
                                        {name}
                                    </button>
                                }
                            })
                            .collect_view()}
                        {(overflow > 0)
                            .then(|| {
                                view! {
                                    <span class="muted small">
                                        {format!("+{overflow} more — type to use")}
                                    </span>
                                }
                            })}
                    </div>
                }
                    .into_any()
            })}
        </Suspense>
    }
}
