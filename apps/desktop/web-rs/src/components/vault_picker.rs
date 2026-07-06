//! Vault name picker: a free-text input (always type-able, and the source of
//! truth via `value`) plus a **filter-as-you-type** list of discovered vaults.
//! The typed text filters the discovered set (case-insensitive substring), so it
//! scales to hundreds of vaults — clicking a row fills the input. Discovery is
//! best-effort ARM enumeration (`list_available_key_vaults`); if it returns
//! nothing (e.g. no Azure consent), only the free-text input shows, so an
//! operator who knows the name can always proceed.

use leptos::prelude::*;
use thaw::Input;

use crate::bindings::keyvault;
use crate::state::use_session;

/// Max rows rendered at once (the list scrolls; the count line reports the rest).
const SHOW_MAX: usize = 25;

#[component]
pub fn VaultPicker(
    /// The chosen/typed vault name — the source of truth.
    value: RwSignal<String>,
    #[prop(optional, into, default = String::from("myvault"))] placeholder: String,
) -> impl IntoView {
    let session = use_session();
    // All discovered vaults, loaded once per mount / tenant change.
    let all_vaults: RwSignal<Vec<String>> = RwSignal::new(Vec::new());
    Effect::new(move |_| {
        let tenant = session.active_tenant.get();
        all_vaults.set(Vec::new());
        if let Some(t) = tenant {
            let tid = t.tenant_id.clone();
            leptos::task::spawn_local(async move {
                // Degrade to free-text on any error (missing ARM consent, etc.).
                let list = keyvault::list_available_key_vaults(&tid)
                    .await
                    .unwrap_or_default();
                all_vaults.set(list);
            });
        }
    });

    view! {
        <Input value=value placeholder=placeholder />
        {move || {
            let all = all_vaults.get();
            if all.is_empty() {
                return ().into_any();
            }
            let total = all.len();
            let q = value.get().trim().to_lowercase();
            let matched: Vec<String> = if q.is_empty() {
                all
            } else {
                all.into_iter()
                    .filter(|v| v.to_lowercase().contains(&q))
                    .collect()
            };
            let match_count = matched.len();
            let current = value.get();
            let visible: Vec<String> = matched.into_iter().take(SHOW_MAX).collect();
            view! {
                <div class="vault-picker">
                    <div class="vault-picker__count muted small">
                        {if q.is_empty() {
                            format!("{total} discovered vaults — type to filter")
                        } else {
                            format!("{match_count} of {total} match")
                        }}
                    </div>
                    {(match_count > 0)
                        .then(|| {
                            view! {
                                <ul class="vault-picker__list">
                                    {visible
                                        .into_iter()
                                        .map(|name| {
                                            let pick = name.clone();
                                            let is_sel = current == name;
                                            view! {
                                                <li>
                                                    <button
                                                        type="button"
                                                        class="vault-picker__option"
                                                        class:vault-picker__option--selected=is_sel
                                                        on:click=move |_| value.set(pick.clone())
                                                    >
                                                        {name}
                                                    </button>
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            }
                        })}
                    {(match_count > SHOW_MAX)
                        .then(|| {
                            view! {
                                <div class="muted small">
                                    {format!(
                                        "+{} more — keep typing to narrow",
                                        match_count - SHOW_MAX,
                                    )}
                                </div>
                            }
                        })}
                    {(!q.is_empty() && match_count == 0)
                        .then(|| {
                            view! {
                                <div class="muted small">
                                    "No discovered vault matches — the name you typed will be used."
                                </div>
                            }
                        })}
                </div>
            }
                .into_any()
        }}
    }
}
