//! Key Vault browser page — lists / fetches secrets in a named vault. Reached
//! from the nav rail (Tools). Promoted from a modal to a page so it isn't a
//! cramped dialog over the rest of the UI.
//!
//! Security: the shell keeps views alive (never unmounts them), so a revealed
//! secret would otherwise linger in `revealed` until sign-out. A view-watch
//! wipes the sensitive signals whenever the active view leaves Key Vault, so a
//! revealed secret exists in memory only while this page is on screen — the
//! page equivalent of the old `if !open` wipe.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::keyvault::{self, KvSecretItemDto, KvSecretValueDto};
use crate::components::requires_role::RequiresRole;
use crate::components::ui::{DataTable, SectionHeader};
use crate::state::{ActiveView, use_session};

#[component]
pub fn KeyVaultView() -> impl IntoView {
    let session = use_session();
    let vault_name = RwSignal::new(String::new());
    let listed: RwSignal<Vec<KvSecretItemDto>> = RwSignal::new(Vec::new());
    let revealed: RwSignal<Option<KvSecretValueDto>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    // Whether a successful list has completed — so the empty table can say "no
    // secrets in this vault" rather than the pre-load prompt (the list could
    // genuinely return zero, or the same blank state could follow a failure).
    let loaded = RwSignal::new(false);
    // The secret name whose reveal is in flight, if any. Gates concurrent
    // reveals (which would race into `revealed`, last-resolved winning) and
    // drives the per-row spinner / disabled state.
    let revealing: RwSignal<Option<String>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    // Wipe the revealed secret (and any error) whenever the active view leaves
    // Key Vault. The page stays mounted (keep-alive), so this is the page
    // analogue of wiping when a modal closes — the secret never outlives the
    // time this page is on screen.
    let view = session.view;
    Effect::new(move |_| {
        if view.get() != ActiveView::KeyVault {
            revealed.set(None);
            error.set(None);
        }
    });

    let load = move |_| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let tenant = session.active_tenant.get();
        let v = vault_name.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match keyvault::kv_list_secrets(&t.tenant_id, v.trim()).await {
                Ok(items) => {
                    listed.set(items);
                    loaded.set(true);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let reveal = move |secret_name: String| {
        // Guard against a second click (this row or another) while a reveal is
        // in flight — concurrent `kv_get_secret` calls race into `revealed`.
        if revealing.get().is_some() {
            return;
        }
        let tenant = session.active_tenant.get();
        let v = vault_name.get();
        revealing.set(Some(secret_name.clone()));
        error.set(None);
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                revealing.set(None);
                return;
            };
            match keyvault::kv_get_secret(&t.tenant_id, v.trim(), &secret_name).await {
                Ok(value) => revealed.set(Some(value)),
                Err(e) => error.set(Some(e.message)),
            }
            revealing.set(None);
        });
    };

    view! {
        <main class="tool-page">
            <SectionHeader
                title="Key Vault".to_string()
                crumb="Browse and reveal secrets in a named vault".to_string()
            />
            <RequiresRole capability_key="keyvault_secrets" />
            <div class="row">
                <Field label="Vault name">
                    <Input value=vault_name placeholder="myvault" />
                </Field>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(load)
                    disabled=Signal::derive(move || busy.get())
                >
                    {move || {
                        if busy.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }.into_any()
                        } else {
                            view! { "List secrets" }.into_any()
                        }
                    }}
                </Button>
            </div>
            {move || {
                view! {
                    <DataTable
                        headers=vec!["Name", "Content type", "Expires", ""]
                        rows=listed.get()
                        empty_message=if loaded.get() {
                            "No secrets in this vault.".to_string()
                        } else {
                            "Enter a vault name and choose List secrets.".to_string()
                        }
                        row=move |item: KvSecretItemDto| {
                            let name = item.name.clone();
                            let click_name = name.clone();
                            let row_name = name.clone();
                            // This row's reveal is the in-flight one.
                            let this_revealing =
                                Signal::derive(move || revealing.get().as_deref() == Some(row_name.as_str()));
                            // Any reveal in flight disables every Reveal button.
                            let any_revealing = Signal::derive(move || revealing.get().is_some());
                            view! {
                                <tr>
                                    <td class="mono">{name}</td>
                                    <td>{item.content_type.unwrap_or_else(|| "—".into())}</td>
                                    <td>{item.expires.unwrap_or_else(|| "—".into())}</td>
                                    <td>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                            disabled=any_revealing
                                            on_click=Box::new(move |_| reveal(click_name.clone()))
                                        >
                                            {move || {
                                                if this_revealing.get() {
                                                    view! {
                                                        <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                                    }
                                                        .into_any()
                                                } else {
                                                    view! { "Reveal" }.into_any()
                                                }
                                            }}
                                        </Button>
                                    </td>
                                </tr>
                            }
                                .into_any()
                        }
                    />
                }
            }}
            {move || {
                revealed
                    .get()
                    .map(|v| {
                        view! {
                            <div class="alert alert--ok">
                                <strong>{v.name}</strong>
                                <pre class="secret-reveal">{v.value}</pre>
                            </div>
                        }
                    })
            }}
            {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
        </main>
    }
}
