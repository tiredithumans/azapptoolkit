//! Create-app dialog. Minimal port that exposes display name + audience +
//! description + create-SP toggle. Mirrors
//! `apps/desktop/web/src/views/CreateAppDialog.tsx`.

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Select, Spinner, SpinnerSize, Textarea};

use crate::bindings::applications::{self, CreateApplicationInput};
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;

#[component]
pub fn CreateAppDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_created: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let display_name = RwSignal::new(String::new());
    let audience = RwSignal::new("AzureADMyOrg".to_string());
    let description = RwSignal::new(String::new());
    let create_sp = RwSignal::new(true);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    let create = move |_| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let tenant = session.active_tenant.get();
        let dn = display_name.get();
        let aud = audience.get();
        let desc = description.get();
        let csp = create_sp.get();
        let on_close_cb = on_close;
        let on_created_cb = on_created;
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            let input = CreateApplicationInput {
                display_name: dn.trim().to_string(),
                sign_in_audience: Some(aud),
                description: if desc.trim().is_empty() {
                    None
                } else {
                    Some(desc.trim().to_string())
                },
                create_service_principal: csp,
                ..Default::default()
            };
            match applications::create_application(&t.tenant_id, &input).await {
                Ok(_) => {
                    display_name.set(String::new());
                    description.set(String::new());
                    on_created_cb.run(());
                    on_close_cb.run(());
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="create-app-dialog-title"
            >
                <div class="modal modal--wide" node_ref=modal_ref>
                    <h3 id="create-app-dialog-title">"New app registration"</h3>
                    <Field label="Display name">
                        <Input value=display_name />
                        {move || {
                            display_name
                                .with(|d| d.trim().is_empty())
                                .then(|| {
                                    view! {
                                        <Body1 class="hint hint--field">
                                            "Enter a display name to create the app."
                                        </Body1>
                                    }
                                })
                        }}
                    </Field>
                    <Field label="Sign-in audience">
                        <Select value=audience>
                            <option value="AzureADMyOrg">"Single tenant (this directory only)"</option>
                            <option value="AzureADMultipleOrgs">
                                "Multitenant (any Microsoft Entra directory)"
                            </option>
                            <option value="AzureADandPersonalMicrosoftAccount">
                                "Multitenant + personal Microsoft accounts"
                            </option>
                            <option value="PersonalMicrosoftAccount">
                                "Personal Microsoft accounts only"
                            </option>
                        </Select>
                    </Field>
                    <Field label="Description (optional)">
                        <Textarea value=description />
                    </Field>
                    <label class="checkbox-row">
                        <input
                            type="checkbox"
                            prop:checked=move || create_sp.get()
                            on:change=move |ev| {
                                let checked = event_target_checked(&ev);
                                create_sp.set(checked);
                            }
                        />
                        " Provision an enterprise application (service principal) in this tenant"
                    </label>
                    {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| on_close.run(()))
                            disabled=Signal::derive(move || busy.get())
                        >
                            "Cancel"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(create)
                            disabled=Signal::derive(move || {
                                busy.get() || display_name.with(|d| d.trim().is_empty())
                            })
                        >
                            {move || {
                                if busy.get() {
                                    view! {
                                        <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                    }
                                        .into_any()
                                } else {
                                    view! { "Create" }.into_any()
                                }
                            }}
                        </Button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
