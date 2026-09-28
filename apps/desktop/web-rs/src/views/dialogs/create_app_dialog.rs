//! Create-app dialog: display name + sign-in audience + description +
//! create-SP toggle.

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Select, Spinner, SpinnerSize, Textarea};

use crate::bindings::applications::{self, CreateApplicationInput};
use crate::components::ui::FormError;
use crate::hooks::use_command::use_command;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::views::tabs::overview_tab::SIGN_IN_AUDIENCES;

#[component]
pub fn CreateAppDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_created: Callback<()>,
) -> impl IntoView {
    let cmd = use_command();
    let display_name = RwSignal::new(String::new());
    let audience = RwSignal::new(SIGN_IN_AUDIENCES[0].0.to_string());
    let description = RwSignal::new(String::new());
    let create_sp = RwSignal::new(true);

    use_escape(
        move || open.get_untracked() && !cmd.busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    let create = move |_| {
        let dn = display_name.get();
        let aud = audience.get();
        let desc = description.get();
        let csp = create_sp.get();
        cmd.run(
            move |_| {
                display_name.set(String::new());
                description.set(String::new());
                on_created.run(());
                on_close.run(());
            },
            move |tenant_id| {
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
                async move { applications::create_application(&tenant_id, &input).await }
            },
        );
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
                            {SIGN_IN_AUDIENCES
                                .iter()
                                .map(|(value, label)| {
                                    view! { <option value=*value>{*label}</option> }
                                })
                                .collect_view()}
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
                    {move || {
                        cmd.error.get().map(|e| view! { <FormError>{e}</FormError> })
                    }}
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| on_close.run(()))
                            disabled=Signal::derive(move || cmd.busy.get())
                        >
                            "Cancel"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(create)
                            disabled=Signal::derive(move || {
                                cmd.busy.get() || display_name.with(|d| d.trim().is_empty())
                            })
                        >
                            {move || {
                                if cmd.busy.get() {
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
