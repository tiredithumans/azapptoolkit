//! First-run configuration screen.
//!
//! Shown (instead of the sign-in screen) when the app has no usable client /
//! tenant IDs — e.g. a freshly-downloaded release that hasn't been pointed at
//! an Entra app registration yet. The user pastes their Application (client) ID
//! and Directory (tenant) ID; we persist them to `settings.json` and relaunch
//! so the backend re-resolves them at startup. Mirrors `sign_in.rs`'s layout.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::config;
use crate::components::ui::Card;

#[component]
pub fn ConfigScreen() -> impl IntoView {
    let client_id = RwSignal::new(String::new());
    let tenant_id = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let on_save = move |_| {
        if busy.get() {
            return;
        }
        let cid = client_id.get().trim().to_string();
        let tid = tenant_id.get().trim().to_string();
        if cid.is_empty() || tid.is_empty() {
            error.set(Some(
                "Enter both the Application (client) ID and Directory (tenant) ID.".into(),
            ));
            return;
        }
        busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            match config::set_auth_config(cid, tid).await {
                // Saved — relaunch so AppState re-resolves the IDs from
                // settings.json. `restart_app` diverges, so nothing after runs.
                Ok(()) => config::restart_app().await,
                Err(e) => {
                    error.set(Some(format!("error [{}]: {}", e.code, e.message)));
                    busy.set(false);
                }
            }
        });
    };

    view! {
        <main class="signin-shell">
            <Card elevation=4 class="signin-card".to_string()>
                <div class="signin-card__brand">
                    <span class="shell__brand-mark">"a"</span>
                    <span>"azapptoolkit"</span>
                </div>
                <h1 class="signin-card__title">"Configure your tenant"</h1>
                <Body1>
                    "Point azapptoolkit at the single-tenant app registration you created in \
                     Entra ID. These IDs are stored locally in settings.json and used to sign \
                     you in — see the README's first-run configuration section for how to create \
                     the registration."
                </Body1>
                <Field label="Application (client) ID">
                    <Input value=client_id placeholder="00000000-0000-0000-0000-000000000000" />
                </Field>
                <Field label="Directory (tenant) ID">
                    <Input value=tenant_id placeholder="GUID or contoso.onmicrosoft.com" />
                </Field>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(on_save)
                    disabled=Signal::derive(move || busy.get())
                >
                    {move || {
                        if busy.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                .into_any()
                        } else {
                            view! { "Save & restart" }.into_any()
                        }
                    }}
                </Button>
                {move || {
                    error.get().map(|msg| view! { <Body1 class="signin-error">{msg}</Body1> })
                }}
            </Card>
        </main>
    }
}
