//! Client / tenant ID configuration — two surfaces over one form.
//!
//! [`ConfigScreen`] is the first-run screen, shown (instead of the sign-in
//! screen) when the app has no usable client / tenant IDs — e.g. a freshly
//! downloaded release that hasn't been pointed at an Entra app registration
//! yet. It mirrors `sign_in.rs`'s layout.
//!
//! [`AuthConfigForm`] is the form itself, extracted because Settings → Tenant
//! connection mounts the same fields to **re**-point an install that is already
//! configured. That second surface is not a convenience: a well-formed but
//! wrong tenant GUID passes the first-run gate and then fails every sign-in
//! identically, and until it existed the only way out was hand-editing
//! `settings.json`. Both paths persist through `set_auth_config` and relaunch,
//! since `AppState` resolves the IDs once at startup.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::config;
use crate::components::ui::Card;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;

#[component]
pub fn ConfigScreen(
    /// Currently resolved IDs, empty on a fresh install. Prefilled rather than
    /// blank because this screen is reachable a second time (the sign-in card's
    /// "Change" link), where the operator is fixing one wrong character in an
    /// otherwise correct pair — not typing both from scratch.
    client_id: String,
    tenant_id: String,
) -> impl IntoView {
    let client_id = RwSignal::new(client_id);
    let tenant_id = RwSignal::new(tenant_id);

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
                <AuthConfigForm client_id=client_id tenant_id=tenant_id />
            </Card>
        </main>
    }
}

/// The client / tenant ID fields, their validation, and the save → relaunch it
/// takes for either to take effect.
///
/// The caller owns both signals (same contract as `ConfirmDialog`'s `open`) so
/// the Settings tab can hold them at editor scope and keep half-typed edits
/// across a tab switch, exactly as every other field on that page does.
#[component]
pub fn AuthConfigForm(
    client_id: RwSignal<String>,
    tenant_id: RwSignal<String>,
    /// Confirm before relaunching. Off on first run — there is no session to
    /// interrupt and the extra click is friction on the very first screen. On
    /// from Settings, where a restart drops a signed-in session and everything
    /// open in the workspace with it.
    #[prop(default = false)]
    confirm_restart: bool,
) -> impl IntoView {
    let busy = RwSignal::new(false);
    let confirming = RwSignal::new(false);
    // (message, hint) — the backend message paired with the recovery step its
    // code maps to, rendered as two lines. Same shape and the same two classes
    // as `sign_in.rs`'s error, because to the operator this is the same card
    // failing for a neighbouring reason.
    let error: RwSignal<Option<(String, &'static str)>> = RwSignal::new(None);

    let save = move || {
        busy.set(true);
        error.set(None);
        let cid = client_id.get_untracked().trim().to_string();
        let tid = tenant_id.get_untracked().trim().to_string();
        leptos::task::spawn_local(async move {
            match config::set_auth_config(cid, tid).await {
                // Saved — relaunch so AppState re-resolves the IDs from
                // settings.json. `restart_app` diverges, so nothing after runs.
                Ok(()) => config::restart_app().await,
                Err(e) => {
                    // Close the confirmation on the way out: the shape errors
                    // this returns are fixed in the fields behind it, not in
                    // the dialog.
                    confirming.set(false);
                    error.set(Some((e.message, config_error_hint(&e.code))));
                    busy.set(false);
                }
            }
        });
    };

    let on_submit = move |_| {
        if busy.get() {
            return;
        }
        if client_id.get().trim().is_empty() || tenant_id.get().trim().is_empty() {
            error.set(Some((
                "Enter both the Application (client) ID and Directory (tenant) ID.".into(),
                "Both are on the app registration's Overview page in the Entra portal.",
            )));
            return;
        }
        if confirm_restart {
            confirming.set(true);
        } else {
            save();
        }
    };

    view! {
        <Field label="Application (client) ID">
            <Input value=client_id placeholder="00000000-0000-0000-0000-000000000000" />
        </Field>
        <Field label="Directory (tenant) ID">
            <Input value=tenant_id placeholder="GUID or contoso.onmicrosoft.com" />
        </Field>
        <Button
            appearance=Signal::derive(|| ButtonAppearance::Primary)
            on_click=Box::new(on_submit)
            disabled=Signal::derive(move || busy.get())
        >
            {move || {
                if busy.get() {
                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }.into_any()
                } else {
                    view! { "Save & restart" }.into_any()
                }
            }}
        </Button>
        {move || {
            error
                .get()
                .map(|(msg, hint)| {
                    view! {
                        <Body1 class="signin-error">{msg}</Body1>
                        <Body1 class="signin-hint">{hint}</Body1>
                    }
                })
        }}
        {confirm_restart
            .then(|| {
                view! {
                    <ConfirmDialog
                        open=confirming
                        title="Restart and sign in?"
                        body="Saving these IDs relaunches azapptoolkit and signs you in to:"
                        subject=Signal::derive(move || tenant_id.get().trim().to_string())
                        confirm_label="Save & restart"
                        busy=busy
                        on_confirm=Callback::new(move |()| save())
                        on_close=Callback::new(move |()| confirming.set(false))
                    />
                }
            })}
    }
}

/// One actionable recovery step per `UiError.code` from `set_auth_config`.
fn config_error_hint(code: &str) -> &'static str {
    match code {
        "invalid_client_id" => {
            "The Application (client) ID must be a GUID — copy it from the app \
             registration's Overview page in the Entra portal."
        }
        "invalid_tenant_id" => {
            "The Directory (tenant) ID must be a GUID or a domain like \
             contoso.onmicrosoft.com — copy it from the registration's Overview page."
        }
        "io" => {
            "Couldn't write settings.json — check that the app's config folder is \
             writable (not blocked by permissions or disk space), then retry."
        }
        _ => "Double-check the IDs and try again.",
    }
}
