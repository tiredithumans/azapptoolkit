//! Authentication tab — edit the app registration's reply (redirect) URIs per
//! platform (web / SPA / public client), the front-channel logout URL, the
//! implicit-grant flags, and the "Allow public client flows" toggle. The
//! portal's "Authentication" blade, minus the parts this toolkit doesn't manage.
//!
//! Loads current values via `get_application_authentication`, then Save does a
//! full-replace write via `set_application_authentication` (each platform's list
//! is the complete set for that platform, so the editor must load before it
//! saves).
//!
//! Reply URIs are edited one per row (`components::uri_list_editor`) and checked
//! against the same `core::redirect` validator the backend runs, so an offender
//! is marked on its own row before the round trip. That check is advisory: Save
//! is never blocked and `set_application_authentication` stays the authority.

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::applications::{self, ApplicationAuthenticationDto, ApplicationDetail};
use crate::components::ui::DetailSkeleton;
use crate::components::uri_list_editor::{UriListEditor, UriListState, redirect_uri_reason};
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::util::no_tenant;

#[component]
pub fn AuthenticationTab(
    #[prop(into)] detail: Signal<Arc<ApplicationDetail>>,
    #[prop(into)] on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let object_id = Signal::derive(move || detail.with(|d| d.application.id.clone()));
    let reload = RwSignal::new(0_u32);

    let settings = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let id = object_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            applications::get_application_authentication(&t.tenant_id, &id).await
        }
    });

    // After a successful save, refresh this tab's own fetch (so a full-replace
    // round-trips) and the parent detail (the public-client flag also surfaces
    // on the Overview tab).
    let on_saved = Callback::new(move |()| {
        reload.update(|n| *n += 1);
        on_changed.run(());
    });

    view! {
        <div class="authentication-tab">
            <Suspense fallback=move || view! { <DetailSkeleton /> }>
                {move || Suspend::new(async move {
                    match settings.await {
                        Ok(dto) => {
                            let id = object_id.get_untracked();
                            view! { <AuthenticationForm object_id=id dto=dto on_saved=on_saved /> }
                                .into_any()
                        }
                        Err(e) => {
                            view! { <Body1 class="form-error">{e.message}</Body1> }.into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn AuthenticationForm(
    object_id: String,
    dto: ApplicationAuthenticationDto,
    #[prop(into)] on_saved: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let cmd = use_command();

    // One row per URI. Each list owns its own row state and hands back a
    // `Vec<String>` on save — the write is a full replace, which is why the tab
    // loads before it saves.
    let web = UriListState::validated(&dto.web_redirect_uris, redirect_uri_reason);
    let spa = UriListState::validated(&dto.spa_redirect_uris, redirect_uri_reason);
    let public_client =
        UriListState::validated(&dto.public_client_redirect_uris, redirect_uri_reason);
    let logout = RwSignal::new(dto.logout_url.clone().unwrap_or_default());
    let fallback = RwSignal::new(dto.is_fallback_public_client);
    let access_token = RwSignal::new(dto.enable_access_token_issuance);
    let id_token = RwSignal::new(dto.enable_id_token_issuance);

    let save = move |_| {
        let object_id = object_id.clone();
        cmd.run(
            move |()| {
                session.toast_success("Authentication settings saved.");
                on_saved.run(());
            },
            move |tenant_id| {
                let logout_url = {
                    let l = logout.get().trim().to_string();
                    (!l.is_empty()).then_some(l)
                };
                let input = ApplicationAuthenticationDto {
                    // `to_uris` reads untracked: trimmed, blanks dropped, order
                    // preserved — the same contract `lines_to_uris` had.
                    web_redirect_uris: web.to_uris(),
                    spa_redirect_uris: spa.to_uris(),
                    public_client_redirect_uris: public_client.to_uris(),
                    logout_url,
                    is_fallback_public_client: fallback.get(),
                    enable_access_token_issuance: access_token.get(),
                    enable_id_token_issuance: id_token.get(),
                };
                async move {
                    applications::set_application_authentication(&tenant_id, &object_id, &input)
                        .await
                }
            },
        );
    };

    view! {
        <div class="form-grid">
            <Body1>
                "Reply (redirect) URIs. Wildcards aren't allowed; use https (or http only for localhost) or a custom scheme for installed apps."
            </Body1>
            <UriListEditor
                state=web
                class="uri-list--web"
                label="Web redirect URIs"
                noun="web redirect URI"
                placeholder="https://contoso.com/auth/callback"
            />
            <UriListEditor
                state=spa
                class="uri-list--spa"
                label="Single-page application (SPA) redirect URIs"
                noun="SPA redirect URI"
                placeholder="https://contoso.com/"
            />
            <UriListEditor
                state=public_client
                class="uri-list--public-client"
                label="Mobile & desktop (public client) redirect URIs"
                noun="public client redirect URI"
                placeholder="myapp://auth"
            />
            <Field label="Front-channel logout URL">
                <Input value=logout />
            </Field>
            <label class="checkbox-row">
                <input
                    type="checkbox"
                    prop:checked=move || fallback.get()
                    on:change=move |ev| fallback.set(event_target_checked(&ev))
                />
                " Allow public client flows (mobile & desktop / ROPC) — leave off for confidential apps"
            </label>
            <strong>"Implicit grant & hybrid flows (web)"</strong>
            <label class="checkbox-row">
                <input
                    type="checkbox"
                    prop:checked=move || access_token.get()
                    on:change=move |ev| access_token.set(event_target_checked(&ev))
                />
                " Issue access tokens from the authorization endpoint"
            </label>
            <label class="checkbox-row">
                <input
                    type="checkbox"
                    prop:checked=move || id_token.get()
                    on:change=move |ev| id_token.set(event_target_checked(&ev))
                />
                " Issue ID tokens from the authorization endpoint"
            </label>
            {move || cmd.error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(save)
                    disabled=Signal::derive(move || cmd.busy.get())
                >
                    {move || {
                        if cmd.busy.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }.into_any()
                        } else {
                            view! { "Save" }.into_any()
                        }
                    }}
                </Button>
            </div>
        </div>
    }
}
