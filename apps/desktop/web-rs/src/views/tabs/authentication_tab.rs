//! Authentication tab — edit the app registration's reply (redirect) URIs per
//! platform (web / SPA / public client), the front-channel logout URL, the
//! implicit-grant flags, and the "Allow public client flows" toggle. The
//! portal's "Authentication" blade, minus the parts this toolkit doesn't manage.
//!
//! Loads current values via `get_application_authentication`, then Save does a
//! full-replace write via `set_application_authentication` (each URI box is the
//! complete set for that platform, so the editor must load before it saves).
//! Reply URIs are validated server-side (no wildcards; https / loopback-http /
//! custom schemes only) — the rejection reason surfaces inline.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize, Textarea};

use crate::bindings::applications::{
    self, ApplicationAuthenticationDto, ApplicationDetail, SetApplicationAuthenticationInput,
};
use crate::hooks::use_command::use_command;
use crate::state::use_session;

/// Splits a redirect-URI textarea into trimmed, non-empty entries. Unlike the
/// scope forms' `parse_lines`, this splits on newlines ONLY: a redirect URI may
/// legally contain a comma or semicolon (e.g. in a query string), so those must
/// not split one URI into two. The UI labels each box "one per line".
fn lines_to_uris(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

use crate::util::no_tenant;

#[component]
pub fn AuthenticationTab(
    #[prop(into)] detail: Signal<ApplicationDetail>,
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
            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" /> }
            }>
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

    // Seed the editable fields from the loaded settings (one URI per line).
    let web = RwSignal::new(dto.web_redirect_uris.join("\n"));
    let spa = RwSignal::new(dto.spa_redirect_uris.join("\n"));
    let public_client = RwSignal::new(dto.public_client_redirect_uris.join("\n"));
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
                let input = SetApplicationAuthenticationInput {
                    web_redirect_uris: lines_to_uris(&web.get()),
                    spa_redirect_uris: lines_to_uris(&spa.get()),
                    public_client_redirect_uris: lines_to_uris(&public_client.get()),
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
                "Reply (redirect) URIs — one per line. Wildcards aren't allowed; use https (or http only for localhost) or a custom scheme for installed apps."
            </Body1>
            <Field label="Web redirect URIs">
                <Textarea value=web />
            </Field>
            <Field label="Single-page application (SPA) redirect URIs">
                <Textarea value=spa />
            </Field>
            <Field label="Mobile & desktop (public client) redirect URIs">
                <Textarea value=public_client />
            </Field>
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

#[cfg(test)]
mod tests {
    use super::lines_to_uris;

    #[test]
    fn splits_on_newlines_only_and_trims() {
        assert_eq!(
            lines_to_uris("https://a/cb\n  https://b/cb  \n"),
            ["https://a/cb", "https://b/cb"]
        );
        // A comma/semicolon in a query string must NOT split one URI into two.
        assert_eq!(
            lines_to_uris("https://a/cb?x=1,2;3"),
            ["https://a/cb?x=1,2;3"]
        );
        assert!(lines_to_uris("\n  \n").is_empty());
    }
}
