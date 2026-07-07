//! "Browse the Entra gallery" modal. Reached from the New-application chooser.
//! Two stages: **browse** (debounced prefix search of `applicationTemplates` →
//! pick a template) and **confirm** (name the instance → create). Creating calls
//! `create_gallery_application`, which instantiates the gallery template into a
//! paired app + service principal; SSO is then finished on the app's SSO tab.
//!
//! Mounted in the shell (like the SSO wizard) only while its open flag is set, so
//! each open is a fresh component — no manual state reset needed.

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::enterprise_application::{self, ApplicationTemplateDto};
use crate::hooks::use_command::use_command;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;

#[component]
pub fn GalleryDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_created: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let cmd = use_command();

    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);
    // `Some(template)` switches from the browse stage to the confirm stage.
    let selected: RwSignal<Option<ApplicationTemplateDto>> = RwSignal::new(None);
    let name = RwSignal::new(String::new());

    use_escape(
        move || open.get_untracked() && !cmd.busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    let candidates = LocalResource::new(move || {
        let q = query.get();
        let tenant = session.active_tenant.get();
        async move {
            let q = q.trim().to_string();
            if q.len() < 2 {
                return Ok::<Vec<ApplicationTemplateDto>, String>(Vec::new());
            }
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            enterprise_application::search_application_templates(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
        }
    });

    // Move from browse → confirm, seeding the name field with the template's own.
    let pick = move |tpl: ApplicationTemplateDto| {
        name.set(tpl.display_name.clone());
        selected.set(Some(tpl));
    };

    let create = move |_| {
        let Some(tpl) = selected.get() else {
            return;
        };
        let template_id = tpl.id.clone();
        let display_name = name.get().trim().to_string();
        cmd.run(
            move |_| {
                on_created.run(());
                on_close.run(());
            },
            move |tenant_id| {
                let template_id = template_id.clone();
                let display_name = display_name.clone();
                async move {
                    enterprise_application::create_gallery_application(
                        &tenant_id,
                        &template_id,
                        &display_name,
                    )
                    .await
                }
            },
        );
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="gallery-dialog-title"
            >
                <div class="modal modal--wide" node_ref=modal_ref>
                    <h3 id="gallery-dialog-title">"Browse the Entra gallery"</h3>
                    {move || match selected.get() {
                        // ---- Confirm stage: name the instance, then create. ----
                        Some(tpl) => {
                            view! {
                                <div class="gallery-confirm">
                                    <div class="gallery-result gallery-result--selected">
                                        <span class="gallery-result__name">
                                            {tpl.display_name.clone()}
                                        </span>
                                        {tpl
                                            .publisher
                                            .clone()
                                            .map(|p| {
                                                view! {
                                                    <span class="gallery-result__publisher">{p}</span>
                                                }
                                            })}
                                    </div>
                                    <Field label="Name for this application">
                                        <Input value=name />
                                    </Field>
                                    <Body1 class="hint">
                                        "This creates the enterprise application from the gallery \
                                         template. Finish single sign-on on its SSO tab afterward."
                                    </Body1>
                                    {move || {
                                        cmd.error
                                            .get()
                                            .map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                                    }}
                                    <div class="actions-row">
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                            on_click=Box::new(move |_| selected.set(None))
                                            disabled=Signal::derive(move || cmd.busy.get())
                                        >
                                            "Back"
                                        </Button>
                                        <Button
                                            class="gallery-create"
                                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                                            on_click=Box::new(create)
                                            disabled=Signal::derive(move || {
                                                cmd.busy.get() || name.with(|n| n.trim().is_empty())
                                            })
                                        >
                                            {move || {
                                                if cmd.busy.get() {
                                                    view! {
                                                        <Spinner size=Signal::derive(|| {
                                                            SpinnerSize::Tiny
                                                        }) />
                                                    }
                                                        .into_any()
                                                } else {
                                                    view! { "Create" }.into_any()
                                                }
                                            }}
                                        </Button>
                                    </div>
                                </div>
                            }
                                .into_any()
                        }
                        // ---- Browse stage: search the gallery, pick a template. ----
                        None => {
                            view! {
                                <div class="gallery-browse">
                                    <Field label="Search the gallery (2+ characters)">
                                        <Input value=raw_query placeholder="Salesforce" />
                                    </Field>
                                    <Suspense fallback=move || {
                                        view! {
                                            <Spinner
                                                size=Signal::derive(|| SpinnerSize::Tiny)
                                                label="Searching…"
                                            />
                                        }
                                    }>
                                        {move || Suspend::new(async move {
                                            let templates = match candidates.await {
                                                Ok(t) => t,
                                                Err(msg) => {
                                                    return view! {
                                                        <Body1 class="form-error">
                                                            {format!("Search failed: {msg}")}
                                                        </Body1>
                                                    }
                                                        .into_any();
                                                }
                                            };
                                            if templates.is_empty() {
                                                return view! {
                                                    <Body1 class="hint">
                                                        "Type an app name to search the gallery."
                                                    </Body1>
                                                }
                                                    .into_any();
                                            }
                                            view! {
                                                <ul class="gallery-results">
                                                    {templates
                                                        .into_iter()
                                                        .map(|tpl| {
                                                            let modes = tpl
                                                                .supported_single_sign_on_modes
                                                                .join(" · ");
                                                            let publisher = tpl.publisher.clone();
                                                            let display = tpl.display_name.clone();
                                                            let tpl_for_pick = tpl.clone();
                                                            view! {
                                                                <li>
                                                                    <button
                                                                        type="button"
                                                                        class="gallery-result"
                                                                        on:click=move |_| pick(tpl_for_pick.clone())
                                                                    >
                                                                        <span class="gallery-result__name">
                                                                            {display}
                                                                        </span>
                                                                        {publisher
                                                                            .map(|p| {
                                                                                view! {
                                                                                    <span class="gallery-result__publisher">
                                                                                        {p}
                                                                                    </span>
                                                                                }
                                                                            })}
                                                                        {(!modes.is_empty())
                                                                            .then(|| {
                                                                                view! {
                                                                                    <span class="gallery-result__modes">{modes}</span>
                                                                                }
                                                                            })}
                                                                    </button>
                                                                </li>
                                                            }
                                                        })
                                                        .collect_view()}
                                                </ul>
                                            }
                                                .into_any()
                                        })}
                                    </Suspense>
                                    <div class="actions-row">
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| on_close.run(()))
                                        >
                                            "Cancel"
                                        </Button>
                                    </div>
                                </div>
                            }
                                .into_any()
                        }
                    }}
                </div>
            </div>
        </Show>
    }
}
