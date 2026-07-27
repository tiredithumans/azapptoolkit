//! "Browse the Entra gallery" modal. Reached from the New-application chooser.
//! Two stages: **browse** (debounced search of `applicationTemplates` → pick a
//! template) and **confirm** (name the instance → create). Creating calls
//! `create_gallery_application`, which instantiates the gallery template into a
//! paired app + service principal; SSO is then finished on the app's SSO tab.
//!
//! Matching happens backend-side in memory over the cached gallery, so a query
//! hits anywhere in a name or publisher ("force" → Salesforce) rather than only
//! as a prefix; see `commands::enterprise_application::search_application_templates`.
//!
//! Mounted in the shell (like the SSO wizard) only while its open flag is set, so
//! each open is a fresh component — no manual state reset needed.

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::enterprise_application::{
    self, ApplicationTemplateDto, GallerySearchResultsDto,
};
use crate::hooks::use_command::use_command;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;

/// Minimum query length before a search fires, in **characters** — mirrors the
/// backend's `GALLERY_MIN_QUERY_CHARS` and the on-screen label. Counting chars
/// (not bytes) keeps a 1-char CJK query on the same side of the gate as the
/// backend puts it.
const MIN_QUERY_CHARS: usize = 2;

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

    // On open, warm the gallery corpus so the operator's first query is instant.
    // The whole-catalog fetch is a one-time cost that overlaps them typing;
    // fire-and-forget and best-effort — a failure just makes the first search
    // pay the fetch itself (and it's idempotent once cached).
    Effect::new(move |_| {
        if open.get()
            && let Some(t) = session.active_tenant.get()
        {
            leptos::task::spawn_local(async move {
                let _ = enterprise_application::prefetch_application_gallery(&t.tenant_id).await;
            });
        }
    });

    // `Ok(None)` = no query yet (or no tenant); `Ok(Some(results))` = a real
    // search ran. The distinction is load-bearing: an empty `Vec` alone can't
    // tell "type something" from "nothing matched", and conflating them told
    // operators to start typing when their query had genuinely found nothing.
    let candidates = LocalResource::new(move || {
        let q = query.get();
        let tenant = session.active_tenant.get();
        async move {
            let q = q.trim().to_string();
            // Chars, not bytes — matches the backend's gate, so a 1-char CJK
            // query (3 bytes) isn't waved through by one side and rejected by
            // the other.
            if q.chars().count() < MIN_QUERY_CHARS {
                return Ok::<Option<GallerySearchResultsDto>, String>(None);
            }
            let Some(t) = tenant else {
                return Ok(None);
            };
            enterprise_application::search_application_templates(&t.tenant_id, &q)
                .await
                .map(Some)
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
                                        {move || {
                                            // Read the query synchronously, before the
                                            // async block: a signal read *after* an await
                                            // inside `Suspend` subscribes mid-flight and
                                            // can drift from the result being rendered.
                                            let asked = query.get().trim().to_string();
                                            Suspend::new(async move {
                                                let found = match candidates.await {
                                                    Ok(f) => f,
                                                    Err(msg) => {
                                                        return view! {
                                                            <Body1 class="form-error">
                                                                {format!("Search failed: {msg}")}
                                                            </Body1>
                                                        }
                                                            .into_any();
                                                    }
                                                };
                                                // No query yet — the only case that earns the
                                                // "start typing" prompt.
                                                let Some(found) = found else {
                                                    return view! {
                                                        <Body1 class="hint">
                                                            "Type an app name to search the gallery."
                                                        </Body1>
                                                    }
                                                        .into_any();
                                                };
                                                if found.results.is_empty() {
                                                    // A real search that matched nothing says so,
                                                    // and owns up when the catalog was partial
                                                    // rather than implying the app doesn't exist.
                                                    let msg = if found.partial_catalog {
                                                        "No gallery apps match that search, but the \
                                                         gallery was only partly loaded — try a \
                                                         narrower name."
                                                            .to_string()
                                                    } else {
                                                        format!(
                                                            "No gallery apps match \u{201c}{asked}\u{201d}.",
                                                        )
                                                    };
                                                    return view! { <Body1 class="hint">{msg}</Body1> }
                                                        .into_any();
                                                }
                                                let narrowed = found
                                                    .truncated
                                                    .then(|| {
                                                        format!(
                                                            "Showing the closest {} of {} matches — \
                                                             refine the search to narrow it.",
                                                            found.results.len(),
                                                            found.total_matches,
                                                        )
                                                    });
                                                view! {
                                                    <ul class="gallery-results">
                                                        {found
                                                            .results
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
                                                    {narrowed
                                                        .map(|n| {
                                                            view! {
                                                                <Body1 class="hint gallery-results__narrowed">
                                                                    {n}
                                                                </Body1>
                                                            }
                                                        })}
                                                }
                                                    .into_any()
                                            })
                                        }}
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
