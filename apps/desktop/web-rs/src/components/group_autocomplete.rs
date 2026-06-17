//! Reusable mail-enabled-group typeahead for the Exchange scope forms. Searches
//! groups live (`search_groups`) and appends a picked group's name to a free-text
//! field (one identifier per line), keeping that field the source of truth and
//! the fallback for the raw mailbox identifiers Exchange also accepts.

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Spinner, SpinnerSize};

use crate::bindings::applications;
use crate::hooks::use_debounced::use_debounced;
use crate::state::use_session;

#[component]
pub fn GroupAutocomplete(
    /// The free-text group field this typeahead appends to (one per line).
    target: RwSignal<String>,
) -> impl IntoView {
    let session = use_session();
    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);

    let candidates = LocalResource::new(move || {
        let q = query.get();
        let tenant = session.active_tenant.get();
        async move {
            let q = q.trim().to_string();
            if q.len() < 2 {
                return Ok::<Vec<DirectoryObject>, String>(Vec::new());
            }
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            applications::search_groups(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
        }
    });

    // Append the picked group's name on its own line (deduped); clear the query.
    let pick = Callback::new(move |identifier: String| {
        target.update(|t| {
            if t.lines().any(|l| l.trim() == identifier) {
                return;
            }
            if !t.is_empty() && !t.ends_with('\n') {
                t.push('\n');
            }
            t.push_str(&identifier);
        });
        raw_query.set(String::new());
    });

    view! {
        <Input value=raw_query placeholder="Search mail-enabled groups (2+ chars)…" />
        <Suspense fallback=move || {
            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Searching…" /> }
        }>
            {move || Suspend::new(async move {
                match candidates.await {
                    Err(msg) => {
                        view! { <Body1 class="form-error">{format!("Search failed: {msg}")}</Body1> }
                            .into_any()
                    }
                    Ok(groups) if groups.is_empty() => ().into_any(),
                    Ok(groups) => {
                        view! {
                            <ul class="candidates">
                                {groups
                                    .into_iter()
                                    .map(|g| {
                                        let identifier = g
                                            .display_name
                                            .clone()
                                            .unwrap_or_else(|| g.id.clone());
                                        let display = identifier.clone();
                                        let id_click = identifier.clone();
                                        view! {
                                            <li>
                                                <div>
                                                    <div>{display}</div>
                                                    <div class="mono small">{g.id.clone()}</div>
                                                </div>
                                                <Button
                                                    appearance=Signal::derive(|| {
                                                        ButtonAppearance::Secondary
                                                    })
                                                    on_click=Box::new(move |_| pick.run(
                                                        id_click.clone(),
                                                    ))
                                                >
                                                    "Add"
                                                </Button>
                                            </li>
                                        }
                                    })
                                    .collect::<Vec<_>>()}
                            </ul>
                        }
                            .into_any()
                    }
                }
            })}
        </Suspense>
    }
}
