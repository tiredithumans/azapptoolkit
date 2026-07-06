//! Reusable owner search-and-pick control: a debounced user search (2+ chars)
//! that emits the chosen [`DirectoryObject`] via `on_pick`. Extracted so the
//! Settings page's default-owner editors share one implementation; the existing
//! owner tabs keep their own (richer) flows for now.

use std::collections::HashSet;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::applications;
use crate::hooks::use_debounced::use_debounced;
use crate::state::use_session;

#[component]
pub fn OwnerPicker(
    /// Fired with the picked directory object when the user clicks "Add".
    on_pick: Callback<DirectoryObject>,
    /// Ids already selected — hidden from results so they can't be re-added.
    #[prop(into)]
    exclude: Signal<HashSet<String>>,
    #[prop(optional, into, default = String::from("Search by display name or UPN (2+ chars)"))]
    label: String,
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
            applications::search_users(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
        }
    });

    view! {
        <div class="owner-picker">
            <Field label=label>
                <Input value=raw_query placeholder="alice@contoso.com" />
            </Field>
            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Searching…" /> }
            }>
                {move || Suspend::new(async move {
                    let users = match candidates.await {
                        Ok(u) => u,
                        Err(msg) => {
                            return view! {
                                <Body1 class="form-error">{format!("Search failed: {msg}")}</Body1>
                            }
                                .into_any();
                        }
                    };
                    let ex = exclude.get();
                    let filtered: Vec<DirectoryObject> =
                        users.into_iter().filter(|u| !ex.contains(&u.id)).collect();
                    if filtered.is_empty() {
                        return view! { <Body1>"No matches."</Body1> }.into_any();
                    }
                    view! {
                        <ul class="candidates">
                            {filtered
                                .into_iter()
                                .map(|u| {
                                    let picked = u.clone();
                                    let display = u
                                        .display_name
                                        .clone()
                                        .unwrap_or_else(|| u.id.clone());
                                    let upn = u
                                        .user_principal_name
                                        .clone()
                                        .unwrap_or_else(|| u.id.clone());
                                    view! {
                                        <li>
                                            <div>
                                                <div>{display}</div>
                                                <div class="mono small">{upn}</div>
                                            </div>
                                            <Button
                                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                on_click=Box::new(move |_| {
                                                    on_pick.run(picked.clone());
                                                    raw_query.set(String::new());
                                                })
                                            >
                                                "Add"
                                            </Button>
                                        </li>
                                    }
                                })
                                .collect_view()}
                        </ul>
                    }
                        .into_any()
                })}
            </Suspense>
        </div>
    }
}
