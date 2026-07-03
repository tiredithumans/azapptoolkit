//! Guided add-owner remediation for the Security-audit view: a button + modal
//! that closes the Rule-14 ownership gap (no owners / single owner) by
//! searching the directory and adding the picked user via the existing
//! add-owner mutation. Advisory only — the admin picks and confirms; purely
//! additive, so it can't break a working sign-in.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Spinner, SpinnerSize};

use azapptoolkit_core::audit::RemediationAction;
use azapptoolkit_core::models::DirectoryObject;

use crate::bindings::applications;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;

/// "Add owner" remediation — searches users and adds the picked one as an
/// owner of the app registration. Adding directly from the candidate row
/// mirrors the Owners tab (no separate select-then-confirm step); success
/// closes the modal and fires `on_done` so the row's Fix button clears.
#[component]
pub fn AddOwnerButton(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);

    let candidates = LocalResource::new(move || {
        let q = query.get();
        let tenant = tenant.get();
        async move {
            let q = q.trim().to_string();
            if q.len() < 2 {
                return Ok::<Vec<DirectoryObject>, String>(Vec::new());
            }
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            // Carry the error message so a Graph/network failure shows up as an
            // error instead of being indistinguishable from "No matches."
            applications::search_users(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
        }
    });

    // A `Callback` (Copy) so every candidate row's click handler can capture it.
    let add = Callback::new(move |principal_id: String| {
        if busy.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        busy.set(true);
        error.set(None);
        let object_id = object_id.clone();
        leptos::task::spawn_local(async move {
            match applications::add_application_owner(&t.tenant_id, &object_id, &principal_id).await
            {
                Ok(()) => {
                    open.set(false);
                    raw_query.set(String::new());
                    session.toast_success(
                        "Owner added — re-run the audit to refresh the ownership finding.",
                    );
                    on_done.run(object_id);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    });

    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || open.set(false),
    );
    let modal_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open.into());

    let label = action.label.clone();
    let detail = action.detail.clone();
    view! {
        <div class="audit-actions">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| open.set(true))
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <Show when=move || open.get() fallback=|| view! { <></> }>
                <div
                    class="modal-backdrop"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="add-owner-dialog-title"
                >
                    <div class="modal" node_ref=modal_ref>
                        <h3 id="add-owner-dialog-title">"Add an owner"</h3>
                        <Body1>
                            "Search the directory and add an owner so this application has clear accountability. Adding an owner is purely additive — it can't disrupt the app's sign-in or permissions."
                        </Body1>
                        <Input value=raw_query placeholder="Search users by name or UPN (min 2 chars)" />
                        {move || {
                            candidates
                                .get()
                                .map(|res| match res {
                                    Ok(users) if users.is_empty() => {
                                        if query.get().trim().len() < 2 {
                                            ().into_any()
                                        } else {
                                            view! { <p class="muted">"No matches."</p> }.into_any()
                                        }
                                    }
                                    Ok(users) => {
                                        view! {
                                            <ul class="add-owner-candidates">
                                                {users
                                                    .into_iter()
                                                    .map(|u| {
                                                        let name = u
                                                            .display_name
                                                            .clone()
                                                            .unwrap_or_else(|| "—".to_string());
                                                        let upn = u.user_principal_name.clone().unwrap_or_default();
                                                        let id = u.id.clone();
                                                        view! {
                                                            <li class="add-owner-candidates__row">
                                                                <span>
                                                                    {name} <span class="muted">{" "}{upn}</span>
                                                                </span>
                                                                <Button
                                                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                                                    disabled=Signal::derive(move || busy.get())
                                                                    on_click=Box::new(move |_| add.run(id.clone()))
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
                                    }
                                    Err(e) => {
                                        view! { <Body1 class="form-error">{e}</Body1> }.into_any()
                                    }
                                })
                        }}
                        {move || {
                            error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                        }}
                        <div class="actions-row">
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                on_click=Box::new(move |_| open.set(false))
                                disabled=Signal::derive(move || busy.get())
                            >
                                "Cancel"
                            </Button>
                            {move || {
                                busy.get()
                                    .then(|| {
                                        view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    })
                            }}
                        </div>
                    </div>
                </div>
            </Show>
        </div>
    }
    .into_any()
}
