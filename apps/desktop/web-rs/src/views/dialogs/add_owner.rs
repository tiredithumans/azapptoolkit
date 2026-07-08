//! Guided add-owner remediation for the Security-audit view: a button + modal
//! that closes the Rule-14 ownership gap (no owners / single owner) either by
//! one-click applying the tenant's Settings-configured default owners or by
//! searching the directory for a specific user — both via the existing add-owner
//! mutation. Advisory only — the admin chooses; purely additive, so it can't
//! break a working sign-in.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Spinner, SpinnerSize};

use azapptoolkit_core::audit::RemediationAction;
use azapptoolkit_core::models::DirectoryObject;

use crate::bindings::applications;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;

/// "Add owner" remediation — one-click applies the tenant's default owners
/// (Settings → `app_registration.default_owners`) or searches users and adds the
/// picked one as an owner of the app registration. Adding directly from the
/// candidate row mirrors the Owners tab (no separate select-then-confirm step);
/// success closes the modal and fires `on_done` so the row's Fix button clears.
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
    let adding_defaults = RwSignal::new(false);
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

    // `object_id` is consumed by both the per-row add and the default-owners
    // handler; give each its own clone.
    let object_id_row = object_id.clone();
    // A `Callback` (Copy) so every candidate row's click handler can capture it.
    let add = Callback::new(move |principal_id: String| {
        if busy.get() || adding_defaults.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        busy.set(true);
        error.set(None);
        let object_id = object_id_row.clone();
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

    // One-click apply of the tenant's Settings-configured default owners
    // (`app_registration.default_owners`). Additive: skips anyone already an
    // owner (via the cached detail), reports per-owner failures, and only clears
    // the finding's Fix button (`on_done`) when nothing failed.
    let add_defaults = Callback::new(move |_: ()| {
        if busy.get() || adding_defaults.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        adding_defaults.set(true);
        error.set(None);
        let object_id = object_id.clone();
        leptos::task::spawn_local(async move {
            let defaults = crate::bindings::defaults::get_tenant_defaults(&t.tenant_id).await;
            let owners = defaults.app_registration.default_owners;
            if owners.is_empty() {
                error.set(Some(
                    "No default owners configured — set them in Settings.".into(),
                ));
                adding_defaults.set(false);
                return;
            }
            // Skip anyone already an owner so a re-run doesn't error on the
            // existing single owner. `get_application_detail` is cached.
            let existing: std::collections::HashSet<String> =
                match applications::get_application_detail(&t.tenant_id, &object_id).await {
                    Ok(d) => d.owners.iter().map(|o| o.id.clone()).collect(),
                    Err(_) => std::collections::HashSet::new(),
                };
            let mut added = 0usize;
            let mut failures = Vec::new();
            for p in owners {
                if existing.contains(&p.id) {
                    continue;
                }
                match applications::add_application_owner(&t.tenant_id, &object_id, &p.id).await {
                    Ok(()) => added += 1,
                    Err(e) => {
                        failures.push(format!("{}: {}", p.display_name.unwrap_or(p.id), e.message))
                    }
                }
            }
            adding_defaults.set(false);
            if !failures.is_empty() {
                // Leave the modal open with the error so the operator can retry;
                // don't clear the Fix button.
                error.set(Some(format!(
                    "{} default owner(s) failed — {}",
                    failures.len(),
                    failures.join("; ")
                )));
                return;
            }
            open.set(false);
            raw_query.set(String::new());
            if added > 0 {
                session.toast_success(format!(
                    "Added {added} default owner(s) — re-run the audit to refresh the ownership finding."
                ));
            } else {
                session.toast_success(
                    "Default owners are already present — re-run the audit to refresh.",
                );
            }
            on_done.run(object_id);
        });
    });

    use_escape(
        move || open.get_untracked() && !busy.get_untracked() && !adding_defaults.get_untracked(),
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
                        <div class="actions-row">
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                disabled=Signal::derive(move || busy.get() || adding_defaults.get())
                                on_click=Box::new(move |_| add_defaults.run(()))
                            >
                                "Add default owners"
                            </Button>
                            {move || {
                                adding_defaults
                                    .get()
                                    .then(|| {
                                        view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    })
                            }}
                        </div>
                        <Body1 class="muted">
                            "Adds the owners configured for this tenant in Settings (additive — skips anyone already an owner). Or search below to add someone specific."
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
                                                                    disabled=Signal::derive(move || busy.get() || adding_defaults.get())
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
                                disabled=Signal::derive(move || busy.get() || adding_defaults.get())
                            >
                                "Cancel"
                            </Button>
                            {move || {
                                (busy.get() || adding_defaults.get())
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
