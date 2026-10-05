//! Owners tab. Lists current owners + lets you search and add.

use std::collections::HashSet;
use std::sync::Arc;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::bindings::applications::{self, ApplicationDetail};
use crate::components::directory_search::DirectorySearch;
use crate::components::tenant_defaults_hint::OwnerDefaultsHint;
use crate::components::ui::{DataTable, FormError};
use crate::state::use_session;
use crate::util::count_noun;
use crate::views::dialogs::add_owner::{DefaultOwnersOutcome, add_default_owners};
use crate::views::dialogs::confirm_dialog::ConfirmDialog;

fn owner_kind(o: &DirectoryObject) -> &'static str {
    let t = o.odata_type.as_deref().unwrap_or("");
    if t.contains("user") {
        "User"
    } else if t.contains("servicePrincipal") {
        "Service Principal"
    } else if t.contains("group") {
        "Group"
    } else {
        "—"
    }
}

#[component]
pub fn OwnersTab(
    #[prop(into)] detail: Signal<Arc<ApplicationDetail>>,
    #[prop(into)] on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    // Owned here (not by `DirectorySearch`) so a successful add can clear it.
    let raw_query = RwSignal::new(String::new());
    let adding: RwSignal<Option<String>> = RwSignal::new(None);
    let removing: RwSignal<Option<String>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    // (owner id, label): one dialog covers the whole owners table, so the row's
    // own label rides along to be its subject and is discarded there.
    let pending_remove: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    // Replace-all-owners (ports `Set-AzAppOwner`): stage a target set, then
    // reconcile in one call.
    let replacing = RwSignal::new(false);
    let staged: RwSignal<Vec<DirectoryObject>> = RwSignal::new(Vec::new());
    let applying = RwSignal::new(false);

    // Hidden from the search: the staged set while replacing, else the
    // current owners.
    let exclude = Signal::derive(move || -> HashSet<String> {
        if replacing.get() {
            staged.with(|s| s.iter().map(|o| o.id.clone()).collect())
        } else {
            detail.with(|d| d.owners.iter().map(|o| o.id.clone()).collect())
        }
    });

    let add = move |principal_id: String| {
        if adding.get().is_some() {
            return;
        }
        adding.set(Some(principal_id.clone()));
        error.set(None);
        let tenant = session.active_tenant.get();
        let object_id = detail.with_untracked(|d| d.application.id.clone());
        let on_changed_cb = on_changed;
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                adding.set(None);
                return;
            };
            match applications::add_application_owner(&t.tenant_id, &object_id, &principal_id).await
            {
                Ok(()) => {
                    raw_query.set(String::new());
                    session.toast_success("Owner added.");
                    on_changed_cb.try_run(());
                }
                Err(e) => error.set(Some(e.message)),
            }
            adding.set(None);
        });
    };

    // Adds the tenant's configured default owners in one click (additive — skips
    // any already present; never removes). Falls back to a hint if none are set.
    let adding_defaults = RwSignal::new(false);
    // Distinct from `error`: this one is not a failure the operator can retry,
    // it is a missing setting with a place to go, so it renders as a hint with
    // the route in it rather than as dead red text (`OwnerDefaultsHint`).
    let no_owner_defaults = RwSignal::new(false);
    let add_defaults = move |_| {
        if adding_defaults.get() {
            return;
        }
        adding_defaults.set(true);
        error.set(None);
        no_owner_defaults.set(false);
        let tenant = session.active_tenant.get();
        let object_id = detail.with_untracked(|d| d.application.id.clone());
        let existing: HashSet<String> =
            detail.with_untracked(|d| d.owners.iter().map(|o| o.id.clone()).collect());
        let on_changed_cb = on_changed;
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                adding_defaults.set(false);
                return;
            };
            let (added, failures) =
                match add_default_owners(&t.tenant_id, &object_id, Some(existing)).await {
                    DefaultOwnersOutcome::NoneConfigured => {
                        no_owner_defaults.set(true);
                        adding_defaults.set(false);
                        return;
                    }
                    DefaultOwnersOutcome::Done { added, failures } => (added, failures),
                };
            if let Some(msg) = DefaultOwnersOutcome::failure_message(&failures) {
                error.set(Some(msg));
            } else if added > 0 {
                session.toast_success(format!(
                    "Added {}.",
                    count_noun(added, "default owner", "default owners")
                ));
            } else {
                session.toast_success("Default owners are already present.");
            }
            on_changed_cb.try_run(());
            adding_defaults.set(false);
        });
    };

    let remove = move |principal_id: String| {
        if removing.get().is_some() {
            return;
        }
        removing.set(Some(principal_id.clone()));
        error.set(None);
        let tenant = session.active_tenant.get();
        let object_id = detail.with_untracked(|d| d.application.id.clone());
        let on_changed_cb = on_changed;
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                removing.set(None);
                return;
            };
            match applications::remove_application_owner(&t.tenant_id, &object_id, &principal_id)
                .await
            {
                Ok(()) => {
                    session.toast_success("Owner removed.");
                    on_changed_cb.try_run(());
                }
                Err(e) => error.set(Some(e.message)),
            }
            removing.set(None);
        });
    };

    let start_replace = move |_| {
        staged.set(detail.with_untracked(|d| d.owners.clone()));
        error.set(None);
        replacing.set(true);
    };

    let cancel_replace = move |_| {
        replacing.set(false);
        staged.set(Vec::new());
    };

    let stage = move |o: DirectoryObject| {
        staged.update(|s| {
            if !s.iter().any(|x| x.id == o.id) {
                s.push(o);
            }
        });
        raw_query.set(String::new());
    };

    let unstage = move |id: String| {
        staged.update(|s| s.retain(|x| x.id != id));
    };

    let apply_replace = move |_| {
        if applying.get() {
            return;
        }
        applying.set(true);
        error.set(None);
        let tenant = session.active_tenant.get();
        let object_id = detail.with_untracked(|d| d.application.id.clone());
        let ids: Vec<String> = staged
            .get_untracked()
            .iter()
            .map(|o| o.id.clone())
            .collect();
        // Map principal ids to display names so a partial failure can name the
        // principal instead of showing a bare count (removals come from the
        // current owner list, additions from the staged set).
        let mut names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        detail.with_untracked(|d| {
            for o in &d.owners {
                if let Some(n) = &o.display_name {
                    names.insert(o.id.clone(), n.clone());
                }
            }
        });
        for o in staged.get_untracked().iter() {
            if let Some(n) = &o.display_name {
                names.insert(o.id.clone(), n.clone());
            }
        }
        let on_changed_cb = on_changed;
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                applying.set(false);
                return;
            };
            match applications::set_application_owners(&t.tenant_id, &object_id, &ids).await {
                Ok(res) => {
                    replacing.set(false);
                    staged.set(Vec::new());
                    // A re-auth-fatal failure means the backend stopped the
                    // reconcile on a dead session: offer Re-authenticate.
                    if let Some(f) = res.failures.iter().find(|f| f.is_reauth_fatal()) {
                        session.report_if_session_dead(&azapptoolkit_dto::UiError::new(
                            f.code.clone(),
                            f.message.clone(),
                            false,
                        ));
                    }
                    if !res.failures.is_empty() {
                        let details = res
                            .failures
                            .iter()
                            .map(|f| {
                                let who = names
                                    .get(&f.principal_id)
                                    .cloned()
                                    .unwrap_or_else(|| f.principal_id.clone());
                                format!("{} {who}: {}", f.action, f.message)
                            })
                            .collect::<Vec<_>>()
                            .join("; ");
                        error.set(Some(format!(
                            "{} failed — {details}",
                            count_noun(res.failures.len(), "owner change", "owner changes")
                        )));
                    } else {
                        session.toast_success("Owners updated.");
                    }
                    on_changed_cb.try_run(());
                }
                Err(e) => {
                    session.report_if_session_dead(&e);
                    error.set(Some(e.message));
                }
            }
            applying.set(false);
        });
    };

    view! {
        <div class="owners-tab">
            <section>
                <div class="section-header">
                    <h3>
                        "Current owners (" {move || detail.with(|d| d.owners.len())} ")"
                    </h3>
                    <Show when=move || !replacing.get() fallback=|| view! { <></> }>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(start_replace)
                        >
                            "Replace all…"
                        </Button>
                    </Show>
                </div>
                {move || {
                    view! {
                        <DataTable
                            headers=vec!["Name", "UPN / Id", "Kind", ""]
                            rows=detail.with(|d| d.owners.clone())
                            empty_message="No owners. Anyone with Application Administrator rights can manage it."
                            row=move |o: DirectoryObject| {
                                let upn = o
                                    .user_principal_name
                                    .clone()
                                    .unwrap_or_else(|| o.id.clone());
                                let display = o.display_name.clone().unwrap_or_else(|| "—".into());
                                let kind = owner_kind(&o);
                                let id_disabled = o.id.clone();
                                let id_click = o.id.clone();
                                let id_label = o.id.clone();
                                // What the row shows, in the order it shows it: the
                                // display name, else the UPN the second column falls
                                // back to. Never the bare "—" placeholder.
                                let remove_label = o
                                    .display_name
                                    .clone()
                                    .or_else(|| o.user_principal_name.clone())
                                    .unwrap_or_default();
                                let remove_aria = if remove_label.is_empty() {
                                    format!("Remove owner {}", o.id)
                                } else {
                                    format!("Remove owner {remove_label}")
                                };
                                view! {
                                    <tr>
                                        <td>{display}</td>
                                        <td class="mono">{upn}</td>
                                        <td>{kind}</td>
                                        <td class="cell-mid">
                                            <Button
                                                class="button--danger"
                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                attr:aria-label=remove_aria
                                                disabled=Signal::derive(move || {
                                                    removing.with(|r| r.as_deref() == Some(id_disabled.as_str()))
                                                })
                                                on_click=Box::new(move |_| {
                                                    pending_remove
                                                        .set(Some((id_click.clone(), remove_label.clone())))
                                                })
                                            >
                                                {move || {
                                                    if removing.with(|r| r.as_deref() == Some(id_label.as_str())) {
                                                        view! {
                                                            <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                                        }
                                                            .into_any()
                                                    } else {
                                                        view! { "Remove" }.into_any()
                                                    }
                                                }}
                                            </Button>
                                        </td>
                                    </tr>
                                }
                                    .into_any()
                            }
                        />
                    }
                }}
            </section>
            <Show when=move || replacing.get() fallback=|| view! { <></> }>
                <section class="replace-owners">
                    <h3>"Target owner set (" {move || staged.with(|s| s.len())} ")"</h3>
                    <Body1>
                        "Apply sets the owners to exactly this list — any current owner not listed is removed."
                    </Body1>
                    {move || {
                        let items = staged.get();
                        if items.is_empty() {
                            view! {
                                <FormError>
                                    "No owners staged — applying would leave the app with no explicit owners."
                                </FormError>
                            }
                                .into_any()
                        } else {
                            view! {
                                <ul class="candidates">
                                    {items
                                        .into_iter()
                                        .map(|o| {
                                            let id = o.id.clone();
                                            let display = o
                                                .display_name
                                                .clone()
                                                .unwrap_or_else(|| o.id.clone());
                                            let unstage_aria = format!(
                                                "Remove {display} from the target owner set",
                                            );
                                            let upn = o
                                                .user_principal_name
                                                .clone()
                                                .unwrap_or_else(|| o.id.clone());
                                            view! {
                                                <li>
                                                    <div>
                                                        <div>{display}</div>
                                                        <div class="mono small">{upn}</div>
                                                    </div>
                                                    <Button
                                                        class="button--danger"
                                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                        attr:aria-label=unstage_aria
                                                        on_click=Box::new(move |_| unstage(id.clone()))
                                                    >
                                                        "Remove"
                                                    </Button>
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            }
                                .into_any()
                        }
                    }}
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            disabled=Signal::derive(move || applying.get())
                            on_click=Box::new(apply_replace)
                        >
                            {move || {
                                if applying.get() {
                                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                        .into_any()
                                } else {
                                    view! { "Apply — set as only owners" }.into_any()
                                }
                            }}
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(cancel_replace)
                        >
                            "Cancel"
                        </Button>
                    </div>
                </section>
            </Show>
            <section>
                <h3>
                    {move || if replacing.get() { "Add to target set" } else { "Add an owner" }}
                </h3>
                <Show when=move || !replacing.get() fallback=|| view! { <></> }>
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            disabled=Signal::derive(move || adding_defaults.get())
                            on_click=Box::new(add_defaults)
                        >
                            {move || {
                                if adding_defaults.get() {
                                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                        .into_any()
                                } else {
                                    view! { "Add Default Owners" }.into_any()
                                }
                            }}
                        </Button>
                    </div>
                </Show>
                // One instance per mode so the row action reads "Stage" or
                // "Add"; both share `raw_query`, so flipping mode keeps the text.
                {move || {
                    if replacing.get() {
                        view! {
                            <DirectorySearch
                                on_pick=Callback::new(move |u: DirectoryObject| stage(u))
                                exclude=exclude
                                query=raw_query
                                label="Search by display name or UPN (2+ chars)"
                                placeholder="alice@contoso.com"
                                action_label="Stage"
                                clear_on_pick=false
                            />
                        }
                            .into_any()
                    } else {
                        view! {
                            <DirectorySearch
                                on_pick=Callback::new(move |u: DirectoryObject| add(u.id))
                                exclude=exclude
                                query=raw_query
                                label="Search by display name or UPN (2+ chars)"
                                placeholder="alice@contoso.com"
                                clear_on_pick=false
                                row_disabled=Callback::new(move |id: String| {
                                    adding.with(|a| a.as_deref() == Some(id.as_str()))
                                })
                            />
                        }
                            .into_any()
                    }
                }}
            </section>
            {move || error.get().map(|e| view! { <FormError>{e}</FormError> })}
            <Show when=move || no_owner_defaults.get() fallback=|| ()>
                <OwnerDefaultsHint class="form-error" tab="app-reg" />
            </Show>
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this owner?"
                body="The owner loses the ability to manage this app registration. You can re-add them later."
                subject=Signal::derive(move || {
                    pending_remove.with(|p| p.as_ref().map(|(_, label)| label.clone())).unwrap_or_default()
                })
                confirm_label="Remove"
                busy=Signal::derive(move || removing.with(|r| r.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some((id, _)) = pending_remove.get() {
                        pending_remove.set(None);
                        remove(id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
        </div>
    }
}
