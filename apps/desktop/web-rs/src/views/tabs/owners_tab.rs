//! Owners tab. Lists current owners + lets you search and add. Mirrors
//! `apps/desktop/web/src/views/tabs/OwnersTab.tsx`.

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::applications::{self, ApplicationDetail};
use crate::components::ui::DataTable;
use crate::hooks::use_debounced::use_debounced;
use crate::state::use_session;
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
    #[prop(into)] detail: Signal<ApplicationDetail>,
    #[prop(into)] on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);
    let adding: RwSignal<Option<String>> = RwSignal::new(None);
    let removing: RwSignal<Option<String>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_remove: RwSignal<Option<String>> = RwSignal::new(None);
    // Replace-all-owners (ports `Set-AzAppOwner`): stage a target set, then
    // reconcile in one call.
    let replacing = RwSignal::new(false);
    let staged: RwSignal<Vec<DirectoryObject>> = RwSignal::new(Vec::new());
    let applying = RwSignal::new(false);

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
            // Carry the error message so a Graph/network failure shows up as an
            // error instead of being indistinguishable from "No matches."
            applications::search_users(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
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
                    on_changed_cb.run(());
                }
                Err(e) => error.set(Some(e.message)),
            }
            adding.set(None);
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
                    on_changed_cb.run(());
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
                            "{} owner change(s) failed — {details}",
                            res.failures.len()
                        )));
                    } else {
                        session.toast_success("Owners updated.");
                    }
                    on_changed_cb.run(());
                }
                Err(e) => error.set(Some(e.message)),
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
                                view! {
                                    <tr>
                                        <td>{display}</td>
                                        <td class="mono">{upn}</td>
                                        <td>{kind}</td>
                                        <td>
                                            <Button
                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                disabled=Signal::derive(move || {
                                                    removing.with(|r| r.as_deref() == Some(id_disabled.as_str()))
                                                })
                                                on_click=Box::new(move |_| {
                                                    pending_remove.set(Some(id_click.clone()))
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
                                <Body1 class="form-error">
                                    "No owners staged — applying would leave the app with no explicit owners."
                                </Body1>
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
                                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
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
                <Field label="Search by display name or UPN (2+ chars)">
                    <Input value=raw_query placeholder="alice@contoso.com" />
                </Field>
                <Suspense fallback=move || {
                    view! {
                        <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Searching…" />
                    }
                }>
                    {move || Suspend::new(async move {
                        let result = candidates.await;
                        let users = match result {
                            Ok(users) => users,
                            Err(msg) => {
                                return view! {
                                    <Body1 class="form-error">
                                        {format!("Search failed: {msg}")}
                                    </Body1>
                                }
                                    .into_any();
                            }
                        };
                        let exclude: std::collections::HashSet<String> = if replacing.get() {
                            staged.with(|s| s.iter().map(|o| o.id.clone()).collect())
                        } else {
                            detail.with(|d| d.owners.iter().map(|o| o.id.clone()).collect())
                        };
                        let filtered: Vec<DirectoryObject> = users
                            .into_iter()
                            .filter(|u| !exclude.contains(&u.id))
                            .collect();
                        if filtered.is_empty() {
                            return view! { <Body1>"No matches."</Body1> }.into_any();
                        }
                        view! {
                            <ul class="candidates">
                                {filtered
                                    .into_iter()
                                    .map(|u| {
                                        let id_disabled = u.id.clone();
                                        let id_click = u.id.clone();
                                        let id_label = u.id.clone();
                                        let u_stage = u.clone();
                                        let upn = u.user_principal_name.clone().unwrap_or_else(|| u.id.clone());
                                        let display = u.display_name.clone().unwrap_or_else(|| u.id.clone());
                                        view! {
                                            <li>
                                                <div>
                                                    <div>{display}</div>
                                                    <div class="mono small">{upn}</div>
                                                </div>
                                                <Button
                                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                    disabled=Signal::derive(move || {
                                                        !replacing.get()
                                                            && adding.with(|a| a.as_deref() == Some(id_disabled.as_str()))
                                                    })
                                                    on_click=Box::new(move |_| {
                                                        if replacing.get_untracked() {
                                                            stage(u_stage.clone());
                                                        } else {
                                                            add(id_click.clone());
                                                        }
                                                    })
                                                >
                                                    {move || {
                                                        if replacing.get() {
                                                            view! { "Stage" }.into_any()
                                                        } else if adding
                                                            .with(|a| a.as_deref() == Some(id_label.as_str()))
                                                        {
                                                            view! {
                                                                <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                                            }
                                                                .into_any()
                                                        } else {
                                                            view! { "Add" }.into_any()
                                                        }
                                                    }}
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
            </section>
            {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this owner?"
                body="The owner loses the ability to manage this app registration. You can re-add them later."
                confirm_label="Remove"
                busy=Signal::derive(move || removing.with(|r| r.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_remove.get() {
                        pending_remove.set(None);
                        remove(id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
        </div>
    }
}
