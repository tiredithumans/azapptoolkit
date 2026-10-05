use super::*;
use crate::components::tenant_defaults_hint::OwnerDefaultsHint;
use crate::components::ui::Callout;
use crate::util::count_noun;

/// Owners tab — lists current owners and lets you add/remove them. Only **users**
/// can own a service principal (Graph rejects groups), so the search targets
/// users only. An owner can manage this app's SSO, provisioning, and user
/// assignments. Mutations bump the detail `on_refresh` so the owners list
/// refetches.
#[component]
pub(super) fn OwnersContent(
    signal: Signal<Arc<EnterpriseApplicationDetail>>,
    #[prop(into)] on_refresh: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));

    // The principal id currently being added/removed (drives per-row disabling).
    let busy: RwSignal<Option<String>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    // (owner id, name): one dialog covers a list of owners, so the row's name is
    // staged with the id purely to be the dialog's subject, then discarded there.
    let pending_remove: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    // Distinct from `error`: this one is not a failure the operator can retry,
    // it is a missing setting with a place to go, so it renders as a hint with
    // the route in it rather than as dead red text (`OwnerDefaultsHint`).
    let no_owner_defaults = RwSignal::new(false);

    // Already-owners are hidden from the search so they can't be added twice.
    let existing_owner_ids = Signal::derive(move || {
        signal.with(|d| {
            d.owners
                .iter()
                .map(|o| o.id.clone())
                .collect::<HashSet<String>>()
        })
    });

    let mutate = move |add: bool, principal_id: String| {
        if busy.get().is_some() {
            return;
        }
        busy.set(Some(principal_id.clone()));
        error.set(None);
        let tenant = tenant.get();
        let sp = sp_id.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(None);
                return;
            };
            let result = if add {
                enterprise_application::add_enterprise_app_owner(&t.tenant_id, &sp, &principal_id)
                    .await
            } else {
                enterprise_application::remove_enterprise_app_owner(
                    &t.tenant_id,
                    &sp,
                    &principal_id,
                )
                .await
            };
            match result {
                Ok(()) => {
                    session.toast_success(if add {
                        "Owner added."
                    } else {
                        "Owner removed."
                    });
                    // Reloads the detail (refetches owners) and tears this
                    // component down — do it last and skip resetting `busy`.
                    on_refresh.try_run(());
                }
                Err(e) => {
                    error.set(Some(e.message));
                    busy.set(None);
                }
            }
        });
    };

    // Adds the tenant's configured default owners in one click (additive — skips
    // any already present). Enterprise-app owners are users only.
    let adding_defaults = RwSignal::new(false);
    let add_defaults = move |_| {
        if adding_defaults.get() {
            return;
        }
        adding_defaults.set(true);
        error.set(None);
        no_owner_defaults.set(false);
        let tenant_v = tenant.get();
        let sp = sp_id.get();
        let existing: std::collections::HashSet<String> =
            signal.with_untracked(|d| d.owners.iter().map(|o| o.id.clone()).collect());
        leptos::task::spawn_local(async move {
            let Some(t) = tenant_v else {
                adding_defaults.set(false);
                return;
            };
            let defaults = crate::bindings::defaults::get_tenant_defaults(&t.tenant_id).await;
            let owners = defaults.enterprise_application.default_owners;
            if owners.is_empty() {
                no_owner_defaults.set(true);
                adding_defaults.set(false);
                return;
            }
            let mut added = 0usize;
            let mut failures = Vec::new();
            for p in owners {
                if existing.contains(&p.id) {
                    continue;
                }
                match enterprise_application::add_enterprise_app_owner(&t.tenant_id, &sp, &p.id)
                    .await
                {
                    Ok(()) => added += 1,
                    Err(e) => {
                        failures.push(format!("{}: {}", p.display_name.unwrap_or(p.id), e.message))
                    }
                }
            }
            if !failures.is_empty() {
                error.set(Some(format!(
                    "{} failed — {}",
                    count_noun(failures.len(), "default owner", "default owners"),
                    failures.join("; ")
                )));
                adding_defaults.set(false);
            } else {
                session.toast_success(if added > 0 {
                    format!(
                        "Added {}.",
                        count_noun(added, "default owner", "default owners")
                    )
                } else {
                    "Default owners are already present.".to_string()
                });
                // Reloads the detail (refetches owners) and tears this down.
                on_refresh.try_run(());
            }
        });
    };

    view! {
        <div class="ent-owners">
            {move || {
                let owners = signal.with(|d| d.owners.clone());
                let empty = owners.is_empty();
                view! {
                    <h4>"Owners (" {owners.len()} ")"</h4>
                    {empty
                        .then(|| {
                            view! {
                                <Callout tone="warn">
                                    "No owners assigned — no one is accountable for this enterprise application. Only Application Administrators can manage it."
                                </Callout>
                            }
                        })}
                    <ul class="candidates">
                        {owners
                            .into_iter()
                            .map(|o| {
                                let name = o.display_name.clone().unwrap_or_else(|| o.id.clone());
                                let sub = o
                                    .user_principal_name
                                    .clone()
                                    .unwrap_or_else(|| o.id.clone());
                                let id_click = o.id.clone();
                                let id_busy = o.id.clone();
                                let name_click = name.clone();
                                let remove_aria = format!("Remove owner {name}");
                                view! {
                                    <li>
                                        <div>
                                            <div>{name}</div>
                                            <div class="mono small">{sub}</div>
                                        </div>
                                        <Button
                                            class="button--danger"
                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                            attr:aria-label=remove_aria
                                            disabled=Signal::derive(move || {
                                                busy.with(|b| b.as_deref() == Some(id_busy.as_str()))
                                            })
                                            on_click=Box::new(move |_| {
                                                pending_remove
                                                    .set(Some((id_click.clone(), name_click.clone())))
                                            })
                                        >
                                            "Remove"
                                        </Button>
                                    </li>
                                }
                            })
                            .collect_view()}
                    </ul>
                }
            }}

            <h4>"Add an owner"</h4>
            <p class="muted">
                "Only users can own a service principal. An owner can manage this app's single sign-on, provisioning, and user assignments."
            </p>
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
            // The same debounced directory search the Access tab and the
            // Settings owner editors use; a successful add reloads the detail
            // (tearing this down), so the box needs no clear-on-success.
            <DirectorySearch
                on_pick=Callback::new(move |u: DirectoryObject| mutate(true, u.id))
                exclude=existing_owner_ids
                label="Search users by name or UPN (2+ chars)"
                placeholder="alice@contoso.com"
                clear_on_pick=false
                row_disabled=Callback::new(move |id: String| {
                    busy.with(|b| b.as_deref() == Some(id.as_str()))
                })
            />
            {move || error.get().map(|e| view! { <Body1 class="app-detail__error">{e}</Body1> })}
            <Show when=move || no_owner_defaults.get() fallback=|| ()>
                <OwnerDefaultsHint class="app-detail__error" tab="enterprise" />
            </Show>
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this owner?"
                body="The owner loses the ability to manage this enterprise application. You can re-add them later."
                subject=Signal::derive(move || {
                    pending_remove.with(|p| p.as_ref().map(|(_, name)| name.clone())).unwrap_or_default()
                })
                confirm_label="Remove"
                busy=Signal::derive(move || busy.with(|b| b.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some((id, _)) = pending_remove.get() {
                        pending_remove.set(None);
                        mutate(false, id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
        </div>
    }
}
