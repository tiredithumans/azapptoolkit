use super::*;

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
    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);
    let pending_remove: RwSignal<Option<String>> = RwSignal::new(None);

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
            applications::search_users(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
        }
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
                    on_refresh.run(());
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
                error.set(Some(
                    "No default owners configured — set them in Settings.".into(),
                ));
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
                    "{} default owner(s) failed — {}",
                    failures.len(),
                    failures.join("; ")
                )));
                adding_defaults.set(false);
            } else {
                session.toast_success(if added > 0 {
                    format!("Added {added} default owner(s).")
                } else {
                    "Default owners are already present.".to_string()
                });
                // Reloads the detail (refetches owners) and tears this down.
                on_refresh.run(());
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
                                <div class="alert alert--warn">
                                    "No owners assigned — no one is accountable for this enterprise application. Only Application Administrators can manage it."
                                </div>
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
                                view! {
                                    <li>
                                        <div>
                                            <div>{name}</div>
                                            <div class="mono small">{sub}</div>
                                        </div>
                                        <Button
                                            class="button--danger"
                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                            disabled=Signal::derive(move || {
                                                busy.with(|b| b.as_deref() == Some(id_busy.as_str()))
                                            })
                                            on_click=Box::new(move |_| {
                                                pending_remove.set(Some(id_click.clone()))
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
            <Field label="Search users by name or UPN (2+ chars)">
                <Input value=raw_query placeholder="alice@contoso.com" />
            </Field>
            {move || {
                if raw_query.get().trim().len() < 2 {
                    return ().into_any();
                }
                view! {
                    <Suspense fallback=move || {
                        view! {
                            <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Searching…" />
                        }
                    }>
                        {move || Suspend::new(async move {
                            match candidates.await {
                                Err(msg) => {
                                    view! {
                                        <Body1 class="app-detail__error">
                                            {format!("Search failed: {msg}")}
                                        </Body1>
                                    }
                                        .into_any()
                                }
                                Ok(users) => {
                                    let existing: std::collections::HashSet<String> = signal
                                        .with_untracked(|d| {
                                            d.owners.iter().map(|o| o.id.clone()).collect()
                                        });
                                    let filtered: Vec<DirectoryObject> = users
                                        .into_iter()
                                        .filter(|u| !existing.contains(&u.id))
                                        .collect();
                                    if filtered.is_empty() {
                                        return view! { <Body1>"No matches."</Body1> }.into_any();
                                    }
                                    view! {
                                        <ul class="candidates">
                                            {filtered
                                                .into_iter()
                                                .map(|u| {
                                                    let id_click = u.id.clone();
                                                    let id_busy = u.id.clone();
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
                                                                disabled=Signal::derive(move || {
                                                                    busy.with(|b| b.as_deref() == Some(id_busy.as_str()))
                                                                })
                                                                on_click=Box::new(move |_| {
                                                                    mutate(true, id_click.clone())
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
                                }
                            }
                        })}
                    </Suspense>
                }
                    .into_any()
            }}
            {move || error.get().map(|e| view! { <Body1 class="app-detail__error">{e}</Body1> })}
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this owner?"
                body="The owner loses the ability to manage this enterprise application. You can re-add them later."
                confirm_label="Remove"
                busy=Signal::derive(move || busy.with(|b| b.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_remove.get() {
                        pending_remove.set(None);
                        mutate(false, id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
        </div>
    }
}
