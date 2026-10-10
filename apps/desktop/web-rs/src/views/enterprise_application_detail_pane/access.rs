use super::*;
use crate::components::ui::{Callout, FormError, SearchInput};
use crate::constants::LIST_FILTER_DEBOUNCE_MS;
use crate::util::contains_ignore_case;
use azapptoolkit_core::models::AppRole;
use enterprise_application::AppAssignmentDto;

#[component]
pub fn AccessContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));

    // Bumped after assign/remove to refetch the assignment list.
    let reload = RwSignal::new(0_u32);
    // The principal id or assignment id currently being processed.
    let busy: RwSignal<Option<String>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let selected_role = RwSignal::new(DEFAULT_ACCESS_ROLE.to_string());
    // Owned here (not by `DirectorySearch`) purely so the mutation handlers
    // can clear the box after a successful round trip.
    let raw_query = RwSignal::new(String::new());
    // Both stage (id, name). The two dialogs are mounted once and cover the row
    // or search hit they were opened from, so the name rides along purely to be
    // the dialog's subject and is discarded there.
    let pending_remove: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let pending_assign: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    // Which directory object type the search targets ("users" or "groups").
    let principal_kind = RwSignal::new(String::from("users"));

    let assignments = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = sp_id.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => {
                    enterprise_application::list_enterprise_app_assignments(&t.tenant_id, &id).await
                }
                None => Ok(Vec::new()),
            }
        }
    });

    // Principals already holding the SELECTED role, hidden from the search so
    // they can't be assigned it twice (Graph rejects only a duplicate
    // principal + role pair, so someone on another role stays pickable). Read
    // here, outside the Suspend below — a signal write inside that render loops.
    let exclude = Signal::derive(move || {
        let role = selected_role.get();
        assignments.with(|r| match r {
            Some(Ok(list)) => assigned_to_role(list, &role),
            _ => HashSet::new(),
        })
    });

    // Client-side filter over the loaded assignments. Component-local, not on
    // `Session.tenant_ui`: the pane unmounts on a tenant switch.
    let filter = RwSignal::new(String::new());
    let filter_q = use_debounced(filter.into(), LIST_FILTER_DEBOUNCE_MS);

    // Switching between Users and Groups clears the query. `candidates` already
    // re-runs on `principal_kind`, so this is not for correctness — it is the
    // behaviour the two buttons carried inline before they became a `TabBar`,
    // which can only write the one signal it is bound to. Searching the group
    // directory for a half-typed person's name returns nothing useful, so the
    // box starts clean.
    Effect::new(move |prev: Option<String>| {
        let kind = principal_kind.get();
        // Skip the first run: it would clear a query the user may have arrived
        // with, and there is nothing to reset on mount anyway.
        if prev.is_some_and(|p| p != kind) {
            raw_query.set(String::new());
        }
        kind
    });

    let assign = move |principal_id: String| {
        if busy.get().is_some() {
            return;
        }
        busy.set(Some(principal_id.clone()));
        error.set(None);
        let tenant = tenant.get();
        let sp = sp_id.get();
        let role = selected_role.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(None);
                return;
            };
            let res = enterprise_application::assign_enterprise_app_access(
                &t.tenant_id,
                &sp,
                &principal_id,
                &role,
            )
            .await;
            // Sign-out mid-assign: the toast would surface at the next sign-in.
            if !session.is_active_tenant(&t.tenant_id) {
                busy.set(None);
                return;
            }
            match res {
                Ok(()) => {
                    raw_query.set(String::new());
                    session.toast_success("Access granted.");
                    reload.update(|n| *n += 1);
                }
                Err(e) => session.fail_inline(&e, "write", error),
            }
            busy.set(None);
        });
    };

    let remove = move |assignment_id: String| {
        if busy.get().is_some() {
            return;
        }
        busy.set(Some(assignment_id.clone()));
        error.set(None);
        let tenant = tenant.get();
        let sp = sp_id.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(None);
                return;
            };
            let res = enterprise_application::remove_enterprise_app_access(
                &t.tenant_id,
                &sp,
                &assignment_id,
            )
            .await;
            if !session.is_active_tenant(&t.tenant_id) {
                busy.set(None);
                return;
            }
            match res {
                Ok(()) => {
                    session.toast_success("Access removed.");
                    reload.update(|n| *n += 1);
                }
                Err(e) => session.fail_inline(&e, "write", error),
            }
            busy.set(None);
        });
    };

    // App roles are stable once the detail is loaded (which is the case when
    // this tab renders), so snapshot them untracked for the role picker + the
    // assignment-row role resolution.
    let role_options = signal.with_untracked(|d| d.service_principal.app_roles.clone());

    view! {
        <div class="ent-access">
            <h4>"Assigned users & groups"</h4>
            <SearchInput value=filter placeholder="Filter by name, type, or role…" />
            <Suspense fallback=move || {
                view! { <SkeletonList rows=6 /> }
            }>
                {move || {
                    let roles = signal.with_untracked(|d| d.service_principal.app_roles.clone());
                    Suspend::new(async move {
                        match assignments.await {
                            Ok(list) => {
                                let empty = if list.is_empty() {
                                    "No users or groups are assigned to this application."
                                } else {
                                    "No assignments match the filter."
                                };
                                // Stored so the filter closure below re-reads them per
                                // keystroke without cloning the whole set each render.
                                let list = StoredValue::new(list);
                                let roles = StoredValue::new(roles);
                                // DataTable takes its rows by value, so a reactive
                                // caller rebuilds it inside its own `move ||`.
                                let table = move || {
                                    let needle = filter_q.get().trim().to_lowercase();
                                    let rows: Vec<AppAssignmentDto> = list
                                        .with_value(|l| {
                                            roles
                                                .with_value(|rs| {
                                                    l.iter()
                                                        .filter(|a| {
                                                            assignment_matches(
                                                                a,
                                                                &resolve_role(rs, &a.app_role_id),
                                                                &needle,
                                                            )
                                                        })
                                                        .cloned()
                                                        .collect()
                                                })
                                        });
                                    view! {
                                        <DataTable
                                            headers=vec!["Principal", "Type", "Role", ""]
                                            rows=rows
                                            empty_message=empty
                                            row=move |a: AppAssignmentDto| {
                                                let principal = a
                                                    .principal_display_name
                                                    .clone()
                                                    .unwrap_or_else(|| "—".into());
                                                let ptype = a
                                                    .principal_type
                                                    .clone()
                                                    .unwrap_or_else(|| "—".into());
                                                let role = roles
                                                    .with_value(|rs| resolve_role(rs, &a.app_role_id));
                                                let aid_click = a.assignment_id.clone();
                                                let aid_busy = a.assignment_id.clone();
                                                // The Principal cell, staged for the dialog's subject.
                                                // A nameless assignment stages nothing rather than the
                                                // "—" placeholder, which would name no one.
                                                let principal_label = a
                                                    .principal_display_name
                                                    .clone()
                                                    .unwrap_or_default();
                                                // The row's accessible name: who, and in which
                                                // role (one principal can hold several).
                                                let remove_aria = format!(
                                                    "Remove {} ({role})",
                                                    if principal_label.is_empty() {
                                                        a.principal_id.as_str()
                                                    } else {
                                                        principal_label.as_str()
                                                    },
                                                );
                                                view! {
                                                    <tr>
                                                        <td class="cell-mid">{principal}</td>
                                                        <td class="cell-mid">{ptype}</td>
                                                        <td class="cell-mid">{role}</td>
                                                        <td class="cell-mid">
                                                            <Button
                                                                class="button--danger"
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                attr:aria-label=remove_aria
                                                                disabled=Signal::derive(move || {
                                                                    busy.with(|b| b.as_deref() == Some(aid_busy.as_str()))
                                                                })
                                                                on_click=Box::new(move |_| {
                                                                    pending_remove
                                                                        .set(
                                                                            Some((aid_click.clone(), principal_label.clone())),
                                                                        )
                                                                })
                                                            >
                                                                "Remove"
                                                            </Button>
                                                        </td>
                                                    </tr>
                                                }
                                                    .into_any()
                                            }
                                        />
                                    }
                                };
                                view! { {table} }.into_any()
                            }
                            Err(e) => {
                                view! {
                                    <DetailLoadError
                                        error=e
                                        on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                    />
                                }
                                    .into_any()
                            }
                        }
                    })
                }}
            </Suspense>

            <h4>"Grant access"</h4>
            <Field label="Role">
                <select
                    class="ui-select"
                    on:change=move |ev| selected_role.set(event_target_value(&ev))
                >
                    <option value=DEFAULT_ACCESS_ROLE>"Default access"</option>
                    {role_options
                        .into_iter()
                        .filter(|r| r.is_enabled.unwrap_or(true))
                        .map(|r| {
                            let label = if r.display_name.is_empty() {
                                r.value.clone()
                            } else {
                                r.display_name.clone()
                            };
                            // An Application-only role is listed (so it stays
                            // discoverable) but unpickable: Graph rejects it for a
                            // user or group, and only after the confirm dialog.
                            let ok = assignable_to_users_and_groups(&r);
                            let label = if ok { label } else { format!("{label} (applications only)") };
                            view! {
                                <option value=r.id.clone() disabled=!ok>
                                    {label}
                                </option>
                            }
                        })
                        .collect_view()}
                </select>
            </Field>
            // The same `TabBar` the permission picker uses for its
            // Application/Delegated choice — this is the identical shape
            // (pick which KIND of thing the list below searches), so it takes
            // the same primitive rather than a second hand-rolled pair of
            // buttons whose "selected" state was a Primary appearance.
            <TabBar
                items=vec![
                    TabBarItem { value: "users", label: "Users" },
                    TabBarItem { value: "groups", label: "Groups" },
                ]
                selected=principal_kind
            />
            // The same debounced directory search the Settings owner editors and
            // the Exchange group typeahead use. `query` is handed in and
            // `clear_on_pick=false` because this flow is asynchronous: picking
            // only stages the confirm dialog, and `assign` clears the box once
            // the round trip returns `Ok`.
            <DirectorySearch
                scope=Signal::derive(move || {
                    if principal_kind.get() == "groups" {
                        DirectoryScope::Groups
                    } else {
                        DirectoryScope::Users
                    }
                })
                on_pick=Callback::new(move |o: DirectoryObject| {
                    // The results list is covered by the modal, so the picked
                    // principal's name goes with the id to be its subject.
                    let label = o
                        .display_name
                        .clone()
                        .or_else(|| o.user_principal_name.clone())
                        .unwrap_or_default();
                    pending_assign.set(Some((o.id, label)));
                })
                exclude=exclude
                query=raw_query
                clear_on_pick=false
                label="Search by name (2+ chars)"
                action_label="Assign"
                row_disabled=Callback::new(move |id: String| {
                    busy.with(|b| b.as_deref() == Some(id.as_str()))
                })
            />

            {move || error.get().map(|e| view! { <FormError>{e}</FormError> })}
            <GroupMembershipSection sp_id=sp_id />
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this assignment?"
                body="The principal loses access to this enterprise application. You can re-assign them later."
                subject=Signal::derive(move || {
                    pending_remove.with(|p| p.as_ref().map(|(_, name)| name.clone())).unwrap_or_default()
                })
                confirm_label="Remove"
                busy=Signal::derive(move || busy.with(|b| b.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some((id, _)) = pending_remove.get() {
                        pending_remove.set(None);
                        remove(id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
            <ConfirmDialog
                open=Signal::derive(move || pending_assign.with(|p| p.is_some()))
                title="Grant access?"
                body="Assigns the selected principal to this enterprise application's chosen role. They gain access immediately."
                subject=Signal::derive(move || {
                    pending_assign.with(|p| p.as_ref().map(|(_, name)| name.clone())).unwrap_or_default()
                })
                confirm_label="Grant"
                busy=Signal::derive(move || busy.with(|b| b.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some((id, _)) = pending_assign.get() {
                        pending_assign.set(None);
                        assign(id);
                    }
                })
                on_close=Callback::new(move |()| pending_assign.set(None))
            />
        </div>
    }
}

/// Friendly kind label for a group row. `Unified` = Microsoft 365 group;
/// otherwise `securityEnabled` separates security from distribution groups.
/// Dynamic-membership groups are flagged — Graph rejects direct member changes
/// on them, so the UI also hides their Remove button.
fn group_type_label(security_enabled: Option<bool>, group_types: &[String]) -> String {
    let base = if group_types.iter().any(|t| t == "Unified") {
        "Microsoft 365"
    } else if security_enabled == Some(true) {
        "Security"
    } else {
        "Distribution"
    };
    if group_types.iter().any(|t| t == "DynamicMembership") {
        format!("{base} · Dynamic")
    } else {
        base.to_string()
    }
}

/// "Group memberships" — the outbound half of the Access tab: the groups this
/// service principal belongs to (the assignments table above is the inbound
/// half). Group-gated APIs — e.g. Power BI's "Service principals can use
/// Fabric APIs" tenant setting — grant API access via security-group
/// membership, so integrations routinely need the SP added to a group right
/// after creation. Writes ride the on-demand `GroupMember.ReadWrite.All`
/// scope; a `consent_required` failure stashes the attempted change and offers
/// "Grant consent & retry" (mirroring the SharePoint site access section's
/// consent affordance).
#[component]
fn GroupMembershipSection(#[prop(into)] sp_id: Signal<String>) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // Bumped after add/remove to refetch the membership list.
    let reload = RwSignal::new(0_u32);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<azapptoolkit_dto::UiError>> = RwSignal::new(None);
    // The (add?, group_id) change that hit `consent_required` — replayed after
    // a successful interactive grant so the user doesn't re-pick the group.
    let retry_op: RwSignal<Option<(bool, String)>> = RwSignal::new(None);
    let consenting = RwSignal::new(false);
    // Groups awaiting dialog confirmation, staged as (id, name): the id drives
    // the mutation, the name is the dialog's subject and is discarded there.
    let pending_add: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let pending_remove: RwSignal<Option<(String, String)>> = RwSignal::new(None);

    // Owned here (not by `DirectorySearch`) purely so the mutation handlers
    // can clear the box after a successful round trip.
    let raw_query = RwSignal::new(String::new());

    let memberships = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = sp_id.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => {
                    enterprise_application::list_sp_group_memberships(&t.tenant_id, &id).await
                }
                None => Ok(Vec::new()),
            }
        }
    });

    // Single mutation path for add + remove so the consent flow can replay
    // whichever change was rejected.
    let mutate = move |add: bool, group_id: String| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let tenant = tenant.get();
        let sp = sp_id.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            let result = if add {
                enterprise_application::add_sp_to_group(&t.tenant_id, &group_id, &sp).await
            } else {
                enterprise_application::remove_sp_from_group(&t.tenant_id, &group_id, &sp).await
            };
            if !session.is_active_tenant(&t.tenant_id) {
                busy.set(false);
                return;
            }
            match result {
                Ok(()) => {
                    retry_op.set(None);
                    raw_query.set(String::new());
                    session.toast_success(if add {
                        "Added to group."
                    } else {
                        "Removed from group."
                    });
                    reload.update(|n| *n += 1);
                }
                Err(e) => {
                    if e.is_consent_required() {
                        // This section's own "Grant consent & retry" covers it.
                        retry_op.set(Some((add, group_id)));
                    } else {
                        // A dead session or rejected token needs the sink's
                        // lever; the typed error below keeps the text.
                        session.report_recovery_action(&e, "group_membership");
                    }
                    error.set(Some(e));
                }
            }
            busy.set(false);
        });
    };

    let on_consent = move |_| {
        if consenting.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        consenting.set(true);
        leptos::task::spawn_local(async move {
            let res = auth::request_scope_consent(&t.tenant_id, "group_membership").await;
            // The consent round trip is a browser prompt answered minutes
            // later, perhaps after the pane closed or a sign-out: `retry_op`
            // is disposed then, and `mutate` reads `busy` — both panic once
            // disposed — and the replay would run for another session.
            if consenting.is_disposed() || !session.is_active_tenant(&t.tenant_id) {
                return;
            }
            match res {
                Ok(()) => {
                    error.set(None);
                    if let Some((add, group_id)) = retry_op.try_get_untracked().flatten() {
                        retry_op.set(None);
                        mutate(add, group_id);
                    }
                }
                Err(e) => error.set(Some(e)),
            }
            consenting.set(false);
        });
    };

    view! {
        <header class="row-between">
            <div class="row">
                <strong>"Group memberships"</strong>
                <RequiresRole capability_key="group_membership" />
            </div>
        </header>
        <p class="muted">
            "Groups this service principal is a direct member of. Group-gated APIs — e.g. Power BI's \"Service principals can use Fabric APIs\" tenant setting — grant API access via security-group membership."
        </p>
        <Suspense fallback=move || {
            view! { <SkeletonList rows=4 /> }
        }>
            {move || Suspend::new(async move {
                match memberships.await {
                    Ok(list) => {
                        view! {
                            <DataTable
                                headers=vec!["Group", "Type", ""]
                                rows=list
                                empty_message="This service principal is not a member of any group."
                                row=move |g: enterprise_application::GroupMembershipDto| {
                                    let type_label = group_type_label(
                                        g.security_enabled,
                                        &g.group_types,
                                    );
                                    let dynamic = g
                                        .group_types
                                        .iter()
                                        .any(|t| t == "DynamicMembership");
                                    let gid = g.id.clone();
                                    // Two rows can differ only by group, and the
                                    // modal covers them both — so the name goes
                                    // with the id to be the dialog's subject.
                                    let gname = g.display_name.clone();
                                    let remove_aria = format!("Remove group {}", g.display_name);
                                    view! {
                                        <tr>
                                            // Two-line identity cell: stays top-aligned
                                            // per `.cell-mid`'s carve-out — the name should
                                            // start where you read it, and only the control
                                            // columns centre against it.
                                            <td>
                                                <div>{g.display_name.clone()}</div>
                                                <div class="mono small">{g.id.clone()}</div>
                                            </td>
                                            <td class="cell-mid">{type_label}</td>
                                            <td class="cell-mid">
                                                {(!dynamic)
                                                    .then(|| {
                                                        view! {
                                                            <Button
                                                                class="button--danger"
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                disabled=Signal::derive(move || busy.get())
                                                                attr:aria-label=remove_aria
                                                                on_click=Box::new(move |_| {
                                                                    pending_remove
                                                                        .set(Some((gid.clone(), gname.clone())))
                                                                })
                                                            >
                                                                "Remove"
                                                            </Button>
                                                        }
                                                    })}
                                            </td>
                                        </tr>
                                    }
                                        .into_any()
                                }
                            />
                        }
                            .into_any()
                    }
                    Err(e) => {
                        view! {
                            <DetailLoadError
                                error=e
                                on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                            />
                        }
                            .into_any()
                    }
                }
            })}
        </Suspense>
        // Same primitive as the assignments block above, group-scoped. Adding a
        // membership also stages a confirm dialog, so the box is cleared by the
        // mutation, not by the pick.
        <DirectorySearch
            scope=Signal::derive(|| DirectoryScope::Groups)
            on_pick=Callback::new(move |g: DirectoryObject| {
                let label = g.display_name.clone().unwrap_or_default();
                pending_add.set(Some((g.id, label)));
            })
            query=raw_query
            clear_on_pick=false
            label="Add to group (search by name, 2+ chars)"
            placeholder="Search groups…"
            row_disabled=Callback::new(move |_id: String| busy.get())
        />
        {move || {
            error
                .get()
                .map(|e| {
                    if e.is_consent_required() {
                        view! {
                            <Callout tone="warn">
                                <Body1>
                                    {format!("Group membership changes need consent — {}", e.message)}
                                </Body1>
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(on_consent)
                                        disabled=Signal::derive(move || consenting.get())
                                    >
                                        "Grant consent & retry"
                                    </Button>
                                </div>
                            </Callout>
                        }
                            .into_any()
                    } else {
                        view! { <FormError>{e.message}</FormError> }.into_any()
                    }
                })
        }}
        <ConfirmDialog
            open=Signal::derive(move || pending_add.with(|p| p.is_some()))
            title="Add to this group?"
            body="The service principal becomes a member immediately and gains whatever access the group is granted — including group-gated API settings (e.g. Power BI tenant settings scoped to the group)."
            subject=Signal::derive(move || {
                pending_add.with(|p| p.as_ref().map(|(_, name)| name.clone())).unwrap_or_default()
            })
            confirm_label="Add"
            busy=Signal::derive(move || busy.get())
            on_confirm=Callback::new(move |()| {
                if let Some((id, _)) = pending_add.get() {
                    pending_add.set(None);
                    mutate(true, id);
                }
            })
            on_close=Callback::new(move |()| pending_add.set(None))
        />
        <ConfirmDialog
            open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
            title="Remove from this group?"
            body="The service principal loses any access granted via this group — for group-gated APIs (e.g. Power BI) that can break the integration immediately."
            subject=Signal::derive(move || {
                pending_remove.with(|p| p.as_ref().map(|(_, name)| name.clone())).unwrap_or_default()
            })
            confirm_label="Remove"
            busy=Signal::derive(move || busy.get())
            on_confirm=Callback::new(move |()| {
                if let Some((id, _)) = pending_remove.get() {
                    pending_remove.set(None);
                    mutate(false, id);
                }
            })
            on_close=Callback::new(move |()| pending_remove.set(None))
        />
    }
}

/// Resolves an `appRoleId` to a friendly name against the SP's defined roles.
/// The all-zero GUID is Entra's "default access" assignment (no specific role).
fn resolve_role(roles: &[azapptoolkit_core::models::AppRole], id: &str) -> String {
    if id.chars().all(|c| c == '0' || c == '-') {
        return "Default access".to_string();
    }
    roles
        .iter()
        .find(|r| r.id == id)
        .map(|r| {
            if r.display_name.is_empty() {
                r.value.clone()
            } else {
                r.display_name.clone()
            }
        })
        .unwrap_or_else(|| id.to_string())
}

/// Principals already holding `role_id` — Graph rejects only a duplicate
/// (principal, role) pair, so a principal on another role stays pickable.
fn assigned_to_role(list: &[AppAssignmentDto], role_id: &str) -> HashSet<String> {
    list.iter()
        .filter(|a| a.app_role_id.eq_ignore_ascii_case(role_id))
        .map(|a| a.principal_id.clone())
        .collect()
}

/// The Access tab's client-side filter over name / type / resolved role name.
/// `needle_lower` is already lowercased (once per keystroke).
fn assignment_matches(a: &AppAssignmentDto, role_name: &str, needle_lower: &str) -> bool {
    needle_lower.is_empty()
        || a.principal_display_name
            .as_deref()
            .is_some_and(|n| contains_ignore_case(n, needle_lower))
        || a.principal_type
            .as_deref()
            .is_some_and(|t| contains_ignore_case(t, needle_lower))
        || contains_ignore_case(role_name, needle_lower)
}

/// Roles a user or group can hold. Graph's `User` member type covers groups
/// too; an empty list is unknown and left for Graph to judge (the permission
/// picker's stance).
fn assignable_to_users_and_groups(r: &AppRole) -> bool {
    r.allowed_member_types.is_empty()
        || r.allowed_member_types
            .iter()
            .any(|t| t.eq_ignore_ascii_case("User"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use azapptoolkit_core::models::AppRole;
    use azapptoolkit_dto::enterprise_application::AppAssignmentDto;

    use super::{
        assignable_to_users_and_groups, assigned_to_role, assignment_matches, group_type_label,
    };

    const DEFAULT: &str = "00000000-0000-0000-0000-000000000000";

    fn assignment(principal: &str, name: &str, ptype: &str, role: &str) -> AppAssignmentDto {
        AppAssignmentDto {
            assignment_id: format!("assign:{principal}:{role}"),
            principal_id: principal.to_string(),
            principal_display_name: Some(name.to_string()),
            principal_type: Some(ptype.to_string()),
            app_role_id: role.to_string(),
        }
    }

    fn set(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn assigned_to_role_keys_on_principal_and_role() {
        let list = vec![
            assignment("p1", "Alice", "User", "role-a"),
            assignment("p1", "Alice", "User", DEFAULT),
            assignment("p2", "Finance", "Group", "role-b"),
        ];
        assert_eq!(assigned_to_role(&list, "role-a"), set(&["p1"]));
        assert_eq!(assigned_to_role(&list, DEFAULT), set(&["p1"]));
        // p1 holds other roles but not B, so it stays pickable for B.
        assert_eq!(assigned_to_role(&list, "role-b"), set(&["p2"]));
        assert!(assigned_to_role(&list, "role-c").is_empty());
        // Role ids are GUIDs; case must not matter.
        assert_eq!(assigned_to_role(&list, "ROLE-A"), set(&["p1"]));
    }

    #[test]
    fn assignment_matches_name_type_and_role() {
        let a = assignment("p2", "Finance Team", "Group", "role-b");
        assert!(assignment_matches(&a, "Approver", ""));
        assert!(assignment_matches(&a, "Approver", "finance"));
        assert!(assignment_matches(&a, "Approver", "group"));
        assert!(assignment_matches(&a, "Approver", "approv"));
        assert!(!assignment_matches(&a, "Approver", "zzz-nothing"));
    }

    #[test]
    fn assignable_to_users_and_groups_predicate() {
        let role = |types: &[&str]| AppRole {
            allowed_member_types: types.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        assert!(assignable_to_users_and_groups(&role(&["User"])));
        assert!(assignable_to_users_and_groups(&role(&[
            "User",
            "Application"
        ])));
        assert!(!assignable_to_users_and_groups(&role(&["Application"])));
        // Unknown member types: left for Graph to judge.
        assert!(assignable_to_users_and_groups(&role(&[])));
        assert!(assignable_to_users_and_groups(&role(&["user"])));
    }

    fn types(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn group_type_label_classifies_kinds() {
        // The security group a Power BI tenant setting would be scoped to.
        assert_eq!(group_type_label(Some(true), &[]), "Security");
        // M365 ("Unified") wins over the security flag.
        assert_eq!(
            group_type_label(Some(true), &types(&["Unified"])),
            "Microsoft 365"
        );
        // Neither unified nor security-enabled (incl. an unreadable flag).
        assert_eq!(group_type_label(Some(false), &[]), "Distribution");
        assert_eq!(group_type_label(None, &[]), "Distribution");
    }

    #[test]
    fn group_type_label_flags_dynamic_membership() {
        // Dynamic groups reject direct member changes — the label must say so.
        assert_eq!(
            group_type_label(Some(true), &types(&["DynamicMembership"])),
            "Security · Dynamic"
        );
        assert_eq!(
            group_type_label(None, &types(&["Unified", "DynamicMembership"])),
            "Microsoft 365 · Dynamic"
        );
    }
}
