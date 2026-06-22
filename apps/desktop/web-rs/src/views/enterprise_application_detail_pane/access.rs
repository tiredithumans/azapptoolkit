use super::*;

#[component]
pub(super) fn AccessContent(signal: Signal<EnterpriseApplicationDetail>) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));

    // Bumped after assign/remove to refetch the assignment list.
    let reload = RwSignal::new(0_u32);
    // The principal id or assignment id currently being processed.
    let busy: RwSignal<Option<String>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let selected_role = RwSignal::new(DEFAULT_ACCESS_ROLE.to_string());
    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);
    let pending_remove: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_assign: RwSignal<Option<String>> = RwSignal::new(None);
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

    let candidates = LocalResource::new(move || {
        let q = query.get();
        let tenant = tenant.get();
        let groups = principal_kind.get() == "groups";
        async move {
            let q = q.trim().to_string();
            if q.len() < 2 {
                return Ok::<Vec<DirectoryObject>, String>(Vec::new());
            }
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            let result = if groups {
                applications::search_groups(&t.tenant_id, &q).await
            } else {
                applications::search_users(&t.tenant_id, &q).await
            };
            result.map_err(|e| e.message)
        }
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
            match enterprise_application::assign_enterprise_app_access(
                &t.tenant_id,
                &sp,
                &principal_id,
                &role,
            )
            .await
            {
                Ok(()) => {
                    raw_query.set(String::new());
                    session.toast_success("Access granted.");
                    reload.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.message)),
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
            match enterprise_application::remove_enterprise_app_access(
                &t.tenant_id,
                &sp,
                &assignment_id,
            )
            .await
            {
                Ok(()) => {
                    session.toast_success("Access removed.");
                    reload.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.message)),
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
            <Suspense fallback=move || {
                view! {
                    <div class="centered-pad">
                        <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading access…" />
                    </div>
                }
            }>
                {move || {
                    let roles = signal.with_untracked(|d| d.service_principal.app_roles.clone());
                    Suspend::new(async move {
                        match assignments.await {
                            Ok(list) => {
                                view! {
                                    <DataTable
                                        headers=vec!["Principal", "Type", "Role", ""]
                                        rows=list
                                        empty_message="No users or groups are assigned to this application."
                                        row=move |a: enterprise_application::AppAssignmentDto| {
                                            let principal = a
                                                .principal_display_name
                                                .clone()
                                                .unwrap_or_else(|| "—".into());
                                            let ptype = a
                                                .principal_type
                                                .clone()
                                                .unwrap_or_else(|| "—".into());
                                            let role = resolve_role(&roles, &a.app_role_id);
                                            let aid_click = a.assignment_id.clone();
                                            let aid_busy = a.assignment_id.clone();
                                            view! {
                                                <tr>
                                                    <td>{principal}</td>
                                                    <td>{ptype}</td>
                                                    <td>{role}</td>
                                                    <td>
                                                        <Button
                                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                            disabled=Signal::derive(move || {
                                                                busy.with(|b| b.as_deref() == Some(aid_busy.as_str()))
                                                            })
                                                            on_click=Box::new(move |_| {
                                                                pending_remove.set(Some(aid_click.clone()))
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
                                    .into_any()
                            }
                            Err(e) => {
                                view! {
                                    <Body1 class="app-detail__error">
                                        {format!("error [{}]: {}", e.code, e.message)}
                                    </Body1>
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
                    class="ent-access__role"
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
                            view! { <option value=r.id.clone()>{label}</option> }
                        })
                        .collect_view()}
                </select>
            </Field>
            <Field label="Assign">
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(move || {
                            if principal_kind.get() == "users" {
                                ButtonAppearance::Primary
                            } else {
                                ButtonAppearance::Secondary
                            }
                        })
                        on_click=Box::new(move |_| {
                            principal_kind.set("users".into());
                            raw_query.set(String::new());
                        })
                    >
                        "Users"
                    </Button>
                    <Button
                        appearance=Signal::derive(move || {
                            if principal_kind.get() == "groups" {
                                ButtonAppearance::Primary
                            } else {
                                ButtonAppearance::Secondary
                            }
                        })
                        on_click=Box::new(move |_| {
                            principal_kind.set("groups".into());
                            raw_query.set(String::new());
                        })
                    >
                        "Groups"
                    </Button>
                </div>
            </Field>
            <Field label="Search by name (2+ chars)">
                <Input value=raw_query placeholder="Search the directory…" />
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
                                Ok(users) if users.is_empty() => {
                                    view! { <Body1>"No matches."</Body1> }.into_any()
                                }
                                Ok(users) => {
                                    view! {
                                        <ul class="candidates">
                                            {users
                                                .into_iter()
                                                .map(|u| {
                                                    let id_click = u.id.clone();
                                                    let id_busy = u.id.clone();
                                                    let display = u
                                                        .display_name
                                                        .clone()
                                                        .unwrap_or_else(|| u.id.clone());
                                                    // Groups have no UPN — label them as such instead
                                                    // of falling back to a bare GUID.
                                                    let upn = u
                                                        .user_principal_name
                                                        .clone()
                                                        .unwrap_or_else(|| "Group".to_string());
                                                    view! {
                                                        <li>
                                                            <div>
                                                                <div>{display}</div>
                                                                <div class="mono small">{upn}</div>
                                                            </div>
                                                            <Button
                                                                appearance=Signal::derive(|| {
                                                                    ButtonAppearance::Primary
                                                                })
                                                                disabled=Signal::derive(move || {
                                                                    busy.with(|b| b.as_deref() == Some(id_busy.as_str()))
                                                                })
                                                                on_click=Box::new(move |_| pending_assign.set(Some(id_click.clone())))
                                                            >
                                                                "Assign"
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
            <GroupMembershipSection sp_id=sp_id />
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this assignment?"
                body="The principal loses access to this enterprise application. You can re-assign them later."
                confirm_label="Remove"
                busy=Signal::derive(move || busy.with(|b| b.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_remove.get() {
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
                confirm_label="Grant"
                busy=Signal::derive(move || busy.with(|b| b.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_assign.get() {
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
    // Group ids awaiting dialog confirmation.
    let pending_add: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_remove: RwSignal<Option<String>> = RwSignal::new(None);

    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);

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
            applications::search_groups(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
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
                    if e.code == "consent_required" {
                        retry_op.set(Some((add, group_id)));
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
            match auth::request_scope_consent(&t.tenant_id, "group_membership").await {
                Ok(()) => {
                    error.set(None);
                    if let Some((add, group_id)) = retry_op.get_untracked() {
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
        <h4>"Group memberships" <RequiresRole capability_key="group_membership" /></h4>
        <p class="muted">
            "Groups this service principal is a direct member of. Group-gated APIs — e.g. Power BI's \"Service principals can use Fabric APIs\" tenant setting — grant API access via security-group membership."
        </p>
        <Suspense fallback=move || {
            view! {
                <div class="centered-pad">
                    <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading groups…" />
                </div>
            }
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
                                    view! {
                                        <tr>
                                            <td>
                                                <div>{g.display_name.clone()}</div>
                                                <div class="mono small">{g.id.clone()}</div>
                                            </td>
                                            <td>{type_label}</td>
                                            <td>
                                                {(!dynamic)
                                                    .then(|| {
                                                        view! {
                                                            <Button
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                disabled=Signal::derive(move || busy.get())
                                                                on_click=Box::new(move |_| {
                                                                    pending_remove.set(Some(gid.clone()))
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
                            <Body1 class="app-detail__error">
                                {format!("error [{}]: {}", e.code, e.message)}
                            </Body1>
                        }
                            .into_any()
                    }
                }
            })}
        </Suspense>
        <Field label="Add to group (search by name, 2+ chars)">
            <Input value=raw_query placeholder="Search groups…" />
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
                            Ok(groups) if groups.is_empty() => {
                                view! { <Body1>"No matches."</Body1> }.into_any()
                            }
                            Ok(groups) => {
                                view! {
                                    <ul class="candidates">
                                        {groups
                                            .into_iter()
                                            .map(|g| {
                                                let id_click = g.id.clone();
                                                let display = g
                                                    .display_name
                                                    .clone()
                                                    .unwrap_or_else(|| g.id.clone());
                                                view! {
                                                    <li>
                                                        <div>
                                                            <div>{display}</div>
                                                            <div class="mono small">{g.id.clone()}</div>
                                                        </div>
                                                        <Button
                                                            appearance=Signal::derive(|| {
                                                                ButtonAppearance::Primary
                                                            })
                                                            disabled=Signal::derive(move || busy.get())
                                                            on_click=Box::new(move |_| {
                                                                pending_add.set(Some(id_click.clone()))
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
        {move || {
            error
                .get()
                .map(|e| {
                    if e.code == "consent_required" {
                        view! {
                            <div class="alert alert--warn">
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
                            </div>
                        }
                            .into_any()
                    } else {
                        view! {
                            <Body1 class="app-detail__error">
                                {format!("error [{}]: {}", e.code, e.message)}
                            </Body1>
                        }
                            .into_any()
                    }
                })
        }}
        <ConfirmDialog
            open=Signal::derive(move || pending_add.with(|p| p.is_some()))
            title="Add to this group?"
            body="The service principal becomes a member immediately and gains whatever access the group is granted — including group-gated API settings (e.g. Power BI tenant settings scoped to the group)."
            confirm_label="Add"
            busy=Signal::derive(move || busy.get())
            on_confirm=Callback::new(move |()| {
                if let Some(id) = pending_add.get() {
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
            confirm_label="Remove"
            busy=Signal::derive(move || busy.get())
            on_confirm=Callback::new(move |()| {
                if let Some(id) = pending_remove.get() {
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

#[cfg(test)]
mod tests {
    use super::group_type_label;

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
