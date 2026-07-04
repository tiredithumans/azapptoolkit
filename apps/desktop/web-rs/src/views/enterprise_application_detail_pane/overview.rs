use super::*;

#[component]
pub(super) fn OverviewContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let session = use_session();
    let sp = signal.with(|d| d.service_principal.clone());

    // My Apps portal visibility (the `HideApp` tag). Toggled optimistically so
    // the row reflects the change without re-fetching the whole detail.
    let sp_id = sp.id.clone();
    let initial_hidden = sp.tags.iter().any(|t| t == "HideApp");
    let hidden_override: RwSignal<Option<bool>> = RwSignal::new(None);
    let toggling = RwSignal::new(false);
    let toggle_visibility = move |_| {
        if toggling.get() {
            return;
        }
        let new_hidden = !hidden_override.get_untracked().unwrap_or(initial_hidden);
        toggling.set(true);
        let tenant = session.active_tenant.get();
        let sp_id = sp_id.clone();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                toggling.set(false);
                return;
            };
            match enterprise_application::set_enterprise_app_visibility(
                &t.tenant_id,
                &sp_id,
                new_hidden,
            )
            .await
            {
                Ok(()) => {
                    hidden_override.set(Some(new_hidden));
                    session.toast_success(if new_hidden {
                        "Hidden from the My Apps portal."
                    } else {
                        "Visible on the My Apps portal."
                    });
                }
                Err(e) => {
                    session.report_command_error(&e);
                }
            }
            toggling.set(false);
        });
    };

    // ---- "Enabled for users to sign in?" toggle (accountEnabled). Optimistic
    // local override (like the My Apps visibility toggle); the backend busts the
    // list caches so the list reflects it on next load. ----
    let initial_enabled = sp.account_enabled;
    let enabled_override: RwSignal<Option<bool>> = RwSignal::new(None);
    let enabled_cmd = use_command();
    let sp_id_enabled = StoredValue::new(sp.id.clone());
    let toggle_enabled = move |_| {
        let next = !enabled_override
            .get_untracked()
            .or(initial_enabled)
            .unwrap_or(true);
        enabled_cmd.run_toast_err(
            move |()| {
                enabled_override.set(Some(next));
                session.toast_success(if next {
                    "Users can sign in to this application."
                } else {
                    "Sign-in disabled — no tokens will be issued for this application."
                });
            },
            move |tenant_id| {
                let id = sp_id_enabled.get_value();
                async move {
                    enterprise_application::set_enterprise_app_account_enabled(
                        &tenant_id, &id, next,
                    )
                    .await
                }
            },
        );
    };

    // ---- "Assignment required?" toggle (appRoleAssignmentRequired). ----
    let initial_assign = sp.app_role_assignment_required;
    let assign_override: RwSignal<Option<bool>> = RwSignal::new(None);
    let assign_cmd = use_command();
    let sp_id_assign = StoredValue::new(sp.id.clone());
    let toggle_assign = move |_| {
        let next = !assign_override
            .get_untracked()
            .or(initial_assign)
            .unwrap_or(false);
        assign_cmd.run_toast_err(
            move |()| {
                assign_override.set(Some(next));
                session.toast_success(if next {
                    "Assignment now required — only assigned users/services can get a token."
                } else {
                    "Assignment no longer required."
                });
            },
            move |tenant_id| {
                let id = sp_id_assign.get_value();
                async move {
                    enterprise_application::set_enterprise_app_assignment_required(
                        &tenant_id, &id, next,
                    )
                    .await
                }
            },
        );
    };

    // ---- Free-text management notes editor. ----
    let notes_text = RwSignal::new(sp.notes.clone().unwrap_or_default());
    let notes_cmd = use_command();
    let sp_id_notes = StoredValue::new(sp.id.clone());
    let save_notes = move |_| {
        notes_cmd.run_toast_err(
            move |()| {
                session.toast_success("Notes saved.");
            },
            move |tenant_id| {
                let id = sp_id_notes.get_value();
                let n = notes_text.get_untracked();
                async move {
                    enterprise_application::set_enterprise_app_notes(&tenant_id, &id, &n).await
                }
            },
        );
    };

    let sp_type = sp
        .service_principal_type
        .clone()
        .unwrap_or_else(|| "—".to_string());
    let created = fmt_date(sp.created_date_time);
    let owner_org = sp
        .app_owner_organization_id
        .clone()
        .unwrap_or_else(|| "—".to_string());

    view! {
        <dl class="read-field">
            <dt>"Service principal id"</dt>
            <dd class="mono">{sp.id.clone()}</dd>
            <dt>"Application id"</dt>
            <dd class="mono">{sp.app_id.clone()}</dd>
            <dt>"Type"</dt>
            <dd>{sp_type}</dd>
            <dt>"Enabled for sign-in"</dt>
            <dd class="row-meta">
                {move || {
                    let eff = enabled_override.get().or(initial_enabled);
                    let (label, cls) = match eff {
                        Some(true) => ("Enabled", "badge badge--ok"),
                        Some(false) => ("Disabled", "badge badge--danger"),
                        None => ("Unknown", "badge"),
                    };
                    view! { <span class=cls>{label}</span> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    disabled=Signal::derive(move || enabled_cmd.busy.get())
                    on_click=Box::new(toggle_enabled)
                >
                    {move || {
                        if enabled_override.get().or(initial_enabled).unwrap_or(true) {
                            "Disable sign-in"
                        } else {
                            "Enable sign-in"
                        }
                    }}
                </Button>
            </dd>
            <dt>"Assignment required"</dt>
            <dd class="row-meta">
                {move || {
                    let eff = assign_override.get().or(initial_assign);
                    let (label, cls) = match eff {
                        Some(true) => ("Required", "badge badge--ok"),
                        Some(false) => ("Not required", "badge badge--warning"),
                        None => ("Unknown", "badge"),
                    };
                    view! { <span class=cls>{label}</span> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    disabled=Signal::derive(move || assign_cmd.busy.get())
                    on_click=Box::new(toggle_assign)
                >
                    {move || {
                        if assign_override.get().or(initial_assign).unwrap_or(false) {
                            "Make optional"
                        } else {
                            "Require assignment"
                        }
                    }}
                </Button>
            </dd>
            <dt>"Created"</dt>
            <dd>{created}</dd>
            <dt>"Owner tenant"</dt>
            <dd class="mono">{owner_org}</dd>
            <dt>"My Apps visibility"</dt>
            <dd class="row-meta">
                {move || {
                    let hidden = hidden_override.get().unwrap_or(initial_hidden);
                    let (label, cls) = if hidden {
                        ("Hidden", "badge badge--warning")
                    } else {
                        ("Visible", "badge badge--ok")
                    };
                    view! { <span class=cls>{label}</span> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    disabled=Signal::derive(move || toggling.get())
                    on_click=Box::new(toggle_visibility)
                >
                    {move || {
                        if hidden_override.get().unwrap_or(initial_hidden) {
                            "Show on My Apps"
                        } else {
                            "Hide from My Apps"
                        }
                    }}
                </Button>
            </dd>
        </dl>
        <h4>"Notes"</h4>
        <Field label="Management notes (max 1024 characters)">
            <Textarea value=notes_text />
        </Field>
        <Button
            appearance=Signal::derive(|| ButtonAppearance::Primary)
            disabled=Signal::derive(move || notes_cmd.busy.get())
            on_click=Box::new(save_notes)
        >
            "Save notes"
        </Button>
    }
}
