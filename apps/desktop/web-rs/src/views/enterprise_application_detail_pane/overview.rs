use super::*;

#[component]
pub(super) fn OverviewContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let session = use_session();
    let sp = signal.with(|d| d.service_principal.clone());

    // My Apps portal visibility (the `HideApp` tag). Toggled optimistically so
    // the row reflects the change without re-fetching the whole detail.
    let initial_hidden = sp.tags.iter().any(|t| t == "HideApp");
    let hidden_override: RwSignal<Option<bool>> = RwSignal::new(None);
    // Same runner as the two toggles below: double-submit guard, busy flag and
    // the shared error sink (with Retry).
    let visibility_cmd = use_command();
    let toggling = visibility_cmd.busy;
    let sp_id_visibility = StoredValue::new(sp.id.clone());
    let toggle_visibility = move |_| {
        let new_hidden = !hidden_override.get_untracked().unwrap_or(initial_hidden);
        visibility_cmd.run_toast_err(
            move |()| {
                hidden_override.set(Some(new_hidden));
                session.toast_success(if new_hidden {
                    "Hidden from the My Apps portal."
                } else {
                    "Visible on the My Apps portal."
                });
            },
            move |tenant_id| {
                let id = sp_id_visibility.get_value();
                async move {
                    enterprise_application::set_enterprise_app_visibility(
                        &tenant_id, &id, new_hidden,
                    )
                    .await
                }
            },
        );
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
    // What the directory holds, so Save is offered only for a real change and
    // an unsaved note is known to the pane (closing or refreshing asks first).
    let saved_notes = RwSignal::new(sp.notes.clone().unwrap_or_default());
    let notes_dirty = move || notes_text.with(|n| saved_notes.with(|s| n != s));
    crate::hooks::use_unsaved_marker(notes_dirty);
    let notes_cmd = use_command();
    let sp_id_notes = StoredValue::new(sp.id.clone());
    let save_notes = move |_| {
        let saving = notes_text.get_untracked();
        notes_cmd.run_toast_err(
            move |()| {
                saved_notes.set(saving.clone());
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
        // The same `.read-grid` and the same id labels as the app-registration
        // Overview ("Object ID" / "App ID") — the two panes are one object seen
        // from two sides, and used to name and set these differently.
        <dl class="read-grid">
            <div class="read-grid__item">
                <dt>"Object ID"</dt>
                <dd class="mono">{sp.id.clone()}</dd>
            </div>
            <div class="read-grid__item">
                <dt>"App ID"</dt>
                <dd class="mono">{sp.app_id.clone()}</dd>
            </div>
            <div class="read-grid__item">
                <dt>"Type"</dt>
                <dd>{sp_type}</dd>
            </div>
            <div class="read-grid__item">
            <dt>"Enabled for sign-in"</dt>
            <dd class="read-grid__value-row">
                {move || {
                    let eff = enabled_override.get().or(initial_enabled);
                    let (label, tone) = match eff {
                        Some(true) => ("Enabled", BadgeTone::Ok),
                        Some(false) => ("Disabled", BadgeTone::Danger),
                        None => ("Unknown", BadgeTone::Neutral),
                    };
                    view! { <Badge label=label tone=tone /> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
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
            </div>
            <div class="read-grid__item">
            <dt>"Assignment required"</dt>
            <dd class="read-grid__value-row">
                {move || {
                    let eff = assign_override.get().or(initial_assign);
                    let (label, tone) = match eff {
                        Some(true) => ("Required", BadgeTone::Ok),
                        Some(false) => ("Not required", BadgeTone::Warning),
                        None => ("Unknown", BadgeTone::Neutral),
                    };
                    view! { <Badge label=label tone=tone /> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
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
            </div>
            <div class="read-grid__item">
                <dt>"Created"</dt>
                <dd>{created}</dd>
            </div>
            <div class="read-grid__item">
                <dt>"Owner tenant"</dt>
                <dd class="mono">{owner_org}</dd>
            </div>
            <div class="read-grid__item">
            <dt>"My Apps visibility"</dt>
            <dd class="read-grid__value-row">
                {move || {
                    let hidden = hidden_override.get().unwrap_or(initial_hidden);
                    let (label, tone) = if hidden {
                        ("Hidden", BadgeTone::Warning)
                    } else {
                        ("Visible", BadgeTone::Ok)
                    };
                    view! { <Badge label=label tone=tone /> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
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
            </div>
        </dl>
        <h4>"Notes"</h4>
        <Field label="Management notes (max 1024 characters)">
            <Textarea value=notes_text />
        </Field>
        <Button
            appearance=Signal::derive(|| ButtonAppearance::Primary)
            disabled=Signal::derive(move || notes_cmd.busy.get() || !notes_dirty())
            on_click=Box::new(save_notes)
        >
            "Save notes"
        </Button>
    }
}
