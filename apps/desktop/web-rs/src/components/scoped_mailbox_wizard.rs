//! "Grant mailbox access" wizard — one guided flow to give an app scoped
//! Exchange mailbox access without the old grant-org-wide-then-scope dance.
//!
//! Three steps (modeled on `sso_wizard_dialog.rs`): pick the mail permissions →
//! choose the mailboxes/reach → review & apply. Scoped is the default and the
//! recommended path: the permission is **declared** (so it's visible + the
//! Exchange scoping path can derive its target) while access comes solely from a
//! scoped Exchange RBAC role assignment — no org-wide Entra grant is ever created
//! (`declare_app_permission`). An explicit, de-emphasized "org-wide" option
//! remains for the rare permission that genuinely needs tenant-wide reach.
//!
//! Works for every principal `ExchangeScopeTarget` covers — an app registration
//! declares into its manifest; a bare service principal (enterprise app or
//! managed identity) is scoped by the permission values it should hold.

use std::collections::HashMap;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize, Textarea};

use crate::bindings::exchange::{self, ExchangeScopeGroupDto};
use crate::bindings::{auth, managed_identity, permissions};
use crate::components::exchange_scoping_section::ExchangeScopeTarget;
use crate::components::group_autocomplete::GroupAutocomplete;
use crate::components::managed_scope_group_panel::ManagedScopeGroupPanel;
use crate::components::requires_role::RequiresRole;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;
use crate::util::parse_lines;
use azapptoolkit_dto::permissions::PermissionKind;
use azapptoolkit_dto::UiError;

/// Microsoft Graph's well-known resource appId — the resource every mail
/// application permission lives on.
const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// The Exchange-scopable mail permissions shown first (the common case).
const PRIMARY_PERMS: &[(&str, &str)] = &[
    ("Mail.Read", "Read mail"),
    ("Mail.ReadWrite", "Read and write mail"),
    ("Mail.Send", "Send mail as the mailbox"),
];

/// Additional scopable permissions behind the "More" expander. Every value here
/// must map in `azapptoolkit_core::scoping::exchange_role_for_graph_permission`.
const MORE_PERMS: &[(&str, &str)] = &[
    ("Mail.ReadBasic.All", "Read basic mail (envelope only)"),
    ("Calendars.Read", "Read calendars"),
    ("Calendars.ReadWrite", "Read and write calendars"),
    ("Contacts.Read", "Read contacts"),
    ("Contacts.ReadWrite", "Read and write contacts"),
    ("MailboxSettings.Read", "Read mailbox settings"),
    (
        "MailboxSettings.ReadWrite",
        "Read and write mailbox settings",
    ),
];

/// How step 2 confines (or doesn't) the granted permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeMode {
    /// Scope to the toolkit-managed group (`azapptoolkit_<appId>`).
    Managed,
    /// Scope to one or more existing mail-enabled groups.
    Existing,
    /// Rare: grant org-wide, no Exchange RBAC scoping.
    OrgWide,
}

/// Resolves Microsoft Graph's application-permission `value -> id` map, needed to
/// declare/grant a permission on an app registration (the bare-SP path grants by
/// value and skips this).
async fn graph_app_role_ids(tenant_id: &str) -> Result<HashMap<String, String>, UiError> {
    let perms = permissions::list_resource_permissions(tenant_id, GRAPH_APP_ID).await?;
    Ok(perms
        .app_roles
        .into_iter()
        .map(|r| (r.value, r.id))
        .collect())
}

fn scoped_summary(r: &exchange::ExchangeAccessResult) -> String {
    let mut s = format!(
        "Scoped “{}”: assigned {} role(s), removed {} org-wide grant(s).",
        r.scope_name,
        r.roles_assigned.len(),
        r.removed_entra_grants.len(),
    );
    if !r.warnings.is_empty() {
        s.push_str(&format!(" {} warning(s).", r.warnings.len()));
    }
    s
}

/// Default (recommended) path: declare each permission without an org-wide grant
/// (app registration only), then assign the scoped Exchange RBAC roles + strip
/// any org-wide grant so scoping bites.
async fn apply_scoped(
    tenant_id: String,
    target: ExchangeScopeTarget,
    app_id: String,
    perms: Vec<String>,
    groups: Vec<String>,
) -> Result<String, UiError> {
    match target {
        ExchangeScopeTarget::Application { object_id } => {
            let ids = graph_app_role_ids(&tenant_id).await?;
            for p in &perms {
                let id = ids.get(p).ok_or_else(|| {
                    UiError::validation(
                        "unknown_permission",
                        format!("{p} is not a Microsoft Graph application permission"),
                    )
                })?;
                permissions::declare_app_permission(
                    &tenant_id,
                    &object_id,
                    GRAPH_APP_ID,
                    id,
                    PermissionKind::Application,
                )
                .await?;
            }
            let r = exchange::grant_exchange_mailbox_access(
                &tenant_id,
                &object_id,
                Some(&perms),
                &groups,
                true,
            )
            .await?;
            Ok(scoped_summary(&r))
        }
        ExchangeScopeTarget::ServicePrincipal {
            sp_object_id,
            display_name,
            ..
        } => {
            let r = exchange::grant_managed_identity_scoped_exchange_access(
                &tenant_id,
                &sp_object_id,
                &app_id,
                &display_name,
                &perms,
                &groups,
                true,
            )
            .await?;
            Ok(scoped_summary(&r))
        }
    }
}

/// Rare path: grant the permissions org-wide (no Exchange RBAC scoping). App
/// registrations go through `grant_single_permission` per value; bare service
/// principals get a single app-role grant by value.
async fn apply_orgwide(
    tenant_id: String,
    target: ExchangeScopeTarget,
    perms: Vec<String>,
) -> Result<String, UiError> {
    match target {
        ExchangeScopeTarget::Application { object_id } => {
            let ids = graph_app_role_ids(&tenant_id).await?;
            let mut failures: Vec<String> = Vec::new();
            for p in &perms {
                let Some(id) = ids.get(p) else {
                    failures.push(format!("{p}: not a Graph application permission"));
                    continue;
                };
                match permissions::grant_single_permission(
                    &tenant_id,
                    &object_id,
                    GRAPH_APP_ID,
                    id,
                    PermissionKind::Application,
                )
                .await
                {
                    Ok(r) => failures.extend(r.failures.into_iter().map(|f| f.message)),
                    Err(e) => return Err(e),
                }
            }
            let mut s = format!("Granted {} permission(s) org-wide.", perms.len());
            if !failures.is_empty() {
                s.push_str(&format!(
                    " {} issue(s): {}",
                    failures.len(),
                    failures.join("; ")
                ));
            }
            Ok(s)
        }
        ExchangeScopeTarget::ServicePrincipal { sp_object_id, .. } => {
            let r = managed_identity::grant_managed_identity_permission(
                &tenant_id,
                &sp_object_id,
                GRAPH_APP_ID,
                &perms,
            )
            .await?;
            let mut s = format!("Granted {} permission(s) org-wide", r.granted.len());
            if !r.skipped.is_empty() {
                s.push_str(&format!(", {} already present", r.skipped.len()));
            }
            s.push('.');
            if !r.failures.is_empty() {
                s.push_str(&format!(
                    " {} issue(s): {}",
                    r.failures.len(),
                    r.failures.join("; ")
                ));
            }
            Ok(s)
        }
    }
}

#[component]
pub fn ScopedMailboxWizard(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] target: Signal<ExchangeScopeTarget>,
    /// appId (client id) — resolves the managed group + labels the summary.
    #[prop(into)]
    app_id: Signal<String>,
    #[prop(into)] on_close: Callback<()>,
    /// Fired after a successful grant so the host refreshes detail + scope badges.
    #[prop(into)]
    on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();

    let step = RwSignal::new(0u8);
    let selected: RwSignal<Vec<String>> = RwSignal::new(Vec::new());
    let show_more = RwSignal::new(false);
    let scope_mode = RwSignal::new(ScopeMode::Managed);
    let existing_groups = RwSignal::new(String::new());
    // Resolved managed-group state, owned here so apply can read the group's SMTP
    // even after the panel unmounts (step 2). Populated by the embedded panel.
    let group_state: RwSignal<Option<Result<ExchangeScopeGroupDto, UiError>>> = RwSignal::new(None);

    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    // Set when a scoped grant fails for want of the Exchange admin scope consent.
    let needs_consent = RwSignal::new(false);

    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    let reset = move || {
        step.set(0);
        selected.set(Vec::new());
        show_more.set(false);
        scope_mode.set(ScopeMode::Managed);
        existing_groups.set(String::new());
        group_state.set(None);
        busy.set(false);
        error.set(None);
        needs_consent.set(false);
    };
    let close = move || {
        reset();
        on_close.run(());
    };

    let toggle = move |value: String| {
        selected.update(|s| {
            if let Some(pos) = s.iter().position(|v| v == &value) {
                s.remove(pos);
            } else {
                s.push(value);
            }
        });
        error.set(None);
    };

    // Run the grant for the chosen permissions + scope mode. Reused by the Apply
    // button and the consent-retry button.
    let run_apply = move || {
        if busy.get_untracked() {
            return;
        }
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        let perms = selected.get_untracked();
        if perms.is_empty() {
            error.set(Some("Select at least one permission.".into()));
            return;
        }
        let mode = scope_mode.get_untracked();
        // Resolve the group identifiers for the scoped modes up front so a missing
        // selection fails fast with a clear message (no spinner flash).
        let groups: Vec<String> = match mode {
            ScopeMode::Managed => match group_state.get_untracked() {
                Some(Ok(g)) if g.exists => {
                    vec![g
                        .primary_smtp_address
                        .clone()
                        .unwrap_or(g.group_name.clone())]
                }
                _ => {
                    error.set(Some(
                        "Add at least one mailbox to the managed group first — that creates the group to scope to."
                            .into(),
                    ));
                    return;
                }
            },
            ScopeMode::Existing => {
                let g = parse_lines(&existing_groups.get_untracked());
                if g.is_empty() {
                    error.set(Some(
                        "Enter at least one group identifier (one per line).".into(),
                    ));
                    return;
                }
                g
            }
            ScopeMode::OrgWide => Vec::new(),
        };

        let tenant_id = t.tenant_id.clone();
        let target = target.get_untracked();
        let app = app_id.get_untracked();
        busy.set(true);
        error.set(None);
        needs_consent.set(false);
        leptos::task::spawn_local(async move {
            let res = match mode {
                ScopeMode::OrgWide => apply_orgwide(tenant_id, target, perms).await,
                _ => apply_scoped(tenant_id, target, app, perms, groups).await,
            };
            match res {
                Ok(summary) => {
                    session.toast_success(summary);
                    on_changed.run(());
                    close();
                }
                Err(e) => {
                    if e.code == "consent_required" {
                        needs_consent.set(true);
                    }
                    error.set(Some(e.message));
                    busy.set(false);
                }
            }
        });
    };

    // Grant the Exchange admin scope consent, then retry the apply.
    let consent_and_retry = move |_| {
        if busy.get_untracked() {
            return;
        }
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        busy.set(true);
        error.set(None);
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&tenant_id, "exchange").await {
                Ok(()) => {
                    needs_consent.set(false);
                    busy.set(false);
                    run_apply();
                }
                Err(e) => {
                    error.set(Some(e.message));
                    busy.set(false);
                }
            }
        });
    };

    // Step 0 "Next" is allowed once at least one permission is checked.
    let step0_ready = move || selected.with(|s| !s.is_empty());

    let review_line = move || {
        let perms = selected.get().join(", ");
        match scope_mode.get() {
            ScopeMode::OrgWide => format!(
                "Grant {perms} org-wide. The app will be able to reach EVERY mailbox in the tenant — use only when the permission genuinely needs tenant-wide reach.",
            ),
            ScopeMode::Managed => format!(
                "Grant {perms}, scoped to the toolkit-managed mailbox group. The app will not have org-wide mailbox access.",
            ),
            ScopeMode::Existing => format!(
                "Grant {perms}, scoped to the entered group(s). The app will not have org-wide mailbox access.",
            ),
        }
    };

    let perm_checklist = move |perms: &'static [(&'static str, &'static str)]| {
        perms
            .iter()
            .map(|(value, label)| {
                let v = value.to_string();
                let v2 = value.to_string();
                view! {
                    <label class="checkbox-row">
                        <input
                            type="checkbox"
                            prop:checked=move || selected.with(|s| s.iter().any(|x| x == &v))
                            on:change=move |_| toggle(v2.clone())
                        />
                        <span><span class="mono">{*value}</span> " — " {*label}</span>
                    </label>
                }
            })
            .collect_view()
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="scoped-mailbox-wizard-title"
            >
                <div class="modal modal--wide" node_ref=modal_ref>
                    <h3 id="scoped-mailbox-wizard-title">"Grant mailbox access"</h3>
                    <div class="sso-wizard__steps">
                        <Body1 class="hint">
                            {move || match step.get() {
                                0 => "Step 1 of 3 — Permissions",
                                1 => "Step 2 of 3 — Mailboxes",
                                _ => "Step 3 of 3 — Review & grant",
                            }}
                        </Body1>
                    </div>

                    // ---- Step 0: permissions ----
                    <Show when=move || step.get() == 0 fallback=|| ()>
                        <Body1 class="hint">
                            "Choose the mailbox permissions to grant. You'll confine them to specific mailboxes next."
                        </Body1>
                        <div class="checkbox-list">{move || perm_checklist(PRIMARY_PERMS)}</div>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                            on_click=Box::new(move |_| show_more.update(|m| *m = !*m))
                        >
                            {move || if show_more.get() { "Fewer permissions" } else { "More permissions" }}
                        </Button>
                        <Show when=move || show_more.get() fallback=|| ()>
                            <div class="checkbox-list">{move || perm_checklist(MORE_PERMS)}</div>
                        </Show>
                    </Show>

                    // ---- Step 1: mailboxes / reach ----
                    <Show when=move || step.get() == 1 fallback=|| ()>
                        <label class="radio-row">
                            <input
                                type="radio"
                                name="scoped-mailbox-mode"
                                prop:checked=move || scope_mode.get() == ScopeMode::Managed
                                on:change=move |_| scope_mode.set(ScopeMode::Managed)
                            />
                            <span><strong>"Specific mailboxes"</strong> " (recommended)"</span>
                        </label>
                        <Show when=move || scope_mode.get() == ScopeMode::Managed fallback=|| ()>
                            <Body1 class="hint">
                                "We manage a mail-enabled security group with these mailboxes; adjust scope later by changing its membership."
                            </Body1>
                            <ManagedScopeGroupPanel app_id=app_id group_state=group_state />
                        </Show>

                        <label class="radio-row">
                            <input
                                type="radio"
                                name="scoped-mailbox-mode"
                                prop:checked=move || scope_mode.get() == ScopeMode::Existing
                                on:change=move |_| scope_mode.set(ScopeMode::Existing)
                            />
                            <span><strong>"Existing group(s)"</strong></span>
                        </label>
                        <Show when=move || scope_mode.get() == ScopeMode::Existing fallback=|| ()>
                            <GroupAutocomplete target=existing_groups />
                            <Textarea
                                value=existing_groups
                                placeholder="hr-team@contoso.com\nFinanceMailboxes"
                            />
                        </Show>

                        <label class="radio-row">
                            <input
                                type="radio"
                                name="scoped-mailbox-mode"
                                prop:checked=move || scope_mode.get() == ScopeMode::OrgWide
                                on:change=move |_| scope_mode.set(ScopeMode::OrgWide)
                            />
                            <span class="muted">"Org-wide — no scoping (rare)"</span>
                        </label>
                        <Show when=move || scope_mode.get() == ScopeMode::OrgWide fallback=|| ()>
                            <div class="alert alert--warn">
                                <Body1>
                                    "The app will reach every mailbox in the tenant. Only choose this when the permission genuinely needs tenant-wide reach."
                                </Body1>
                            </div>
                        </Show>
                        <RequiresRole capability_key="exchange_rbac" />
                    </Show>

                    // ---- Step 2: review & grant ----
                    <Show when=move || step.get() == 2 fallback=|| ()>
                        <Body1>{review_line}</Body1>
                        {move || {
                            needs_consent
                                .get()
                                .then(|| {
                                    view! {
                                        <div class="alert alert--warn">
                                            "Scoping needs the Exchange admin consent."
                                            <Button
                                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                on_click=Box::new(consent_and_retry)
                                                disabled=Signal::derive(move || busy.get())
                                            >
                                                "Grant consent & retry"
                                            </Button>
                                        </div>
                                    }
                                })
                        }}
                    </Show>

                    {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}

                    // ---- Footer ----
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| {
                                if step.get() == 0 { close() } else { step.update(|s| *s -= 1) }
                            })
                            disabled=Signal::derive(move || busy.get())
                        >
                            {move || if step.get() == 0 { "Cancel" } else { "Back" }}
                        </Button>
                        <Show when=move || step.get() < 2 fallback=move || {
                            view! {
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(move |_| run_apply())
                                    disabled=Signal::derive(move || busy.get())
                                >
                                    {move || {
                                        if busy.get() {
                                            view! {
                                                <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                            }
                                                .into_any()
                                        } else {
                                            view! { "Grant access" }.into_any()
                                        }
                                    }}
                                </Button>
                            }
                        }>
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                on_click=Box::new(move |_| step.update(|s| *s += 1))
                                disabled=Signal::derive(move || step.get() == 0 && !step0_ready())
                            >
                                "Next"
                            </Button>
                        </Show>
                    </div>
                </div>
            </div>
        </Show>
    }
}
