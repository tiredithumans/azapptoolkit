//! Collapsible "Exchange scoping" section rendered under the permissions table
//! (app-registration Permissions tab and enterprise-app Permissions content).
//! Folds in what used to be the standalone Exchange access tab: the coarse
//! "scope all mail permissions" RBAC-for-Applications grant, the current
//! Exchange role assignments, and the legacy Application Access Policy
//! migration. The old tab's "Effective mailbox scope" table is gone on
//! purpose — the per-row Scope badges in the table above are that view.
//!
//! Callers render this only when the principal declares/holds an
//! Exchange-scopable permission, so the section never probes Exchange for the
//! vast majority of apps. Accepted tradeoff: an app whose *only* Exchange
//! artifact is a leftover RBAC role assignment (no mail permission anywhere)
//! won't show the section — the Resource Access mailbox lookup still surfaces
//! those.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize, Textarea};

use crate::bindings::auth;
use crate::bindings::exchange::{self, AapMigrationReport};
use crate::components::collapsible_scoping_section::CollapsibleScopingSection;
use crate::components::managed_scope_group_panel::ManagedScopeGroupPanel;
use crate::components::ui::DataTable;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::util::parse_lines;

/// How the "scope all mail permissions" grant addresses the principal.
#[derive(Clone, PartialEq)]
pub enum ExchangeScopeTarget {
    /// App registration: the backend derives the mail roles from the app's
    /// manifest (`grant_exchange_mailbox_access` with `permissions = None`).
    Application { object_id: String },
    /// Bare service principal (enterprise app **or** managed identity): scope the
    /// explicitly-held mail permission values
    /// (`grant_managed_identity_scoped_exchange_access`). `is_managed_identity`
    /// picks the right noun in the copy ("managed identity" vs "application") and
    /// hides the AAP-migration sub-section (which never applies to a MI).
    ServicePrincipal {
        sp_object_id: String,
        display_name: String,
        mail_permissions: Vec<String>,
        is_managed_identity: bool,
    },
}

#[component]
pub fn ExchangeScopingSection(
    /// appId (client id) — keys the role-assignment list and AAP migration.
    #[prop(into)]
    app_id: Signal<String>,
    #[prop(into)] target: Signal<ExchangeScopeTarget>,
    /// Fired after a mutation (grant, or a non-dry-run migration with no
    /// failures). The caller's reload rebuilds this whole section, so durable
    /// success feedback rides a toast — inline notes here only survive on the
    /// error path (no reload happens then).
    on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let open = RwSignal::new(false);

    // Principal-aware copy: an app registration derives its mail roles from its
    // manifest, whereas a bare service principal (enterprise app or managed
    // identity) derives them from the permissions it actually holds. The noun
    // also tracks the principal kind so a managed identity never reads as
    // "application", and `is_mi` hides the AAP-migration block (never relevant
    // to a managed identity).
    let noun = Signal::derive(move || {
        target.with(|t| match t {
            ExchangeScopeTarget::ServicePrincipal {
                is_managed_identity: true,
                ..
            } => "managed identity",
            _ => "application",
        })
    });
    let derivation = Signal::derive(move || {
        target.with(|t| match t {
            ExchangeScopeTarget::Application { .. } => {
                "Roles are derived from the app's declared Mail/Calendars/Contacts permissions."
            }
            ExchangeScopeTarget::ServicePrincipal { .. } => {
                "Roles are derived from the Mail/Calendars/Contacts permissions it holds."
            }
        })
    });
    let is_mi = Signal::derive(move || {
        target.with(|t| {
            matches!(
                t,
                ExchangeScopeTarget::ServicePrincipal {
                    is_managed_identity: true,
                    ..
                }
            )
        })
    });

    let groups_text = RwSignal::new(String::new());
    // Drives the shared-core grant flow (`run_grant`).
    let grant_cmd = use_command();

    // Resolved managed scope group (`azapptoolkit_<appId>`) state — owned here,
    // populated by the embedded `ManagedScopeGroupPanel`, and read by
    // `do_grant_managed` to pull the group's SMTP for the recommended grant.
    #[allow(clippy::type_complexity)]
    let group_state: RwSignal<
        Option<Result<exchange::ExchangeScopeGroupDto, azapptoolkit_dto::UiError>>,
    > = RwSignal::new(None);

    // Drives the legacy Application Access Policy migration (`do_migrate`).
    let mig_cmd = use_command();
    let mig_result: RwSignal<Option<AapMigrationReport>> = RwSignal::new(None);
    // Optional override for the management-scope name. Blank => backend default
    // (`app_scope_<appId>`). The concrete default is surfaced as helper text.
    let scope_name_override = RwSignal::new(String::new());
    let default_scope_name = Signal::derive(move || format!("app_scope_{}", app_id.get()));

    // Bumped to refresh the assignments list (consent retry / manual refresh).
    let reload = RwSignal::new(0_u32);

    // Gated on `open` so a collapsed section costs no Exchange round trip.
    let assignments = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let app_id = app_id.get();
        let is_open = open.get();
        let _ = reload.get();
        async move {
            if !is_open {
                return Ok(Vec::new());
            }
            let Some(t) = tenant else {
                return Err(azapptoolkit_dto::UiError {
                    code: "no_tenant".into(),
                    message: "tenant missing".into(),
                    retryable: false,
                });
            };
            exchange::list_exchange_role_assignments(&t.tenant_id, &app_id).await
        }
    });

    // Interactive consent for the Exchange admin scope, then refresh.
    let do_consent = move || {
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        leptos::task::spawn_local(async move {
            if auth::request_scope_consent(&t.tenant_id, "exchange")
                .await
                .is_ok()
            {
                reload.update(|n| *n += 1);
            }
        });
    };

    // Shared grant core: scope the principal to `groups` (the managed group, or
    // the free-text advanced groups), assigning the mail roles and — when
    // `remove_unscoped` — stripping the org-wide Entra grant so scoping bites.
    let run_grant = move |groups: Vec<String>, remove_unscoped: bool| {
        if groups.is_empty() {
            grant_cmd.error.set(Some(
                "Add at least one mailbox to the managed group, or enter a group below.".into(),
            ));
            return;
        }
        let target = target.get();
        let app = app_id.get();
        grant_cmd.run(
            move |r: exchange::ExchangeAccessResult| {
                let mut summary = format!(
                    "Scope “{}”: assigned {} role(s), skipped {}, removed {} org-wide grant(s).",
                    r.scope_name,
                    r.roles_assigned.len(),
                    r.roles_skipped.len(),
                    r.removed_entra_grants.len(),
                );
                if !r.warnings.is_empty() {
                    summary.push_str(&format!(" {} warning(s).", r.warnings.len()));
                }
                session.toast_success(summary);
                on_changed.run(());
            },
            move |tenant_id| async move {
                match &target {
                    ExchangeScopeTarget::Application { object_id } => {
                        exchange::grant_exchange_mailbox_access(
                            &tenant_id,
                            object_id,
                            None,
                            &groups,
                            remove_unscoped,
                        )
                        .await
                    }
                    ExchangeScopeTarget::ServicePrincipal {
                        sp_object_id,
                        display_name,
                        mail_permissions,
                        ..
                    } => {
                        exchange::grant_managed_identity_scoped_exchange_access(
                            &tenant_id,
                            sp_object_id,
                            &app,
                            display_name,
                            mail_permissions,
                            &groups,
                            remove_unscoped,
                        )
                        .await
                    }
                }
            },
        );
    };

    // Advanced path: scope to the free-text groups the user typed.
    let do_grant =
        move |remove_unscoped: bool| run_grant(parse_lines(&groups_text.get()), remove_unscoped);

    // Recommended path: scope to the toolkit-managed group. Requires the group
    // to exist (created by adding at least one mailbox).
    let do_grant_managed = move |remove_unscoped: bool| match group_state.get() {
        Some(Ok(g)) if g.exists => {
            let identifier = g
                .primary_smtp_address
                .clone()
                .unwrap_or_else(|| g.group_name.clone());
            run_grant(vec![identifier], remove_unscoped);
        }
        _ => grant_cmd.error.set(Some(
            "Add at least one mailbox first — that creates the managed group to scope to.".into(),
        )),
    };

    let do_migrate = move |dry_run: bool| {
        if mig_cmd.busy.get_untracked() {
            return;
        }
        mig_result.set(None);
        let app_id = app_id.get();
        // Blank override => None, so the backend applies the `app_scope_<appId>` default.
        let scope = scope_name_override.get_untracked().trim().to_string();
        let scope = (!scope.is_empty()).then_some(scope);
        mig_cmd.run(
            move |r: AapMigrationReport| {
                // Dry run mutated nothing — show the plan inline. A clean
                // execute reloads the caller (which rebuilds this section), so
                // the summary rides a toast instead. A partial failure keeps
                // the report inline (no reload) so the failure lines survive;
                // Refresh picks up whatever did land.
                if dry_run || !r.failures.is_empty() {
                    mig_result.set(Some(r));
                } else {
                    session.toast_success(format!("Migrated {} policy(ies).", r.items.len()));
                    on_changed.run(());
                }
            },
            move |tenant_id| async move {
                exchange::migrate_application_access_policies(
                    &tenant_id,
                    Some(&app_id),
                    scope.as_deref(),
                    dry_run,
                )
                .await
            },
        );
    };

    view! {
        <CollapsibleScopingSection
            title="Exchange scoping"
            capability_key="exchange_rbac"
            open=open
        >
            <Body1>
                {move || {
                    format!(
                        "Manage which mailboxes this {}'s scoped mail access covers, using RBAC for Applications (the replacement for Application Access Policies). Add mailboxes to the toolkit-managed group, then grant once — afterwards you adjust who's in scope just by changing its membership (no re-grant needed). {}",
                        noun.get(),
                        derivation.get(),
                    )
                }}
            </Body1>

            <ManagedScopeGroupPanel app_id=app_id group_state=group_state />

            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| do_grant_managed(true))
                    disabled=Signal::derive(move || grant_cmd.busy.get())
                >
                    {move || {
                        if grant_cmd.busy.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }.into_any()
                        } else {
                            view! { "Grant scoped access (recommended)" }.into_any()
                        }
                    }}
                </Button>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| do_grant_managed(false))
                    disabled=Signal::derive(move || grant_cmd.busy.get())
                >
                    "Grant, keep org-wide grants"
                </Button>
            </div>
            <Body1 class="hint">
                {move || {
                    format!(
                        "“Recommended” also removes the {}'s org-wide Microsoft Entra grant for the scoped permissions — required for scoping to take effect. Only direct members are in scope (nested groups don't count), and Exchange can take 30 min–2 h to apply RBAC changes (the permission tester bypasses that cache).",
                        noun.get(),
                    )
                }}
            </Body1>

                            <hr />
                            <strong>"Advanced: scope to existing groups"</strong>
                            <Field label="Existing group identifiers (one per line)">
                                <Textarea
                                    value=groups_text
                                    placeholder="hr-team@contoso.com\nFinanceMailboxes"
                                />
                            </Field>
                            <div class="actions-row">
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(move |_| do_grant(true))
                                    disabled=Signal::derive(move || grant_cmd.busy.get())
                                >
                                    "Grant scoped (remove org-wide)"
                                </Button>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                    on_click=Box::new(move |_| do_grant(false))
                                    disabled=Signal::derive(move || grant_cmd.busy.get())
                                >
                                    "Grant, keep org-wide grants"
                                </Button>
                            </div>
                            {move || {
                                grant_cmd
                                    .error
                                    .get()
                                    .map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                            }}

                            <hr />
                            <header class="row-between">
                                <strong>"Current Exchange role assignments"</strong>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                    on_click=Box::new(move |_| reload.update(|n| *n += 1))
                                >
                                    "Refresh"
                                </Button>
                            </header>
                            <Suspense fallback=move || {
                                view! {
                                    <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" />
                                }
                            }>
                                {move || Suspend::new(async move {
                                    match assignments.await {
                                        Ok(list) => {
                                            view! {
                                                <DataTable
                                                    headers=vec!["Role", "Scope"]
                                                    rows=list
                                                    empty_message=format!(
                                                        "No Exchange role assignments for this {}.",
                                                        noun.get_untracked(),
                                                    )
                                                    row=|a: exchange::ExchangeRoleAssignmentDto| {
                                                        view! {
                                                            <tr>
                                                                <td>{a.role.unwrap_or_default()}</td>
                                                                <td class="mono">
                                                                    {a
                                                                        .custom_resource_scope
                                                                        .unwrap_or_else(|| "(org-wide)".into())}
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
                                            let needs_consent = e.code == "consent_required";
                                            view! {
                                                <div class="alert alert--warn">
                                                    <Body1>{e.message}</Body1>
                                                    <div class="actions-row">
                                                        {needs_consent
                                                            .then(|| {
                                                                view! {
                                                                    <Button
                                                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                                        on_click=Box::new(move |_| do_consent())
                                                                    >
                                                                        "Grant consent & retry"
                                                                    </Button>
                                                                }
                                                            })}
                                                        <Button
                                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                                            on_click=Box::new(move |_| reload.update(|n| *n += 1))
                                                        >
                                                            "Retry"
                                                        </Button>
                                                    </div>
                                                </div>
                                            }
                                                .into_any()
                                        }
                                    }
                                })}
                            </Suspense>

                            {move || (!is_mi.get()).then(|| view! {
                            <hr />
                            <header class="row-between">
                                <strong>"Migrate legacy Application Access Policy"</strong>
                            </header>
                            <Body1>
                                "If this app is still scoped by a legacy Application Access Policy, migrate it to RBAC: a management scope is built from the policy's group, the scoped roles are assigned, the org-wide Entra grants are removed, and the policy is deleted. Preview first to see the plan."
                            </Body1>
                            <Field label="Management scope name (optional)">
                                <Input
                                    value=scope_name_override
                                    placeholder="app_scope_<appId>"
                                />
                            </Field>
                            <Body1 class="hint">
                                "Leave blank to use the default "
                                <code>{move || default_scope_name.get()}</code>
                                "."
                            </Body1>
                            <div class="actions-row">
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(move |_| do_migrate(true))
                                    disabled=Signal::derive(move || mig_cmd.busy.get())
                                >
                                    "Preview migration"
                                </Button>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(move |_| do_migrate(false))
                                    disabled=Signal::derive(move || mig_cmd.busy.get())
                                >
                                    {move || {
                                        if mig_cmd.busy.get() {
                                            view! {
                                                <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                            }
                                                .into_any()
                                        } else {
                                            view! { "Migrate this app" }.into_any()
                                        }
                                    }}
                                </Button>
                            </div>
                            {move || {
                                mig_cmd
                                    .error
                                    .get()
                                    .map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                            }}
                            {move || {
                                mig_result
                                    .get()
                                    .map(|r| {
                                        let header = if r.dry_run {
                                            format!(
                                                "Plan: {} policy(ies) would be migrated.",
                                                r.items.len(),
                                            )
                                        } else {
                                            format!("Migrated {} policy(ies).", r.items.len())
                                        };
                                        let items = r.items.clone();
                                        let failures = r.failures.clone();
                                        view! {
                                            <div class="alert alert--ok">{header}</div>
                                            <ul class="warnings">
                                                {items
                                                    .into_iter()
                                                    .map(|i| {
                                                        let line = format!(
                                                            "{} — {} | roles: {} | removed grants: {} | policy removed: {}",
                                                            i.app_id,
                                                            i.status,
                                                            i.roles_assigned.join(", "),
                                                            i.removed_entra_grants.join(", "),
                                                            i.removed_policy,
                                                        );
                                                        view! { <li>{line}</li> }
                                                    })
                                                    .collect_view()}
                                                {failures
                                                    .into_iter()
                                                    .map(|f| view! { <li class="form-error">{f}</li> })
                                                    .collect_view()}
                                            </ul>
                                        }
                                    })
                            }}
                            })}
        </CollapsibleScopingSection>
    }
}
