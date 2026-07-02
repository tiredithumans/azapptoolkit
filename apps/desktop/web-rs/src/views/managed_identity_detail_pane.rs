//! Detail pane for a managed identity: header (TypeChip + name + Refresh) +
//! properties + "Current permissions" + "Grant application permissions" +
//! "Azure RBAC roles". A pure presenter — `ManagedIdentityDetailWindow` owns
//! the resources, signals, and mutation callbacks and passes them in; this
//! component only reads those handles and renders.

use std::collections::HashMap;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Select, Spinner, SpinnerSize, Tab, TabList};

use azapptoolkit_core::audit::MailPermissionScope;

use crate::bindings::TenantContext;
use crate::bindings::auth as auth_bindings;
use crate::bindings::managed_identity::{self, AppRoleGrantDto, ManagedIdentityDto};
use crate::components::detail_header::DetailHeader;
use crate::components::exchange_scoping_section::{ExchangeScopeTarget, ExchangeScopingSection};
use crate::components::held_permissions_panel::HeldPermissionsPanel;
use crate::components::orgwide_scope_callout::OrgwideScopeCallout;
use crate::components::permission_picker::PickerSelection;
use crate::components::requires_role::RequiresRole;
use crate::components::scope_badge::is_exchange_scopable;
use crate::components::scope_unavailable_banner::ScopeUnavailableBanner;
use crate::components::scope_wizard::{ScopeTarget, ScopeWizard};
use crate::components::ui::{CopyableId, DataTable, DetailLoadError, SkeletonList};
use crate::state::use_session;
use crate::views::managed_identities::chip_kind_for;

#[component]
pub fn ManagedIdentityDetailPane(
    /// The selected managed identity (already resolved from the list).
    #[prop(into)]
    mi: ManagedIdentityDto,

    // Shared resources (read only) — awaited inside this component's Suspends.
    #[prop(into)] permissions: LocalResource<
        Result<Vec<AppRoleGrantDto>, azapptoolkit_dto::UiError>,
    >,
    #[prop(into)] mail_scopes: LocalResource<
        Result<HashMap<String, MailPermissionScope>, azapptoolkit_dto::UiError>,
    >,
    #[prop(into)] azure_roles: LocalResource<
        Result<managed_identity::AzureRolesResult, azapptoolkit_dto::UiError>,
    >,

    // Shared state signals (all Copy — pass the same handle, never re-wrap).
    #[prop(into)] busy: RwSignal<bool>,
    #[prop(into)] refreshing: RwSignal<bool>,
    #[prop(into)] consenting: RwSignal<bool>,
    #[prop(into)] consent_error: RwSignal<Option<String>>,
    #[prop(into)] reload: RwSignal<u32>,
    #[prop(into)] arm_reload: RwSignal<u32>,
    #[prop(into)] tenant: RwSignal<Option<TenantContext>>,
    // The identity's service-principal id, for the Azure-role assign form. A
    // `Signal` (not the old `RwSignal<selected_id>`) so each open window passes
    // its own id derived from `mi_id`, independent of any global selection.
    #[prop(into)] principal_id: Signal<Option<String>>,

    // Callbacks (all defined in the parent — this pane only invokes them).
    #[prop(into)] on_revoke: Callback<(String, String)>,
    #[prop(into)] on_refresh: Callback<()>,
) -> impl IntoView {
    let title = mi.display_name.clone();
    let mi_id = mi.id.clone();
    let mi_id_for_table = mi.id.clone();
    let mi_app_id = mi.app_id.clone();
    let mi_app_id_for_scope = mi.app_id.clone();
    let mi_name_for_scope = mi.display_name.clone();
    let mi_enabled = mi
        .account_enabled
        .map(|e| if e { "Enabled" } else { "Disabled" })
        .unwrap_or("Unknown");
    let chip_kind = chip_kind_for(mi.mi_subtype);

    // The unified "Grant access" wizard — always reachable, so the MI can be
    // granted/scoped from the start (the Exchange section only appears once it
    // holds a mail permission). A row's "Scope…" opens it pre-selected to that
    // permission (`wizard_preseed`); the header button opens it blank.
    let wizard_open = RwSignal::new(false);
    let wizard_preseed: RwSignal<Option<PickerSelection>> = RwSignal::new(None);
    let wiz_sp = mi.id.clone();
    let wiz_name = mi.display_name.clone();
    let wiz_app = mi.app_id.clone();
    let wizard_target = Signal::derive(move || ScopeTarget {
        object_id: None,
        sp_object_id: wiz_sp.clone(),
        app_id: wiz_app.clone(),
        display_name: wiz_name.clone(),
        is_managed_identity: true,
    });

    // Tabbed layout (Overview / Permissions / Azure RBAC) to match the app-reg
    // and enterprise panes — the Azure RBAC section was previously buried below
    // a long held-permissions list + grant picker. Restore the last-viewed tab
    // so it survives switching between identities.
    let session = use_session();
    let active_tab = RwSignal::new(session.last_mi_tab.get_untracked());
    Effect::new(move |_| session.last_mi_tab.set(active_tab.get()));

    view! {
        <DetailHeader
            kind=chip_kind
            title=title
            app_id=mi_app_id.clone()
            on_refresh=on_refresh
            refreshing=refreshing
        />
        // (managed identities can't be deleted from here — no on_delete passed)
        <TabList selected_value=active_tab>
            <Tab value="overview">"Overview"</Tab>
            <Tab value="permissions">"Permissions"</Tab>
            <Tab value="azure">"Azure RBAC"</Tab>
        </TabList>
        <div
            class="mi-tab"
            style:display=move || if active_tab.get() == "overview" { "block" } else { "none" }
        >
            <dl class="mi-properties">
                <dt>"Service principal id"</dt>
            <dd><CopyableId value=mi_id label="service principal id" full=true /></dd>
            <dt>"App id"</dt>
            <dd><CopyableId value=mi_app_id label="app id" full=true /></dd>
            <dt>"Status"</dt>
            <dd>{mi_enabled}</dd>
            </dl>
        </div>
        <div
            class="mi-tab"
            style:display=move || if active_tab.get() == "permissions" { "block" } else { "none" }
        >
        <div>
            <header class="row-between">
                <h4>"Current permissions"</h4>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| wizard_open.set(true))
                >
                    "Grant access"
                </Button>
            </header>
            <ScopeWizard
                open=wizard_open
                target=wizard_target
                preseed=wizard_preseed
                on_close=Callback::new(move |()| {
                    wizard_open.set(false);
                    wizard_preseed.set(None);
                })
                on_changed=Callback::new(move |()| reload.update(|n| *n += 1))
            />
            <Suspense fallback=move || view! { <SkeletonList rows=4 /> }>
                {move || {
                    let mi_sp_id = mi_id_for_table.clone();
                    let mi_app_id_row = mi_app_id_for_scope.clone();
                    let mi_name_row = mi_name_for_scope.clone();
                    Suspend::new(async move {
                    match permissions.await {
                        Ok(list) => {
                            // Effective Exchange mailbox scoping for the MI's
                            // mail permissions (resolved in its own resource).
                            // An error (genuine 403/consent) drives the banner
                            // below; the empty map then paints cells "Unknown",
                            // now accurate since scoping couldn't be determined.
                            let scope_result = mail_scopes.await;
                            let scope_error =
                                scope_result.as_ref().err().cloned();
                            let scope_map =
                                scope_result.unwrap_or_default();
                            // Scoping unavailable (a genuine 403/consent gap —
                            // the EXO "Role Management" RBAC role is missing, or
                            // Exchange.ManageAsApp isn't consented): explain +
                            // offer consent/retry, via the shared banner.
                            let scope_banner = scope_error.map(|e| {
                                view! {
                                    <ScopeUnavailableBanner
                                        error=e
                                        on_retry=Callback::new(move |()| {
                                            reload.update(|n| *n += 1)
                                        })
                                    />
                                }
                            });
                            // Revoke a held grant (generic app-role
                            // assignment delete) and open the inline scope
                            // panel for a restrictable permission — the same
                            // panel the grant flow uses. Same `sp`/`app`/`name`
                            // for every row (one identity), so built once here.
                            let on_revoke = Callback::new({
                                let sp = mi_sp_id.clone();
                                move |aid: String| on_revoke.run((aid, sp.clone()))
                            });
                            // A held org-wide Sites.* row's "Scope…" opens the
                            // wizard pre-selected to that permission.
                            let on_scope = Callback::new(move |sel: PickerSelection| {
                                wizard_preseed.set(Some(sel));
                                wizard_open.set(true);
                            });
                            // App-wide Exchange scoping for the MI's held mail
                            // permissions (mirrors the enterprise pane). Mail
                            // scoping is app-wide — a single management scope binds
                            // the whole principal's mail roles — so it lives here,
                            // not on a per-row "Scope…" button. Shown only when the
                            // MI holds a scopable mail permission; the `reload` bump
                            // refetches the held list + scope verdicts after a grant.
                            let mail_values: Vec<String> = list
                                .iter()
                                .filter_map(|p| p.app_role_value.clone())
                                .filter(|v| is_exchange_scopable(v))
                                .collect();
                            let exchange_section = (!mail_values.is_empty())
                                .then(move || {
                                    view! {
                                        <ExchangeScopingSection
                                            app_id=Signal::derive(move || mi_app_id_row.clone())
                                            target=Signal::derive(move || {
                                                ExchangeScopeTarget::ServicePrincipal {
                                                    sp_object_id: mi_sp_id.clone(),
                                                    display_name: mi_name_row.clone(),
                                                    mail_permissions: mail_values.clone(),
                                                    is_managed_identity: true,
                                                }
                                            })
                                            on_changed=Callback::new(move |()| {
                                                reload.update(|n| *n += 1)
                                            })
                                        />
                                    }
                                });
                            view! {
                                {scope_banner}
                                // Org-wide discoverability callout — same shared
                                // component as the enterprise pane (both are bare
                                // SPs; mail has no per-row "Scope…").
                                <OrgwideScopeCallout
                                    permissions=list.clone()
                                    scope_map=scope_map.clone()
                                    on_scope=on_scope
                                />
                                <HeldPermissionsPanel
                                    permissions=list
                                    scope_map=scope_map
                                    show_scope_column=true
                                    on_revoke=on_revoke
                                    on_scope=on_scope
                                    busy=Signal::derive(move || busy.get())
                                />
                                {exchange_section}
                            }
                                .into_any()
                        }
                        Err(e) => {
                            view! { <DetailLoadError error=e reload=reload /> }.into_any()
                        }
                    }
                    })
                }}
            </Suspense>
        </div>
        </div>
        <div
            class="mi-tab"
            style:display=move || if active_tab.get() == "azure" { "block" } else { "none" }
        >
        <div>
            <h4>"Azure RBAC roles"</h4>
            <AssignAzureRolePanel
                tenant_id=Signal::derive(move || {
                    tenant.get().map(|t| t.tenant_id)
                })
                principal_id=principal_id
                on_assigned=Callback::new(move |()| {
                    arm_reload.update(|n| *n += 1)
                })
            />
            <Suspense fallback=move || view! { <SkeletonList rows=4 /> }>
                {move || Suspend::new(async move {
                    match azure_roles.await {
                        // The signed-in user (or tenant admin) hasn't
                        // consented to ARM yet. Offer to run interactive
                        // incremental consent, then the resource re-runs.
                        Err(e) if e.code == "consent_required" => {
                            let on_consent = move |_| {
                                if consenting.get() {
                                    return;
                                }
                                let Some(t) = tenant.get() else {
                                    return;
                                };
                                consenting.set(true);
                                consent_error.set(None);
                                leptos::task::spawn_local(async move {
                                    match auth_bindings::request_scope_consent(
                                            &t.tenant_id,
                                            "arm",
                                        )
                                        .await
                                    {
                                        Ok(()) => arm_reload.update(|n| *n += 1),
                                        Err(e) => consent_error.set(Some(e.message)),
                                    }
                                    consenting.set(false);
                                });
                            };
                            view! {
                                <div class="alert alert--warn">
                                    <p>
                                        "Azure RBAC needs your consent to read Azure Service Management (management.azure.com). Granting opens your browser once."
                                    </p>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(on_consent)
                                        disabled=Signal::derive(move || consenting.get())
                                    >
                                        "Grant access"
                                    </Button>
                                    {move || {
                                        consent_error
                                            .get()
                                            .map(|m| view! { <Body1 class="form-error">{m}</Body1> })
                                    }}
                                </div>
                            }
                                .into_any()
                        }
                        Err(_) => {
                            view! {
                                <div class="alert alert--warn">
                                    "Azure RBAC is unavailable — it needs consent to Azure Service Management (management.azure.com) and an Azure subscription you can read."
                                </div>
                            }
                                .into_any()
                        }
                        Ok(res) => {
                            // Warn when the scan was partial — an identity
                            // shown with no high-privilege roles could be Owner
                            // on an unscanned/unreadable subscription, so a
                            // partial view must never read as authoritative.
                            let coverage = (res.scanned < res.total
                                || res.skipped > 0)
                                .then(|| {
                                    let mut parts = Vec::new();
                                    if res.scanned < res.total {
                                        parts
                                            .push(format!(
                                                "scanned {} of {} subscriptions (capped)",
                                                res.scanned, res.total,
                                            ));
                                    }
                                    if res.skipped > 0 {
                                        parts
                                            .push(format!(
                                                "{} unreadable and skipped",
                                                res.skipped,
                                            ));
                                    }
                                    let msg = format!(
                                        "Partial view — {}. Roles on subscriptions not scanned aren't shown.",
                                        parts.join("; "),
                                    );
                                    view! { <div class="alert alert--warn">{msg}</div> }
                                });
                            view! {
                                {coverage}
                                <DataTable
                                    headers=vec!["Role", "Scope", "Subscription"]
                                    rows=res.roles
                                    empty_message="No Azure role assignments found for this identity."
                                    row=|r: managed_identity::AzureRoleDto| {
                                        let badge = r
                                            .high_privilege
                                            .then(|| {
                                                view! {
                                                    <span class="badge badge--danger">"High"</span>
                                                }
                                            });
                                        view! {
                                            <tr>
                                                <td title=r.scope.clone()>
                                                    {r.role_name.clone()} {badge}
                                                </td>
                                                <td>{r.scope_level.clone()}</td>
                                                <td>{r.subscription.clone()}</td>
                                            </tr>
                                        }
                                            .into_any()
                                    }
                                />
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
        </div>
    }
}

/// Common built-in Azure RBAC roles (display name → role-definition GUID). These
/// GUIDs are the same across every subscription; the backend expands them to the
/// subscription-scoped role-definition path for the chosen scope.
const COMMON_AZURE_ROLES: &[(&str, &str)] = &[
    ("Reader", "acdd72a7-3385-48ef-bd42-f606fba81ae7"),
    ("Contributor", "b24988ac-6180-42a0-ab88-20f7382dd24c"),
    ("Owner", "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"),
    (
        "User Access Administrator",
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    ),
    (
        "Storage Blob Data Reader",
        "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
    ),
    (
        "Storage Blob Data Contributor",
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    ),
    (
        "Key Vault Secrets User",
        "4633458b-17de-408a-b874-0445c86b69e6",
    ),
    (
        "Key Vault Secrets Officer",
        "b86a8fe4-44ce-4948-aee5-eccb2c155cd6",
    ),
];

/// Inline form to create an Azure RBAC role assignment for the selected managed
/// identity (`Microsoft.Authorization/roleAssignments` PUT). Collapsed by
/// default; on success it calls `on_assigned` so the parent re-reads the roles.
#[component]
fn AssignAzureRolePanel(
    #[prop(into)] tenant_id: Signal<Option<String>>,
    #[prop(into)] principal_id: Signal<Option<String>>,
    #[prop(into)] on_assigned: Callback<()>,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let role = RwSignal::new(COMMON_AZURE_ROLES[0].1.to_string());
    let scope = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let submit = move |_| {
        if busy.get() {
            return;
        }
        let (Some(tid), Some(pid)) = (tenant_id.get(), principal_id.get()) else {
            return;
        };
        let scope_v = scope.get().trim().to_string();
        if scope_v.is_empty() {
            error.set(Some(
                "Enter a scope, e.g. /subscriptions/<id> or a resource path.".into(),
            ));
            return;
        }
        let role_v = role.get();
        busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            match managed_identity::assign_managed_identity_azure_role(
                &tid, &scope_v, &role_v, &pid,
            )
            .await
            {
                Ok(()) => {
                    open.set(false);
                    scope.set(String::new());
                    on_assigned.run(());
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="assign-azure-role">
            <Show
                when=move || open.get()
                fallback=move || {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| open.set(true))
                            disabled=Signal::derive(move || principal_id.get().is_none())
                        >
                            "+ Assign Azure role"
                        </Button>
                    }
                }
            >
                {
                    let submit = submit;
                    view! {
                        <div class="form-grid">
                            <RequiresRole capability_key="azure_role_assign" />
                            <div class="read-field">
                                <strong>"Role"</strong>
                                <Select value=role>
                                    {COMMON_AZURE_ROLES
                                        .iter()
                                        .map(|(name, guid)| {
                                            view! { <option value=*guid>{*name}</option> }
                                        })
                                        .collect_view()}
                                </Select>
                            </div>
                            <div class="read-field">
                                <strong>"Scope (/subscriptions/<id>[/resourceGroups/<rg>])"</strong>
                                <Input value=scope />
                            </div>
                            {move || {
                                error.get().map(|m| view! { <Body1 class="form-error">{m}</Body1> })
                            }}
                            <div class="actions-row">
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(submit)
                                    disabled=Signal::derive(move || busy.get())
                                >
                                    {move || {
                                        if busy.get() {
                                            view! {
                                                <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                            }
                                                .into_any()
                                        } else {
                                            view! { "Assign" }.into_any()
                                        }
                                    }}
                                </Button>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(move |_| open.set(false))
                                    disabled=Signal::derive(move || busy.get())
                                >
                                    "Cancel"
                                </Button>
                            </div>
                        </div>
                    }
                }
            </Show>
        </div>
    }
}
