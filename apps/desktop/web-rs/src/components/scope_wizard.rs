//! "Grant scoped access" wizard — one guided flow to confine a Graph application
//! permission to specific resources, dispatching on the scoping mechanism
//! (`azapptoolkit_core::scoping::ScopeKind`). The UX shell is uniform — pick
//! permissions → choose targets → review & grant — while Step 2's target panel
//! and Step 3's apply call vary per mechanism:
//!
//! - **Exchange RBAC** (mail/calendar/contacts) → confine to a mailbox group;
//!   declare-only (no org-wide Entra grant is ever created), access comes from the
//!   scoped RBAC role assignment.
//! - **SharePoint** (`Sites.*`) → confine to specific sites via `Sites.Selected`
//!   (`convert_site_access_to_selected` grants the narrow role + per-site access
//!   and strips the broad grant).
//!
//! A de-emphasized org-wide option stays for the rare permission that needs
//! tenant-wide reach. **One mechanism per run** — picking a permission locks the
//! checklist to its mechanism (scope the other mechanism in a separate pass).
//! Opening with `preseed = Some(value)` jumps straight to the target step for that
//! permission (the per-row "Scope…" entry).

use std::collections::HashMap;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize, Textarea};

use crate::bindings::exchange::{self, ExchangeScopeGroupDto};
use crate::bindings::{auth, managed_identity, permissions, sharepoint};
use crate::components::group_autocomplete::GroupAutocomplete;
use crate::components::managed_scope_group_panel::ManagedScopeGroupPanel;
use crate::components::requires_role::RequiresRole;
use crate::components::site_selection_panel::SiteSelectionPanel;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;
use crate::util::parse_lines;
use azapptoolkit_core::scoping::{scope_kind, ScopeKind};
use azapptoolkit_dto::permissions::PermissionKind;
use azapptoolkit_dto::UiError;

/// Microsoft Graph's well-known resource appId — the resource every scopable
/// application permission here lives on.
const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// Everything the wizard needs about the principal, across mechanisms.
/// `object_id` is the app-registration object id (drives the Exchange
/// declare-only manifest path) — `None` for a bare service principal (enterprise
/// app / managed identity). `sp_object_id` receives `Sites.Selected` / scoped
/// roles and is always required.
#[derive(Clone, Default)]
pub struct ScopeTarget {
    pub object_id: Option<String>,
    pub sp_object_id: String,
    pub app_id: String,
    pub display_name: String,
    pub is_managed_identity: bool,
}

/// The Exchange-scopable mail permissions shown first (the common case).
const PRIMARY_PERMS: &[(&str, &str)] = &[
    ("Mail.Read", "Read mail"),
    ("Mail.ReadWrite", "Read and write mail"),
    ("Mail.Send", "Send mail as the mailbox"),
];

/// Additional Exchange-scopable permissions behind the "More" expander.
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

/// The SharePoint `Sites.*` permissions, scopable via `Sites.Selected`.
const SHAREPOINT_PERMS: &[(&str, &str)] = &[
    ("Sites.Read.All", "Read items in site collections"),
    (
        "Sites.ReadWrite.All",
        "Read and write items in site collections",
    ),
    (
        "Sites.Manage.All",
        "Manage lists and items in site collections",
    ),
    ("Sites.FullControl.All", "Full control of site collections"),
];

/// How step 2 confines (or doesn't) the granted permissions. Which options apply
/// depends on the inferred mechanism (Managed/Existing for Exchange, Sites for
/// SharePoint; OrgWide for both).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeMode {
    Managed,
    Existing,
    Sites,
    OrgWide,
}

/// The default scope mode for a mechanism (the recommended scoped path).
fn default_mode(kind: ScopeKind) -> ScopeMode {
    match kind {
        ScopeKind::Exchange => ScopeMode::Managed,
        ScopeKind::SharePoint => ScopeMode::Sites,
    }
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

fn exchange_summary(r: &exchange::ExchangeAccessResult) -> String {
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

fn sharepoint_summary(r: &sharepoint::SiteScopeResult) -> String {
    let mut s = format!(
        "Scoped to {} site(s), removed {} org-wide grant(s).",
        r.sites_granted.len(),
        r.removed_orgwide_grants.len(),
    );
    if !r.warnings.is_empty() {
        s.push_str(&format!(" {} warning(s).", r.warnings.len()));
    }
    s
}

/// Exchange scoped path: declare each permission without an org-wide grant (app
/// registration only), then assign the scoped Exchange RBAC roles + strip any
/// org-wide grant so scoping bites.
async fn apply_exchange_scoped(
    tenant_id: String,
    target: ScopeTarget,
    perms: Vec<String>,
    groups: Vec<String>,
) -> Result<String, UiError> {
    if let Some(object_id) = &target.object_id {
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
                object_id,
                GRAPH_APP_ID,
                id,
                PermissionKind::Application,
            )
            .await?;
        }
        let r = exchange::grant_exchange_mailbox_access(
            &tenant_id,
            object_id,
            Some(&perms),
            &groups,
            true,
        )
        .await?;
        Ok(exchange_summary(&r))
    } else {
        let r = exchange::grant_managed_identity_scoped_exchange_access(
            &tenant_id,
            &target.sp_object_id,
            &target.app_id,
            &target.display_name,
            &perms,
            &groups,
            true,
        )
        .await?;
        Ok(exchange_summary(&r))
    }
}

/// SharePoint scoped path: grant `Sites.Selected` + per-site access on the given
/// sites and strip the org-wide `Sites.*` grant (`convert_site_access_to_selected`
/// handles the grant-before-strip ordering).
async fn apply_sharepoint_scoped(
    tenant_id: String,
    target: ScopeTarget,
    site_urls: Vec<String>,
    role: &'static str,
) -> Result<String, UiError> {
    if target.sp_object_id.is_empty() {
        return Err(UiError::validation(
            "no_service_principal",
            "This app has no service principal yet — create one before scoping site access.",
        ));
    }
    let r = sharepoint::convert_site_access_to_selected(
        &tenant_id,
        &target.sp_object_id,
        &target.app_id,
        &target.display_name,
        &site_urls,
        role,
        true,
    )
    .await?;
    Ok(sharepoint_summary(&r))
}

/// Rare path: grant the permissions org-wide (no scoping). Mechanism-agnostic —
/// app registrations go through `grant_single_permission` per value; bare service
/// principals get a single app-role grant by value.
async fn apply_orgwide(
    tenant_id: String,
    target: ScopeTarget,
    perms: Vec<String>,
) -> Result<String, UiError> {
    if let Some(object_id) = &target.object_id {
        let ids = graph_app_role_ids(&tenant_id).await?;
        let mut failures: Vec<String> = Vec::new();
        for p in &perms {
            let Some(id) = ids.get(p) else {
                failures.push(format!("{p}: not a Graph application permission"));
                continue;
            };
            match permissions::grant_single_permission(
                &tenant_id,
                object_id,
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
    } else {
        let r = managed_identity::grant_managed_identity_permission(
            &tenant_id,
            &target.sp_object_id,
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

#[component]
pub fn ScopeWizard(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] target: Signal<ScopeTarget>,
    /// When set on open, pre-selects this permission and jumps to the target step
    /// (the per-row "Scope…" entry). `None` opens a blank pick step.
    #[prop(into)]
    preseed: Signal<Option<String>>,
    #[prop(into)] on_close: Callback<()>,
    /// Fired after a successful grant so the host refreshes detail + scope badges.
    #[prop(into)]
    on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let app_id = Signal::derive(move || target.with(|t| t.app_id.clone()));

    let step = RwSignal::new(0u8);
    let selected: RwSignal<Vec<String>> = RwSignal::new(Vec::new());
    let show_more = RwSignal::new(false);
    let scope_mode = RwSignal::new(ScopeMode::Managed);

    // Exchange target state.
    let existing_groups = RwSignal::new(String::new());
    let group_state: RwSignal<Option<Result<ExchangeScopeGroupDto, UiError>>> = RwSignal::new(None);
    // SharePoint target state.
    let site_urls = RwSignal::new(String::new());
    let site_write = RwSignal::new(false);

    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let needs_consent = RwSignal::new(false);

    // The single mechanism this run scopes — inferred from the first picked
    // permission (the checklist locks to it).
    let mechanism =
        Signal::derive(move || selected.with(|s| s.first().and_then(|v| scope_kind(v))));

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
        site_urls.set(String::new());
        site_write.set(false);
        busy.set(false);
        error.set(None);
        needs_consent.set(false);
    };
    let close = move || {
        reset();
        on_close.run(());
    };

    // Pre-seed on open: a row "Scope…" opens the wizard with one permission
    // already chosen, jumping to the target step for its mechanism.
    Effect::new(move |_| {
        if open.get() {
            if let Some(v) = preseed.get_untracked() {
                if let Some(k) = scope_kind(&v) {
                    if k == ScopeKind::SharePoint {
                        site_write.set(v != "Sites.Read.All");
                    }
                    scope_mode.set(default_mode(k));
                    selected.set(vec![v]);
                    step.set(1);
                }
            }
        }
    });

    let toggle = move |value: String| {
        selected.update(|s| {
            if let Some(pos) = s.iter().position(|v| v == &value) {
                s.remove(pos);
            } else {
                s.push(value.clone());
            }
        });
        // Entering SharePoint mode: default the role from the picked permission.
        if scope_kind(&value) == Some(ScopeKind::SharePoint) {
            site_write.set(value != "Sites.Read.All");
        }
        // Re-anchor the scope mode to the (possibly new) mechanism's default.
        if let Some(k) = selected.with_untracked(|s| s.first().and_then(|v| scope_kind(v))) {
            scope_mode.set(default_mode(k));
        }
        error.set(None);
    };

    // A checklist row is disabled once a different mechanism is locked in.
    let locked_out = move |value: &str| {
        mechanism
            .get()
            .is_some_and(|m| Some(m) != scope_kind(value))
    };

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
        let Some(kind) = mechanism.get_untracked() else {
            return;
        };
        let mode = scope_mode.get_untracked();
        let tenant_id = t.tenant_id.clone();
        let target = target.get_untracked();

        // Resolve targets for the scoped modes up front so a missing selection
        // fails fast with a clear message.
        enum Plan {
            ExchangeScoped(Vec<String>),
            SharePointScoped(Vec<String>, &'static str),
            OrgWide,
        }
        let plan = match (kind, mode) {
            (_, ScopeMode::OrgWide) => Plan::OrgWide,
            (ScopeKind::Exchange, ScopeMode::Managed) => match group_state.get_untracked() {
                Some(Ok(g)) if g.exists => Plan::ExchangeScoped(vec![g
                    .primary_smtp_address
                    .clone()
                    .unwrap_or(g.group_name.clone())]),
                _ => {
                    error.set(Some(
                        "Add at least one mailbox to the managed group first — that creates the group to scope to.".into(),
                    ));
                    return;
                }
            },
            (ScopeKind::Exchange, ScopeMode::Existing) => {
                let g = parse_lines(&existing_groups.get_untracked());
                if g.is_empty() {
                    error.set(Some(
                        "Enter at least one group identifier (one per line).".into(),
                    ));
                    return;
                }
                Plan::ExchangeScoped(g)
            }
            (ScopeKind::SharePoint, ScopeMode::Sites) => {
                let urls = parse_lines(&site_urls.get_untracked());
                if urls.is_empty() {
                    error.set(Some("Enter at least one site URL (one per line).".into()));
                    return;
                }
                let role = if site_write.get_untracked() {
                    "write"
                } else {
                    "read"
                };
                Plan::SharePointScoped(urls, role)
            }
            _ => return,
        };

        busy.set(true);
        error.set(None);
        needs_consent.set(false);
        leptos::task::spawn_local(async move {
            let res = match plan {
                Plan::OrgWide => apply_orgwide(tenant_id, target, perms).await,
                Plan::ExchangeScoped(groups) => {
                    apply_exchange_scoped(tenant_id, target, perms, groups).await
                }
                Plan::SharePointScoped(urls, role) => {
                    apply_sharepoint_scoped(tenant_id, target, urls, role).await
                }
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

    // Grant the admin scope consent the mechanism needs, then retry the apply.
    let consent_and_retry = move |_| {
        if busy.get_untracked() {
            return;
        }
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        let scope = match mechanism.get_untracked() {
            Some(ScopeKind::SharePoint) => "sharepoint",
            _ => "exchange",
        };
        busy.set(true);
        error.set(None);
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&tenant_id, scope).await {
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

    let step0_ready = move || selected.with(|s| !s.is_empty());

    let review_line = move || {
        let perms = selected.get().join(", ");
        match scope_mode.get() {
            ScopeMode::OrgWide => format!(
                "Grant {perms} org-wide. The app will reach EVERY resource in the tenant — use only when the permission genuinely needs tenant-wide reach.",
            ),
            ScopeMode::Managed | ScopeMode::Existing => format!(
                "Grant {perms}, scoped to the chosen mailbox group(s). The app will not have org-wide mailbox access.",
            ),
            ScopeMode::Sites => format!(
                "Grant {perms}, scoped to the chosen site(s) via Sites.Selected. The app will not have org-wide site access.",
            ),
        }
    };

    let perm_checklist = move |perms: &'static [(&'static str, &'static str)]| {
        perms
            .iter()
            .map(|(value, label)| {
                let v = value.to_string();
                let v2 = value.to_string();
                let v3 = value.to_string();
                view! {
                    <label class="checkbox-row">
                        <input
                            type="checkbox"
                            prop:checked=move || selected.with(|s| s.iter().any(|x| x == &v))
                            prop:disabled=move || locked_out(&v3)
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
                aria-labelledby="scope-wizard-title"
            >
                <div class="modal modal--wide" node_ref=modal_ref>
                    <h3 id="scope-wizard-title">"Grant scoped access"</h3>
                    <div class="sso-wizard__steps">
                        <Body1 class="hint">
                            {move || match step.get() {
                                0 => "Step 1 of 3 — Permissions",
                                1 => "Step 2 of 3 — Targets",
                                _ => "Step 3 of 3 — Review & grant",
                            }}
                        </Body1>
                    </div>

                    // ---- Step 0: permissions ----
                    <Show when=move || step.get() == 0 fallback=|| ()>
                        <Body1 class="hint">
                            "Choose the permissions to grant. You'll confine them to specific mailboxes or sites next; once you pick one, the rest lock to that mechanism (scope the other separately)."
                        </Body1>
                        <strong>"Mailbox access"</strong>
                        <div class="checkbox-list">{move || perm_checklist(PRIMARY_PERMS)}</div>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                            on_click=Box::new(move |_| show_more.update(|m| *m = !*m))
                        >
                            {move || if show_more.get() { "Fewer mailbox permissions" } else { "More mailbox permissions" }}
                        </Button>
                        <Show when=move || show_more.get() fallback=|| ()>
                            <div class="checkbox-list">{move || perm_checklist(MORE_PERMS)}</div>
                        </Show>
                        <strong>"SharePoint site access"</strong>
                        <div class="checkbox-list">{move || perm_checklist(SHAREPOINT_PERMS)}</div>
                    </Show>

                    // ---- Step 1: targets (dispatched on mechanism) ----
                    <Show when=move || step.get() == 1 fallback=|| ()>
                        <Show
                            when=move || mechanism.get() == Some(ScopeKind::Exchange)
                            fallback=|| ()
                        >
                            <label class="radio-row">
                                <input
                                    type="radio"
                                    name="scope-mode"
                                    prop:checked=move || scope_mode.get() == ScopeMode::Managed
                                    on:change=move |_| scope_mode.set(ScopeMode::Managed)
                                />
                                <span><strong>"Specific mailboxes"</strong> " (recommended)"</span>
                            </label>
                            <Show when=move || scope_mode.get() == ScopeMode::Managed fallback=|| ()>
                                <ManagedScopeGroupPanel app_id=app_id group_state=group_state />
                            </Show>
                            <label class="radio-row">
                                <input
                                    type="radio"
                                    name="scope-mode"
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
                        </Show>

                        <Show
                            when=move || mechanism.get() == Some(ScopeKind::SharePoint)
                            fallback=|| ()
                        >
                            <Show when=move || scope_mode.get() == ScopeMode::Sites fallback=|| ()>
                                <SiteSelectionPanel site_urls=site_urls write=site_write />
                            </Show>
                        </Show>

                        <label class="radio-row">
                            <input
                                type="radio"
                                name="scope-mode"
                                prop:checked=move || scope_mode.get() == ScopeMode::OrgWide
                                on:change=move |_| scope_mode.set(ScopeMode::OrgWide)
                            />
                            <span class="muted">"Org-wide — no scoping (rare)"</span>
                        </label>
                        <Show when=move || scope_mode.get() == ScopeMode::OrgWide fallback=|| ()>
                            <div class="alert alert--warn">
                                <Body1>
                                    "The app will reach every resource in the tenant. Only choose this when the permission genuinely needs tenant-wide reach."
                                </Body1>
                            </div>
                        </Show>
                        {move || {
                            mechanism
                                .get()
                                .map(|k| view! { <RequiresRole capability_key=k.capability_key() /> })
                        }}
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
                                            "Scoping needs an admin consent for this mechanism."
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
