//! "Grant access" wizard — one guided flow to grant Graph permissions and,
//! where the mechanism allows, confine them to specific resources. The shell is
//! uniform — **select permissions → choose access → review & grant** — while the
//! "choose access" step's target panel and the apply call vary by scoping
//! mechanism (`azapptoolkit_core::scoping::ScopeKind`):
//!
//! - **Exchange RBAC** (mail/calendar/contacts) → confine to a mailbox group;
//!   declare-only (no org-wide Entra grant is ever created), access comes from the
//!   scoped RBAC role assignment.
//! - **SharePoint** (`Sites.*`) → confine to specific sites via `Sites.Selected`
//!   (`convert_site_access_to_selected` grants the narrow role + per-site access
//!   and strips the broad grant).
//! - **SharePoint item** (`Lists.`/`ListItems.`/`Files.SelectedOperations.Selected`)
//!   → confine to specific libraries, folders or files
//!   (`grant_selected_item_access`). Strips nothing: these scopes have no
//!   org-wide predecessor — they are least-privilege from the start.
//!
//! Step 1 is the full live permission catalog (the [`PermissionPicker`]) as a
//! multi-select cart, so any permission — scopable or not — can be granted from
//! here. Scoped targets are offered **only** when the whole cart is one scopable
//! mechanism (all mailbox, or all SharePoint); mixed / non-scopable / delegated
//! selections grant org-wide. **One mechanism per run.** Opening with
//! `preseed = Some(selection)` seeds the cart with that one permission and jumps
//! to the choose-access step (the per-row "Scope…" entry).

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize, Textarea};

use crate::bindings::exchange::{self, ExchangeScopeGroupDto};
use crate::bindings::{auth, managed_identity, permissions, sharepoint};
use crate::components::group_autocomplete::GroupAutocomplete;
use crate::components::item_selection_panel::ItemSelectionPanel;
use crate::components::managed_scope_group_panel::ManagedScopeGroupPanel;
use crate::components::permission_picker::{PermissionPicker, PickerMode, PickerSelection};
use crate::components::requires_role::RequiresRole;
use crate::components::site_selection_panel::SiteSelectionPanel;
use crate::components::ui::Callout;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;
use crate::util::parse_lines;
use azapptoolkit_core::scoping::{
    ScopeKind, SelectedScopeLevel, scope_kind_for, selected_scope_level_for,
};
use azapptoolkit_dto::UiError;
use azapptoolkit_dto::permissions::PermissionKind;

/// Everything the wizard needs about the principal, across mechanisms.
/// `object_id` is the app-registration object id (drives the Exchange
/// declare-only manifest path, and enables delegated permissions) — `None` for a
/// bare service principal (enterprise app / managed identity), whose org-wide
/// grants are app-role-only. `sp_object_id` receives `Sites.Selected` / scoped
/// roles and is always required.
#[derive(Clone, Default)]
pub struct ScopeTarget {
    pub object_id: Option<String>,
    pub sp_object_id: String,
    pub app_id: String,
    pub display_name: String,
    pub is_managed_identity: bool,
}

/// How step 2 confines (or doesn't) the granted permissions. Which options apply
/// depends on the inferred mechanism (Managed/Existing for Exchange, Sites for
/// SharePoint; OrgWide for both, and the only option when the cart isn't
/// homogeneously scopable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeMode {
    Managed,
    Existing,
    Sites,
    Items,
    OrgWide,
}

/// The default scope mode for a mechanism (the recommended scoped path).
fn default_mode(kind: ScopeKind) -> ScopeMode {
    match kind {
        ScopeKind::Exchange => ScopeMode::Managed,
        ScopeKind::SharePoint => ScopeMode::Sites,
        ScopeKind::SharePointItem => ScopeMode::Items,
    }
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
    if r.declared_permission {
        s.push_str(" Added Sites.Selected to the app registration.");
    }
    if !r.warnings.is_empty() {
        s.push_str(&format!(" {} warning(s).", r.warnings.len()));
    }
    s
}

fn sharepoint_item_summary(r: &sharepoint::SelectedItemScopeResult) -> String {
    let mut s = format!("Scoped to {} resource(s).", r.granted.len());
    if r.granted_role_added {
        s.push_str(" Granted the Selected permission.");
    }
    if r.declared_permission {
        s.push_str(" Added it to the app registration.");
    }
    if !r.warnings.is_empty() {
        s.push_str(&format!(" {} warning(s).", r.warnings.len()));
    }
    s
}

/// Comma-joined permission values for the review line / summaries.
fn perm_values(items: &[PickerSelection]) -> Vec<String> {
    items.iter().map(|i| i.permission_value.clone()).collect()
}

/// Exchange scoped path: declare each permission without an org-wide grant (app
/// registration only) — using the id the cart already carries — then assign the
/// scoped Exchange RBAC roles + strip any org-wide grant so scoping bites.
async fn apply_exchange_scoped(
    tenant_id: String,
    target: ScopeTarget,
    items: Vec<PickerSelection>,
    groups: Vec<String>,
) -> Result<String, UiError> {
    let perms = perm_values(&items);
    if let Some(object_id) = &target.object_id {
        for item in &items {
            permissions::declare_app_permission(
                &tenant_id,
                object_id,
                &item.resource_app_id,
                &item.permission_id,
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
/// SharePoint per-item path: grant the Selected appRole plus per-resource
/// access on each target.
///
/// No org-wide strip, deliberately — unlike the site path there is no broad
/// grant to convert away from. A `Files.SelectedOperations.Selected` grant
/// starts confined, so "remove the org-wide grant" has nothing to remove and a
/// caller passing `remove_orgwide` would be describing a different flow.
async fn apply_sharepoint_item_scoped(
    tenant_id: String,
    target: ScopeTarget,
    target_urls: Vec<String>,
    role: &'static str,
    permission_value: String,
) -> Result<String, UiError> {
    if target.sp_object_id.is_empty() {
        return Err(UiError::validation(
            "no_service_principal",
            "This app has no service principal yet — create one before scoping resource access.",
        ));
    }
    let r = sharepoint::grant_selected_item_access(
        &tenant_id,
        &target.sp_object_id,
        target.object_id.as_deref(),
        &target.app_id,
        &target.display_name,
        &permission_value,
        &target_urls,
        role,
    )
    .await?;
    Ok(sharepoint_item_summary(&r))
}

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
        target.object_id.as_deref(),
        &target.app_id,
        &target.display_name,
        &site_urls,
        role,
        true,
    )
    .await?;
    Ok(sharepoint_summary(&r))
}

/// Org-wide path: grant the permissions with tenant-wide reach (no scoping).
/// App registrations grant each `(resource, permission, kind)` directly — so any
/// resource and delegated scopes work. Bare service principals get app-role
/// grants by value, one call per resource.
async fn apply_orgwide(
    tenant_id: String,
    target: ScopeTarget,
    items: Vec<PickerSelection>,
) -> Result<String, UiError> {
    if let Some(object_id) = &target.object_id {
        let mut failures: Vec<String> = Vec::new();
        for item in &items {
            match permissions::grant_single_permission(
                &tenant_id,
                object_id,
                &item.resource_app_id,
                &item.permission_id,
                item.kind,
            )
            .await
            {
                Ok(r) => failures.extend(r.failures.into_iter().map(|f| f.message)),
                Err(e) => return Err(e),
            }
        }
        let mut s = format!("Granted {} permission(s) org-wide.", items.len());
        if !failures.is_empty() {
            s.push_str(&format!(
                " {} issue(s): {}",
                failures.len(),
                failures.join("; ")
            ));
        }
        Ok(s)
    } else {
        // Bare SP: app-role grants only, grouped by resource (one call each).
        let mut by_resource: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for item in &items {
            by_resource
                .entry(item.resource_app_id.clone())
                .or_default()
                .push(item.permission_value.clone());
        }
        let (mut granted, mut skipped) = (0usize, 0usize);
        let mut failures: Vec<String> = Vec::new();
        for (resource, values) in &by_resource {
            let r = managed_identity::grant_managed_identity_permission(
                &tenant_id,
                &target.sp_object_id,
                resource,
                values,
            )
            .await?;
            granted += r.granted.len();
            skipped += r.skipped.len();
            failures.extend(r.failures);
        }
        let mut s = format!("Granted {granted} permission(s) org-wide");
        if skipped > 0 {
            s.push_str(&format!(", {skipped} already present"));
        }
        s.push('.');
        if !failures.is_empty() {
            s.push_str(&format!(
                " {} issue(s): {}",
                failures.len(),
                failures.join("; ")
            ));
        }
        Ok(s)
    }
}

/// The single scoping mechanism this cart can apply, or `None` for org-wide.
///
/// `Some(k)` only when the cart is non-empty **and** every item is an
/// Application permission resolving to the same [`ScopeKind`] on its own
/// resource. A delegated scope, a mixed cart, or anything unscopable forces
/// `None` — the wizard then offers org-wide only, because there is no single
/// apply path that would honour every item.
///
/// A free function so the rule is testable without mounting the wizard: it
/// decides whether a scoped apply is offered at all, and getting it wrong
/// either hides a scoping the operator can perform or offers one that silently
/// leaves half the cart org-wide.
fn cart_mechanism(cart: &[PickerSelection]) -> Option<ScopeKind> {
    if cart.is_empty() {
        return None;
    }
    let mut kind: Option<ScopeKind> = None;
    for item in cart {
        if item.kind != PermissionKind::Application {
            return None;
        }
        // Resource-aware: `PickerSelection` carries the resource the permission
        // was picked on, and only Graph's mail family and `Sites.*` can actually
        // be confined. Inferring from the value alone offered an apply step that
        // would leave the grant org-wide on the legacy resource.
        let k = scope_kind_for(Some(&item.resource_app_id), &item.permission_value)?;
        match kind {
            None => kind = Some(k),
            Some(prev) if prev == k => {}
            // Two mechanisms have two apply paths and two target types; there
            // is no single scoped apply that honours both.
            _ => return None,
        }
    }
    // Within the item mechanism the *level* must agree too. `Lists.*` grants
    // against a library and `Files.*` against an item inside one — two
    // securables, two endpoints — so a cart holding both has no single target
    // panel to show and falls back to org-wide, exactly as a mixed-mechanism
    // cart does. One level is what makes the resolved-target preview meaningful.
    if kind == Some(ScopeKind::SharePointItem) && cart_level(cart).is_none() {
        return None;
    }
    kind
}

/// The single [`SelectedScopeLevel`] every item in the cart grants at, or `None`
/// when the cart is empty, mixed, or holds something that isn't a sub-site
/// Selected scope.
///
/// Also the level the target panel checks resolved URLs against, so the
/// wizard's "can this be scoped" question and its "can this URL be granted"
/// question are answered from one place.
fn cart_level(cart: &[PickerSelection]) -> Option<SelectedScopeLevel> {
    let mut level: Option<SelectedScopeLevel> = None;
    for item in cart {
        let l = selected_scope_level_for(Some(&item.resource_app_id), &item.permission_value)?;
        match level {
            None => level = Some(l),
            Some(prev) if prev == l => {}
            _ => return None,
        }
    }
    level
}

/// Whether a SharePoint site grant needs write access: true unless every item
/// in the cart is the read-only `Sites.Read.All`.
///
/// Erring toward write on a mixed cart is deliberate — under-granting here
/// produces a scoped grant that cannot do what the app was consented for, and
/// the operator has no signal beyond the app failing later.
fn sites_need_write(cart: &[PickerSelection]) -> bool {
    cart.iter().any(|i| i.permission_value != "Sites.Read.All")
}

#[component]
pub fn ScopeWizard(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] target: Signal<ScopeTarget>,
    /// When set on open, seeds the cart with this permission and jumps to the
    /// choose-access step (the per-row "Scope…" entry). `None` opens a blank
    /// select step.
    #[prop(into)]
    preseed: Signal<Option<PickerSelection>>,
    #[prop(into)] on_close: Callback<()>,
    /// Fired after a successful grant so the host refreshes detail + scope badges.
    #[prop(into)]
    on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let app_id = Signal::derive(move || target.with(|t| t.app_id.clone()));
    let tenant_for_picker: Signal<Option<String>> =
        Signal::derive(move || session.active_tenant.get().map(|t| t.tenant_id.clone()));
    // App registrations (manifest present) can grant delegated scopes; a bare
    // service principal (MI / enterprise app) only takes app-role grants, so
    // restrict its picker to Application permissions.
    let picker_mode = if target.with_untracked(|t| t.object_id.is_some()) {
        PickerMode::AppAndDelegated
    } else {
        PickerMode::ApplicationOnly
    };

    let step = RwSignal::new(0u8);
    let selected: RwSignal<Vec<PickerSelection>> = RwSignal::new(Vec::new());
    let scope_mode = RwSignal::new(ScopeMode::Managed);

    // Exchange target state.
    let existing_groups = RwSignal::new(String::new());
    let group_state: RwSignal<Option<Result<ExchangeScopeGroupDto, UiError>>> = RwSignal::new(None);
    // SharePoint target state.
    let site_urls = RwSignal::new(String::new());
    let site_write = RwSignal::new(false);
    let item_urls = RwSignal::new(String::new());
    let item_write = RwSignal::new(false);
    // The level the cart grants at — drives the target panel's per-URL
    // accept/reject preview. `None` whenever the cart isn't a homogeneous
    // sub-site Selected selection, which is also when the panel isn't shown.
    let cart_scope_level = Signal::derive(move || selected.with(|s| cart_level(s)));

    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let needs_consent = RwSignal::new(false);

    // The single mechanism this run scopes: `Some(k)` only when the cart is
    // non-empty and every item is an Application permission mapping to the same
    // `ScopeKind`; otherwise `None` (org-wide only). Delegated scopes never
    // scope, so they force `None`.
    let mechanism = Signal::derive(move || selected.with(|s| cart_mechanism(s)));

    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    let reset = move || {
        step.set(0);
        selected.set(Vec::new());
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
    // already in the cart, jumping to the choose-access step for its mechanism.
    Effect::new(move |_| {
        if open.get()
            && let Some(sel) = preseed.get_untracked()
        {
            if let Some(k) = scope_kind_for(Some(&sel.resource_app_id), &sel.permission_value) {
                if k == ScopeKind::SharePoint {
                    site_write.set(sel.permission_value != "Sites.Read.All");
                }
                scope_mode.set(default_mode(k));
            }
            selected.set(vec![sel]);
            step.set(1);
        }
    });

    // Add/remove a permission from the cart, then re-anchor the scope mode to the
    // resulting mechanism's default (org-wide when the cart isn't scopable).
    let toggle = move |sel: PickerSelection| {
        selected.update(|s| {
            if let Some(pos) = s.iter().position(|x| x == &sel) {
                s.remove(pos);
            } else {
                s.push(sel.clone());
            }
        });
        error.set(None);
        match mechanism.get_untracked() {
            Some(ScopeKind::SharePoint) => {
                site_write.set(selected.with_untracked(|s| sites_need_write(s)));
                scope_mode.set(ScopeMode::Sites);
            }
            Some(k) => scope_mode.set(default_mode(k)),
            None => scope_mode.set(ScopeMode::OrgWide),
        }
    };
    let on_toggle = Callback::new(move |sel: PickerSelection| toggle(sel));

    let run_apply = move || {
        if busy.get_untracked() {
            return;
        }
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        let items = selected.get_untracked();
        if items.is_empty() {
            error.set(Some("Select at least one permission.".into()));
            return;
        }
        let mode = scope_mode.get_untracked();
        let tenant_id = t.tenant_id.clone();
        let target = target.get_untracked();

        // Resolve targets for the scoped modes up front so a missing selection
        // fails fast with a clear message. Org-wide needs no mechanism.
        enum Plan {
            ExchangeScoped(Vec<String>),
            SharePointScoped(Vec<String>, &'static str),
            SharePointItemScoped(Vec<String>, &'static str, String),
            OrgWide,
        }
        let plan = if mode == ScopeMode::OrgWide {
            Plan::OrgWide
        } else {
            let Some(kind) = mechanism.get_untracked() else {
                return;
            };
            match (kind, mode) {
                (ScopeKind::Exchange, ScopeMode::Managed) => match group_state.get_untracked() {
                    Some(Ok(g)) if g.exists => Plan::ExchangeScoped(vec![
                        g.primary_smtp_address
                            .clone()
                            .unwrap_or(g.group_name.clone()),
                    ]),
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
                (ScopeKind::SharePointItem, ScopeMode::Items) => {
                    let urls = parse_lines(&item_urls.get_untracked());
                    if urls.is_empty() {
                        error.set(Some(
                            "Enter at least one library, folder or file URL (one per line).".into(),
                        ));
                        return;
                    }
                    // The cart is level-homogeneous whenever the mechanism
                    // resolved, so any item's value names the scope to grant.
                    let Some(value) = items.first().map(|i| i.permission_value.clone()) else {
                        return;
                    };
                    let role = if item_write.get_untracked() {
                        "write"
                    } else {
                        "read"
                    };
                    Plan::SharePointItemScoped(urls, role, value)
                }
                _ => return,
            }
        };

        busy.set(true);
        error.set(None);
        needs_consent.set(false);
        leptos::task::spawn_local(async move {
            let res = match plan {
                Plan::OrgWide => apply_orgwide(tenant_id, target, items).await,
                Plan::ExchangeScoped(groups) => {
                    apply_exchange_scoped(tenant_id, target, items, groups).await
                }
                Plan::SharePointScoped(urls, role) => {
                    apply_sharepoint_scoped(tenant_id, target, urls, role).await
                }
                Plan::SharePointItemScoped(urls, role, value) => {
                    apply_sharepoint_item_scoped(tenant_id, target, urls, role, value).await
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
            // Both SharePoint mechanisms ride the same Sites.FullControl.All
            // consent — the permission endpoints need it at every level.
            Some(ScopeKind::SharePoint | ScopeKind::SharePointItem) => "sharepoint",
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
        let perms = selected.with(|s| perm_values(s).join(", "));
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
            ScopeMode::Items => format!(
                "Grant {perms}, scoped to the chosen library/folder/file(s). The app reaches nothing else, and permission inheritance is broken on each target.",
            ),
        }
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
                    <h3 id="scope-wizard-title">"Grant access"</h3>
                    <div class="sso-wizard__steps">
                        <Body1 class="hint">
                            {move || match step.get() {
                                0 => "Step 1 of 3 — Select permissions",
                                1 => "Step 2 of 3 — Choose access",
                                _ => "Step 3 of 3 — Review & grant",
                            }}
                        </Body1>
                    </div>

                    // ---- Step 0: select permissions (full catalog, multi-select) ----
                    <Show when=move || step.get() == 0 fallback=|| ()>
                        <SelectPermissionsStep
                            tenant_id=tenant_for_picker
                            mode=picker_mode
                            selected=selected
                            on_toggle=on_toggle
                        />
                    </Show>

                    // ---- Step 1: choose access (dispatched on mechanism) ----
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

                        <Show
                            when=move || mechanism.get() == Some(ScopeKind::SharePointItem)
                            fallback=|| ()
                        >
                            <Show when=move || scope_mode.get() == ScopeMode::Items fallback=|| ()>
                                <ItemSelectionPanel
                                    target_urls=item_urls
                                    write=item_write
                                    scope_level=cart_scope_level
                                />
                            </Show>
                        </Show>

                        // Org-wide: a de-emphasized alternative when the cart is
                        // scopable; the only path otherwise.
                        {move || {
                            mechanism
                                .get()
                                .is_some()
                                .then(|| {
                                    view! {
                                        <label class="radio-row">
                                            <input
                                                type="radio"
                                                name="scope-mode"
                                                prop:checked=move || {
                                                    scope_mode.get() == ScopeMode::OrgWide
                                                }
                                                on:change=move |_| scope_mode.set(ScopeMode::OrgWide)
                                            />
                                            <span class="muted">"Org-wide — no scoping (rare)"</span>
                                        </label>
                                    }
                                })
                        }}
                        {move || {
                            mechanism
                                .get()
                                .is_none()
                                .then(|| {
                                    view! {
                                        <Body1 class="hint">
                                            "These permissions can't be scoped together — they'll be granted org-wide. To scope instead, select only mailbox permissions, only SharePoint site permissions, or only one Selected permission for libraries/folders/files, in one pass."
                                        </Body1>
                                    }
                                })
                        }}
                        <Show when=move || scope_mode.get() == ScopeMode::OrgWide fallback=|| ()>
                            <Callout tone="warn">
                                <Body1>
                                    "The app will reach every resource in the tenant. Only choose this when the permission genuinely needs tenant-wide reach."
                                </Body1>
                            </Callout>
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
                                        <Callout tone="warn">
                                            "Scoping needs an admin consent for this mechanism."
                                            <Button
                                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                on_click=Box::new(consent_and_retry)
                                                disabled=Signal::derive(move || busy.get())
                                            >
                                                "Grant consent & retry"
                                            </Button>
                                        </Callout>
                                    }
                                })
                        }}
                    </Show>

                    {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}

                    // Tell the user why "Next" is disabled on step 1 — the cart is
                    // empty. The apply-time validation message is unreachable from
                    // step 0, so without this the disabled button has no explanation.
                    {move || {
                        (step.get() == 0 && selected.with(|s| s.is_empty()))
                            .then(|| {
                                view! {
                                    <Body1 class="hint">
                                        "Select at least one permission to continue."
                                    </Body1>
                                }
                            })
                    }}

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

/// Step 1: the full live permission catalog as a multi-select cart. The picker
/// emits toggles; this renders the running cart (removable chips) above it.
#[component]
fn SelectPermissionsStep(
    #[prop(into)] tenant_id: Signal<Option<String>>,
    mode: PickerMode,
    selected: RwSignal<Vec<PickerSelection>>,
    on_toggle: Callback<PickerSelection>,
) -> impl IntoView {
    view! {
        <Body1 class="hint">
            "Choose the permissions to grant. You'll decide how to grant them — org-wide, or scoped to specific mailboxes or sites — next."
        </Body1>
        {move || {
            let items = selected.get();
            (!items.is_empty())
                .then(|| {
                    view! {
                        <div class="scope-wizard__cart">
                            <span class="hint">{format!("{} selected", items.len())}</span>
                            {items
                                .into_iter()
                                .map(|item| {
                                    let sel = item.clone();
                                    let label = item.permission_value.clone();
                                    view! {
                                        <button
                                            type="button"
                                            class="scope-wizard__chip"
                                            title="Remove"
                                            on:click=move |_| on_toggle.run(sel.clone())
                                        >
                                            <span class="mono">{label}</span>
                                            " ✕"
                                        </button>
                                    }
                                })
                                .collect_view()}
                        </div>
                    }
                })
        }}
        <PermissionPicker tenant_id=tenant_id mode=mode selected=selected on_toggle=on_toggle />
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::scoping::{
        MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
        OFFICE365_SHAREPOINT_ONLINE_APP_ID,
    };

    fn app(resource: &str, value: &str) -> PickerSelection {
        PickerSelection {
            resource_app_id: resource.to_string(),
            kind: PermissionKind::Application,
            permission_id: format!("id-{value}"),
            permission_value: value.to_string(),
        }
    }

    fn delegated(resource: &str, value: &str) -> PickerSelection {
        PickerSelection {
            kind: PermissionKind::Delegated,
            ..app(resource, value)
        }
    }

    #[test]
    fn an_empty_cart_has_no_mechanism() {
        assert_eq!(cart_mechanism(&[]), None);
    }

    #[test]
    fn a_uniform_application_cart_resolves_to_its_one_mechanism() {
        assert_eq!(
            cart_mechanism(&[
                app(MICROSOFT_GRAPH_APP_ID, "Mail.Read"),
                app(MICROSOFT_GRAPH_APP_ID, "Calendars.Read"),
            ]),
            Some(ScopeKind::Exchange)
        );
        assert_eq!(
            cart_mechanism(&[
                app(MICROSOFT_GRAPH_APP_ID, "Sites.Read.All"),
                app(MICROSOFT_GRAPH_APP_ID, "Sites.Selected"),
            ]),
            Some(ScopeKind::SharePoint)
        );
    }

    #[test]
    fn a_mixed_cart_falls_back_to_org_wide() {
        // Two mechanisms have two different apply paths and two target types;
        // there is no single scoped apply that honours both, so offering one
        // would leave half the cart org-wide without saying so.
        assert_eq!(
            cart_mechanism(&[
                app(MICROSOFT_GRAPH_APP_ID, "Mail.Read"),
                app(MICROSOFT_GRAPH_APP_ID, "Sites.Read.All"),
            ]),
            None
        );
    }

    #[test]
    fn one_unscopable_item_disqualifies_the_whole_cart() {
        assert_eq!(
            cart_mechanism(&[
                app(MICROSOFT_GRAPH_APP_ID, "Mail.Read"),
                app(MICROSOFT_GRAPH_APP_ID, "Directory.Read.All"),
            ]),
            None,
            "a scoped apply that silently skips Directory.Read.All would report \
             success while leaving it org-wide"
        );
    }

    #[test]
    fn a_delegated_scope_never_scopes() {
        // Delegated permissions are consented per user and carry no
        // resource-scoping mechanism at all.
        assert_eq!(
            cart_mechanism(&[delegated(MICROSOFT_GRAPH_APP_ID, "Mail.Read")]),
            None
        );
        assert_eq!(
            cart_mechanism(&[
                app(MICROSOFT_GRAPH_APP_ID, "Mail.Read"),
                delegated(MICROSOFT_GRAPH_APP_ID, "Mail.Read"),
            ]),
            None
        );
    }

    #[test]
    fn the_legacy_resources_offer_no_mechanism_even_under_a_familiar_name() {
        // The resource-blind version of this rule offered an Exchange apply for
        // Office 365 Exchange Online's retired Outlook REST `Mail.*`, which RBAC
        // for Applications cannot confine — the apply would report success and
        // the grant would stay org-wide.
        assert_eq!(
            cart_mechanism(&[app(OFFICE365_EXCHANGE_ONLINE_APP_ID, "Mail.Read")]),
            None
        );
        assert_eq!(
            cart_mechanism(&[app(OFFICE365_SHAREPOINT_ONLINE_APP_ID, "Sites.Read.All")]),
            None
        );
        // The EWS scope on that same resource IS scopable, so the rule must not
        // be "reject the whole resource".
        assert_eq!(
            cart_mechanism(&[app(OFFICE365_EXCHANGE_ONLINE_APP_ID, "full_access_as_app")]),
            Some(ScopeKind::Exchange)
        );
    }

    #[test]
    fn site_write_is_needed_unless_every_item_is_read_only() {
        assert!(!sites_need_write(&[app(
            MICROSOFT_GRAPH_APP_ID,
            "Sites.Read.All"
        )]));
        assert!(sites_need_write(&[app(
            MICROSOFT_GRAPH_APP_ID,
            "Sites.ReadWrite.All"
        )]));
        assert!(
            sites_need_write(&[
                app(MICROSOFT_GRAPH_APP_ID, "Sites.Read.All"),
                app(MICROSOFT_GRAPH_APP_ID, "Sites.ReadWrite.All"),
            ]),
            "a mixed cart must not under-grant — the app would fail later with no signal here"
        );
        assert!(
            !sites_need_write(&[]),
            "an empty cart never reaches the sites step"
        );
    }
}
