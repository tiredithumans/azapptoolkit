//! Permissions tab. Lists declared `requiredResourceAccess` entries with
//! human-friendly resource + permission names resolved server-side via the
//! bundled catalog (`PermissionsCatalog::lookup_permission`). Application vs.
//! Delegated permissions get distinct chips. Lets you grant admin consent.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::bindings::applications::ApplicationDetail;
use crate::bindings::auth;
use crate::bindings::exchange;
use crate::bindings::permissions::{self, GrantResult};
use crate::bindings::usage;
use crate::components::exchange_scoping_section::{ExchangeScopeTarget, ExchangeScopingSection};
use crate::components::icon::IconName;
use crate::components::permission_picker::PickerSelection;
use crate::components::requires_role::RequiresRole;
use crate::components::scope_badge::{
    is_exchange_scopable, is_sharepoint_orgwide, permission_scope_cell,
};
use crate::components::scope_unavailable_banner::ScopeUnavailableBanner;
use crate::components::scope_wizard::{ScopeTarget, ScopeWizard};
use crate::components::sharepoint_sites_section::SharePointSitesSection;
use crate::components::toast::ToastAction;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::IconButton;
use crate::hooks::use_command::use_command;
use crate::state::{use_session, Session};
use azapptoolkit_core::audit::{downgrade_alternatives, MailPermissionScope};
use azapptoolkit_core::scoping::ScopeKind;
use azapptoolkit_dto::permissions::{PermissionKind, ResolvedPermission};
use azapptoolkit_dto::UiError;

/// A held broad application permission the user chose to swap for a documented
/// narrower alternative. Held until the user picks the target (or cancels) —
/// the swap is admin-judged, never automatic (the narrower permission only
/// suffices if the app doesn't use the broader capability).
#[derive(Clone)]
struct PendingDowngrade {
    object_id: String,
    resource_app_id: String,
    broad_value: String,
    /// Documented narrower alternatives, closest tier first.
    alternatives: Vec<&'static str>,
}

/// Classifies whether an already-granted Application permission can be restricted
/// *per row* after the fact. SharePoint org-wide `Sites.*` only (the
/// convert-to-`Sites.Selected` case). Mail/calendar/contacts are excluded —
/// Exchange RBAC scoping is **app-wide** (one management scope binds the whole
/// principal's mail roles), so it's driven solely by the app-wide "Exchange
/// scoping" section below, never per row.
fn row_scope_kind(value: &str) -> Option<ScopeKind> {
    is_sharepoint_orgwide(value).then_some(ScopeKind::SharePoint)
}

/// Runs the admin-consent grant for the app in `detail`, reporting via toasts.
/// Pulled out of the component so a retryable-error toast can re-invoke it: on
/// a retryable failure it builds an `Rc<dyn Fn()>` that calls back into this
/// same function. Every captured handle is `Copy`, so the recursion needs no
/// `RefCell` self-reference cell.
fn run_grant(
    session: Session,
    detail: Signal<Arc<ApplicationDetail>>,
    consenting: RwSignal<bool>,
    consent_error: RwSignal<Option<String>>,
    consent_result: RwSignal<Option<GrantResult>>,
    on_changed: Callback<()>,
) {
    if consenting.get_untracked() {
        return;
    }
    consenting.set(true);
    consent_error.set(None);
    consent_result.set(None);
    let tenant = session.active_tenant.get_untracked();
    let object_id = detail.with_untracked(|d| d.application.id.clone());
    leptos::task::spawn_local(async move {
        let Some(t) = tenant else {
            consenting.set(false);
            return;
        };
        match permissions::grant_admin_consent(&t.tenant_id, &object_id).await {
            Ok(r) => {
                session.toast_success(format!(
                    "Admin consent granted: {} role assignment(s), {} scope grant(s).",
                    r.role_assignments_created.len(),
                    r.scope_grants_upserted.len(),
                ));
                consent_result.set(Some(r));
                on_changed.run(());
            }
            Err(e) => {
                // Offer Retry only when the backend says the failure is transient.
                let retry: Option<ToastAction> = e.retryable.then(|| {
                    Rc::new(move || {
                        run_grant(
                            session,
                            detail,
                            consenting,
                            consent_error,
                            consent_result,
                            on_changed,
                        )
                    }) as ToastAction
                });
                session.toast_error(e.message.clone(), retry);
                consent_error.set(Some(e.message));
            }
        }
        consenting.set(false);
    });
}

/// Fetches effective Exchange mailbox scoping for `object_id` and updates the
/// signals. On success `mail_scopes` holds the per-permission verdicts and
/// `scope_unavailable` is cleared; on failure (e.g. a 403 from missing Exchange
/// RBAC, or `consent_required`) `mail_scopes` is emptied and `scope_unavailable`
/// carries the actionable reason so the tab can explain it rather than silently
/// painting every row "Unknown".
fn load_mail_scopes(
    tenant_id: String,
    object_id: String,
    mail_scopes: RwSignal<HashMap<String, MailPermissionScope>>,
    scope_unavailable: RwSignal<Option<UiError>>,
    scopes_loading: RwSignal<bool>,
) {
    scopes_loading.set(true);
    leptos::task::spawn_local(async move {
        match exchange::get_mail_permission_scopes(&tenant_id, &object_id).await {
            Ok(entries) => {
                let map = entries
                    .into_iter()
                    .map(|e| (e.graph_permission, e.scope))
                    .collect();
                mail_scopes.set(map);
                scope_unavailable.set(None);
            }
            Err(e) => {
                mail_scopes.set(HashMap::new());
                scope_unavailable.set(Some(e));
            }
        }
        scopes_loading.set(false);
    });
}

#[component]
pub fn PermissionsTab(
    #[prop(into)] detail: Signal<Arc<ApplicationDetail>>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let consenting = RwSignal::new(false);
    let consent_error: RwSignal<Option<String>> = RwSignal::new(None);
    let consent_result: RwSignal<Option<GrantResult>> = RwSignal::new(None);
    // The unified "Grant access" wizard — always reachable, so adding/scoping is
    // the obvious first move. `wizard_preseed` carries a permission selection when
    // a row's "Scope…" opens the wizard pre-selected; None opens a blank select step.
    let wizard_open = RwSignal::new(false);
    let wizard_preseed: RwSignal<Option<PickerSelection>> = RwSignal::new(None);
    let wizard_target = Signal::derive(move || {
        detail.with(|d| ScopeTarget {
            object_id: Some(d.application.id.clone()),
            sp_object_id: d
                .service_principal
                .as_ref()
                .map(|sp| sp.id.clone())
                .unwrap_or_default(),
            app_id: d.application.app_id.clone(),
            display_name: d.application.display_name.clone(),
            is_managed_identity: false,
        })
    });
    // One shared runner for every grant/revoke/scope/downgrade mutation in this
    // tab — they share a single busy + error (`cmd.error` is the row-level error
    // surface, formerly `row_error`).
    let cmd = use_command();
    // Outcome note for the per-row downgrade flow (reports inline rather than via
    // a toast, since the success path keeps the chooser open).
    let scope_note: RwSignal<Option<String>> = RwSignal::new(None);

    // Application/Delegated filter toggles. Both default on.
    let show_application = RwSignal::new(true);
    let show_delegated = RwSignal::new(true);

    // Effective Exchange mailbox scoping per Graph permission value, lazily
    // resolved when the app declares any scopable mail permission. Empty until
    // loaded; degrades to `Unknown` entries when the user isn't an Exchange
    // admin (the backend never hard-errors here).
    let mail_scopes: RwSignal<HashMap<String, MailPermissionScope>> = RwSignal::new(HashMap::new());
    // `Some` when the Exchange scoping lookup failed — carries the actionable
    // reason (and a `consent_required` code) so the tab shows a banner + a
    // "Grant consent" / "Retry" affordance instead of silent "Unknown" badges.
    let scope_unavailable: RwSignal<Option<UiError>> = RwSignal::new(None);
    // True while the Exchange lookup is in flight, so verdict-less rows read
    // "Resolving…" instead of "Unknown" (which is reserved for a failed lookup).
    let scopes_loading = RwSignal::new(false);
    Effect::new(move |_| {
        let tenant = session.active_tenant.get();
        let (object_id, has_mail) = detail.with(|d| {
            let has = d.resolved_permissions.iter().any(|p| {
                p.permission_value
                    .as_deref()
                    .is_some_and(is_exchange_scopable)
            });
            (d.application.id.clone(), has)
        });
        mail_scopes.set(HashMap::new());
        scope_unavailable.set(None);
        let Some(t) = tenant else { return };
        if !has_mail {
            return;
        }
        load_mail_scopes(
            t.tenant_id.clone(),
            object_id,
            mail_scopes,
            scope_unavailable,
            scopes_loading,
        );
    });

    // Re-run the scope lookup (after granting consent, or on a Retry click).
    let reload_scopes = move || {
        let tenant = session.active_tenant.get_untracked();
        let object_id = detail.with_untracked(|d| d.application.id.clone());
        let Some(t) = tenant else { return };
        load_mail_scopes(
            t.tenant_id.clone(),
            object_id,
            mail_scopes,
            scope_unavailable,
            scopes_loading,
        );
    };
    let grant = move |_| {
        run_grant(
            session,
            detail,
            consenting,
            consent_error,
            consent_result,
            on_changed,
        )
    };

    // A row's "Scope…" opens the wizard pre-selected to that permission, jumping
    // to the choose-access step. The wizard infers the mechanism from it.
    let open_scope = move |sel: PickerSelection| {
        cmd.error.set(None);
        wizard_preseed.set(Some(sel));
        wizard_open.set(true);
    };

    // Inline "swap a broad permission for a narrower one" chooser. Opened from a
    // row's Downgrade… action; the user picks the target alternative (or cancels).
    let pending_downgrade: RwSignal<Option<PendingDowngrade>> = RwSignal::new(None);

    let open_downgrade = move |resource_app_id: String, broad_value: String| {
        let alternatives = downgrade_alternatives(&broad_value);
        if alternatives.is_empty() {
            return;
        }
        let object_id = detail.with(|d| d.application.id.clone());
        cmd.error.set(None);
        scope_note.set(None);
        pending_downgrade.set(Some(PendingDowngrade {
            object_id,
            resource_app_id,
            broad_value,
            alternatives,
        }));
    };

    let cancel_downgrade = move |_| {
        pending_downgrade.set(None);
        cmd.error.set(None);
    };

    let submit_downgrade = move |narrow: &'static str| {
        let Some(p) = pending_downgrade.get() else {
            return;
        };
        if cmd.busy.get() {
            return;
        }
        let broad_value = p.broad_value.clone();
        cmd.run(
            move |o: permissions::DowngradeOutcome| {
                let note = if o.broad_revoked || o.declaration_swapped {
                    format!(
                        "Downgraded {} → {narrow}{}.",
                        broad_value,
                        if o.narrow_granted {
                            ""
                        } else {
                            " (narrower permission was already in place)"
                        }
                    )
                } else {
                    format!("{broad_value} was already gone — nothing to change.")
                };
                scope_note.set(Some(note));
                pending_downgrade.set(None);
                on_changed.run(());
            },
            move |tenant_id| async move {
                permissions::downgrade_application_permission(
                    &tenant_id,
                    &p.object_id,
                    &p.resource_app_id,
                    &p.broad_value,
                    narrow,
                )
                .await
            },
        );
    };

    let do_revoke_application = move |assignment_id: String| {
        let Some(sp_id) = detail.with(|d| d.service_principal.as_ref().map(|sp| sp.id.clone()))
        else {
            cmd.error.set(Some(
                "App has no service principal — nothing to revoke.".into(),
            ));
            return;
        };
        cmd.run(
            move |()| on_changed.run(()),
            move |tenant_id| async move {
                permissions::revoke_app_role_assignment(&tenant_id, &sp_id, &assignment_id).await
            },
        );
    };

    let do_revoke_delegated = move |grant_id: String, scope_value: String| {
        cmd.run(
            move |_| on_changed.run(()),
            move |tenant_id| async move {
                permissions::revoke_oauth2_scope(&tenant_id, &grant_id, &scope_value).await
            },
        );
    };

    // Remove a not-granted (declared-only) permission from the manifest. The
    // Trash icon on a granted row revokes the runtime grant; on a not-granted
    // row it removes the declaration instead, so every row has a way out.
    let do_remove_declared =
        move |resource_app_id: String, permission_id: String, kind: PermissionKind| {
            let object_id = detail.with(|d| d.application.id.clone());
            cmd.run(
                move |()| on_changed.run(()),
                move |tenant_id| async move {
                    permissions::remove_declared_permission(
                        &tenant_id,
                        &object_id,
                        &resource_app_id,
                        &permission_id,
                        kind,
                    )
                    .await
                },
            );
        };

    view! {
        <div class="permissions-tab">
            <header class="row-between">
                <div class="row">
                    <strong>"Declared permissions"</strong>
                    <RequiresRole capability_key="admin_consent" />
                </div>
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| wizard_open.set(true))
                    >
                        "Grant access"
                    </Button>
                    // Secondary so "Grant access" (the wizard) reads as the
                    // primary action; this in-place consent of already-declared
                    // permissions is the alternate path, not the default one.
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(grant)
                        disabled=Signal::derive(move || consenting.get())
                    >
                        {move || {
                            if consenting.get() {
                                view! {
                                    <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                }
                                    .into_any()
                            } else {
                                view! { "Grant admin consent" }.into_any()
                            }
                        }}
                    </Button>
                </div>
            </header>
            <ScopeWizard
                open=wizard_open
                target=wizard_target
                preseed=wizard_preseed
                on_close=Callback::new(move |()| {
                    wizard_open.set(false);
                    wizard_preseed.set(None);
                })
                on_changed=on_changed
            />
            {move || cmd.error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            <div class="permissions-tab__filters">
                <button
                    class=move || filter_chip_class(show_application.get())
                    type="button"
                    on:click=move |_| show_application.update(|v| *v = !*v)
                >
                    "Application"
                </button>
                <button
                    class=move || filter_chip_class(show_delegated.get())
                    type="button"
                    on:click=move |_| show_delegated.update(|v| *v = !*v)
                >
                    "Delegated"
                </button>
            </div>
            // Shared banner (consent-and-retry handled internally) so the Scope
            // column's unavailable state matches the MI and enterprise panes.
            {move || {
                scope_unavailable.get().map(|e| {
                    view! { <ScopeUnavailableBanner error=e on_retry=move |_| reload_scopes() /> }
                })
            }}
            {move || {
                // The empty check reads only the (stable) resolved set, so this
                // outer block renders the table shell once. The rows are a keyed
                // `<For>` whose `each` tracks just the filters — so toggling
                // Application/Delegated diffs rows instead of rebuilding the table.
                if detail.with(|d| d.resolved_permissions.is_empty()) {
                    return view! {
                        <Body1>
                            "No permissions declared. Use the Entra portal or restore from a saved manifest."
                        </Body1>
                    }
                        .into_any();
                }
                view! {
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>"Resource"</th>
                                <th>"Permission"</th>
                                <th>"Kind"</th>
                                <th>"Scope"</th>
                                <th>"Status"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=move || {
                                    let show_app = show_application.get();
                                    let show_del = show_delegated.get();
                                    detail.with(|d| {
                                        d.resolved_permissions
                                            .iter()
                                            .filter(|p| match p.permission_kind {
                                                PermissionKind::Application => show_app,
                                                PermissionKind::Delegated => show_del,
                                                // Unknown shows whenever either filter is on.
                                                PermissionKind::Unknown => show_app || show_del,
                                            })
                                            .cloned()
                                            .collect::<Vec<_>>()
                                    })
                                }
                                key=|p| {
                                    let k = match p.permission_kind {
                                        PermissionKind::Application => 'a',
                                        PermissionKind::Delegated => 'd',
                                        PermissionKind::Unknown => 'u',
                                    };
                                    format!(
                                        "{}|{}|{}|{}",
                                        p.resource_app_id,
                                        p.permission_id,
                                        k,
                                        p.permission_value.as_deref().unwrap_or(""),
                                    )
                                }
                                children=move |p| {
                                    view_resolved_row(
                                        p,
                                        mail_scopes,
                                        scopes_loading,
                                        do_revoke_application,
                                        do_revoke_delegated,
                                        do_remove_declared,
                                        open_scope,
                                        open_downgrade,
                                    )
                                }
                            />
                        </tbody>
                    </table>
                }
                    .into_any()
            }}
            {move || {
                pending_downgrade
                    .get()
                    .map(|p| {
                        let buttons = p
                            .alternatives
                            .iter()
                            .map(|alt| {
                                let alt = *alt;
                                view! {
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        on_click=Box::new(move |_| submit_downgrade(alt))
                                    >
                                        {format!("Downgrade to {alt}")}
                                    </Button>
                                }
                            })
                            .collect_view();
                        view! {
                            <div class="alert alert--warn">
                                <Body1>
                                    {format!(
                                        "Replace {} with a narrower permission. The narrower one is granted first, then {} is removed — only proceed if the app doesn't use the broader capability, because this changes its effective access.",
                                        p.broad_value,
                                        p.broad_value,
                                    )}
                                </Body1>
                                <div class="actions-row">
                                    {buttons}
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                        on_click=Box::new(move |_| cancel_downgrade(()))
                                    >
                                        "Cancel"
                                    </Button>
                                </div>
                            </div>
                        }
                    })
            }}
            {move || scope_note.get().map(|m| view! { <div class="alert alert--ok">{m}</div> })}
            {move || consent_error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            {move || {
                consent_result
                    .get()
                    .map(|r| {
                        view! {
                            <div class="alert alert--ok">
                                {format!(
                                    "Created {} role assignment(s); {} scope grant(s); {} skipped; {} failure(s).",
                                    r.role_assignments_created.len(),
                                    r.scope_grants_upserted.len(),
                                    r.role_assignments_skipped.len(),
                                    r.failures.len(),
                                )}
                            </div>
                        }
                    })
            }}
            {move || {
                let has_mail = detail.with(|d| {
                    d.resolved_permissions.iter().any(|p| {
                        p.permission_value
                            .as_deref()
                            .is_some_and(is_exchange_scopable)
                    })
                });
                has_mail
                    .then(|| {
                        view! {
                            <ExchangeScopingSection
                                app_id=Signal::derive(move || {
                                    detail.with(|d| d.application.app_id.clone())
                                })
                                target=Signal::derive(move || ExchangeScopeTarget::Application {
                                    object_id: detail.with(|d| d.application.id.clone()),
                                })
                                on_changed=on_changed
                            />
                        }
                    })
            }}
            {move || {
                let has_sites = detail.with(|d| {
                    d.resolved_permissions.iter().any(|p| {
                        p.permission_value
                            .as_deref()
                            .is_some_and(|v| v == "Sites.Selected" || is_sharepoint_orgwide(v))
                    })
                });
                has_sites
                    .then(|| {
                        view! {
                            <SharePointSitesSection
                                app_id=Signal::derive(move || {
                                    detail.with(|d| d.application.app_id.clone())
                                })
                                app_display_name=Signal::derive(move || {
                                    detail.with(|d| d.application.display_name.clone())
                                })
                            />
                        }
                    })
            }}
            <UsagePanel detail=detail />
        </div>
    }
}

/// "Observed Graph activity" — the granted-vs-used lens. Loads on demand (the
/// workspace discovery + KQL query cost a few round trips, so it never runs on
/// tab open): summarizes the app's actual Graph calls over the last 90 days
/// from MicrosoftGraphActivityLogs, so an admin can compare what the app
/// *does* against the permissions above (e.g. `Mail.ReadWrite` granted but
/// only GETs observed → the Downgrade… action applies). Degrades to setup
/// guidance (`usage_unavailable`) or a consent button — never breaks the tab.
#[component]
fn UsagePanel(#[prop(into)] detail: Signal<Arc<ApplicationDetail>>) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<usage::GraphUsageResult>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let consent_needed = RwSignal::new(false);
    let unavailable = RwSignal::new(false);

    // Stale-usage guard: a different app's detail in the same pane must not
    // show the previous app's call patterns.
    Effect::new(move |_| {
        let _ = detail.with(|d| d.application.app_id.clone());
        result.set(None);
        error.set(None);
        consent_needed.set(false);
        unavailable.set(false);
    });

    let do_load = move || {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        consent_needed.set(false);
        unavailable.set(false);
        let tenant = tenant.get();
        let app_id = detail.with(|d| d.application.app_id.clone());
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match usage::get_app_graph_usage(&t.tenant_id, &app_id, 90).await {
                Ok(r) => result.set(Some(r)),
                Err(e) => {
                    consent_needed.set(e.code == "consent_required");
                    unavailable.set(e.code == "usage_unavailable");
                    error.set(Some(e.message));
                }
            }
            busy.set(false);
        });
    };

    let grant_consent = move |_| {
        let Some(t) = tenant.get() else { return };
        error.set(None);
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&t.tenant_id, "log_analytics").await {
                Ok(()) => do_load(),
                Err(e) => error.set(Some(e.message)),
            }
        });
    };

    view! {
        <div class="permissions-tab__usage">
            <h3>"Observed Graph activity"</h3>
            <Body1>
                "What this app actually called over the last 90 days (from MicrosoftGraphActivityLogs) — compare against the permissions above to spot unused or over-broad grants."
            </Body1>
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| do_load())
                >
                    {move || {
                        if busy.get() {
                            "Loading…"
                        } else if result.with(|r| r.is_some()) {
                            "Refresh observed usage"
                        } else {
                            "Check observed usage (90d)"
                        }
                    }}
                </Button>
            </div>
            {move || {
                error
                    .get()
                    .map(|e| {
                        let class = if unavailable.get() { "alert" } else { "alert alert--warn" };
                        view! {
                            <div class=class>
                                <Body1>{e}</Body1>
                                {consent_needed
                                    .get()
                                    .then(|| {
                                        view! {
                                            <div class="actions-row">
                                                <Button
                                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                    on_click=Box::new(grant_consent)
                                                >
                                                    "Grant consent & retry"
                                                </Button>
                                            </div>
                                        }
                                    })}
                            </div>
                        }
                    })
            }}
            {move || {
                result
                    .get()
                    .map(|r| {
                        let summary = format!(
                            "{} call pattern{} over {} days (workspace: {}){}{}",
                            r.rows.len(),
                            if r.rows.len() == 1 { "" } else { "s" },
                            r.days,
                            r.workspace_name,
                            if r.truncated { " — long tail truncated" } else { "" },
                            if r.rows.is_empty() {
                                " — no Graph calls observed; if this persists, the app may not need its Graph permissions at all"
                            } else {
                                ""
                            },
                        );
                        view! {
                            <Body1 class="page__summary">{summary}</Body1>
                            {(!r.rows.is_empty())
                                .then(|| {
                                    view! {
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Method"</th>
                                                    <th>"Path"</th>
                                                    <th>"Calls"</th>
                                                    <th>"Last seen"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {r
                                                    .rows
                                                    .into_iter()
                                                    .map(|row| {
                                                        view! {
                                                            <tr>
                                                                <td class="cell-mid">{row.method}</td>
                                                                <td class="mono">{row.path}</td>
                                                                <td class="cell-mid">{row.count}</td>
                                                                <td class="cell-mid">
                                                                    {row.last_seen.unwrap_or_default()}
                                                                </td>
                                                            </tr>
                                                        }
                                                    })
                                                    .collect_view()}
                                            </tbody>
                                        </table>
                                    }
                                })}
                        }
                    })
            }}
        </div>
    }
}

fn filter_chip_class(on: bool) -> String {
    let mut c = String::from("permissions-tab__filter-chip");
    if on {
        c.push_str(" permissions-tab__filter-chip--on");
    }
    c
}

fn chip_kind_for_permission(kind: PermissionKind) -> AppKind {
    match kind {
        PermissionKind::Application => AppKind::PermissionApplication,
        PermissionKind::Delegated => AppKind::PermissionDelegated,
        PermissionKind::Unknown => AppKind::PermissionUnknown,
    }
}

// Row renderer wiring one resolved permission to the five mutation callbacks the
// table exposes (revoke app/delegated, remove declaration, scope, downgrade); the
// props are genuinely independent, so a parameter struct would only add ceremony.
#[allow(clippy::too_many_arguments)]
fn view_resolved_row<RevApp, RevDel, Remove, Scope, Downgrade>(
    p: ResolvedPermission,
    // Read reactively in the Scope cell (below) so that under a keyed `<For>` a
    // row's scope still updates when the async mail-scopes resolve — without
    // re-rendering the whole table on every filter toggle.
    mail_scopes: RwSignal<HashMap<String, MailPermissionScope>>,
    scopes_loading: RwSignal<bool>,
    revoke_application: RevApp,
    revoke_delegated: RevDel,
    remove_declared: Remove,
    scope: Scope,
    downgrade: Downgrade,
) -> impl IntoView
where
    RevApp: Fn(String) + Send + Sync + Copy + 'static,
    RevDel: Fn(String, String) + Send + Sync + Copy + 'static,
    Remove: Fn(String, String, PermissionKind) + Send + Sync + Copy + 'static,
    Scope: Fn(PickerSelection) + Send + Sync + Copy + 'static,
    Downgrade: Fn(String, String) + Send + Sync + Copy + 'static,
{
    let resource_display = p
        .resource_display_name
        .clone()
        .unwrap_or_else(|| p.resource_app_id.clone());
    let resource_guid = p.resource_app_id.clone();
    let perm_primary = p
        .permission_value
        .clone()
        .or_else(|| p.permission_display_name.clone())
        .unwrap_or_else(|| p.permission_id.clone());
    let perm_secondary = p
        .permission_display_name
        .clone()
        .filter(|d| Some(d) != p.permission_value.as_ref())
        .unwrap_or_else(|| p.permission_id.clone());
    let perm_guid_attr = p.permission_id.clone();
    let perm_guid_body = p.permission_id.clone();
    let chip_kind = chip_kind_for_permission(p.permission_kind);

    let runtime_assignment_id = p.runtime_assignment_id.clone();
    let runtime_grant_id = p.runtime_grant_id.clone();
    let permission_value = p.permission_value.clone();
    let scope_value = p.permission_value.clone();
    let permission_kind = p.permission_kind;
    // Identity of the declared row, for the "remove declaration" (not-granted) path.
    let remove_resource_app_id = p.resource_app_id.clone();
    let remove_permission_id = p.permission_id.clone();
    let granted = runtime_assignment_id.is_some() || runtime_grant_id.is_some();
    let status_label = if granted { "Granted" } else { "Not granted" };
    let status_class = if granted { "badge badge--ok" } else { "badge" };

    let trash_button = match (permission_kind, runtime_assignment_id, runtime_grant_id) {
        (PermissionKind::Application, Some(assignment_id), _) => {
            let on_click = move |_| revoke_application(assignment_id.clone());
            view! {
                <IconButton
                    icon=IconName::Trash
                    aria_label="Revoke application permission".to_string()
                    title="Revoke".to_string()
                    on_click=Callback::new(on_click)
                />
            }
            .into_any()
        }
        (PermissionKind::Delegated, _, Some(grant_id)) => match permission_value {
            Some(value) => {
                let on_click = move |_| revoke_delegated(grant_id.clone(), value.clone());
                view! {
                    <IconButton
                        icon=IconName::Trash
                        aria_label="Revoke delegated permission".to_string()
                        title="Revoke".to_string()
                        on_click=Callback::new(on_click)
                    />
                }
                .into_any()
            }
            None => ().into_any(),
        },
        // Not granted (declared only): the Trash icon removes the declaration
        // from the manifest rather than revoking a (nonexistent) runtime grant.
        _ => {
            let resource_app_id = remove_resource_app_id.clone();
            let permission_id = remove_permission_id.clone();
            let on_click = move |_| {
                remove_declared(
                    resource_app_id.clone(),
                    permission_id.clone(),
                    permission_kind,
                )
            };
            view! {
                <IconButton
                    icon=IconName::Trash
                    aria_label="Remove declared permission".to_string()
                    title="Remove".to_string()
                    on_click=Callback::new(on_click)
                />
            }
            .into_any()
        }
    };

    // "Scope…" appears only on a granted Application permission that can be
    // restricted per row after the fact — an org-wide Sites.* (mail scoping is
    // app-wide, handled by the "Exchange scoping" section, not this button).
    let scope_button = match (permission_kind, granted, scope_value.as_deref()) {
        // A held-scopable row is always a Microsoft Graph `Sites.*` application
        // role, so the selection is fully determined here; the wizard infers the
        // mechanism from it.
        (PermissionKind::Application, true, Some(value)) => row_scope_kind(value).map(|_kind| {
            let sel = PickerSelection {
                resource_app_id: p.resource_app_id.clone(),
                kind: PermissionKind::Application,
                permission_id: p.permission_id.clone(),
                permission_value: value.to_string(),
            };
            let on_click = move |_| scope(sel.clone());
            view! {
                <IconButton
                    icon=IconName::Filter
                    aria_label="Scope this permission".to_string()
                    title="Scope…".to_string()
                    on_click=Callback::new(on_click)
                />
            }
        }),
        _ => None,
    };

    // "Downgrade…" appears on an Application row whose value has a documented
    // narrower alternative (granted or declared-only — the backend swaps
    // whichever halves exist). Opens the chooser; the swap itself is
    // admin-judged, so this is never a one-click mutation.
    let downgrade_resource_app_id = p.resource_app_id.clone();
    let downgrade_button = match (permission_kind, p.permission_value.as_deref()) {
        (PermissionKind::Application, Some(value)) if !downgrade_alternatives(value).is_empty() => {
            let value = value.to_string();
            let on_click = move |_| downgrade(downgrade_resource_app_id.clone(), value.clone());
            Some(view! {
                <IconButton
                    icon=IconName::ChevronDown
                    aria_label="Downgrade to a narrower permission".to_string()
                    title="Downgrade…".to_string()
                    on_click=Callback::new(on_click)
                />
            })
        }
        _ => None,
    };

    view! {
        <tr>
            <td class="permission-cell">
                <div class="permissions-cell__primary">{resource_display}</div>
                <div class="permissions-cell__secondary mono">{resource_guid}</div>
            </td>
            <td class="permission-cell" title=perm_guid_attr>
                <div class="permissions-cell__primary">{perm_primary}</div>
                <div class="permissions-cell__secondary">{perm_secondary}</div>
                <div class="permissions-cell__secondary mono">{perm_guid_body}</div>
            </td>
            <td class="cell-mid">
                <TypeChip kind=chip_kind />
            </td>
            <td class="cell-mid">
                {
                    let is_app = permission_kind == PermissionKind::Application;
                    move || {
                        // Same lookup as before, but reactive: re-resolves when the
                        // mail-scopes map / loading flag change.
                        let mail_scope = scope_value
                            .as_deref()
                            .and_then(|v| mail_scopes.with(|m| m.get(v).cloned()));
                        permission_scope_cell(
                            scope_value.as_deref(),
                            mail_scope,
                            is_app,
                            scopes_loading.get(),
                        )
                    }
                }
            </td>
            <td class="cell-mid">
                <span class=status_class>{status_label}</span>
            </td>
            <td class="cell-mid">
                <div class="cell-actions">
                    {scope_button}
                    {downgrade_button}
                    {trash_button}
                </div>
            </td>
        </tr>
    }
}
