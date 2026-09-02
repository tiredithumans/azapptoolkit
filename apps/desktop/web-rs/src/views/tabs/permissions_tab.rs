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
use crate::bindings::exchange;
use crate::bindings::permissions::{self, GrantResult};
use crate::components::exchange_scoping_section::ExchangeScopingSection;
use crate::components::icon::IconName;
use crate::components::legacy_exchange_grants_callout::{
    AppPermissionRow, LegacyExchangeGrantsCallout,
};
use crate::components::permission_picker::PickerSelection;
use crate::components::requires_role::RequiresRole;
use crate::components::scope_badge::{
    is_exchange_scopable_on, is_sharepoint_orgwide, permission_scope_cell,
    permission_scope_reach_is_unstated,
};
use crate::components::scope_unavailable_banner::ScopeUnavailableBanner;
use crate::components::scope_wizard::{ScopeTarget, ScopeWizard};
use crate::components::sharepoint_sites_section::SharePointSitesSection;
use crate::components::toast::ToastAction;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::Callout;
use crate::components::ui::IconButton;
use crate::hooks::use_command::use_command;
use crate::state::{Session, use_session};
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::tabs::usage_panel::UsagePanel;
use azapptoolkit_core::audit::{MailPermissionScope, downgrade_alternatives};
use azapptoolkit_core::scoping::{
    ScopeKind, is_scopable_sharepoint_resource_permission,
    is_scoped_sharepoint_item_resource_permission,
};
use azapptoolkit_dto::UiError;
use azapptoolkit_dto::permissions::{PermissionKind, ResolvedPermission};

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
///
/// Resource-aware: `Sites.*` exists on Office 365 SharePoint Online as well as
/// on Microsoft Graph, and only Graph's per-site grants are the ones this
/// toolkit reads and writes. The row's own `resource_app_id` settles it, so the
/// button appears only where the conversion can actually be performed.
fn row_scope_kind(resource_app_id: Option<&str>, value: &str) -> Option<ScopeKind> {
    if is_scopable_sharepoint_resource_permission(resource_app_id, value) {
        return Some(ScopeKind::SharePoint);
    }
    // The sub-site Selected scopes get the button for the opposite reason: not
    // to convert an org-wide grant away, but because the scope grants **nothing**
    // until a resource is picked. A held `Files.SelectedOperations.Selected` with
    // no per-item grants is an app that cannot read a single file, and this is
    // the row an operator lands on when they go looking for why.
    is_scoped_sharepoint_item_resource_permission(resource_app_id, value)
        .then_some(ScopeKind::SharePointItem)
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
                    .is_some_and(|v| is_exchange_scopable_on(Some(&p.resource_app_id), v))
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

    // A row's "Test access…" seeds the Permission tester with THIS principal and
    // jumps to it. Offered only beside a badge that can't state its own reach
    // (org-wide, unknown, or a non-enumerable Selected-items scope) — see
    // `permission_scope_reach_is_unstated`. Keyed on appId because that is what
    // both live checks resolve the service principal by, so the seed works for
    // an app registration exactly as it would for its enterprise-app twin.
    let open_tester = move || {
        let app_id = detail.with_untracked(|d| d.application.app_id.clone());
        session.open_permission_tester_for(app_id);
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

    // What a row's Trash icon is about to do, held while its confirm dialog is
    // open. The icon used to call the mutation directly: one click on a 32px
    // glyph in a dense table stripped a live production grant, with no dialog,
    // no subject and no success toast — the only signal being a row vanishing on
    // refetch. The identical `revoke_app_role_assignment` call is confirm-gated
    // on both the Enterprise Application and Managed Identity panes, so this was
    // the busiest surface in the app and the only unguarded one.
    //
    // Each variant carries the row's own display value so the dialog can name
    // it: `ConfirmDialog::body` is `&'static str` and describes the *kind* of
    // thing, which is exactly how six identical dialogs happened before.
    #[derive(Clone)]
    enum PendingRevoke {
        /// A live app-role assignment (an Application permission).
        Application {
            assignment_id: String,
            subject: String,
        },
        /// A consented delegated scope. Its value is its own subject.
        Delegated { grant_id: String, value: String },
        /// Declared-but-never-granted: removes the manifest entry, not a grant.
        Declared {
            resource_app_id: String,
            permission_id: String,
            kind: PermissionKind,
            subject: String,
        },
    }

    let pending_revoke: RwSignal<Option<PendingRevoke>> = RwSignal::new(None);
    let close_revoke = move || {
        pending_revoke.set(None);
        cmd.error.set(None);
    };

    let do_revoke_application = move |assignment_id: String, subject: String| {
        let Some(sp_id) = detail.with(|d| d.service_principal.as_ref().map(|sp| sp.id.clone()))
        else {
            cmd.error.set(Some(
                "App has no service principal — nothing to revoke.".into(),
            ));
            return;
        };
        cmd.run(
            move |()| {
                session.toast_success(format!("Revoked {subject}."));
                pending_revoke.set(None);
                on_changed.run(());
            },
            move |tenant_id| async move {
                permissions::revoke_app_role_assignment(&tenant_id, &sp_id, &assignment_id).await
            },
        );
    };

    let do_revoke_delegated = move |grant_id: String, scope_value: String| {
        let subject = scope_value.clone();
        cmd.run(
            move |_| {
                session.toast_success(format!("Revoked {subject}."));
                pending_revoke.set(None);
                on_changed.run(());
            },
            move |tenant_id| async move {
                permissions::revoke_oauth2_scope(&tenant_id, &grant_id, &scope_value).await
            },
        );
    };

    // Remove a not-granted (declared-only) permission from the manifest. The
    // Trash icon on a granted row revokes the runtime grant; on a not-granted
    // row it removes the declaration instead, so every row has a way out.
    let do_remove_declared = move |resource_app_id: String,
                                   permission_id: String,
                                   kind: PermissionKind,
                                   subject: String| {
        let object_id = detail.with(|d| d.application.id.clone());
        cmd.run(
            move |()| {
                session.toast_success(format!("Removed the {subject} declaration."));
                pending_revoke.set(None);
                on_changed.run(());
            },
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

    // The row hands the dialog what it is about to act on; the dialog runs it.
    let arm_revoke_application = move |assignment_id: String, subject: String| {
        pending_revoke.set(Some(PendingRevoke::Application {
            assignment_id,
            subject,
        }));
    };
    let arm_revoke_delegated = move |grant_id: String, value: String| {
        pending_revoke.set(Some(PendingRevoke::Delegated { grant_id, value }));
    };
    let arm_remove_declared = move |resource_app_id: String,
                                    permission_id: String,
                                    kind: PermissionKind,
                                    subject: String| {
        pending_revoke.set(Some(PendingRevoke::Declared {
            resource_app_id,
            permission_id,
            kind,
            subject,
        }));
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
            // Legacy Office 365 Exchange Online mail grants can't be scoped and
            // override the Graph rows' verdicts, so nothing in the table above can
            // explain an "Org-wide" badge on a scoped app. Declared rows carry
            // their grant state, so the callout sees both halves.
            {move || {
                let rows = detail
                    .with(|d| {
                        d.resolved_permissions
                            .iter()
                            .filter(|p| p.permission_kind == PermissionKind::Application)
                            .filter_map(|p| {
                                Some(AppPermissionRow {
                                    resource_app_id: Some(p.resource_app_id.clone()),
                                    value: p.permission_value.clone()?,
                                    granted: p.runtime_assignment_id.is_some(),
                                })
                            })
                            .collect::<Vec<_>>()
                    });
                view! { <LegacyExchangeGrantsCallout rows=rows /> }
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
                                        arm_revoke_application,
                                        arm_revoke_delegated,
                                        arm_remove_declared,
                                        open_scope,
                                        open_downgrade,
                                        open_tester,
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
                            <Callout tone="warn">
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
                            </Callout>
                        }
                    })
            }}
            // Three always-mounted dialogs rather than one, and three bodies:
            // revoking a runtime grant breaks the app's calls the moment it
            // lands, while removing a declaration only edits the manifest an
            // admin would consent to next. Collapsing them into one "Are you
            // sure?" is what let the two read as the same act. Mounted (rather
            // than rendered on demand) so `use_focus_trap` sees a real
            // false->true edge and returns focus to the Trash icon on close —
            // the same shape the Enterprise Application pane uses.
            <ConfirmDialog
                open=Signal::derive(move || {
                    matches!(pending_revoke.get(), Some(PendingRevoke::Application { .. }))
                })
                title="Revoke this permission?"
                body="The app loses this app-role assignment as soon as this lands, and any call relying on it starts failing. The live grant is re-checked before removal, and it can be granted again."
                subject=Signal::derive(move || match pending_revoke.get() {
                    Some(PendingRevoke::Application { subject, .. }) => subject,
                    _ => String::new(),
                })
                confirm_label="Revoke"
                busy=cmd.busy
                error=cmd.error
                on_confirm=Callback::new(move |()| {
                    if let Some(PendingRevoke::Application { assignment_id, subject }) = pending_revoke
                        .get()
                    {
                        do_revoke_application(assignment_id, subject);
                    }
                })
                on_close=Callback::new(move |()| close_revoke())
            />
            <ConfirmDialog
                open=Signal::derive(move || {
                    matches!(pending_revoke.get(), Some(PendingRevoke::Delegated { .. }))
                })
                title="Revoke this delegated scope?"
                body="The app loses this consented scope for the users it was granted for. They are prompted to consent again the next time it is requested."
                subject=Signal::derive(move || match pending_revoke.get() {
                    Some(PendingRevoke::Delegated { value, .. }) => value,
                    _ => String::new(),
                })
                confirm_label="Revoke"
                busy=cmd.busy
                error=cmd.error
                on_confirm=Callback::new(move |()| {
                    if let Some(PendingRevoke::Delegated { grant_id, value }) = pending_revoke.get() {
                        do_revoke_delegated(grant_id, value);
                    }
                })
                on_close=Callback::new(move |()| close_revoke())
            />
            <ConfirmDialog
                open=Signal::derive(move || {
                    matches!(pending_revoke.get(), Some(PendingRevoke::Declared { .. }))
                })
                title="Remove this declared permission?"
                body="This permission was never granted, so nothing the app can do today changes. It is removed from the app's manifest, so it is no longer part of what an admin would consent to."
                subject=Signal::derive(move || match pending_revoke.get() {
                    Some(PendingRevoke::Declared { subject, .. }) => subject,
                    _ => String::new(),
                })
                confirm_label="Remove"
                busy=cmd.busy
                error=cmd.error
                on_confirm=Callback::new(move |()| {
                    if let Some(PendingRevoke::Declared {
                        resource_app_id,
                        permission_id,
                        kind,
                        subject,
                    }) = pending_revoke.get()
                    {
                        do_remove_declared(resource_app_id, permission_id, kind, subject);
                    }
                })
                on_close=Callback::new(move |()| close_revoke())
            />
            {move || {
                scope_note.get().map(|m| view! { <Callout tone="ok" role="status">{m}</Callout> })
            }}
            {move || consent_error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            {move || {
                consent_result
                    .get()
                    .map(|r| {
                        view! {
                            <Callout tone="ok" role="status">
                                {format!(
                                    "Created {} role assignment(s); {} scope grant(s); {} skipped; {} failure(s).",
                                    r.role_assignments_created.len(),
                                    r.scope_grants_upserted.len(),
                                    r.role_assignments_skipped.len(),
                                    r.failures.len(),
                                )}
                            </Callout>
                        }
                    })
            }}
            {move || {
                let has_mail = detail.with(|d| {
                    d.resolved_permissions.iter().any(|p| {
                        p.permission_value
                            .as_deref()
                            .is_some_and(|v| is_exchange_scopable_on(Some(&p.resource_app_id), v))
                    })
                });
                has_mail
                    .then(|| {
                        view! {
                            <ExchangeScopingSection
                                app_id=Signal::derive(move || {
                                    detail.with(|d| d.application.app_id.clone())
                                })
                                target=Signal::derive(move || ScopeTarget {
                                    object_id: Some(detail.with(|d| d.application.id.clone())),
                                    sp_object_id: String::new(),
                                    app_id: detail.with(|d| d.application.app_id.clone()),
                                    display_name: detail
                                        .with(|d| d.application.display_name.clone()),
                                    is_managed_identity: false,
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
// table exposes (revoke app/delegated, remove declaration, scope, downgrade) plus
// the read-only jump into the Permission tester; the props are genuinely
// independent, so a parameter struct would only add ceremony.
#[allow(clippy::too_many_arguments)]
fn view_resolved_row<RevApp, RevDel, Remove, Scope, Downgrade, TestAccess>(
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
    test_access: TestAccess,
) -> impl IntoView
where
    RevApp: Fn(String, String) + Send + Sync + Copy + 'static,
    RevDel: Fn(String, String) + Send + Sync + Copy + 'static,
    Remove: Fn(String, String, PermissionKind, String) + Send + Sync + Copy + 'static,
    Scope: Fn(PickerSelection) + Send + Sync + Copy + 'static,
    TestAccess: Fn() + Send + Sync + Copy + 'static,
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

    // The row's own human label, handed to the confirm dialog as its subject so
    // the modal names the permission the operator clicked rather than "this
    // permission" over a row it is covering.
    let revoke_subject = perm_primary.clone();
    let runtime_assignment_id = p.runtime_assignment_id.clone();
    let runtime_grant_id = p.runtime_grant_id.clone();
    let permission_value = p.permission_value.clone();
    let scope_value = p.permission_value.clone();
    // Scopability is per-resource (both mailbox resources expose a `Mail.Read`),
    // so the Scope cell needs the row's own resource, not just its value.
    let scope_resource_app_id = p.resource_app_id.clone();
    let permission_kind = p.permission_kind;
    // Identity of the declared row, for the "remove declaration" (not-granted) path.
    let remove_resource_app_id = p.resource_app_id.clone();
    let remove_permission_id = p.permission_id.clone();
    let granted = runtime_assignment_id.is_some() || runtime_grant_id.is_some();
    let status_label = if granted { "Granted" } else { "Not granted" };
    let status_class = if granted { "badge badge--ok" } else { "badge" };

    let trash_button = match (permission_kind, runtime_assignment_id, runtime_grant_id) {
        (PermissionKind::Application, Some(assignment_id), _) => {
            let subject = revoke_subject.clone();
            let on_click = move |_| revoke_application(assignment_id.clone(), subject.clone());
            view! {
                <IconButton
                    icon=IconName::Trash
                    aria_label="Revoke application permission".to_string()
                    title="Revoke".to_string()
                    class="button--danger".to_string()
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
                        class="button--danger".to_string()
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
            let subject = revoke_subject.clone();
            let on_click = move |_| {
                remove_declared(
                    resource_app_id.clone(),
                    permission_id.clone(),
                    permission_kind,
                    subject.clone(),
                )
            };
            view! {
                <IconButton
                    icon=IconName::Trash
                    aria_label="Remove declared permission".to_string()
                    title="Remove".to_string()
                    class="button--danger".to_string()
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
        // A held-scopable row is a Microsoft Graph `Sites.*` application role —
        // now checked rather than assumed, since the row carries its resource.
        (PermissionKind::Application, true, Some(value)) => {
            row_scope_kind(Some(&p.resource_app_id), value).map(|_kind| {
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
            })
        }
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
                        let loading = scopes_loading.get();
                        // Both the badge and the affordance beside it answer from
                        // the ONE `scope_cell_for` decision, so "Test access…"
                        // can never appear next to a badge that does state its
                        // reach — or go missing next to one that doesn't.
                        let unstated = permission_scope_reach_is_unstated(
                            scope_value.as_deref(),
                            Some(&scope_resource_app_id),
                            mail_scope.clone(),
                            is_app,
                            loading,
                        );
                        view! {
                            {permission_scope_cell(
                                scope_value.as_deref(),
                                Some(&scope_resource_app_id),
                                mail_scope,
                                is_app,
                                loading,
                            )}
                            {unstated
                                .then(|| {
                                    view! {
                                        <button
                                            type="button"
                                            class="link-btn scope-cell__test-access"
                                            title="Check this app against one specific mailbox or SharePoint resource in the Permission Tester"
                                            on:click=move |_| test_access()
                                        >
                                            "Test access…"
                                        </button>
                                    }
                                })}
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::scoping::{MICROSOFT_GRAPH_APP_ID, OFFICE365_SHAREPOINT_ONLINE_APP_ID};

    /// The "Scope…" button's gate. It must appear exactly where the per-row
    /// conversion to `Sites.Selected` can actually be performed: offering it
    /// elsewhere runs an apply that changes nothing while the row re-renders as
    /// handled, and withholding it hides a remediation the operator can do.
    #[test]
    fn the_scope_button_is_offered_only_for_graph_org_wide_sites() {
        assert_eq!(
            row_scope_kind(Some(MICROSOFT_GRAPH_APP_ID), "Sites.Read.All"),
            Some(ScopeKind::SharePoint)
        );
        assert_eq!(
            row_scope_kind(Some(MICROSOFT_GRAPH_APP_ID), "Sites.ReadWrite.All"),
            Some(ScopeKind::SharePoint)
        );
    }

    #[test]
    fn an_already_scoped_row_needs_no_conversion() {
        assert_eq!(
            row_scope_kind(Some(MICROSOFT_GRAPH_APP_ID), "Sites.Selected"),
            None
        );
    }

    #[test]
    fn mail_is_never_a_per_row_scope() {
        // Exchange RBAC scoping is app-wide — one management scope binds the
        // whole principal's mail roles — so it is driven by the app-wide
        // "Exchange scoping" section, never this button.
        assert_eq!(
            row_scope_kind(Some(MICROSOFT_GRAPH_APP_ID), "Mail.Read"),
            None
        );
    }

    #[test]
    fn the_legacy_sharepoint_resource_gets_no_button() {
        // Office 365 SharePoint Online exposes the same `Sites.*` names, but the
        // per-site grants this toolkit reads and writes are Graph's — the
        // conversion cannot be performed there.
        assert_eq!(
            row_scope_kind(Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID), "Sites.Read.All"),
            None
        );
        assert_eq!(
            row_scope_kind(None, "Sites.Read.All"),
            None,
            "an unresolved resource must not earn an apply action"
        );
    }

    #[test]
    fn a_non_sites_permission_has_no_per_row_mechanism() {
        assert_eq!(
            row_scope_kind(Some(MICROSOFT_GRAPH_APP_ID), "Directory.Read.All"),
            None
        );
    }
}
