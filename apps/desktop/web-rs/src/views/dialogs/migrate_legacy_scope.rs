//! The Security workbench's one-click "Migrate to RBAC for Applications" fix,
//! for a principal whose mailbox access is still confined by a legacy
//! Application Access Policy (audit Rule 11's legacy bucket).
//!
//! **Plan first, then apply.** Opening the modal runs the migration as a dry run
//! and shows what it would do; nothing is mutated until the operator commits.
//! That is not decoration: the migration folds every `RestrictAccess` policy on
//! the app into ONE management scope, copies the policy groups' mailboxes onto
//! the toolkit-managed group, and removes org-wide Entra grants — and it fails
//! closed in ways worth reading first (an unverifiable mailbox leaves the scope
//! on the legacy group; a grant that couldn't be re-scoped keeps the policy).
//!
//! Unlike the other scope fixes there is **no `ScopeFixTarget` split**: an
//! Application Access Policy names an *appId*, and the migration works from the
//! principal's granted roles, so one call serves an app registration, a foreign
//! enterprise app and a managed identity alike. There is also no dedicated
//! `commands/remediation.rs` handler (the `AddOwner` precedent) — the existing
//! `migrate_application_access_policies` command already re-resolves every input
//! live and carries the guards; wrapping it would add a second door to the same
//! room.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use azapptoolkit_core::audit::RemediationAction;

use crate::bindings::exchange::{self, AapMigrationReport};
use crate::components::aap_migration_report::AapMigrationReportView;
use crate::components::modal_shell::ModalShell;
use crate::state::use_session;

#[component]
pub fn MigrateLegacyScopeButton(
    /// The principal's **appId** — what an Application Access Policy is keyed on.
    app_id: String,
    /// The audit row's `object_id`, reported back through `on_done` so the row
    /// that owns this Fix is the one cleared.
    row_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let report: RwSignal<Option<AapMigrationReport>> = RwSignal::new(None);

    let run = {
        let app_id = app_id.clone();
        let row_id = row_id.clone();
        Callback::new(move |dry_run: bool| {
            if busy.get_untracked() {
                return;
            }
            let Some(t) = tenant.get_untracked() else {
                return;
            };
            busy.set(true);
            error.set(None);
            report.set(None);
            let app_id = app_id.clone();
            let row_id = row_id.clone();
            leptos::task::spawn_local(async move {
                // `scope_name: None` ⇒ the tenant's configured scope-name
                // pattern (default `app_scope_<appId>`), the same name a fresh
                // scoped grant would use. An override belongs to the deliberate
                // per-app flow on the Permissions tab, not to a one-click fix.
                match exchange::migrate_application_access_policies(
                    &t.tenant_id,
                    Some(&app_id),
                    None,
                    dry_run,
                )
                .await
                {
                    Ok(r) => {
                        // A clean run is the only one that closes: `partial`
                        // means the fail-closed guards held something back, and
                        // those notes are the point of the flow.
                        let clean = !dry_run
                            && r.failures.is_empty()
                            && !r.items.is_empty()
                            && r.items.iter().all(|i| i.status == "migrated");
                        if clean {
                            open.set(false);
                            session.toast_success(
                                "Migrated to RBAC for Applications — the legacy policy is gone. \
                                 Exchange can take 30 min–2 h to apply RBAC changes. Re-run the \
                                 audit to refresh scores.",
                            );
                            on_done.run(row_id);
                        } else {
                            report.set(Some(r));
                        }
                    }
                    Err(e) => error.set(Some(e.message)),
                }
                busy.set(false);
            });
        })
    };

    // The plan costs nothing and mutates nothing, so it runs on open rather than
    // behind a second click — the operator's first view is what would change.
    let label = action.label.clone();
    let detail = action.detail.clone();
    let preview = action.detail.clone();
    view! {
        <div class="audit-actions">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| {
                    open.set(true);
                    run.run(true);
                })
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{preview}</div>
            <ModalShell
                open=Signal::derive(move || open.get())
                title="Migrate to RBAC for Applications".to_string()
                busy=Signal::derive(move || busy.get())
                on_close=Callback::new(move |()| open.set(false))
                wide=true
            >
                <Body1>
                    "Replaces this app's legacy Application Access Policy with the current model: the policy group's mailboxes (every group's, if the app has several policies) are copied into the toolkit-managed group, a management scope is built over it, the scoped Exchange roles are assigned, and only then are the matching org-wide Microsoft Entra grants removed. The legacy policy is deleted last, and only once every grant it was confining has been re-scoped — anything left org-wide keeps its policy, because that policy is the only thing still restricting it. If a mailbox can't be verified in the managed group, the scope is built over the legacy group instead, so the app never loses reach. You must be an Exchange administrator."
                </Body1>
                <p class="muted">{detail.clone()}</p>
                {move || {
                    busy.get()
                        .then(|| {
                            view! {
                                <div class="actions-row">
                                    <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                    <Body1>"Working…"</Body1>
                                </div>
                            }
                        })
                }}
                {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
                {move || {
                    report.get().map(|r| view! { <AapMigrationReportView report=r /> })
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| open.set(false))
                        disabled=Signal::derive(move || busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| run.run(true))
                        disabled=Signal::derive(move || busy.get())
                    >
                        "Re-plan"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| run.run(false))
                        // Never offer the commit before a plan has been read:
                        // the plan is what surfaces the fail-closed outcomes.
                        disabled=Signal::derive(move || {
                            busy.get() || report.with(|r| r.is_none())
                        })
                    >
                        "Migrate"
                    </Button>
                </div>
            </ModalShell>
        </div>
    }
    .into_any()
}
