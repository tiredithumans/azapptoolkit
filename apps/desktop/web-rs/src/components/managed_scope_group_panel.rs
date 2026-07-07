//! Membership panel for the toolkit-managed mail-enabled scope group (named by
//! the tenant's group-name pattern, default `app_scope_group_<appId>`): resolves
//! the group's members and lets the user add/remove mailboxes inline. Backed by
//! `list_/add_/remove_exchange_scope_group(_members)`.
//!
//! Once an app is scoped via Exchange RBAC, the management scope's
//! `MemberOfGroup` filter resolves this group's membership live, so adjusting
//! who's in scope is *only* a membership change here — no re-grant needed. The
//! panel is shared by the persistent "Exchange scoping" section (ongoing
//! management) and the scoped-mailbox wizard (first-run setup); the host owns
//! `group_state` so it can read the resolved group (e.g. its SMTP for a grant).

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Spinner, SpinnerSize, Textarea};

use crate::bindings::auth;
use crate::bindings::exchange;
use crate::components::ui::Callout;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::util::parse_lines;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;

#[allow(clippy::type_complexity)]
type GroupState =
    RwSignal<Option<Result<exchange::ExchangeScopeGroupDto, azapptoolkit_dto::UiError>>>;

#[component]
pub fn ManagedScopeGroupPanel(
    /// appId (client id) — resolves the tenant's scope group (default `app_scope_group_<appId>`).
    #[prop(into)]
    app_id: Signal<String>,
    /// Host-owned resolved group state (existence + members). The panel loads it
    /// on mount and after each membership mutation; hosts may read it (e.g. to
    /// pull the group's SMTP for a grant).
    group_state: GroupState,
) -> impl IntoView {
    let session = use_session();
    let add_text = RwSignal::new(String::new());
    // Drives the membership mutations (`do_add` / `do_remove`) + initial load.
    let group_cmd = use_command();
    // Confirmation gate for removing a mailbox — a server mutation that stops the
    // app reaching it via the scoped grant.
    let pending_remove_mailbox: RwSignal<Option<String>> = RwSignal::new(None);

    // Loads the managed group's state (existence + members). Reads `app_id`
    // reactively so it reloads when the app changes; also called imperatively
    // after a membership mutation.
    let load_group = move || {
        let Some(t) = session.active_tenant.get() else {
            group_state.set(None);
            return;
        };
        let app = app_id.get();
        group_cmd.busy.set(true);
        leptos::task::spawn_local(async move {
            let res = exchange::list_exchange_scope_group(&t.tenant_id, &app).await;
            group_state.set(Some(res));
            group_cmd.busy.set(false);
        });
    };

    // Load on mount (the panel is only mounted when its host is showing it, so
    // this costs nothing while collapsed) and whenever `app_id` changes.
    Effect::new(move |_| {
        let _ = app_id.get();
        load_group();
    });

    // Interactive consent for the Exchange admin scope, then reload.
    let do_consent = move || {
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        leptos::task::spawn_local(async move {
            if auth::request_scope_consent(&t.tenant_id, "exchange")
                .await
                .is_ok()
            {
                load_group();
            }
        });
    };

    let do_add = move || {
        let mailboxes = parse_lines(&add_text.get());
        if mailboxes.is_empty() {
            group_cmd
                .error
                .set(Some("Enter at least one mailbox (one per line).".into()));
            return;
        }
        let app = app_id.get();
        group_cmd.run(
            move |r: exchange::ExchangeMemberMutationResult| {
                add_text.set(String::new());
                let mut msg = format!(
                    "Added {} mailbox(es) to {}.",
                    r.succeeded.len(),
                    r.group_name
                );
                if r.group_created {
                    msg.push_str(" Group created.");
                }
                session.toast_success(msg);
                if !r.failed.is_empty() {
                    group_cmd.error.set(Some(format!(
                        "{} mailbox(es) could not be added: {}",
                        r.failed.len(),
                        r.failed
                            .iter()
                            .map(|f| format!("{} ({})", f.mailbox, f.reason))
                            .collect::<Vec<_>>()
                            .join("; "),
                    )));
                }
                // Membership changed but the scope verdict didn't, so no cache
                // bust — just refresh the live member list.
                load_group();
            },
            move |tenant_id| async move {
                exchange::add_exchange_scope_group_members(&tenant_id, &app, &mailboxes).await
            },
        );
    };

    let do_remove = move |mailbox: String| {
        let app = app_id.get();
        let mailboxes = vec![mailbox.clone()];
        group_cmd.run(
            move |r: exchange::ExchangeMemberMutationResult| {
                if r.failed.is_empty() {
                    session.toast_success(format!("Removed {mailbox} from {}.", r.group_name));
                    load_group();
                    pending_remove_mailbox.set(None);
                } else {
                    group_cmd.error.set(Some(format!(
                        "Could not remove {mailbox}: {}",
                        r.failed
                            .iter()
                            .map(|f| f.reason.clone())
                            .collect::<Vec<_>>()
                            .join("; "),
                    )));
                }
            },
            move |tenant_id| async move {
                exchange::remove_exchange_scope_group_members(&tenant_id, &app, &mailboxes).await
            },
        );
    };

    view! {
        <section class="managed-scope-group">
            <ConfirmDialog
                open=Signal::derive(move || pending_remove_mailbox.with(|p| p.is_some()))
                title="Remove mailbox from scope group?"
                body="Removes the mailbox from the toolkit-managed scope group, so the app can no longer reach it via the scoped Exchange grant. Exchange can take up to ~2 hours to apply RBAC changes."
                confirm_label="Remove"
                busy=group_cmd.busy
                error=group_cmd.error
                on_confirm=Callback::new(move |()| {
                    if let Some(mb) = pending_remove_mailbox.get() {
                        do_remove(mb);
                    }
                })
                on_close=Callback::new(move |()| {
                    pending_remove_mailbox.set(None);
                    group_cmd.error.set(None);
                })
            />
            {move || {
                // State-aware status header: whether the group already EXISTS (with
                // its live member count) or WILL BE CREATED on first add — the DTO
                // always carries the resolved name, so the bare name alone can't tell
                // them apart.
                match group_state.get() {
                    Some(Ok(g)) if !g.exists => {
                        let name = g.group_name.clone();
                        view! {
                            <div class="managed-scope-group__status">
                                <div>
                                    <strong>"Mailboxes in scope"</strong>
                                    " "
                                    <span class="badge">"Will be created"</span>
                                </div>
                                <Callout tone="info" role="status">
                                    "The managed scope group " <span class="mono">{name}</span>
                                    " doesn't exist yet — it's created automatically when you add the "
                                    "first mailbox below. Its membership is exactly the set of mailboxes "
                                    "this app can reach through the scoped grant."
                                </Callout>
                            </div>
                        }
                            .into_any()
                    }
                    Some(Ok(g)) => {
                        let name = g.group_name.clone();
                        let n = g.members.len();
                        let noun = if n == 1 { "mailbox" } else { "mailboxes" };
                        view! {
                            <div class="managed-scope-group__status">
                                <div>
                                    <strong>{format!("Mailboxes in scope — managed group “{name}”")}</strong>
                                    " "
                                    <span class="badge badge--ok">"Exists"</span>
                                </div>
                                <Body1 class="hint">
                                    {format!(
                                        "{n} {noun} in scope — the app can reach exactly these through the scoped grant.",
                                    )}
                                </Body1>
                            </div>
                        }
                            .into_any()
                    }
                    _ => view! { <strong>"Mailboxes in scope (managed group)"</strong> }.into_any(),
                }
            }}
            <Field label="Add mailboxes (one per line)">
                <Textarea value=add_text placeholder="alice@contoso.com\nbob@contoso.com" />
            </Field>
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| do_add())
                    disabled=Signal::derive(move || group_cmd.busy.get())
                >
                    {move || {
                        if group_cmd.busy.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }.into_any()
                        } else {
                            view! { "Add mailboxes" }.into_any()
                        }
                    }}
                </Button>
            </div>
            {move || {
                group_cmd.error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
            }}
            {move || {
                match group_state.get() {
                    None => view! { <Body1 class="hint">"Loading…"</Body1> }.into_any(),
                    Some(Err(e)) => {
                        let needs_consent = e.code == "consent_required";
                        view! {
                            <div class="alert alert--warn">
                                <Body1>{e.message}</Body1>
                                {needs_consent
                                    .then(|| {
                                        view! {
                                            <div class="actions-row">
                                                <Button
                                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                    on_click=Box::new(move |_| do_consent())
                                                >
                                                    "Grant consent & retry"
                                                </Button>
                                            </div>
                                        }
                                    })}
                            </div>
                        }
                            .into_any()
                    }
                    // Not-yet-created: the status header's callout already explains it.
                    Some(Ok(g)) if !g.exists => ().into_any(),
                    Some(Ok(g)) if g.members.is_empty() => {
                        view! {
                            <Body1 class="hint">
                                "No mailboxes in scope yet — add at least one above."
                            </Body1>
                        }
                            .into_any()
                    }
                    Some(Ok(g)) => {
                        let members = g.members.clone();
                        view! {
                            <ul class="member-list">
                                {members
                                    .into_iter()
                                    .map(|m| {
                                        let smtp = m.primary_smtp_address.clone().unwrap_or_default();
                                        let label = m
                                            .display_name
                                            .clone()
                                            .filter(|d| !d.is_empty())
                                            .unwrap_or_else(|| smtp.clone());
                                        let remove_id = smtp.clone();
                                        view! {
                                            <li class="row-between">
                                                <span>{label} " " <span class="mono">{smtp}</span></span>
                                                <Button
                                                    class="button--danger"
                                                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                    on_click=Box::new(move |_| {
                                                        pending_remove_mailbox.set(Some(remove_id.clone()))
                                                    })
                                                    disabled=Signal::derive(move || group_cmd.busy.get())
                                                >
                                                    "Remove"
                                                </Button>
                                            </li>
                                        }
                                    })
                                    .collect_view()}
                            </ul>
                        }
                            .into_any()
                    }
                }
            }}
        </section>
    }
}
