//! The cleanup panel for groups a consolidation retired: names each one and,
//! when nothing the toolkit can enumerate still references it, offers a
//! confirmed delete.
//!
//! Shared by both surfaces that repoint a management scope — the Exchange
//! scoping section's "Move to managed group" and the migration report (itself
//! shared by the Permissions tab and the Security tab's one-click Fix) — so the
//! caveat below is written once.
//!
//! **The delete is offered, never automatic.** `Remove-DistributionGroup` has no
//! undo: the group, its address and its membership are gone, and mail sent to it
//! starts bouncing. The toolkit can only enumerate two kinds of reference
//! (management scopes and legacy Application Access Policies); it cannot see
//! transport rules, retention/DLP policies, group nesting, or the people and
//! systems that simply mail the address. So a clean check is presented as "no
//! reference found here", the residual risk is spelled out on screen, and the
//! operator commits by typing the group's name.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Spinner, SpinnerSize};

use crate::bindings::exchange::{self, RetiredScopeGroupDto};
use crate::components::ui::Callout;
use crate::state::use_session;

/// The label an operator recognises the group by, falling back to the DN — which
/// is what the scope filter referenced, so it always exists.
fn group_label(group: &RetiredScopeGroupDto) -> String {
    group
        .display_name
        .clone()
        .or_else(|| group.primary_smtp_address.clone())
        .unwrap_or_else(|| group.distinguished_name.clone())
}

#[component]
pub fn RetiredScopeGroups(
    /// The app whose scope stopped referencing these groups — the backend uses
    /// it to refuse this app's own managed group.
    app_id: String,
    groups: Vec<RetiredScopeGroupDto>,
    /// Fired after a successful delete so the host can refresh.
    #[prop(optional, into)]
    on_deleted: Option<Callback<()>>,
) -> impl IntoView {
    if groups.is_empty() {
        return ().into_any();
    }
    view! {
        <Callout tone="info" role="status">
            <Body1>
                "This app's mailboxes now come from the toolkit-managed group. The group(s) below were the previous scope source, left in place for you to retire — with whatever still references them, as far as Exchange can be asked."
            </Body1>
            <ul class="warnings">
                {groups
                    .into_iter()
                    .map(|g| {
                        view! {
                            <RetiredGroupRow
                                app_id=app_id.clone()
                                group=g
                                on_deleted=on_deleted
                            />
                        }
                    })
                    .collect_view()}
            </ul>
        </Callout>
    }
        .into_any()
}

/// One retired group: its identifiers, what still references it (if anything),
/// and the guarded delete.
#[component]
fn RetiredGroupRow(
    app_id: String,
    group: RetiredScopeGroupDto,
    /// Forwarded verbatim from the panel, so it stays `Option` rather than
    /// being re-wrapped by an `into` prop.
    on_deleted: Option<Callback<()>>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let label = group_label(&group);
    let smtp = group.primary_smtp_address.clone();
    let dn = group.distinguished_name.clone();
    let references = group.still_referenced_by.clone();
    let checked = group.reference_check_complete;
    // Deletable only on a COMPLETED check that found nothing. An incomplete
    // check is an unknown, and an unknown must not read as a clean bill of
    // health for an irreversible action.
    let deletable = checked && references.is_empty();

    let armed = RwSignal::new(false);
    let typed = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let deleted = RwSignal::new(false);

    // Typed confirmation: the group's own label, so muscle memory can't fire it.
    let confirm_label = StoredValue::new(label.clone());
    let matches_typed =
        move || confirm_label.with_value(|l| typed.get().trim().eq_ignore_ascii_case(l));

    // `StoredValue` (Copy) rather than captured `String`s: these are read from
    // several `Fn` closures inside the view, which a moved String can't be.
    let target = StoredValue::new((
        app_id,
        // Prefer the SMTP address: it survives a group rename, and the backend
        // re-resolves whatever identity it is handed anyway.
        smtp.clone().unwrap_or_else(|| dn.clone()),
    ));
    let do_delete = Callback::new(move |()| {
        if busy.get_untracked() || !matches_typed() {
            return;
        }
        let Some(t) = tenant.get_untracked() else {
            return;
        };
        busy.set(true);
        error.set(None);
        let (app_id, identity) = target.get_value();
        leptos::task::spawn_local(async move {
            match exchange::delete_exchange_scope_group(&t.tenant_id, &app_id, &identity).await {
                Ok(()) => {
                    deleted.set(true);
                    armed.set(false);
                    session.toast_success("Group deleted.");
                    if let Some(cb) = on_deleted {
                        cb.run(());
                    }
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    });

    let heading = label.clone();
    let address = smtp
        .map(|s| format!(" ({s})"))
        .unwrap_or_else(|| format!(" ({dn})"));
    let type_prompt = RwSignal::new(format!("Type “{label}” to confirm"));
    view! {
        <li>
            <strong>{heading}</strong>
            <span class="hint">{address}</span>
            {move || {
                deleted
                    .get()
                    .then(|| view! { <div class="hint">"Deleted."</div> })
            }}
            <Show when=move || !deleted.get() fallback=|| view! { <></> }>
                {(!references.is_empty())
                    .then(|| {
                        view! {
                            <div class="form-error">
                                {format!("Still referenced by {}. Repoint or remove those before deleting.", references.join(", "))}
                            </div>
                        }
                    })}
                {(checked && references.is_empty())
                    .then(|| {
                        view! {
                            <div class="hint">
                                "No management scope or Application Access Policy references it. That is all the toolkit can check — mail flow, transport rules, group nesting and anything outside Exchange are not visible here, and deleting a group cannot be undone."
                            </div>
                        }
                    })}
                {(!checked)
                    .then(|| {
                        view! {
                            <div class="hint">
                                "The toolkit could not finish checking what else references this group, so no delete is offered. Review it in the Exchange admin center."
                            </div>
                        }
                    })}
                <Show when=move || deletable fallback=|| view! { <></> }>
                    <Show
                        when=move || armed.get()
                        fallback=move || {
                            view! {
                                <Button
                                    class="button--danger"
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(move |_| armed.set(true))
                                >
                                    "Delete group…"
                                </Button>
                            }
                        }
                    >
                        <div class="actions-row">
                            <Input value=typed placeholder=Signal::derive(move || type_prompt.get()) />
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                on_click=Box::new(move |_| armed.set(false))
                                disabled=Signal::derive(move || busy.get())
                            >
                                "Cancel"
                            </Button>
                            <Button
                                class="button--danger"
                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                on_click=Box::new(move |_| do_delete.run(()))
                                disabled=Signal::derive(move || busy.get() || !matches_typed())
                            >
                                {move || {
                                    if busy.get() {
                                        view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                            .into_any()
                                    } else {
                                        view! { "Delete permanently" }.into_any()
                                    }
                                }}
                            </Button>
                        </div>
                    </Show>
                </Show>
                {move || error.get().map(|e| view! { <div class="form-error">{e}</div> })}
            </Show>
        </li>
    }
}
