//! Guided add-owner remediation for the Security-audit view: a button + modal
//! that closes the Rule-14 ownership gap (no owners / single owner) either by
//! one-click applying the tenant's Settings-configured default owners or by
//! searching the directory for a specific user — both via the existing add-owner
//! mutation. Advisory only — the admin chooses; purely additive, so it can't
//! break a working sign-in.

use std::collections::HashSet;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use azapptoolkit_core::audit::RemediationAction;
use azapptoolkit_core::models::DirectoryObject;

use crate::bindings::applications;
use crate::components::directory_search::DirectorySearch;
use crate::components::modal_shell::ModalShell;
use crate::components::tenant_defaults_hint::OwnerDefaultsHint;
use crate::components::ui::FormError;
use crate::state::{Session, use_session};
use crate::util::count_noun;

/// Outcome of [`add_default_owners`].
pub(crate) enum DefaultOwnersOutcome {
    /// The tenant has no app-registration default owners configured.
    NoneConfigured,
    Done {
        added: usize,
        /// `(who, why)` per owner that could not be added. The typed error is
        /// kept (not flattened to text) so a dead session or missing consent
        /// among them can still raise its lever.
        failures: Vec<(String, azapptoolkit_dto::UiError)>,
    },
}

impl DefaultOwnersOutcome {
    /// The per-owner failure line both callers render, or `None` when nothing
    /// failed.
    pub(crate) fn failure_message(
        failures: &[(String, azapptoolkit_dto::UiError)],
    ) -> Option<String> {
        (!failures.is_empty()).then(|| {
            format!(
                "{} failed — {}",
                count_noun(failures.len(), "default owner", "default owners"),
                failures
                    .iter()
                    .map(|(who, e)| format!("{who}: {}", e.message))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })
    }

    /// Raises the recovery lever for the first failure that needs one (a dead
    /// session ends the loop, so it is also the last). Returns whether one was.
    pub(crate) fn report_recovery(
        session: Session,
        failures: &[(String, azapptoolkit_dto::UiError)],
    ) -> bool {
        failures
            .iter()
            .any(|(_, e)| session.report_recovery_action(e, "write"))
    }
}

/// Adds the tenant's Settings-configured app-registration default owners
/// (`app_registration.default_owners`) to one app registration. Additive:
/// skips anyone in `existing` (or, when `None`, anyone already an owner per the
/// cached detail) and never removes. The one loop behind the Owners tab's and
/// the audit remediation's "Add default owners" buttons.
pub(crate) async fn add_default_owners(
    tenant_id: &str,
    object_id: &str,
    existing: Option<HashSet<String>>,
) -> DefaultOwnersOutcome {
    let defaults = crate::bindings::defaults::get_tenant_defaults(tenant_id).await;
    let owners = defaults.app_registration.default_owners;
    if owners.is_empty() {
        return DefaultOwnersOutcome::NoneConfigured;
    }
    // Skip anyone already an owner so a re-run doesn't error on an existing
    // owner. `get_application_detail` is cached.
    let existing = match existing {
        Some(e) => e,
        None => match applications::get_application_detail(tenant_id, object_id).await {
            Ok(d) => d.owners.iter().map(|o| o.id.clone()).collect(),
            Err(_) => HashSet::new(),
        },
    };
    let mut added = 0usize;
    let mut failures = Vec::new();
    for p in owners {
        if existing.contains(&p.id) {
            continue;
        }
        match applications::add_application_owner(tenant_id, object_id, &p.id).await {
            Ok(()) => added += 1,
            Err(e) => {
                // A dead session fails every remaining owner identically:
                // stop, and let the caller raise Re-authenticate once.
                let fatal = e.is_reauth_fatal();
                failures.push((p.display_name.unwrap_or(p.id), e));
                if fatal {
                    break;
                }
            }
        }
    }
    DefaultOwnersOutcome::Done { added, failures }
}

/// "Add owner" remediation — one-click applies the tenant's default owners
/// (Settings → `app_registration.default_owners`) or searches users and adds the
/// picked one as an owner of the app registration. Adding directly from the
/// candidate row mirrors the Owners tab (no separate select-then-confirm step);
/// success closes the modal and fires `on_done` so the row's Fix button clears.
#[component]
pub fn AddOwnerButton(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let adding_defaults = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    // Distinct from `error`: this one is not a failure the operator can retry,
    // it is a missing setting with a place to go, so it renders as a hint with
    // the route in it rather than as dead red text (`OwnerDefaultsHint`).
    let no_owner_defaults = RwSignal::new(false);
    let raw_query = RwSignal::new(String::new());

    // `object_id` is consumed by both the per-row add and the default-owners
    // handler; give each its own clone.
    let object_id_row = object_id.clone();
    // A `Callback` (Copy) so every candidate row's click handler can capture it.
    let add = Callback::new(move |principal_id: String| {
        if busy.get() || adding_defaults.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        busy.set(true);
        error.set(None);
        let object_id = object_id_row.clone();
        leptos::task::spawn_local(async move {
            let res =
                applications::add_application_owner(&t.tenant_id, &object_id, &principal_id).await;
            // Sign-out mid-add: the toast would surface at the next sign-in.
            if !session.is_active_tenant(&t.tenant_id) {
                busy.set(false);
                return;
            }
            match res {
                Ok(()) => {
                    open.set(false);
                    raw_query.set(String::new());
                    session.toast_success(
                        "Owner added — re-run the audit to refresh the ownership finding.",
                    );
                    on_done.try_run(object_id);
                }
                Err(e) => session.fail_inline(&e, "write", error),
            }
            busy.set(false);
        });
    });

    // One-click apply of the tenant's Settings-configured default owners
    // (`app_registration.default_owners`). Additive: skips anyone already an
    // owner (via the cached detail), reports per-owner failures, and only clears
    // the finding's Fix button (`on_done`) when nothing failed.
    let add_defaults = Callback::new(move |_: ()| {
        if busy.get() || adding_defaults.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        adding_defaults.set(true);
        error.set(None);
        no_owner_defaults.set(false);
        let object_id = object_id.clone();
        leptos::task::spawn_local(async move {
            let outcome = add_default_owners(&t.tenant_id, &object_id, None).await;
            if !session.is_active_tenant(&t.tenant_id) {
                adding_defaults.set(false);
                return;
            }
            let (added, failures) = match outcome {
                DefaultOwnersOutcome::NoneConfigured => {
                    no_owner_defaults.set(true);
                    adding_defaults.set(false);
                    return;
                }
                DefaultOwnersOutcome::Done { added, failures } => (added, failures),
            };
            adding_defaults.set(false);
            if let Some(msg) = DefaultOwnersOutcome::failure_message(&failures) {
                // Leave the modal open with the error so the operator can retry;
                // don't clear the Fix button. A dead session or missing consent
                // among the failures gets its lever as well.
                DefaultOwnersOutcome::report_recovery(session, &failures);
                error.set(Some(msg));
                return;
            }
            open.set(false);
            raw_query.set(String::new());
            if added > 0 {
                session.toast_success(format!(
                    "Added {} — re-run the audit to refresh the ownership finding.",
                    count_noun(added, "default owner", "default owners")
                ));
            } else {
                session.toast_success(
                    "Default owners are already present — re-run the audit to refresh.",
                );
            }
            on_done.try_run(object_id);
        });
    });

    let label = action.label.clone();
    let detail = action.detail.clone();
    view! {
        <div class="audit-actions">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| open.set(true))
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ModalShell
                open=open
                title="Add an owner"
                busy=Signal::derive(move || busy.get() || adding_defaults.get())
                on_close=Callback::new(move |()| open.set(false))
            >
                <Body1>
                    "Search the directory and add an owner so this application has clear accountability. Adding an owner is purely additive — it can't disrupt the app's sign-in or permissions."
                </Body1>
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        disabled=Signal::derive(move || busy.get() || adding_defaults.get())
                        on_click=Box::new(move |_| add_defaults.run(()))
                    >
                        "Add default owners"
                    </Button>
                    {move || {
                        adding_defaults
                            .get()
                            .then(|| {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                            })
                    }}
                </div>
                <Body1 class="muted">
                    "Adds the owners configured for this tenant in Settings (additive — skips anyone already an owner). Or search below to add someone specific."
                </Body1>
                // Cleared by the add handler only on success, so a
                // failed add keeps the operator's query.
                <DirectorySearch
                    on_pick=Callback::new(move |u: DirectoryObject| add.run(u.id))
                    query=raw_query
                    placeholder="Search users by name or UPN (min 2 chars)"
                    action_appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    clear_on_pick=false
                    row_disabled=Callback::new(move |_: String| {
                        busy.get() || adding_defaults.get()
                    })
                />
                {move || {
                    error.get().map(|e| view! { <FormError>{e}</FormError> })
                }}
                <Show when=move || no_owner_defaults.get() fallback=|| ()>
                    <OwnerDefaultsHint class="form-error" tab="app-reg" />
                </Show>
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| open.set(false))
                        disabled=Signal::derive(move || busy.get() || adding_defaults.get())
                    >
                        "Cancel"
                    </Button>
                    {move || {
                        (busy.get() || adding_defaults.get())
                            .then(|| {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                            })
                    }}
                </div>
            </ModalShell>
        </div>
    }
    .into_any()
}
