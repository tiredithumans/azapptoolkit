//! Sets or clears the expiry date of one application grant (B3).
//!
//! The date is a tag on the holding service principal; nothing happens on the
//! day itself. The next audit lists the grant under "Grants past their expiry",
//! whose Fix revokes it.

use azapptoolkit_core::audit::GrantExpiry;
use azapptoolkit_dto::permissions::GrantRef;
use jiff::civil::Date;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, Field};

use crate::bindings::permissions;
use crate::components::modal_shell::ModalShell;
use crate::components::ui::{DateInput, FormError, Spinner};
use crate::hooks::use_command::use_command;
use crate::state::use_session;

/// One application grant held by `sp_object_id`, and its current expiry.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpiryTarget {
    pub sp_object_id: String,
    pub resource_app_id: String,
    pub app_role_id: String,
    /// The permission's name, for the title.
    pub label: String,
    pub current: Option<Date>,
}

/// The expiry set on `(resource_app_id, app_role_id)` among `expiries`.
pub fn current_expiry(
    expiries: &[GrantExpiry],
    resource_app_id: &str,
    app_role_id: &str,
) -> Option<Date> {
    expiries
        .iter()
        .find(|e| {
            e.resource_app_id.eq_ignore_ascii_case(resource_app_id)
                && e.app_role_id.eq_ignore_ascii_case(app_role_id)
        })
        .map(|e| e.expires_on)
}

/// "Expires …" / "Expired …" for a grant's date, by the UTC calendar the
/// audit judges expiry in.
pub fn expiry_note(date: Date) -> String {
    if azapptoolkit_core::audit::expiry_has_passed(date, jiff::Timestamp::now()) {
        format!("Expired {date}")
    } else {
        format!("Expires {date}")
    }
}

/// Expiry wiring for a held-permissions panel (an enterprise app's, a managed
/// identity's): the principal's expiries, read live and again after each
/// save; the opener the panel's rows call; and the dialog's target.
#[derive(Clone, Copy)]
pub struct HeldExpiries {
    pub expiries: RwSignal<Vec<GrantExpiry>>,
    pub target: RwSignal<Option<ExpiryTarget>>,
    pub on_expiry: Callback<(String, String, String)>,
    pub on_saved: Callback<Option<Date>>,
}

/// See [`HeldExpiries`]. `sp_object_id` is the service principal holding the
/// panel's grants.
pub fn use_held_expiries(sp_object_id: Signal<String>) -> HeldExpiries {
    let session = use_session();
    let expiries: RwSignal<Vec<GrantExpiry>> = RwSignal::new(Vec::new());
    let target: RwSignal<Option<ExpiryTarget>> = RwSignal::new(None);
    let reload = RwSignal::new(0_u32);
    Effect::new(move |_| {
        let _ = reload.get();
        let sp = sp_object_id.get();
        let Some(t) = session.active_tenant.get() else {
            return;
        };
        if sp.is_empty() {
            return;
        }
        leptos::task::spawn_local(async move {
            let res = permissions::get_grant_expiries(&t.tenant_id, &sp).await;
            if !session.is_active_tenant(&t.tenant_id) {
                return;
            }
            // An unreadable set shows no dates; it never blocks the panel.
            if let Ok(v) = res {
                let _ = expiries.try_set(v);
            }
        });
    });
    let on_expiry = Callback::new(
        move |(resource_app_id, app_role_id, label): (String, String, String)| {
            let current =
                expiries.with_untracked(|v| current_expiry(v, &resource_app_id, &app_role_id));
            target.set(Some(ExpiryTarget {
                sp_object_id: sp_object_id.get_untracked(),
                resource_app_id,
                app_role_id,
                label,
                current,
            }));
        },
    );
    let on_saved = Callback::new(move |date: Option<Date>| {
        if let Some(t) = target.get_untracked() {
            session.toast_success(match date {
                Some(d) => format!("{} expires {d}.", t.label),
                None => format!("Expiry cleared for {}.", t.label),
            });
        }
        reload.update(|n| *n += 1);
    });
    HeldExpiries {
        expiries,
        target,
        on_expiry,
        on_saved,
    }
}

/// Open while `target` is `Some`. `on_saved` runs after a write lands, with
/// the date now set (`None` once cleared), before `target` is closed;
/// `on_close` after Save, Clear or Cancel.
#[component]
pub fn GrantExpiryDialog(
    #[prop(into)] target: Signal<Option<ExpiryTarget>>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_saved: Callback<Option<Date>>,
) -> impl IntoView {
    let cmd = use_command();
    let date: RwSignal<Option<Date>> = RwSignal::new(None);
    // Prefill from each newly opened target, and drop a stale error.
    Effect::new(move |_| {
        let current = target.with(|t| t.as_ref().and_then(|t| t.current));
        date.set(current);
        cmd.error.set(None);
    });

    let write = move |expires_on: Option<Date>| {
        let Some(t) = target.get_untracked() else {
            return;
        };
        cmd.run_with(
            move |()| {
                on_saved.try_run(expires_on);
                on_close.try_run(());
            },
            move |e| cmd.fail_inline(e),
            move |tenant| async move {
                let day = expires_on.map(|d| d.to_string());
                let grant = GrantRef {
                    resource_app_id: t.resource_app_id.clone(),
                    app_role_id: t.app_role_id.clone(),
                };
                permissions::set_grant_expiry(
                    &tenant,
                    &t.sp_object_id,
                    std::slice::from_ref(&grant),
                    day.as_deref(),
                )
                .await
            },
        );
    };

    let open = Signal::derive(move || target.with(Option::is_some));
    let title = Signal::derive(move || {
        target.with(|t| {
            t.as_ref()
                .map(|t| format!("Expiry for {}", t.label))
                .unwrap_or_default()
        })
    });
    let has_current = move || target.with(|t| t.as_ref().is_some_and(|t| t.current.is_some()));

    view! {
        <ModalShell open=open title=title busy=cmd.busy on_close=on_close>
            <span class="ui-text">
                "On this date the grant is due to end. Nothing is revoked automatically: the next \
                 Security audit lists it under \"Grants past their expiry\", whose Fix revokes it. \
                 Dates are UTC: the grant stays valid through the end of that day."
            </span>
            <Field label="Expires on">
                <DateInput
                    value=date
                    label="Expires on"
                    class="grant-expiry__date"
                    min=jiff::tz::Offset::UTC.to_datetime(jiff::Timestamp::now()).date()
                />
            </Field>
            {move || cmd.error.get().map(|e| view! { <FormError>{e}</FormError> })}
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    disabled=Signal::derive(move || cmd.busy.get())
                    on_click=Box::new(move |_| on_close.run(()))
                >
                    "Cancel"
                </Button>
                {move || {
                    has_current()
                        .then(|| {
                            view! {
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    disabled=Signal::derive(move || cmd.busy.get())
                                    on_click=Box::new(move |_| write(None))
                                >
                                    "Clear expiry"
                                </Button>
                            }
                        })
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    disabled=Signal::derive(move || cmd.busy.get() || date.get().is_none())
                    on_click=Box::new(move |_| write(date.get_untracked()))
                >
                    "Save"
                </Button>
                {move || cmd.busy.get().then(|| view! { <Spinner /> })}
            </div>
        </ModalShell>
    }
}
