//! Sets or clears the expiry date of one application grant (B3).
//!
//! The date is a tag on the holding service principal; nothing happens on the
//! day itself. The next audit lists the grant under "Grants past their expiry",
//! whose Fix revokes it.

use azapptoolkit_core::audit::GrantExpiry;
use jiff::civil::Date;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, Field};

use crate::bindings::permissions;
use crate::components::modal_shell::ModalShell;
use crate::components::ui::{DateInput, FormError, Spinner};
use crate::hooks::use_command::use_command;

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
                permissions::set_grant_expiry(
                    &tenant,
                    &t.sp_object_id,
                    &t.resource_app_id,
                    &t.app_role_id,
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
                 Security audit lists it under \"Grants past their expiry\", whose Fix revokes it."
            </span>
            <Field label="Expires on">
                <DateInput value=date label="Expires on" class="grant-expiry__date" />
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
