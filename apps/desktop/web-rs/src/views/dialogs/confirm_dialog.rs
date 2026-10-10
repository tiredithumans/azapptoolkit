//! Reusable confirmation dialog for destructive actions. Caller owns the
//! `open` flag, the `busy` flag (so a "deleting…" spinner can show inside
//! the confirm button), and the optional error string. The dialog itself
//! does no async work — it only routes the user's choice to `on_confirm`
//! or `on_close`.
//!
//! Renders through `ModalShell`, so each instance gets its own title id: a pane
//! mounts several of these at once, and the fixed `confirm-dialog-title` they
//! used to share made a stacked confirmation announce the first one's title.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::components::modal_shell::ModalShell;
use crate::components::ui::FormError;

#[component]
pub fn ConfirmDialog(
    #[prop(into)] open: Signal<bool>,
    title: &'static str,
    body: &'static str,
    /// The specific object this action will affect — a credential's display
    /// name, a federated credential's subject, an app's name. Rendered bolded
    /// under the body.
    ///
    /// `body` is `&'static str` and describes the *kind* of thing ("this client
    /// secret"), which meant an app with six secrets showed six identical
    /// dialogs and the operator had to trust that the button they clicked
    /// belonged to the row they meant. Additive and optional so the existing
    /// static call sites keep working and names thread in incrementally.
    #[prop(into, optional)]
    subject: Signal<String>,
    #[prop(default = "Confirm")] confirm_label: &'static str,
    #[prop(default = "Cancel")] cancel_label: &'static str,
    /// When non-empty, the confirm button stays disabled until the user types
    /// this exact keyword (e.g. `"DELETE"`) — a typed-confirmation guard for the
    /// most dangerous actions, matching the bulk-delete flow. Empty (the default)
    /// keeps the one-click confirm.
    #[prop(default = "")]
    require_keyword: &'static str,
    #[prop(into, optional)] busy: Signal<bool>,
    #[prop(into, optional)] error: Signal<Option<String>>,
    #[prop(into)] on_confirm: Callback<()>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    // Typed-confirmation buffer (used only when `require_keyword` is set). Cleared
    // whenever the dialog closes so a re-open always starts blank.
    let typed = RwSignal::new(String::new());
    Effect::new(move |_| {
        if !open.get() {
            typed.set(String::new());
        }
    });
    let confirm_disabled = move || {
        busy.get() || (!require_keyword.is_empty() && typed.get().trim() != require_keyword)
    };

    view! {
        <ModalShell open=open title=title busy=busy on_close=on_close>
            <Body1>{body}</Body1>
            {move || {
                let s = subject.get();
                (!s.is_empty())
                    .then(|| view! { <p class="confirm-dialog__subject">{s}</p> })
            }}
            {(!require_keyword.is_empty())
                .then(|| {
                    view! {
                        <label class="confirm-dialog__keyword">
                            {format!("Type \"{require_keyword}\" to confirm:")}
                            <input
                                type="text"
                                autocomplete="off"
                                style="display:block;margin-top:4px;"
                                prop:value=move || typed.get()
                                on:input=move |ev| typed.set(event_target_value(&ev))
                            />
                        </label>
                    }
                })}
            {move || error.get().map(|e| view! { <FormError>{e}</FormError> })}
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| on_close.run(()))
                    disabled=Signal::derive(move || busy.get())
                >
                    {cancel_label}
                </Button>
                <Button
                    class="button--danger"
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| on_confirm.run(()))
                    disabled=Signal::derive(confirm_disabled)
                >
                    {move || {
                        if busy.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                .into_any()
                        } else {
                            view! { {confirm_label} }.into_any()
                        }
                    }}
                </Button>
            </div>
        </ModalShell>
    }
}
