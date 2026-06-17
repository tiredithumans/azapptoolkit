//! Reusable confirmation dialog for destructive actions. Caller owns the
//! `open` flag, the `busy` flag (so a "deleting…" spinner can show inside
//! the confirm button), and the optional error string. The dialog itself
//! does no async work — it only routes the user's choice to `on_confirm`
//! or `on_close`.

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;

#[component]
pub fn ConfirmDialog(
    #[prop(into)] open: Signal<bool>,
    title: &'static str,
    body: &'static str,
    #[prop(default = "Confirm")] confirm_label: &'static str,
    #[prop(default = "Cancel")] cancel_label: &'static str,
    #[prop(into, optional)] busy: Signal<bool>,
    #[prop(into, optional)] error: Signal<Option<String>>,
    #[prop(into)] on_confirm: Callback<()>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="confirm-dialog-title"
            >
                <div class="modal" node_ref=modal_ref>
                    <h3 id="confirm-dialog-title">{title}</h3>
                    <Body1>{body}</Body1>
                    {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
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
                            disabled=Signal::derive(move || busy.get())
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
                </div>
            </div>
        </Show>
    }
}
