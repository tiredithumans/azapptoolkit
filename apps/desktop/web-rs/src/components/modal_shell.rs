//! Shared scaffolding for hand-rolled modals: the backdrop + box markup plus the
//! focus-trap, close-on-Escape, and ARIA wiring every modal needs. Form modals
//! pass their fields + actions as children and get the focus contract for free,
//! instead of each re-implementing `<Show>` + `modal-backdrop` and (as several
//! did) silently omitting `use_focus_trap` / `use_escape`.
//!
//! `ConfirmDialog` and the dedicated dialog components predate this and keep
//! their own (equivalent) wiring.

use leptos::html;
use leptos::prelude::*;

use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;

#[component]
pub fn ModalShell(
    /// Whether the modal is shown. The shell is `<Show>`-gated, so children only
    /// mount while open.
    #[prop(into)]
    open: Signal<bool>,
    /// Heading text (static or reactive, e.g. "Add" vs "Edit"); also the
    /// `aria-labelledby` target.
    #[prop(into)]
    title: Signal<String>,
    /// While `busy`, Escape no longer closes the modal (a submit is in flight).
    #[prop(into, optional)]
    busy: Signal<bool>,
    /// Invoked on Escape. The caller still renders its own Cancel/close control.
    #[prop(into)]
    on_close: Callback<()>,
    /// Widens the box (`modal--wide`) for content like reveal/PEM blocks.
    #[prop(optional)]
    wide: bool,
    children: ChildrenFn,
) -> impl IntoView {
    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);
    let modal_class = if wide { "modal modal--wide" } else { "modal" };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="modal-shell-title"
            >
                <div class=modal_class node_ref=modal_ref>
                    <h3 id="modal-shell-title">{move || title.get()}</h3>
                    {children()}
                </div>
            </div>
        </Show>
    }
}
