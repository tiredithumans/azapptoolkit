//! Shared scaffolding for hand-rolled modals: the backdrop + box markup plus the
//! focus-trap, close-on-Escape, and ARIA wiring every modal needs. Form modals
//! pass their fields + actions as children and get the focus contract for free,
//! instead of each re-implementing `<Show>` + `modal-backdrop` and (as several
//! did) silently omitting `use_focus_trap` / `use_escape`.
//!
//! Each instance mints its own title id (`modal-shell-title-{n}`) for
//! `aria-labelledby`: several shells are mounted at once, so a fixed id would
//! make every label resolve to whichever came first in the document.
//!
//! `ConfirmDialog` and the dedicated dialog components predate this and keep
//! their own (equivalent) wiring, each with its own unique hard-coded title id.

use std::sync::atomic::{AtomicUsize, Ordering};

use leptos::html;
use leptos::prelude::*;

use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;

/// Source of per-instance title ids. Several `ModalShell`s can be mounted at
/// once — the shell alone mounts `ShortcutsHelp`, `UpdateSplash`,
/// `ReleaseNotesDialog` and `CacheDiagnosticsDialog` together — so the fixed
/// `id="modal-shell-title"` this replaced made `aria-labelledby` resolve to
/// whichever shell came first, and stacked dialogs shared one id.
static NEXT_MODAL_ID: AtomicUsize = AtomicUsize::new(0);

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
    /// `false` for one-time reveals whose dismissal destroys unrecoverable
    /// material; the caller's own button is then the only way out.
    #[prop(default = true)]
    close_on_escape: bool,
    children: ChildrenFn,
) -> impl IntoView {
    use_escape(
        move || close_on_escape && open.get_untracked() && !busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);
    let modal_class = if wide { "modal modal--wide" } else { "modal" };
    let title_id = StoredValue::new(format!(
        "modal-shell-title-{}",
        NEXT_MODAL_ID.fetch_add(1, Ordering::Relaxed)
    ));

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby=move || title_id.get_value()
            >
                <div class=modal_class node_ref=modal_ref>
                    <h3 id=move || title_id.get_value()>{move || title.get()}</h3>
                    {children()}
                </div>
            </div>
        </Show>
    }
}
