//! Shared reactive hooks. Mirrors `apps/desktop/web/src/hooks/`.

use wasm_bindgen::JsCast;
use web_sys::{HtmlElement, HtmlInputElement};

pub mod use_command;
pub mod use_debounced;
pub mod use_escape;
pub mod use_filtered_list;
pub mod use_focus_return;
pub mod use_focus_trap;
pub mod use_grid_keynav;
pub mod use_list_export;
pub mod use_menu_keynav;
pub mod use_progress_stream;
pub mod use_shortcuts;

pub use use_command::{CommandState, use_command};

/// True when the keystroke came from a text-entry control, where a bare key
/// belongs to the caret and not to a binding.
///
/// The ONE "is the user typing?" predicate, shared by the window layer
/// ([`use_shortcuts`]) and the surface layer ([`use_grid_keynav`]). It lives in
/// this leaf module so neither hook reaches into the other, and so the two can
/// no longer drift (the window copy once treated every `<input>` as typing, so
/// `?` and `/` went dead after Space-toggling a row's bulk-select checkbox).
/// A checkbox, radio or button-type input is explicitly not a text field;
/// `textarea`, `select` and `contenteditable` are.
pub(crate) fn is_text_entry(ev: &leptos::ev::KeyboardEvent) -> bool {
    let Some(el) = ev.target().and_then(|t| t.dyn_into::<HtmlElement>().ok()) else {
        return false;
    };
    if el.is_content_editable() {
        return true;
    }
    match el.tag_name().to_ascii_lowercase().as_str() {
        "textarea" | "select" => true,
        "input" => !matches!(
            el.unchecked_ref::<HtmlInputElement>().type_().as_str(),
            "checkbox" | "radio" | "button" | "submit" | "reset"
        ),
        _ => false,
    }
}

/// True while any modal dialog is shown.
///
/// Every dialog renders its `.modal-backdrop` only while it is shown —
/// `ModalShell` and the hand-rolled dialogs are `<Show>`-gated, and
/// `SecretReveal` is mounted only while shown — so the backdrop's presence is
/// the one app-wide "a dialog owns the keyboard" signal. Window-level bindings
/// (the workspace's Escape, the bare-key shortcuts) gate on it so a keystroke
/// meant for the dialog doesn't also act on the page behind it, or stack a
/// second dialog on top.
pub(crate) fn modal_is_open() -> bool {
    leptos::prelude::document()
        .query_selector(".modal-backdrop")
        .ok()
        .flatten()
        .is_some()
}
