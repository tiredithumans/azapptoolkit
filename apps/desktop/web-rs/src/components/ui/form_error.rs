use leptos::prelude::*;

/// The one inline "this action / load failed" line: the `.form-error` styling
/// (whose `pre-wrap` keeps a `UiError`'s `\n\n` guidance on its own lines) plus
/// `role="alert"`, so an error inserted into the DOM after an async action — a
/// failed save in a dialog, a failed tab load — is announced by a screen reader
/// instead of appearing silently (the same choice `components::toast` documents
/// for error toasts).
///
/// The class stays on the `.ui-text` span itself: wrapping it in a
/// `<div class="form-error">` would lose `pre-wrap` to the span's own
/// `white-space: normal`.
#[component]
pub fn FormError(children: Children) -> impl IntoView {
    view! {
        <span class="ui-text form-error" role="alert">
            {children()}
        </span>
    }
}
