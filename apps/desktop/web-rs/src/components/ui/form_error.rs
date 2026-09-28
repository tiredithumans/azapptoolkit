use leptos::prelude::*;
use thaw::Body1;

/// The one inline "this action / load failed" line: the `.form-error` styling
/// (whose `pre-wrap` keeps a `UiError`'s `\n\n` guidance on its own lines) plus
/// `role="alert"`, so an error inserted into the DOM after an async action — a
/// failed save in a dialog, a failed tab load — is announced by a screen reader
/// instead of appearing silently (the same choice `components::toast` documents
/// for error toasts).
///
/// The class stays on the `Body1` span itself: wrapping it in a
/// `<div class="form-error">` would lose `pre-wrap` to thaw's `.thaw-text`
/// `white-space: normal`.
#[component]
pub fn FormError(children: Children) -> impl IntoView {
    view! {
        <Body1 class="form-error" attr:role="alert">
            {children()}
        </Body1>
    }
}
