use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use azapptoolkit_dto::UiError;

/// The universal "a section failed to load → message + Retry" primitive. Shows
/// the error message prominently (with the error code muted), plus an
/// always-available **Retry** so a transient 429 / network blip is never a
/// dead-end.
///
/// Originally the detail-pane error state; now the single home for every
/// load-failure surface — the app-registration / enterprise-app / managed-identity
/// detail panes, the tenant list views, and the Home dashboard cards all route
/// through it (each passing its own `on_retry` and a context `class`), replacing
/// the ad-hoc `.app-list__error` / `card_error` variants.
#[component]
pub fn DetailLoadError(
    error: UiError,
    /// Re-run the failed load (bumps the caller's `reload` signal / refetches).
    on_retry: Callback<()>,
    /// Extra container class for context (e.g. `"app-detail__body"` for a detail
    /// pane, `"app-list__error"` for a list). Appended to the shared
    /// `.ui-load-error` layout class.
    #[prop(optional, into, default = String::new())]
    class: String,
) -> impl IntoView {
    let UiError { code, message, .. } = error;
    let mut classes = String::from("ui-load-error");
    if !class.is_empty() {
        classes.push(' ');
        classes.push_str(&class);
    }
    view! {
        <div class=classes>
            <Body1 class="form-error">{message}</Body1>
            {(!code.is_empty())
                .then(|| view! { <span class="ui-load-error__code">{format!("[{code}]")}</span> })}
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| on_retry.run(()))
            >
                "Retry"
            </Button>
        </div>
    }
}
