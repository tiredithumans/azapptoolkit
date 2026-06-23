use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use azapptoolkit_dto::UiError;

/// Error state for a detail pane whose load failed. Shows the message
/// prominently with the error code muted, plus an always-available **Retry**
/// that bumps the pane's `reload` signal to re-run the resource — so a transient
/// 429 / network blip is never a dead-end (matching the App Registrations list's
/// error affordance). Shared by the app-registration, enterprise-app, and
/// managed-identity detail panes, which previously each rendered a static
/// `error [code]: message` with no recovery.
#[component]
pub fn DetailLoadError(error: UiError, reload: RwSignal<u32>) -> impl IntoView {
    let UiError { code, message, .. } = error;
    view! {
        <div
            class="app-detail__body detail-load-error"
            style="display:flex;flex-direction:column;align-items:flex-start;gap:8px;"
        >
            <Body1 class="form-error">{message}</Body1>
            <span style="opacity:0.6;font-size:0.85em;">{format!("[{code}]")}</span>
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| reload.update(|n| *n = n.wrapping_add(1)))
            >
                "Retry"
            </Button>
        </div>
    }
}
