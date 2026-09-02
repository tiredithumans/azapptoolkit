//! Inline hint for an action that needs a per-tenant default nobody has
//! configured yet.
//!
//! The copy used to be a dead string set into the surface's `error` signal —
//! "No default owners configured — set them in Settings." — pointing at a page
//! that lives behind the account menu, the one destination with no rail row and
//! no keyboard shortcut. The operator was told the answer and then left to go
//! find it. Here the pointer *is* the route: the phrase is the button, and it
//! opens Settings already on the tab that holds the setting.

use leptos::prelude::*;
use thaw::Body1;

use crate::state::use_session;

/// "No default owners configured — **set them in Settings**." with the trailing
/// phrase as the deep link.
///
/// `class` is the caller's own error-text class, so the hint sits in the
/// surrounding form's visual register rather than introducing a fourth one
/// (`form-error` in the tabs and dialogs, `app-detail__error` in the enterprise
/// pane). `tab` picks the Settings tab that actually holds the defaults —
/// app-registration owners and enterprise-application owners are separate
/// fields on separate tabs, and landing on the wrong one is the same hunt in
/// miniature.
#[component]
pub fn OwnerDefaultsHint(
    #[prop(into)] class: String,
    #[prop(default = "app-reg")] tab: &'static str,
) -> impl IntoView {
    let session = use_session();
    view! {
        <Body1 class=class>
            "No default owners configured — "
            <button class="link-btn" on:click=move |_| session.open_settings(tab)>
                "set them in Settings"
            </button>
            "."
        </Body1>
    }
}
