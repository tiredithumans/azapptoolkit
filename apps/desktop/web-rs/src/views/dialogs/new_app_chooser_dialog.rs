//! "New application" chooser. A small modal that mirrors the Azure portal's
//! New-application landing: pick **Browse the Entra gallery** (a pre-integrated
//! app) or **Create your own application** (the custom SAML/OIDC SSO wizard),
//! then route to the matching flow. Both targets are shell-mounted dialogs, so
//! choosing just flips the relevant open flag (this closes first).

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::components::icon::{Icon, IconName};
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;

#[component]
pub fn NewAppChooserDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    let session = use_session();

    use_escape(move || open.get_untracked(), move || on_close.run(()));
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    // Each choice closes this chooser, then opens the target flow (both are
    // mounted in the shell under the Enterprise Apps view, already active here).
    let choose_gallery = move |_| {
        on_close.run(());
        session.open_gallery();
    };
    let choose_custom = move |_| {
        on_close.run(());
        session.open_sso_wizard();
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="new-app-chooser-title"
            >
                <div class="modal" node_ref=modal_ref>
                    <h3 id="new-app-chooser-title">"New application"</h3>
                    <Body1 class="hint">"How do you want to create it?"</Body1>
                    <div class="new-app-choices">
                        <button class="new-app-choice" type="button" on:click=choose_gallery>
                            <span class="new-app-choice__icon">
                                <Icon name=IconName::Search size=20 />
                            </span>
                            <span class="new-app-choice__body">
                                <span class="new-app-choice__title">
                                    "Browse the Entra gallery"
                                </span>
                                <span class="new-app-choice__desc">
                                    "Add a pre-integrated app (Salesforce, ServiceNow, …) from the \
                                     Microsoft Entra application gallery."
                                </span>
                            </span>
                        </button>
                        <button class="new-app-choice" type="button" on:click=choose_custom>
                            <span class="new-app-choice__icon">
                                <Icon name=IconName::Plus size=20 />
                            </span>
                            <span class="new-app-choice__body">
                                <span class="new-app-choice__title">
                                    "Create your own application"
                                </span>
                                <span class="new-app-choice__desc">
                                    "Register a custom (non-gallery) app and configure SAML or OIDC \
                                     single sign-on."
                                </span>
                            </span>
                        </button>
                    </div>
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| on_close.run(()))
                        >
                            "Cancel"
                        </Button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
