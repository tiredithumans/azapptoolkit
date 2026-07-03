//! Enterprise applications view body. Header + full-width list; opening a row
//! adds it to the shell's open-items workspace.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::state::use_session;
use crate::views::enterprise_application_list::EnterpriseApplicationList;

#[component]
pub fn EnterpriseApplicationsView() -> impl IntoView {
    let session = use_session();

    view! {
        <div class="apps-view">
            <div class="view-header">
                <span class="view-header__title">"Enterprise Applications"</span>
                <div class="view-header__actions">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| session.tenant_ui.sso_wizard_open.set(true))
                    >
                        "+ New SSO application"
                    </Button>
                </div>
            </div>
            <div class="apps-view__body">
                <EnterpriseApplicationList />
            </div>
        </div>
    }
}
