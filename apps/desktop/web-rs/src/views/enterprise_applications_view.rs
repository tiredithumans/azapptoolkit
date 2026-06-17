//! Enterprise applications view body. Header + two-pane list/detail layout.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::components::icon::IconName;
use crate::components::ui::EmptyState;
use crate::state::use_session;
use crate::views::enterprise_application_detail_pane::EnterpriseApplicationDetailPane;
use crate::views::enterprise_application_list::EnterpriseApplicationList;

#[component]
pub fn EnterpriseApplicationsView() -> impl IntoView {
    let session = use_session();
    let selected = session.selected_enterprise_app_id;

    view! {
        <div class="apps-view">
            <div class="view-header">
                <span class="view-header__title">"Enterprise Applications"</span>
                <div class="view-header__actions">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| session.sso_wizard_open.set(true))
                    >
                        "+ New SSO application"
                    </Button>
                </div>
            </div>
            <div class="apps-view__body">
                <EnterpriseApplicationList />
                {move || match selected.get() {
                    Some(id) => {
                        let id_signal = Signal::derive(move || id.clone());
                        view! { <EnterpriseApplicationDetailPane service_principal_id=id_signal /> }.into_any()
                    }
                    None => {
                        view! {
                            <div class="apps-view__placeholder">
                                <EmptyState
                                    icon=IconName::Building
                                    title="No application selected".to_string()
                                    body="Pick an enterprise application from the list to view its details, permissions, and sign-in activity."
                                        .to_string()
                                />
                            </div>
                        }
                            .into_any()
                    }
                }}
            </div>
        </div>
    }
}
