//! Applications view body. Header (title + new-app action) sits above a
//! two-pane body: search list on the left, selected app detail on the right.
//! Tenant info, sign-out, and tool dialogs live in the persistent shell.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::components::icon::IconName;
use crate::components::ui::EmptyState;
use crate::state::{use_session, ActiveView};
use crate::views::application_detail_pane::ApplicationDetailPane;
use crate::views::application_list::ApplicationList;

#[component]
pub fn ApplicationsView() -> impl IntoView {
    let session = use_session();
    let selected = session.selected_app_object_id;

    view! {
        <div class="apps-view">
            <div class="view-header">
                <span class="view-header__title">"App Registrations"</span>
                <div class="view-header__actions">
                    {move || {
                        let n = session.selected_app_ids.with(|s| s.len());
                        (n > 0)
                            .then(|| {
                                view! {
                                    <span class="selection-bar">
                                        <span class="selection-bar__count">
                                            {format!("{n} selected")}
                                        </span>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| session.set_view(ActiveView::BulkActions))
                                        >
                                            "Bulk Actions…"
                                        </Button>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                            on_click=Box::new(move |_| session.clear_app_selection())
                                        >
                                            "Clear"
                                        </Button>
                                    </span>
                                }
                            })
                    }}
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| session.open_create_app())
                    >
                        "+ New app"
                    </Button>
                </div>
            </div>
            <div class="apps-view__body">
                <ApplicationList />
                {move || match selected.get() {
                    Some(id) => {
                        let id_signal = Signal::derive(move || id.clone());
                        view! { <ApplicationDetailPane object_id=id_signal /> }.into_any()
                    }
                    None => {
                        view! {
                            <div class="apps-view__placeholder">
                                <EmptyState
                                    icon=IconName::AppWindow
                                    title="No application selected".to_string()
                                    body="Pick an app registration from the list to view its details, credentials, and permissions."
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
