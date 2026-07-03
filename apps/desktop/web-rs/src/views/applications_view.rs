//! Applications view body. Header (title + new-app action) sits above a
//! full-width list; opening a row adds it to the shell's open-items workspace.
//! Tenant info, sign-out, and tool dialogs live in the persistent shell.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::state::{ActiveView, use_session};
use crate::views::application_list::ApplicationList;

#[component]
pub fn ApplicationsView() -> impl IntoView {
    let session = use_session();

    view! {
        <div class="apps-view">
            <div class="view-header">
                <span class="view-header__title">"App Registrations"</span>
                <div class="view-header__actions">
                    {move || {
                        let n = session.tenant_ui.selected_app_ids.with(|s| s.len());
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
            </div>
        </div>
    }
}
