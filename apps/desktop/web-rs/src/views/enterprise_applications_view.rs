//! Enterprise applications view: the router target. Thin wrapper around the
//! self-contained `EnterpriseApplicationList`, which owns its page header
//! (title + actions) and the full-width list card.

use leptos::prelude::*;

use crate::views::enterprise_application_list::EnterpriseApplicationList;

#[component]
pub fn EnterpriseApplicationsView() -> impl IntoView {
    view! { <EnterpriseApplicationList /> }
}
