//! Applications view: the router target. Thin wrapper around the self-contained
//! `ApplicationList`, which owns its page header (title + actions) and the
//! full-width list card. Tenant info, sign-out, and tool dialogs live in the
//! persistent shell.

use leptos::prelude::*;

use crate::views::application_list::ApplicationList;

#[component]
pub fn ApplicationsView() -> impl IntoView {
    view! { <ApplicationList /> }
}
