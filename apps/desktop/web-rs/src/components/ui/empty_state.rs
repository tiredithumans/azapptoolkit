use leptos::prelude::*;

use crate::components::icon::{Icon, IconName};

/// Empty / placeholder state with an icon, title, body text, and optional
/// action button children passed in.
#[component]
pub fn EmptyState(
    #[prop(optional, default = IconName::Info)] icon: IconName,
    #[prop(into)] title: String,
    #[prop(optional, into, default = String::new())] body: String,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <div class="ui-empty">
            <span class="ui-empty__icon"><Icon name=icon size=20 /></span>
            <h3 class="ui-empty__title">{title}</h3>
            {(!body.is_empty()).then(|| view! { <p class="ui-empty__body">{body}</p> })}
            {children.map(|c| c())}
        </div>
    }
}
