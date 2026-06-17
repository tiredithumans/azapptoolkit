use leptos::prelude::*;

/// View-level header: optional eyebrow / breadcrumb, title, optional actions
/// passed in as children (rendered to the right).
#[component]
pub fn SectionHeader(
    #[prop(into)] title: String,
    #[prop(optional, into, default = String::new())] crumb: String,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <header class="ui-section-header">
            <div class="ui-section-header__group">
                {(!crumb.is_empty())
                    .then(|| view! { <span class="ui-section-header__crumb">{crumb}</span> })}
                <h1 class="ui-section-header__title">{title}</h1>
            </div>
            {children
                .map(|c| view! { <div class="ui-section-header__actions">{c()}</div> })}
        </header>
    }
}
