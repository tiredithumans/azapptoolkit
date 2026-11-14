use leptos::prelude::*;

/// A page's heading row: its name (for assistive tech), an optional one-line
/// description, and its actions (passed as children, drawn on the right).
///
/// **The title is not drawn.** The shell's top bar names the page — nav section
/// crumb plus title, from `ActiveView::section` / `title` — and stays on screen
/// while the content scrolls. This header used to draw the same crumb and title
/// again directly under it (App Registrations read "INVENTORY / App
/// Registrations" twice, sixty pixels apart), which cost every page a band of
/// height and gave the crumb slot three different jobs: the nav section on some
/// pages, an alternate title on others ("Posture", "Backup & Restore"), a whole
/// sentence in capitals on the rest. The `<h1>` is kept, visually hidden, so
/// the page still has its heading for a screen reader and for anything that
/// looks a page up by its name.
///
/// `description` is the sentence that used to be squeezed into the crumb: what
/// the page is for, in ordinary case. Leave it empty where the page's own
/// content already says so.
///
/// With neither a description nor actions the header takes no space at all.
#[component]
pub fn SectionHeader(
    #[prop(into)] title: String,
    #[prop(optional, into)] description: String,
    /// A section inside a page that already has its `<h1>` (a Security lens):
    /// the hidden heading is an `<h2>`.
    #[prop(optional)]
    sub: bool,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    let heading = if sub {
        view! { <h2 class="visually-hidden">{title}</h2> }.into_any()
    } else {
        view! { <h1 class="visually-hidden">{title}</h1> }.into_any()
    };
    let bare = description.is_empty() && children.is_none();
    let class = if bare {
        "ui-section-header ui-section-header--bare"
    } else {
        "ui-section-header"
    };
    view! {
        <header class=class>
            {heading}
            {(!description.is_empty())
                .then(|| view! { <p class="ui-section-header__description">{description}</p> })}
            {children
                .map(|c| view! { <div class="ui-section-header__actions">{c()}</div> })}
        </header>
    }
}
