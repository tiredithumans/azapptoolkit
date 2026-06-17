use leptos::prelude::*;

/// A small status/risk pill. `tone` maps to a `badge--{tone}` modifier
/// (`danger` | `warning` | `ok` | `unknown`); an empty `tone` is the neutral
/// base badge. An optional `title` renders as a hover tooltip. This is the one
/// place the `.badge` chrome is defined — risk/status helpers build on it
/// instead of hand-writing `<span class="badge …">`.
#[component]
pub fn Badge(
    #[prop(into)] label: String,
    #[prop(optional, into, default = String::new())] tone: String,
    #[prop(optional, into, default = String::new())] title: String,
) -> impl IntoView {
    let class = if tone.is_empty() {
        "badge".to_string()
    } else {
        format!("badge badge--{tone}")
    };
    let title = (!title.is_empty()).then_some(title);
    view! {
        <span class=class title=title>
            {label}
        </span>
    }
}
