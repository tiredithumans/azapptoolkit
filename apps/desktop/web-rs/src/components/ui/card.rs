use leptos::prelude::*;

/// Surface container with one of four elevation levels.
/// `elevation = 1` → flat (border only). `2/3/4` map to Fluent depth-2/4/8 shadows.
#[component]
pub fn Card(
    #[prop(optional, default = 2)] elevation: u8,
    #[prop(optional, into)] class: String,
    #[prop(optional)] padless: bool,
    children: Children,
) -> impl IntoView {
    let mut classes = String::from("ui-card");
    match elevation {
        2 => classes.push_str(" ui-card--e1"),
        3 => classes.push_str(" ui-card--e2"),
        4 => classes.push_str(" ui-card--e3"),
        _ => {}
    }
    if padless {
        classes.push_str(" ui-card--padless");
    }
    if !class.is_empty() {
        classes.push(' ');
        classes.push_str(&class);
    }
    view! { <div class=classes>{children()}</div> }
}
