use leptos::prelude::*;

/// Animated shimmer placeholder block. Use for any loading skeleton.
#[component]
pub fn Skeleton(
    #[prop(optional, into, default = String::from("100%"))] width: String,
    #[prop(optional, into, default = String::from("12px"))] height: String,
    #[prop(optional, into)] class: String,
) -> impl IntoView {
    let mut classes = String::from("ui-skel");
    if !class.is_empty() {
        classes.push(' ');
        classes.push_str(&class);
    }
    let style = format!("width:{width};height:{height};");
    view! { <span class=classes style=style></span> }
}

/// Stack of fake list rows shown while a list resource is loading.
#[component]
pub fn SkeletonList(#[prop(optional, default = 8)] rows: usize) -> impl IntoView {
    view! {
        <div class="ui-skel-list" aria-busy="true">
            {(0..rows)
                .map(|_| {
                    view! {
                        <div class="ui-skel-row">
                            <span class="ui-skel ui-skel-row__chip"></span>
                            <span class="ui-skel ui-skel-row__title"></span>
                        </div>
                    }
                })
                .collect_view()}
        </div>
    }
}

/// Placeholder for a detail pane while it loads — a title bar plus a few field
/// lines. Inline styles reuse the `.ui-skel` shimmer; no extra CSS needed.
#[component]
pub fn DetailSkeleton() -> impl IntoView {
    view! {
        <div
            style="display:flex;flex-direction:column;gap:12px;padding:8px;"
            aria-busy="true"
        >
            <Skeleton width="40%".to_string() height="20px".to_string() />
            <Skeleton width="90%".to_string() height="12px".to_string() />
            <Skeleton width="75%".to_string() height="12px".to_string() />
            <Skeleton width="85%".to_string() height="12px".to_string() />
        </div>
    }
}
