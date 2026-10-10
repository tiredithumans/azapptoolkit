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

/// Every skeleton region is a `role="status"` with a visually-hidden
/// "Loading…": a bare container with `aria-busy` (what these used to be) is
/// silent to a screen reader, and it was unmounted on completion so the flag
/// never even flipped. The shapes are textless `<span>`s, so they add nothing
/// to the announcement. The region is inserted already filled, which not every
/// reader announces, but it is at least discoverable — and the loaded content
/// replaces it.
#[component]
fn SkeletonRegion(
    #[prop(into)] class: String,
    #[prop(optional, into)] style: String,
    #[prop(optional, into, default = String::from("Loading…"))] label: String,
    children: Children,
) -> impl IntoView {
    let style = (!style.is_empty()).then_some(style);
    view! {
        <div class=class style=style role="status">
            <span class="visually-hidden">{label}</span>
            {children()}
        </div>
    }
}

/// Stack of fake list rows shown while a list resource is loading.
#[component]
pub fn SkeletonList(
    #[prop(optional, default = 8)] rows: usize,
    #[prop(optional, into)] label: Option<String>,
) -> impl IntoView {
    view! {
        <SkeletonRegion class="ui-skel-list" label=label.unwrap_or_else(|| "Loading…".into())>
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
        </SkeletonRegion>
    }
}

/// Placeholder for a detail pane while it loads — a title bar plus a few field
/// lines. Inline styles reuse the `.ui-skel` shimmer; no extra CSS needed.
#[component]
pub fn DetailSkeleton() -> impl IntoView {
    view! {
        <SkeletonRegion
            class="ui-skel-detail"
            style="display:flex;flex-direction:column;gap:12px;padding:8px;"
        >
            <Skeleton width="40%".to_string() height="20px".to_string() />
            <Skeleton width="90%".to_string() height="12px".to_string() />
            <Skeleton width="75%".to_string() height="12px".to_string() />
            <Skeleton width="85%".to_string() height="12px".to_string() />
        </SkeletonRegion>
    }
}

/// Placeholder for a dashboard card — a big number plus two lines. The Home
/// dashboard used to hand-roll this one.
#[component]
pub fn SkeletonCard() -> impl IntoView {
    view! {
        <SkeletonRegion
            class="ui-skel-card"
            style="display:flex;flex-direction:column;gap:10px;"
        >
            <Skeleton width="64px".to_string() height="30px".to_string() />
            <Skeleton width="80%".to_string() height="12px".to_string() />
            <Skeleton width="60%".to_string() height="12px".to_string() />
        </SkeletonRegion>
    }
}
