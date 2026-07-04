use leptos::prelude::*;

/// One inline notice/alert box, in four tones: `info` (neutral), `ok` (green),
/// `warn` (amber), `danger` (red). The single home for the scattered
/// `<div class="alert alert--…">` boxes — consent prompts, scan/export notices,
/// scoping callouts. It reuses the existing `.alert` classes, so the rendered
/// look is unchanged while call sites migrate off the ad-hoc markup.
#[component]
pub fn Callout(
    /// `"info"` (default) | `"ok"` | `"warn"` | `"danger"`.
    #[prop(optional, into, default = String::from("info"))]
    tone: String,
    /// Optional ARIA role (e.g. `"status"` / `"alert"`).
    #[prop(optional, into, default = String::new())]
    role: String,
    children: Children,
) -> impl IntoView {
    let class = match tone.as_str() {
        "ok" => "alert alert--ok",
        "warn" => "alert alert--warn",
        "danger" => "alert alert--danger",
        // `info` maps to the bare neutral `.alert`.
        _ => "alert",
    };
    view! {
        <div class=class role=(!role.is_empty()).then_some(role)>
            {children()}
        </div>
    }
}
