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
    /// ARIA role (`"status"` / `"alert"`). Left empty, a `warn` or `danger`
    /// callout is a polite `status` region, so one that appears after an
    /// action is announced — most call sites never passed a role, and their
    /// warnings were silent to a screen reader. `info` / `ok` stay roleless.
    #[prop(optional, into, default = String::new())]
    role: String,
    /// Extra class(es) appended to the tone class, for the few callers that
    /// also position or size the box (e.g. a list's cap notice). Exists so
    /// "this one needs one more class" is never a reason to hand-roll the
    /// markup again — that is exactly how the 30 bypass sites accumulated.
    #[prop(optional, into, default = String::new())]
    class: String,
    children: Children,
) -> impl IntoView {
    let tone_class = match tone.as_str() {
        "ok" => "alert alert--ok",
        "warn" => "alert alert--warn",
        "danger" => "alert alert--danger",
        // `info` maps to the bare neutral `.alert`.
        _ => "alert",
    };
    let class = if class.is_empty() {
        tone_class.to_string()
    } else {
        format!("{tone_class} {class}")
    };
    let role = if role.is_empty() && matches!(tone.as_str(), "warn" | "danger") {
        "status".to_string()
    } else {
        role
    };
    view! {
        <div class=class role=(!role.is_empty()).then_some(role)>
            {children()}
        </div>
    }
}
