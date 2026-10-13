use leptos::prelude::*;

/// Determinate progress: a thin full-width track filled to `value`, a fraction
/// in `0.0..=1.0`. Out-of-range values are clamped, and a NaN (a `0 / 0` before
/// a run knows its total) reads as empty: `clamp` would pass it through as an
/// invalid width.
#[component]
pub fn ProgressBar(#[prop(into)] value: Signal<f64>) -> impl IntoView {
    let percent = move || {
        let v = value.get();
        if v.is_nan() {
            0.0
        } else {
            v.clamp(0.0, 1.0) * 100.0
        }
    };
    view! {
        <div
            class="ui-progress"
            role="progressbar"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow=move || format!("{:.0}", percent())
        >
            <div class="ui-progress__bar" style:width=move || format!("{:.2}%", percent())></div>
        </div>
    }
}
