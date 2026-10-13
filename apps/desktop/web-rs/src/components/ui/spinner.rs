use leptos::prelude::*;

/// Indeterminate busy indicator: a 20 px brand-coloured arc that sweeps around
/// a faint track (Fluent's "tiny" spinner, ported off Thaw), optionally with a
/// visible label beside it. A block-level flex row that centres itself, so a
/// bare spinner in a pane sits in the middle and one in a button sits inline.
///
/// The `role="progressbar"` element is named by `label` through `aria-label`;
/// the visible copy is `aria-hidden` so a screen reader does not say it twice.
/// The reduced-motion block in `styles.css` keeps it turning (a stalled arc
/// reads as a hung app), matching every `ui-spinner` class by substring.
#[component]
pub fn Spinner(
    /// Text shown beside the arc, which also names it for assistive tech.
    #[prop(optional, into)]
    label: Option<String>,
) -> impl IntoView {
    let visible = label.clone().map(|text| {
        view! {
            <span class="ui-spinner__label" aria-hidden="true">
                {text}
            </span>
        }
    });
    view! {
        <div class="ui-spinner" role="progressbar" aria-label=label>
            <span class="ui-spinner__arc">
                <span class="ui-spinner__tail"></span>
            </span>
            {visible}
        </div>
    }
}
