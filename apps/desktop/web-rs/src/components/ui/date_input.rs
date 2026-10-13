use chrono::NaiveDate;
use leptos::prelude::*;

/// The ISO format a native `<input type="date">` reads and writes.
const ISO: &str = "%Y-%m-%d";

/// A day picker: the platform's native `<input type="date">`, bound to `value`.
///
/// Native rather than a component-library picker: the webview renders it with
/// no popup or teleport, and Thaw's `DatePicker`, which this replaces, crashed
/// the view when its calendar popup opened. Setting `value` to `None` empties
/// the input (a native date input honours an empty controlled `value`), and an
/// emptied input writes `None` back.
///
/// `label` becomes the input's `aria-label`: callers render their visible label
/// apart from the input, so nothing else names it. `class` adds a caller hook
/// next to the styled `ui-date-input` base.
#[component]
pub fn DateInput(
    value: RwSignal<Option<NaiveDate>>,
    label: &'static str,
    #[prop(optional)] class: &'static str,
) -> impl IntoView {
    let class = if class.is_empty() {
        "ui-date-input".to_string()
    } else {
        format!("ui-date-input {class}")
    };
    view! {
        <input
            type="date"
            class=class
            aria-label=label
            prop:value=move || value.get().map(|d| d.format(ISO).to_string()).unwrap_or_default()
            on:input=move |ev| value.set(NaiveDate::parse_from_str(&event_target_value(&ev), ISO).ok())
        />
    }
}
