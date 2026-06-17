//! Shared "created on" date-range filter for the App Registration and
//! Enterprise Application lists: two day-granular **native** date inputs (an
//! inclusive `[after, before]` window), a per-input clear button, and an
//! inverted-range hint. Rendered "Created before" first, then "Created after".
//!
//! Uses native `<input type="date">` rather than a component-library date
//! picker. The Tauri webview renders it natively, it needs no popup/teleport,
//! and — unlike the previous Thaw `DatePicker`, whose calendar popup crashed the
//! view on open — it opens reliably and clears properly when its bound value is
//! reset to `None` (an empty controlled `value` empties a native date input).

use chrono::NaiveDate;
use leptos::prelude::*;
use thaw::Body1;

use crate::components::icon::IconName;
use crate::components::ui::IconButton;

/// The ISO format a native `<input type="date">` reads and writes.
const ISO: &str = "%Y-%m-%d";

#[component]
pub fn DateRangeFilter(
    /// Inclusive lower bound; `None` leaves the early side open.
    after: RwSignal<Option<NaiveDate>>,
    /// Inclusive upper bound; `None` leaves the late side open.
    before: RwSignal<Option<NaiveDate>>,
    /// Plural noun for the inverted-range hint (e.g. "apps").
    noun: &'static str,
) -> impl IntoView {
    let inverted_msg = format!(
        "\u{201c}Created after\u{201d} is later than \u{201c}created before\u{201d} — no {noun} match this range."
    );
    view! {
        <div class="app-list__filters">
            // "Created before" first, then "Created after".
            {date_field("Created before", "Clear created-before date", before)}
            {date_field("Created after", "Clear created-after date", after)}
            {move || {
                let inverted = matches!(
                    (after.get(), before.get()),
                    (Some(a), Some(b)) if a > b
                );
                let msg = inverted_msg.clone();
                inverted.then(|| {
                    view! { <Body1 class="filter-hint filter-hint--warn">{msg}</Body1> }
                })
            }}
        </div>
    }
}

/// One labeled native date input bound to `value`, with an explicit clear
/// button shown only when set. Setting the signal to `None` clears the input
/// (a native date input honors an empty controlled `value`).
fn date_field(
    label: &'static str,
    clear_aria: &'static str,
    value: RwSignal<Option<NaiveDate>>,
) -> impl IntoView {
    view! {
        <div class="date-range-field">
            <label class="date-range-field__label">{label}</label>
            <div class="date-range-field__input">
                <input
                    type="date"
                    class="date-range-field__native"
                    prop:value=move || {
                        value.get().map(|d| d.format(ISO).to_string()).unwrap_or_default()
                    }
                    on:input=move |ev| {
                        let raw = event_target_value(&ev);
                        value.set(NaiveDate::parse_from_str(&raw, ISO).ok());
                    }
                />
                {move || {
                    value.get().is_some().then(|| {
                        view! {
                            <IconButton
                                icon=IconName::Close
                                aria_label=clear_aria.to_string()
                                title="Clear".to_string()
                                class="date-range-field__clear".to_string()
                                on_click=Callback::new(move |_| value.set(None))
                            />
                        }
                    })
                }}
            </div>
        </div>
    }
}
