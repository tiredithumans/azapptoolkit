use leptos::prelude::*;

use crate::components::ui::CopyIconButton;

/// A GUID/identifier with a copy-to-clipboard button. By default the text is
/// truncated to 8 chars + `…` (full value on hover) — for table cells where a
/// full GUID would crowd the row (Secret ID / Certificate ID). Pass `full` to
/// render the whole value, for a detail-pane property field where the GUID is
/// the thing the operator came to copy.
#[component]
pub fn CopyableId(
    #[prop(into)] value: String,
    #[prop(into)] label: String,
    #[prop(optional)] full: bool,
) -> impl IntoView {
    let shown = if full {
        value.clone()
    } else {
        format!("{}…", value.chars().take(8).collect::<String>())
    };
    let copy_value: Signal<String> = RwSignal::new(value.clone()).into();
    view! {
        <span class="copyable-id">
            <span class="mono" title=value.clone()>
                {shown}
            </span>
            <CopyIconButton value=copy_value aria_label=format!("Copy {label}") />
        </span>
    }
}
