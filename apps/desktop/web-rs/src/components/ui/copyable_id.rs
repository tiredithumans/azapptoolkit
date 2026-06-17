use leptos::prelude::*;

use crate::components::icon::IconName;
use crate::components::ui::IconButton;
use crate::util::copy_text;

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
    let copy_value = value.clone();
    view! {
        <span class="copyable-id">
            <span class="mono" title=value.clone()>
                {shown}
            </span>
            <IconButton
                icon=IconName::Copy
                aria_label=format!("Copy {label}")
                title="Copy".to_string()
                on_click=Callback::new(move |_| copy_text(copy_value.clone()))
            />
        </span>
    }
}
