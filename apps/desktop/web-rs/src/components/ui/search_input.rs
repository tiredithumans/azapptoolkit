use std::sync::atomic::{AtomicUsize, Ordering};

use leptos::prelude::*;
use thaw::{Input, InputSuffix};

use crate::components::icon::{Icon, IconName};

/// One id per field: a page mounts several search boxes at once (a list's
/// filter beside a panel's), and `<label for>` needs each to be unique.
static NEXT_SEARCH_ID: AtomicUsize = AtomicUsize::new(0);

/// A Thaw `Input` bound to `value` with an inline clear (×) button that appears
/// only when the field is non-empty. Keeps the native Thaw input chrome (border,
/// focus ring) and renders the clear control in the input's suffix slot so it
/// sits inside the box.
///
/// Every list/search filter in the app routes through this so the clear
/// affordance is uniform — several empty states literally tell the user to
/// "clear the filters", and the top-bar Global Search seeds these fields, so a
/// one-click reset is essential. The clear button is `tabindex="-1"`: it's a
/// convenience for pointer users, and a keyboard user clears the same field by
/// selecting its text — keeping it out of the tab order avoids an extra stop on
/// every filter box.
///
/// The field is named by a visually-hidden `<label for>`, not by its
/// placeholder: a placeholder vanishes on the first keystroke and is not a
/// reliable accessible name, and `attr:aria-label` on thaw's `Input` lands on
/// its wrapper `<span>`, never the `<input>` — `id` is the one prop thaw
/// forwards to the real control (the claims editor's `LabelledInput` found
/// this first). `label` defaults to the placeholder text.
#[component]
pub fn SearchInput(
    value: RwSignal<String>,
    #[prop(into)] placeholder: String,
    #[prop(into, optional)] label: Option<String>,
) -> impl IntoView {
    let id = format!(
        "search-input-{}",
        NEXT_SEARCH_ID.fetch_add(1, Ordering::Relaxed)
    );
    let label = label.unwrap_or_else(|| placeholder.clone());
    view! {
        <label class="visually-hidden" for=id.clone()>{label}</label>
        <Input id=id value=value placeholder=placeholder>
            <InputSuffix slot>
                {move || {
                    (!value.get().is_empty())
                        .then(|| {
                            view! {
                                <button
                                    class="search-input__clear"
                                    type="button"
                                    tabindex="-1"
                                    aria-label="Clear filter"
                                    title="Clear filter"
                                    on:click=move |_| value.set(String::new())
                                >
                                    <Icon name=IconName::Close size=14 />
                                </button>
                            }
                        })
                }}
            </InputSuffix>
        </Input>
    }
}
