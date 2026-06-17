use leptos::prelude::*;
use thaw::{Input, InputSuffix};

use crate::components::icon::{Icon, IconName};

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
#[component]
pub fn SearchInput(value: RwSignal<String>, #[prop(into)] placeholder: String) -> impl IntoView {
    view! {
        <Input value=value placeholder=placeholder>
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
