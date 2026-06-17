use leptos::ev::MouseEvent;
use leptos::prelude::*;
use thaw::{Spinner, SpinnerSize};

use crate::components::icon::{Icon, IconName};

/// Square 32×32 button that wraps a single icon. `aria_label` is required for
/// screen readers since the icon is decorative. When `busy` is true the button
/// is disabled and shows a spinner in place of the icon (e.g. a Refresh button
/// while its list reloads).
#[component]
pub fn IconButton(
    icon: IconName,
    #[prop(into)] aria_label: String,
    #[prop(optional, default = 16)] size: u32,
    #[prop(optional, into)] on_click: Option<Callback<MouseEvent>>,
    #[prop(optional, default = false)] subtle_border: bool,
    #[prop(optional, into)] class: String,
    #[prop(optional, into)] title: Option<String>,
    #[prop(optional, into)] busy: Option<Signal<bool>>,
    /// Disable the button without showing the busy spinner — e.g. greying a
    /// row's action while a sibling row's mutation is in flight (only the
    /// acting button shows `busy`).
    #[prop(optional, into)]
    disabled: Option<Signal<bool>>,
) -> impl IntoView {
    let is_busy = move || busy.map(|b| b.get()).unwrap_or(false);
    let is_disabled = move || is_busy() || disabled.map(|d| d.get()).unwrap_or(false);
    let classes = move || {
        let mut classes = String::from("ui-icon-btn");
        if subtle_border {
            classes.push_str(" ui-icon-btn--subtle-border");
        }
        if is_busy() {
            classes.push_str(" ui-icon-btn--busy");
        }
        if !class.is_empty() {
            classes.push(' ');
            classes.push_str(&class);
        }
        classes
    };
    let click = move |ev: MouseEvent| {
        if is_disabled() {
            return;
        }
        if let Some(cb) = on_click {
            cb.run(ev);
        }
    };
    view! {
        <button
            type="button"
            class=classes
            aria-label=aria_label
            title=title
            disabled=is_disabled
            on:click=click
        >
            {move || {
                if is_busy() {
                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }.into_any()
                } else {
                    view! { <Icon name=icon size=size /> }.into_any()
                }
            }}
        </button>
    }
}
