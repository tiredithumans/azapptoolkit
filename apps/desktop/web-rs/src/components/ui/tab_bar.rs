use leptos::ev;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::HtmlElement;

#[derive(Clone)]
pub struct TabBarItem {
    pub value: &'static str,
    pub label: &'static str,
}

/// Underlined tab bar bound to an `RwSignal<String>`. Use as a lighter-weight
/// alternative to Thaw's `TabList` when we want a custom underline indicator
/// and tighter visual integration with the rest of the UI.
///
/// Implements the WAI-ARIA tabs pattern: roving `tabindex` (only the active tab
/// is in the tab order) and Left/Right/Home/End move between tabs with automatic
/// activation (the focused tab becomes selected).
#[component]
pub fn TabBar(items: Vec<TabBarItem>, selected: RwSignal<String>) -> impl IntoView {
    let values: Vec<String> = items.iter().map(|i| i.value.to_string()).collect();
    let tablist_ref: NodeRef<html::Div> = NodeRef::new();

    // Move selection (and focus) by a delta / to an end. Focuses the newly
    // selected tab so keyboard focus tracks the active tab.
    let activate_at = move |idx: usize, values: &[String]| {
        if let Some(v) = values.get(idx) {
            selected.set(v.clone());
            if let Some(list) = tablist_ref.get_untracked()
                && let Ok(buttons) = list.query_selector_all("[role=tab]")
                && let Some(btn) = buttons
                    .item(idx as u32)
                    .and_then(|n| n.dyn_into::<HtmlElement>().ok())
            {
                let _ = btn.focus();
            }
        }
    };

    let on_keydown = {
        let values = values.clone();
        move |ev: ev::KeyboardEvent| {
            let len = values.len();
            if len == 0 {
                return;
            }
            let cur = values
                .iter()
                .position(|v| *v == selected.get_untracked())
                .unwrap_or(0);
            let next = match ev.key().as_str() {
                "ArrowRight" => (cur + 1) % len,
                "ArrowLeft" => {
                    if cur == 0 {
                        len - 1
                    } else {
                        cur - 1
                    }
                }
                "Home" => 0,
                "End" => len - 1,
                _ => return,
            };
            ev.prevent_default();
            activate_at(next, &values);
        }
    };

    view! {
        <div class="ui-tabs" role="tablist" node_ref=tablist_ref on:keydown=on_keydown>
            {items
                .into_iter()
                .map(|item| {
                    let value = item.value.to_string();
                    let value_compare = value.clone();
                    let value_tabindex = value.clone();
                    let label = item.label;
                    let class = move || {
                        let mut c = String::from("ui-tabs__btn");
                        if selected.get() == value_compare {
                            c.push_str(" ui-tabs__btn--active");
                        }
                        c
                    };
                    let value_click = value.clone();
                    let on_click = move |_| selected.set(value_click.clone());
                    let aria_selected = {
                        let v = value.clone();
                        move || selected.get() == v
                    };
                    // Roving tabindex — only the active tab is a tab stop.
                    let tabindex = move || {
                        if selected.get() == value_tabindex {
                            "0"
                        } else {
                            "-1"
                        }
                    };
                    view! {
                        <button
                            type="button"
                            class=class
                            role="tab"
                            tabindex=tabindex
                            aria-selected=aria_selected
                            on:click=on_click
                        >
                            {label}
                        </button>
                    }
                })
                .collect_view()}
        </div>
    }
}
