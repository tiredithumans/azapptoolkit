use std::sync::atomic::{AtomicUsize, Ordering};

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

/// One id per strip for the tabs' own ids: a page mounts several strips at
/// once (the Security sub-tabs beside the audit facet bar), so a fixed id
/// would collide.
static NEXT_TABS_ID: AtomicUsize = AtomicUsize::new(0);

/// The `id` of the tab for `value` in the strip `strip` — the string a
/// `role="tabpanel"` names in `aria-labelledby`. `strip` is the `panel_id`
/// the caller gave [`TabBar`], so the two sides derive the same id.
pub fn tab_id(strip: &str, value: &str) -> String {
    format!("{strip}-tab-{value}")
}

/// Underlined tab bar bound to an `RwSignal<String>`. **The** tab implementation
/// — every tab strip and segmented choice in the app routes through it: the two
/// detail panes, the Security / Settings / Bulk Actions sub-tabs, the audit
/// dashboard's facet bar, and small two-option pickers like the Access tab's
/// Users/Groups.
///
/// It replaced Thaw's `TabList` app-wide, which is an accessibility fix and not
/// a matter of taste: `thaw::Tab` emits `role="tab"` + `aria-selected` but has
/// no roving `tabindex` and no keydown handler, so the 10-tab enterprise pane
/// cost a keyboard user ten Tab presses to cross. This implements the WAI-ARIA
/// tabs pattern's keyboard half: roving `tabindex` (only the active tab is a
/// tab stop) and Left/Right/Home/End move between tabs with automatic
/// activation. The naming half is `label` (every strip used to be an unnamed
/// "tab list") and, where a strip switches a real region, `panel_id` links the
/// tabs to it. It also made a CSS workaround redundant — `.ui-tabs` scrolls
/// natively, where `.thaw-tab-list` needed an app-side `overflow-x` patch to
/// stop clipping the tabs past the pane edge.
#[component]
pub fn TabBar(
    items: Vec<TabBarItem>,
    selected: RwSignal<String>,
    /// The strip's accessible name (`aria-label` on the tablist): what a
    /// screen reader announces on entering it ("Security sections, tab list").
    #[prop(into)]
    label: String,
    /// The `id` of the region this strip switches, when the caller renders one
    /// container for it. The tabs then carry `aria-controls`, and the caller
    /// gives that region `role="tabpanel"` and
    /// `aria-labelledby=tab_id(panel_id, selected)` (the Bulk Actions page is
    /// the worked example). Omitted by the filter strips, which switch no
    /// panel, and — for now — by the strips whose panes mount keep-alive
    /// siblings rather than one region (the detail panes, Security, Settings,
    /// Resource Access): a `tabpanel` has to be one element.
    #[prop(optional, into)]
    panel_id: Option<String>,
) -> impl IntoView {
    let values: Vec<String> = items.iter().map(|i| i.value.to_string()).collect();
    let tablist_ref: NodeRef<html::Div> = NodeRef::new();
    let strip = panel_id
        .clone()
        .unwrap_or_else(|| format!("ui-tabs-{}", NEXT_TABS_ID.fetch_add(1, Ordering::Relaxed)));

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
        <div
            class="ui-tabs"
            role="tablist"
            aria-label=label
            node_ref=tablist_ref
            on:keydown=on_keydown
        >
            {items
                .into_iter()
                .map(|item| {
                    let value = item.value.to_string();
                    let value_compare = value.clone();
                    let value_tabindex = value.clone();
                    let label = item.label;
                    let id = tab_id(&strip, &value);
                    let class = move || {
                        let mut c = String::from("ui-tabs__btn");
                        if selected.get() == value_compare {
                            c.push_str(" ui-tabs__btn--active");
                        }
                        c
                    };
                    let value_click = value.clone();
                    let on_click = move |_| selected.set(value_click.clone());
                    // `.to_string()`, not the bare bool: Leptos renders a `bool`
                    // attribute as a *boolean* attribute — present-and-empty for
                    // true, omitted for false — so the selected tab shipped
                    // `aria-selected=""`, which is not a valid ARIA value, and
                    // no tab ever carried `aria-selected="true"`. Matches how
                    // `global_search.rs` and `permission_tester_view.rs` already
                    // set the same attribute.
                    let aria_selected = {
                        let v = value.clone();
                        move || (selected.get() == v).to_string()
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
                            id=id
                            class=class
                            role="tab"
                            tabindex=tabindex
                            aria-selected=aria_selected
                            aria-controls=panel_id.clone()
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
