//! `ExportMenu` — the shared "Export ▾" disclosure dropdown used by the Security
//! workbench and the three tenant list views (App Registrations, Enterprise
//! Applications, Managed Identities).
//!
//! Deliberately a plain-DOM disclosure (mirrors `shell.rs`'s account menu), NOT
//! a Thaw `Menu`: the export opens the native "Save file" dialog, and triggering
//! that from inside a teleported Thaw overlay froze the webview on WebView2 as
//! the overlay tore down (the list-view exports used plain buttons and were
//! never affected). Selecting an item closes the panel FIRST, so the native
//! dialog opens only after the panel has torn down.

use leptos::ev;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};
use wasm_bindgen::JsCast;

use crate::components::icon::{Icon, IconName};
use crate::hooks::use_escape::use_escape;

/// One selectable format: `(format_key, label)`. The key is handed back to
/// `on_select` verbatim (`"csv"`, `"json"`, `"html"`).
pub type ExportOption = (&'static str, &'static str);

/// A compact "Export ▾" dropdown. `disabled` gates the trigger (e.g. while an
/// export is in flight or there is nothing to export); `on_select` receives the
/// chosen format key; `options` are the formats to offer, in display order.
#[component]
pub fn ExportMenu(
    #[prop(into)] disabled: Signal<bool>,
    on_select: Callback<&'static str>,
    options: Vec<ExportOption>,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let root_ref = NodeRef::<leptos::html::Div>::new();
    // Close when a mousedown lands outside the dropdown, and on Escape — the
    // same pattern shell.rs uses for the account menu.
    let outside = window_event_listener(ev::mousedown, move |evt| {
        if !open.get_untracked() {
            return;
        }
        let Some(root) = root_ref.get() else {
            return;
        };
        let target = evt
            .target()
            .and_then(|t| t.dyn_into::<web_sys::Node>().ok());
        if !root.contains(target.as_ref()) {
            open.set(false);
        }
    });
    on_cleanup(move || outside.remove());
    use_escape(move || open.get_untracked(), move || open.set(false));

    let options = StoredValue::new(options);

    view! {
        <div class="export-menu" node_ref=root_ref>
            <Button
                class="btn-icon-label"
                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                disabled=disabled
                on_click=Box::new(move |_| open.update(|o| *o = !*o))
            >
                "Export"
                <Icon name=IconName::ChevronDown size=16 />
            </Button>
            <Show when=move || open.get() fallback=|| view! { <></> }>
                <div class="export-menu__panel" role="menu">
                    {move || {
                        options
                            .get_value()
                            .into_iter()
                            .map(|(format, label)| {
                                view! {
                                    <button
                                        type="button"
                                        role="menuitem"
                                        class="export-menu__item"
                                        on:click=move |_| {
                                            open.set(false);
                                            on_select.run(format);
                                        }
                                    >
                                        {label}
                                    </button>
                                }
                            })
                            .collect_view()
                    }}
                </div>
            </Show>
        </div>
    }
}
