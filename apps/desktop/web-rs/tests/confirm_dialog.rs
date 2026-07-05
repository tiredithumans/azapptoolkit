//! GUI test for the shared `ConfirmDialog`'s typed-confirmation guard
//! (`require_keyword`) — the destructive-delete safety used for foreign-tenant /
//! first-party service principals, mirroring the bulk-delete "type DELETE" gate.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts};
use azapptoolkit_web_rs::views::dialogs::confirm_dialog::ConfirmDialog;

wasm_bindgen_test_configure!(run_in_browser);

/// The danger-styled confirm button (labelled "Delete" here).
fn confirm_button() -> web_sys::HtmlButtonElement {
    ts::query_all("button")
        .into_iter()
        .find_map(|el| {
            let b: web_sys::HtmlButtonElement = el.unchecked_into();
            (b.text_content().unwrap_or_default().trim() == "Delete").then_some(b)
        })
        .expect("Delete button present")
}

#[wasm_bindgen_test]
async fn require_keyword_gates_confirm_until_typed_exactly() {
    ts::reset();
    let _m = ts::mount_view(|| {
        view! {
            <ConfirmDialog
                open=Signal::derive(|| true)
                title="Delete this enterprise application?"
                body="Dangerous."
                confirm_label="Delete"
                require_keyword="DELETE"
                on_confirm=Callback::new(|()| {})
                on_close=Callback::new(|()| {})
            />
        }
    });

    ts::wait_for(|| ts::query(".confirm-dialog__keyword input").is_some()).await;
    // Confirm stays disabled until the keyword matches exactly.
    assert!(
        confirm_button().disabled(),
        "blank input must block confirm"
    );
    ts::set_input_value(".confirm-dialog__keyword input", "delete"); // wrong case
    ts::tick().await;
    assert!(
        confirm_button().disabled(),
        "a near-miss must not enable confirm"
    );
    ts::set_input_value(".confirm-dialog__keyword input", "DELETE");
    ts::wait_for(|| !confirm_button().disabled()).await;
}
