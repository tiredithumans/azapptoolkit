//! GUI test for the shared `ConfirmDialog`'s typed-confirmation guard
//! (`require_keyword`) — the destructive-delete safety used for foreign-tenant /
//! first-party service principals, mirroring the bulk-delete "type DELETE" gate.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts};
use azapptoolkit_web_rs::views::dialogs::confirm_dialog::ConfirmDialog;

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

/// A failed confirm renders its error through `FormError`, which carries
/// `role="alert"` so the failure is announced — the operator is otherwise left
/// on a re-enabled button with no audible cue. This also proves the attribute
/// passed to the thaw `Body1` reaches the DOM.
#[wasm_bindgen_test]
async fn an_error_is_announced_as_an_alert() {
    ts::reset();
    let _m = ts::mount_view(|| {
        view! {
            <ConfirmDialog
                open=Signal::derive(|| true)
                title="Remove this owner?"
                body="Dangerous."
                confirm_label="Remove"
                error=Signal::derive(|| Some("Save failed".to_string()))
                on_confirm=Callback::new(|()| {})
                on_close=Callback::new(|()| {})
            />
        }
    });

    ts::wait_for(|| {
        ts::query(".form-error[role=alert]").is_some_and(|el| {
            el.text_content()
                .unwrap_or_default()
                .contains("Save failed")
        })
    })
    .await;
}

/// A pane mounts several `ConfirmDialog`s at once, and each must be labelled
/// by its own title. They used to share a fixed `id="confirm-dialog-title"`,
/// so `aria-labelledby` on a stacked confirmation resolved to whichever came
/// first in the document and a screen reader announced the wrong question.
#[wasm_bindgen_test]
async fn stacked_confirmations_are_each_labelled_by_their_own_title() {
    ts::reset();
    let _m = ts::mount_view(|| {
        view! {
            <div>
                <ConfirmDialog
                    open=Signal::derive(|| true)
                    title="Remove this owner?"
                    body="First."
                    on_confirm=Callback::new(|()| {})
                    on_close=Callback::new(|()| {})
                />
                <ConfirmDialog
                    open=Signal::derive(|| true)
                    title="Delete this secret?"
                    body="Second."
                    on_confirm=Callback::new(|()| {})
                    on_close=Callback::new(|()| {})
                />
            </div>
        }
    });
    ts::wait_for(|| ts::query_all(".modal-backdrop").len() == 2).await;

    let ids: Vec<String> = ts::query_all(".modal-backdrop")
        .iter()
        .map(|b| b.get_attribute("aria-labelledby").unwrap_or_default())
        .collect();
    assert_ne!(ids[0], ids[1], "each confirmation needs its own title id");
    for (id, title) in ids
        .iter()
        .zip(["Remove this owner?", "Delete this secret?"])
    {
        let heading = ts::query(&format!("#{id}")).expect("aria-labelledby resolves");
        assert_eq!(heading.tag_name(), "H3");
        assert_eq!(heading.text_content().unwrap_or_default().trim(), title);
    }
}
