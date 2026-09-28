//! GUI test for the CopyableId copy-confirmation badge: click → transient
//! "Copied" badge → auto-clears after the timeout.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::ui::CopyableId;
use azapptoolkit_web_rs::test_support as ts;

/// Shadows `navigator.clipboard.writeText` for one test, recording the text on
/// `window.__copiedText`; dropping it restores the real method.
///
/// Headless Chrome answers a real `writeText` in a way that takes window focus
/// from the test page and never gives it back (`document.hasFocus()` goes
/// `true` → `false` across the click). Every later test in the shard that
/// needs a focus event then fails — `el.focus()` still moves
/// `activeElement`, but an unfocused document fires no `focus` event — which
/// is how the global-search tests after this one failed in the full gui_4 run
/// yet passed on their own.
struct ClipboardStub {
    clipboard: JsValue,
}

impl ClipboardStub {
    fn install() -> Self {
        let clipboard: JsValue = web_sys::window().unwrap().navigator().clipboard().into();
        let write_text = js_sys::Function::new_with_args(
            "text",
            "window.__copiedText = text; return Promise.resolve();",
        );
        js_sys::Reflect::set(&clipboard, &"writeText".into(), &write_text).unwrap();
        Self { clipboard }
    }

    fn copied() -> Option<String> {
        js_sys::Reflect::get(&web_sys::window().unwrap(), &"__copiedText".into())
            .ok()
            .and_then(|v| v.as_string())
    }
}

impl Drop for ClipboardStub {
    fn drop(&mut self) {
        // The stub is an own property on the instance; deleting it re-exposes
        // `Clipboard.prototype.writeText`.
        let _ =
            js_sys::Reflect::delete_property(&self.clipboard.clone().into(), &"writeText".into());
        let _ = js_sys::Reflect::delete_property(
            &web_sys::window().unwrap().into(),
            &"__copiedText".into(),
        );
    }
}

#[wasm_bindgen_test]
async fn copy_click_shows_transient_copied_badge() {
    ts::reset();
    let _clipboard = ClipboardStub::install();
    let _m = ts::mount_view(
        || view! { <CopyableId value="00000000-1111-2222-3333-444444444444" label="Test id" /> },
    );

    assert!(
        ts::query(".copyable-id__copied").is_none(),
        "no badge before the click"
    );
    ts::click(".copyable-id .ui-icon-btn");
    ts::wait_for(|| ts::query(".copyable-id__copied").is_some()).await;
    assert_eq!(
        ClipboardStub::copied().as_deref(),
        Some("00000000-1111-2222-3333-444444444444"),
        "the click writes the value itself"
    );
    assert!(
        ts::query(".copyable-id__copied[role=status]").is_some(),
        "the badge is a status live region, so the copy is announced"
    );

    // The badge is transient: it clears itself after the reset timeout.
    ts::wait_for(|| ts::query(".copyable-id__copied").is_none()).await;
}
