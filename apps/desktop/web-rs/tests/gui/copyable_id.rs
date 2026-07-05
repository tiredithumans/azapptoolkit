//! GUI test for the CopyableId copy-confirmation badge: click → transient
//! "Copied" badge → auto-clears after the timeout.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::ui::CopyableId;
use azapptoolkit_web_rs::test_support as ts;

#[wasm_bindgen_test]
async fn copy_click_shows_transient_copied_badge() {
    ts::reset();
    let _m = ts::mount_view(
        || view! { <CopyableId value="00000000-1111-2222-3333-444444444444" label="Test id" /> },
    );

    assert!(
        ts::query(".copyable-id__copied").is_none(),
        "no badge before the click"
    );
    ts::click(".copyable-id .ui-icon-btn");
    ts::wait_for(|| ts::query(".copyable-id__copied").is_some()).await;

    // The badge is transient: it clears itself after the reset timeout.
    ts::wait_for(|| ts::query(".copyable-id__copied").is_none()).await;
}
