//! GUI test for the global-search dropdown's keyboard navigation: record hits
//! (not just commands) are reachable via the roving Arrow/Enter selection.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::global_search::GlobalSearch;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn keyboard_reaches_record_hits_and_enter_opens_one() {
    ts::reset();
    ts::mock_ok(
        "global_search",
        &fixtures::global_search_apps(&["Contoso API"]),
    );

    let _m = ts::mount_view(|| view! { <GlobalSearch /> });

    // Focus + type a query that matches no command (so the only dropdown hit is
    // the record), which opens the dropdown.
    ts::focus(".global-search__field");
    ts::set_input_value(".global-search__field", "zqx");

    // The record hit renders as a roving option (`gs-rec-{index}`), proving it's
    // part of the keyboard selection — not click-only.
    ts::wait_for(|| ts::query("#gs-rec-0").is_some()).await;

    // With no commands, roving index 0 is the record, and the active highlight
    // reacts to the selection. ArrowDown exercises the keydown path.
    ts::press_key(".global-search__field", "ArrowDown");
    ts::wait_for(|| {
        ts::query("#gs-rec-0")
            .map(|e| e.class_name().contains("global-search__row--active"))
            .unwrap_or(false)
    })
    .await;

    // Enter activates the highlighted record (the same `pick_hit` the mouse uses),
    // which clears the query and closes the dropdown.
    ts::press_key(".global-search__field", "Enter");
    ts::wait_for(|| ts::query("#gs-rec-0").is_none()).await;
}
