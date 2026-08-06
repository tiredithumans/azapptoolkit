//! GUI tests for the global-search bar: the dropdown's keyboard navigation
//! (record hits are reachable via the roving Arrow/Enter selection, and Enter
//! opens the highlighted record) and the focus-time corpus prewarm.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::global_search::GlobalSearch;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

fn is_active(selector: &str) -> bool {
    ts::query(selector)
        .map(|e| e.class_name().contains("global-search__row--active"))
        .unwrap_or(false)
}

#[wasm_bindgen_test]
async fn arrow_down_moves_selection_through_record_hits_and_enter_opens() {
    ts::reset();
    ts::mock_ok(
        "global_search",
        &fixtures::global_search_apps(&["Contoso API", "Fabrikam Web"]),
    );

    let _m = ts::mount_view(|| view! { <GlobalSearch /> });

    // Focus + type a query; the two record hits occupy roving indices 0 and 1.
    ts::focus(".global-search__field");
    ts::set_input_value(".global-search__field", "zqx");

    // Both records render as roving options (proving they're in the keyboard
    // selection, not click-only) and the selection starts on the first.
    ts::wait_for(|| ts::query("#gs-rec-0").is_some() && ts::query("#gs-rec-1").is_some()).await;
    ts::wait_for(|| is_active("#gs-rec-0")).await;

    // The regression this guards: ArrowDown must *advance* the highlight to the
    // next record, not stay put — exercises both the record count seen by the
    // handler and the reactive per-row highlight.
    ts::press_key(".global-search__field", "ArrowDown");
    ts::wait_for(|| is_active("#gs-rec-1") && !is_active("#gs-rec-0")).await;

    // Enter activates the highlighted record (the same `pick_hit` the mouse uses),
    // clearing the query and closing the dropdown.
    ts::press_key(".global-search__field", "Enter");
    ts::wait_for(|| ts::query("#gs-rec-1").is_none()).await;
}

/// Focusing the bar warms the tenant's search corpus. It is TTL'd and dropped
/// by every app mutation, so a cold one made the FIRST query pay for two full
/// directory scans on the keystroke path — the multi-second "search hung".
/// Warming on focus overlaps that rebuild with the operator typing.
#[wasm_bindgen_test]
async fn focusing_the_bar_prewarms_the_search_corpus() {
    ts::reset();
    ts::mock_ok("prefetch_search_corpus", &());
    ts::mock_ok("global_search", &fixtures::global_search_apps(&[]));

    let _m = ts::mount_view(|| view! { <GlobalSearch /> });
    assert_eq!(
        ts::call_count("prefetch_search_corpus"),
        0,
        "mounting the bar must not scan the directory — only focusing it does"
    );

    ts::focus(".global-search__field");
    ts::wait_for(|| ts::call_count("prefetch_search_corpus") == 1).await;
}
