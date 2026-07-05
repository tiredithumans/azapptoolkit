//! GUI test for the Disaster Recovery view's backup progress: the progress
//! readout renders from streamed `backup-progress` events, and the rate-limit
//! back-off notice appears only once the adaptive concurrency cap drops below
//! its observed peak (i.e. Graph started throttling and the run is slowing down).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::dr::DisasterRecoveryView;

#[wasm_bindgen_test]
async fn backup_progress_renders_count_and_throttle_notice() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <DisasterRecoveryView /> });
    // Let `use_progress_stream` register its listener before we emit.
    ts::tick().await;
    ts::tick().await;

    // Healthy cap: the readout shows count + live concurrency, no back-off notice.
    ts::emit_event("backup-progress", &fixtures::backup_progress(2, 10, 4));
    ts::wait_for(|| ts::body_contains("Captured 2/10")).await;
    assert!(ts::body_contains("4 concurrent"));
    assert!(
        ts::query(".dr-view__notice").is_none(),
        "no back-off notice while the cap is at its peak"
    );

    // The cap drops below the peak → Graph is throttling → the notice appears.
    ts::emit_event("backup-progress", &fixtures::backup_progress(4, 10, 2));
    ts::wait_for(|| ts::query(".dr-view__notice").is_some()).await;
    assert!(ts::body_contains("2 concurrent"));
}
