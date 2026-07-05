//! GUI test shard 1 of 3. See `tests/gui_2.rs` for the full rationale.
//!
//! The view tests are split across a SMALL number of aggregator binaries
//! (`tests/gui_N.rs`) instead of one-file-per-binary: `wasm-bindgen-test-runner`
//! decodes + boots Chrome once per binary, so 3 shards pay that ~fixed cost 3
//! times instead of 21. They are NOT merged into a single binary because the
//! combined debug wasm then exceeds what headless Chrome will instantiate (~78 MB
//! timed out even at a 120 s timeout); each shard is kept well under the ~52 MB
//! that provably loads. This shard anchors the heavy `open_items_dock` module.
//!
//! Balancing is by measured wasm size, not file count (shared code dedupes when
//! modules merge). To add a test: drop `tests/gui/<view>.rs`, add a
//! `#[path] mod` line to the SMALLEST shard, and check `just web-itest` still
//! passes (a shard over the load cliff fails with "Failed to detect test").
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

// `open_items_dock` mounts the whole dock + open-items workspace, so its wasm is
// by far the largest single module (~52 MB) — right at the load cliff. It gets a
// shard to itself; adding modules here pushes it over what Chrome will instantiate.
#[path = "gui/open_items_dock.rs"]
mod open_items_dock;
