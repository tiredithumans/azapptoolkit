//! GUI test shard 2 of 3.
//!
//! The Leptos view tests run in a headless browser (mock Tauri IPC, no tenant).
//! They are split across a small number of aggregator binaries (`tests/gui_N.rs`)
//! rather than one binary per file: `wasm-bindgen-test-runner` decodes the wasm
//! and boots Chrome once per binary, and with `[profile.test] strip = "debuginfo"`
//! that per-binary cost is cheap — so 3 shards is far faster than 21 while
//! avoiding the single-binary load cliff (a merged ~78 MB module times out in
//! Chrome; each shard stays under the ~52 MB that provably loads).
//!
//! Tests within a shard run serially in one page and share its DOM;
//! `test_support::reset()` (every test's first call) clears the body between
//! them. Balancing is by measured wasm size — see `tests/gui_1.rs`.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/application_detail.rs"]
mod application_detail;
#[path = "gui/application_list.rs"]
mod application_list;
#[path = "gui/copyable_id.rs"]
mod copyable_id;
#[path = "gui/credentials_dashboard.rs"]
mod credentials_dashboard;
#[path = "gui/dr.rs"]
mod dr;
#[path = "gui/enterprise_application_list.rs"]
mod enterprise_application_list;
#[path = "gui/event_streams.rs"]
mod event_streams;
#[path = "gui/key_vault.rs"]
mod key_vault;
#[path = "gui/managed_identities.rs"]
mod managed_identities;
#[path = "gui/readiness.rs"]
mod readiness;
