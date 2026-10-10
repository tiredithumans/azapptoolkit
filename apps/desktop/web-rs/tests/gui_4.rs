//! GUI test shard 4 of 4.
//!
//! Shards keep each served test wasm under the ceiling headless Chrome will
//! instantiate (`just web-itest-size`) and give each binary its own 60 s runner
//! budget (`WASM_BINDGEN_TEST_TIMEOUT`, justfile). Modules are grouped by the
//! **view subtree they mount**, not by count: the linker keeps only referenced
//! views, so two modules that mount the same pane cost barely more than one,
//! while splitting them duplicates that pane across both shards. Re-measure
//! after moving a module (see "Browser GUI tests: sharding" in
//! `docs/architecture/frontend-workspace.md`).
//!
//! This shard holds the small, mostly self-contained surfaces plus shell-level (non-view)
//! behaviour — none pulls a large view subtree.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/confirm_dialog.rs"]
mod confirm_dialog;
#[path = "gui/copyable_id.rs"]
mod copyable_id;
#[path = "gui/dr.rs"]
mod dr;
#[path = "gui/event_streams.rs"]
mod event_streams;
#[path = "gui/global_search.rs"]
mod global_search;
#[path = "gui/harness.rs"]
mod harness;
#[path = "gui/ipc_wire.rs"]
mod ipc_wire;
#[path = "gui/key_vault.rs"]
mod key_vault;
#[path = "gui/primitives.rs"]
mod primitives;
#[path = "gui/reauth.rs"]
mod reauth;
#[path = "gui/settings.rs"]
mod settings;
#[path = "gui/shell.rs"]
mod shell;
#[path = "gui/shortcuts.rs"]
mod shortcuts;
#[path = "gui/sign_in.rs"]
mod sign_in;
