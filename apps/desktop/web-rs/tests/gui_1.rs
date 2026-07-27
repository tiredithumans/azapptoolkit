//! GUI test shard 1 of 4.
//!
//! Shards exist because a single merged test binary's served wasm exceeds what
//! headless Chrome will instantiate. Modules are grouped by the **view subtree
//! they mount**, not by count: the linker keeps only referenced views, so two
//! modules that mount the same pane cost barely more than one, while splitting
//! them duplicates that pane across both shards. Re-measure after moving a
//! module (see the sharding note in AGENTS.md).
//!
//! This shard holds the app-registration / enterprise detail + workspace cluster — these share the
//! detail panes, so co-locating them keeps the linked view code counted once.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/application_detail.rs"]
mod application_detail;
#[path = "gui/application_list.rs"]
mod application_list;
#[path = "gui/enterprise_application_list.rs"]
mod enterprise_application_list;
#[path = "gui/open_items_dock.rs"]
mod open_items_dock;
