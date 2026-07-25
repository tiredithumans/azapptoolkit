//! GUI test shard 4 of 4. See `tests/gui_2.rs` for the full rationale.
//!
//! This shard holds app-shell-level behaviour that isn't tied to one view —
//! currently the global keyboard layer.
//!
//! It exists as a NEW shard rather than an addition to an existing one because
//! shards 1-3 already measure ~60-64 MB of served wasm each, above the ~52 MB
//! working ceiling the AGENTS.md sharding note describes (headless Chrome won't
//! instantiate an over-large module). Growing one further is the failure mode
//! that note exists to prevent.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/shortcuts.rs"]
mod shortcuts;
