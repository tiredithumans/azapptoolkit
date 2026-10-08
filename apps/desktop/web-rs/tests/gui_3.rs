//! GUI test shard 3 of 4.
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
//! This shard holds the scoping cluster — everything that mounts the ScopeWizard / permission
//! picker, which is the other large shared subtree.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/app_site_access.rs"]
mod app_site_access;
#[path = "gui/gallery.rs"]
mod gallery;
#[path = "gui/managed_identities.rs"]
mod managed_identities;
#[path = "gui/managed_identity_scoping.rs"]
mod managed_identity_scoping;
#[path = "gui/orgwide_scope_callout.rs"]
mod orgwide_scope_callout;
#[path = "gui/permission_picker.rs"]
mod permission_picker;
#[path = "gui/scope_wizard.rs"]
mod scope_wizard;
#[path = "gui/sharepoint_item_scopes.rs"]
mod sharepoint_item_scopes;
