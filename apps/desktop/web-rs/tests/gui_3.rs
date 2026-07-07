//! GUI test shard 3 of 3. See `tests/gui_2.rs` for the full rationale.
//!
//! This shard holds the security-audit / scoping cluster of views.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/confirm_dialog.rs"]
mod confirm_dialog;
#[path = "gui/gallery.rs"]
mod gallery;
#[path = "gui/global_search.rs"]
mod global_search;
#[path = "gui/managed_identity_scoping.rs"]
mod managed_identity_scoping;
#[path = "gui/orgwide_scope_callout.rs"]
mod orgwide_scope_callout;
#[path = "gui/permission_picker.rs"]
mod permission_picker;
#[path = "gui/reauth.rs"]
mod reauth;
#[path = "gui/scope_wizard.rs"]
mod scope_wizard;
#[path = "gui/security_audit.rs"]
mod security_audit;
#[path = "gui/security_findings.rs"]
mod security_findings;
#[path = "gui/settings.rs"]
mod settings;
#[path = "gui/view_smoke.rs"]
mod view_smoke;
