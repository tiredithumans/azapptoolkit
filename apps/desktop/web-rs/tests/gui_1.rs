//! GUI test shard 1 of 4.
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
//! This shard holds the app-registration / enterprise detail + workspace cluster — these share the
//! detail panes, so co-locating them keeps the linked view code counted once.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/application_detail.rs"]
mod application_detail;
#[path = "gui/application_list.rs"]
mod application_list;
#[path = "gui/authentication_tab.rs"]
mod authentication_tab;
#[path = "gui/certificate_reveal.rs"]
mod certificate_reveal;
#[path = "gui/credential_policy.rs"]
mod credential_policy;
#[path = "gui/credential_sweep.rs"]
mod credential_sweep;
#[path = "gui/deleted_apps.rs"]
mod deleted_apps;
#[path = "gui/enterprise_access_tab.rs"]
mod enterprise_access_tab;
#[path = "gui/enterprise_application_list.rs"]
mod enterprise_application_list;
#[path = "gui/expose_api_tab.rs"]
mod expose_api_tab;
#[path = "gui/federated_tab.rs"]
mod federated_tab;
#[path = "gui/open_items_dock.rs"]
mod open_items_dock;
#[path = "gui/provisioning_tab.rs"]
mod provisioning_tab;
#[path = "gui/sso_claims.rs"]
mod sso_claims;
#[path = "gui/sso_rollover.rs"]
mod sso_rollover;
#[path = "gui/sso_signed_requests.rs"]
mod sso_signed_requests;
#[path = "gui/sso_wizard.rs"]
mod sso_wizard;
