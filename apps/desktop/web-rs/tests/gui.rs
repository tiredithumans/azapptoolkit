//! Aggregated browser-GUI test binary — the single home of the Leptos view tests.
//!
//! Every view test is a `mod` under `tests/gui/`, compiled into this ONE
//! integration binary. `just web-itest` (`wasm-pack test`) then links the crate,
//! runs `wasm-bindgen`, and boots a single headless-Chrome session for the whole
//! suite — instead of paying ~27s of per-binary `wasm-bindgen` + browser
//! boot/teardown for every file. That fixed per-binary cost, paid 21 times, was
//! ~97% of the old ~13-minute CI step; the actual tests run in ~8s total. See
//! AGENTS.md → Verification playbook.
//!
//! Adding a view test: drop `tests/gui/<view>.rs` and add a
//! `#[path = "gui/<view>.rs"] mod <view>;` line below — keep the list
//! alphabetized. The `#[path]` is required: this file is a test-binary **crate
//! root**, so a bare `mod <view>;` would resolve to `tests/<view>.rs` (which
//! cargo would then auto-compile into its own binary, reintroducing the
//! per-binary overhead this file exists to avoid). Files under `tests/gui/` are
//! not directly in `tests/`, so cargo never auto-discovers them as targets.
//!
//! `wasm_bindgen_test_configure!` must appear **exactly once per crate** — it
//! lives here, never in the modules. The tests run serially in the one page and
//! share its DOM; `test_support::reset()` (every test's first call) clears the
//! body so nothing leaks from one test into the next.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/application_detail.rs"]
mod application_detail;
#[path = "gui/application_list.rs"]
mod application_list;
#[path = "gui/confirm_dialog.rs"]
mod confirm_dialog;
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
#[path = "gui/global_search.rs"]
mod global_search;
#[path = "gui/key_vault.rs"]
mod key_vault;
#[path = "gui/managed_identities.rs"]
mod managed_identities;
#[path = "gui/managed_identity_scoping.rs"]
mod managed_identity_scoping;
#[path = "gui/open_items_dock.rs"]
mod open_items_dock;
#[path = "gui/orgwide_scope_callout.rs"]
mod orgwide_scope_callout;
#[path = "gui/permission_picker.rs"]
mod permission_picker;
#[path = "gui/readiness.rs"]
mod readiness;
#[path = "gui/reauth.rs"]
mod reauth;
#[path = "gui/scope_wizard.rs"]
mod scope_wizard;
#[path = "gui/security_audit.rs"]
mod security_audit;
#[path = "gui/security_findings.rs"]
mod security_findings;
#[path = "gui/view_smoke.rs"]
mod view_smoke;
