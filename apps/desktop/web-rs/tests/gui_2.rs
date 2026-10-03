//! GUI test shard 2 of 4.
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
//! This shard holds the security-audit cluster (both audit panes plus the surfaces that read a
//! run: credential expiry, readiness, the Home posture card, SSO certificates); the permission
//! tester and Resource Access behaviour tests, with `view_smoke`'s reject-everything mounts of
//! those two views; and the Bulk actions mount, co-located because its `BulkActionBar` is the
//! same one the audit panes and the SSO certificates dashboard mount.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/consent_posture.rs"]
mod consent_posture;
#[path = "gui/credentials_dashboard.rs"]
mod credentials_dashboard;
#[path = "gui/home_dashboard.rs"]
mod home_dashboard;
#[path = "gui/permission_tester.rs"]
mod permission_tester;
#[path = "gui/readiness.rs"]
mod readiness;
#[path = "gui/resource_access.rs"]
mod resource_access;
#[path = "gui/security_audit.rs"]
mod security_audit;
#[path = "gui/security_findings.rs"]
mod security_findings;
#[path = "gui/sso_certificates_dashboard.rs"]
mod sso_certificates_dashboard;
#[path = "gui/view_smoke.rs"]
mod view_smoke;
