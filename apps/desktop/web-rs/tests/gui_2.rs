//! GUI test shard 2 of 4.
//!
//! Shards exist because a single merged test binary's served wasm exceeds what
//! headless Chrome will instantiate. Modules are grouped by the **view subtree
//! they mount**, not by count: the linker keeps only referenced views, so two
//! modules that mount the same pane cost barely more than one, while splitting
//! them duplicates that pane across both shards. Re-measure after moving a
//! module (see the sharding note in AGENTS.md).
//!
//! This shard holds the security-audit cluster (both audit panes plus the surfaces that read a
//! run: credential expiry, readiness) and the whole-shell smoke test.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[path = "gui/credentials_dashboard.rs"]
mod credentials_dashboard;
#[path = "gui/readiness.rs"]
mod readiness;
#[path = "gui/security_audit.rs"]
mod security_audit;
#[path = "gui/security_findings.rs"]
mod security_findings;
#[path = "gui/sso_certificates_dashboard.rs"]
mod sso_certificates_dashboard;
#[path = "gui/view_smoke.rs"]
mod view_smoke;
