//! Pins the Resource Access sweep panels to the one shared filter scaffolding
//! (`views::resource_access::use_sweep_filter`): neither the Sites nor the
//! Vault-access panel may grow its own haystack corpus, filtered-rows memo or
//! render-window reset again, or the next fix has to land twice.
//!
//! Runs natively under `just web-test`; gated off for wasm32 because it reads
//! the filesystem.

#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::path::Path;

#[test]
fn sweep_panels_use_the_shared_filter_hook() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/views/resource_access");
    for panel in ["sites.rs", "keyvault.rs"] {
        let src = fs::read_to_string(dir.join(panel))
            .unwrap_or_else(|e| panic!("read {panel}: {e}"))
            .replace("\r\n", "\n");
        assert!(
            src.contains("use_sweep_filter("),
            "{panel} must derive its rows through `use_sweep_filter`"
        );
        for forbidden in [
            "let corpus",
            "let filtered_rows = Memo::new",
            "let search_debounced",
        ] {
            assert!(
                !src.contains(forbidden),
                "{panel} re-implements the sweep filter (`{forbidden}`); use `use_sweep_filter`"
            );
        }
    }
}
