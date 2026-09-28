//! Pins the mock bridge to Tauri's JSON wire shape. `tauri-sys` decodes every
//! reply as `JSON.stringify` + `serde_json`, so a fixture must reach it as the
//! `JSON.parse` of the backend's `serde_json` output — exactly what real Tauri
//! delivers. A `serde_wasm_bindgen` value would break that decode twice over:
//! `()`/`None` become `undefined` (which upstream's decode panics on) and maps
//! become JS `Map`s (which stringify to `{}`, silently dropping the entries).
//! Mounts no view.
#![cfg(target_arch = "wasm32")]

use std::collections::BTreeMap;

use wasm_bindgen_test::*;

use azapptoolkit_web_rs::bindings::backup;
use azapptoolkit_web_rs::bindings::diagnostics::{self, CacheKindDto};
use azapptoolkit_web_rs::bindings::expose_api::{self, ExposeApiDto};
use azapptoolkit_web_rs::test_support as ts;

#[wasm_bindgen_test]
async fn a_unit_reply_resolves_the_infallible_invoke() {
    ts::reset();
    ts::mock_ok("clear_cache", &());

    diagnostics::clear_cache(CacheKindDto::All).await;

    assert_eq!(ts::call_count("clear_cache"), 1);
}

#[wasm_bindgen_test]
async fn a_none_reply_decodes_as_none() {
    ts::reset();
    ts::mock_ok("load_backup_from_file", &None::<String>);

    let loaded = backup::load_backup_from_file()
        .await
        .expect("a null reply is a cancelled dialog, not an error");

    assert!(loaded.is_none());
}

#[wasm_bindgen_test]
async fn a_map_in_a_reply_keeps_its_entries() {
    ts::reset();
    let mut names = BTreeMap::new();
    names.insert("client-1".to_string(), "Contoso Portal".to_string());
    ts::mock_ok(
        "get_expose_api",
        &ExposeApiDto {
            identifier_uris: vec!["api://app-1".into()],
            scopes: Vec::new(),
            pre_authorized_applications: Vec::new(),
            client_display_names: names,
        },
    );

    let dto = expose_api::get_expose_api("t", "o")
        .await
        .expect("get_expose_api decodes");

    assert_eq!(
        dto.client_display_names.get("client-1").map(String::as_str),
        Some("Contoso Portal"),
    );
}
