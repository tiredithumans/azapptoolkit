//! GUI test for the Settings page — loads the tenant's operator defaults and
//! renders the editor sections seeded from them (tenant preset by the harness).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::settings_view::SettingsView;

#[wasm_bindgen_test]
async fn loads_and_renders_default_sections() {
    ts::reset();
    ts::mock_ok("get_tenant_defaults", &fixtures::tenant_defaults());

    let _m = ts::mount_view(|| view! { <SettingsView /> });

    ts::wait_for(|| ts::body_contains("App Registration defaults")).await;
    // The seeded owners from the fixture render in their sections.
    assert!(ts::body_contains("Alex Admin"));
    assert!(ts::body_contains("Enterprise Application defaults"));
    assert!(ts::body_contains("Sam Owner"));
    assert!(ts::body_contains("Management scope name pattern"));
    // The read used the harness-preset tenant.
    assert_eq!(
        ts::last_call("get_tenant_defaults")
            .unwrap()
            .arg_str("tenantId")
            .as_deref(),
        Some("test-tenant")
    );
}
