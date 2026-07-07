//! GUI test for the Settings page — loads the tenant's operator defaults and
//! organizes the editor into three tabs (App Registration / Enterprise
//! Application / Naming). Verifies each tab surfaces its own sections, seeded
//! from the harness-preset tenant's defaults.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::settings_view::SettingsView;

#[wasm_bindgen_test]
async fn tabs_organize_defaults_into_groups() {
    ts::reset();
    ts::mock_ok("get_tenant_defaults", &fixtures::tenant_defaults());

    let _m = ts::mount_view(|| view! { <SettingsView /> });

    // All three tab labels render regardless of which pane is active.
    ts::wait_for(|| ts::body_contains("App Registration Defaults")).await;
    assert!(ts::body_contains("Enterprise Application Defaults"));
    assert!(ts::body_contains("Naming Defaults"));

    // The App Registration pane is active on load: its seeded owner shows.
    assert!(ts::body_contains("Alex Admin"));

    // Enterprise pane: seeded owner + the SSO notification-email field.
    ts::click(".ui-tabs button:nth-of-type(2)");
    ts::wait_for(|| ts::body_contains("Sam Owner")).await;
    assert!(ts::body_contains(
        "Default SSO notification emails (one per line, max 5)"
    ));

    // Naming pane: the three name-pattern fields.
    ts::click(".ui-tabs button:nth-of-type(3)");
    ts::wait_for(|| ts::body_contains("Management scope name pattern")).await;
    assert!(ts::body_contains("Mail-enabled group name pattern"));
    assert!(ts::body_contains("Secret name pattern"));

    // The read used the harness-preset tenant.
    assert_eq!(
        ts::last_call("get_tenant_defaults")
            .unwrap()
            .arg_str("tenantId")
            .as_deref(),
        Some("test-tenant")
    );
}
