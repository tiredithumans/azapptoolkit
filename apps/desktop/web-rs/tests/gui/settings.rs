//! GUI test for the Settings page — loads the tenant's operator defaults and
//! organizes the editor into four tabs (App Registration / Enterprise
//! Application / Naming / Tenant connection). Verifies each tab surfaces its own
//! sections, seeded from the harness-preset tenant's defaults, and that the
//! fourth — the app-level client/tenant IDs, not a tenant default — prefills
//! from `get_auth_config` and confirms before relaunching.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::settings_view::SettingsView;

/// The button labelled `label` inside `scope`. Scoped because the connection
/// form and the confirmation over it deliberately carry the same label — the
/// dialog's is the one that acts.
fn button_in(scope: &str, label: &str) -> web_sys::HtmlElement {
    ts::query_all(&format!("{scope} button"))
        .into_iter()
        .find(|el| el.text_content().unwrap_or_default().trim() == label)
        .map(|el| el.unchecked_into())
        .unwrap_or_else(|| panic!("no {label:?} button under {scope:?}"))
}

/// Every text input's current value in the active tab pane.
fn input_values() -> Vec<String> {
    ts::query_all(".settings-tab input")
        .into_iter()
        .filter_map(|el| el.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|i| i.value())
        .collect()
}

#[wasm_bindgen_test]
async fn tabs_organize_defaults_into_groups() {
    ts::reset();
    ts::mock_ok("get_tenant_defaults", &fixtures::tenant_defaults());

    let _m = ts::mount_view(|| view! { <SettingsView /> });

    // All four tab labels render regardless of which pane is active.
    ts::wait_for(|| ts::body_contains("App Registration Defaults")).await;
    assert!(ts::body_contains("Enterprise Application Defaults"));
    assert!(ts::body_contains("Naming Defaults"));
    assert!(ts::body_contains("Tenant connection"));

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

#[wasm_bindgen_test]
async fn tenant_connection_tab_prefills_then_confirms_the_restart() {
    ts::reset();
    ts::mock_ok("get_tenant_defaults", &fixtures::tenant_defaults());
    ts::mock_ok("get_auth_config", &fixtures::configured());
    ts::mock_ok("set_auth_config", &());
    ts::mock_ok("restart_app", &());
    let configured = fixtures::configured();

    let _m = ts::mount_view(|| view! { <SettingsView /> });
    ts::wait_for(|| ts::body_contains("App Registration Defaults")).await;

    // The connection pane is read lazily — nothing fetches it until it opens.
    assert!(ts::last_call("get_auth_config").is_none());
    ts::click(".ui-tabs button:nth-of-type(4)");
    ts::wait_for(|| ts::body_contains("Directory (tenant) ID")).await;

    // Prefilled from the resolved IDs: this tab exists to *edit* what is
    // configured, and an operator fixing one wrong character shouldn't retype
    // both GUIDs.
    ts::wait_for(|| input_values().contains(&configured.tenant_id)).await;
    assert!(input_values().contains(&configured.client_id));

    // The defaults' Save button doesn't follow the operator here — the two
    // saves write different files, and the wrong one silently does nothing.
    assert!(!ts::body_contains("Save defaults"));

    // Saving asks first (a restart drops the signed-in session) and names the
    // tenant it is about to sign in to.
    button_in(".settings-tab", "Save & restart").click();
    ts::wait_for(|| ts::body_contains("Restart and sign in?")).await;
    assert!(ts::body_contains(&configured.tenant_id));

    // Confirming writes both IDs through, then relaunches.
    button_in(".modal", "Save & restart").click();
    ts::wait_for(|| ts::last_call("set_auth_config").is_some()).await;
    let call = ts::last_call("set_auth_config").unwrap();
    assert_eq!(
        call.arg_str("clientId").as_deref(),
        Some(configured.client_id.as_str())
    );
    assert_eq!(
        call.arg_str("tenantId").as_deref(),
        Some(configured.tenant_id.as_str())
    );
    ts::wait_for(|| ts::last_call("restart_app").is_some()).await;
}
