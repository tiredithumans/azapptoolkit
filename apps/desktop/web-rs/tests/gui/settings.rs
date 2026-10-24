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

use azapptoolkit_web_rs::bindings::config::ConfigSource;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::config_screen::ConfigScreen;
use azapptoolkit_web_rs::views::settings_view::SettingsView;
use azapptoolkit_web_rs::views::sign_in::SignInScreen;

/// What the startup reader says about a damaged settings.json (path and where
/// it broke — never what the file holds).
const SETTINGS_ERROR: &str = "/home/alex/.local/share/azapptoolkit/settings.json could not be \
    read (invalid JSON at line 3, column 5), so azapptoolkit started without it.";

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
    // The TabBar's selection is a real `"true"`/`"false"` string, never a
    // boolean attribute (`aria-selected=""` / absent).
    let selected = |n: usize| {
        ts::query(&format!(".ui-tabs button:nth-of-type({n})"))
            .and_then(|b| b.get_attribute("aria-selected"))
    };
    assert_eq!(selected(1).as_deref(), Some("true"));
    assert_eq!(selected(2).as_deref(), Some("false"));

    // Enterprise pane: seeded owner + the SSO notification-email field.
    ts::click(".ui-tabs button:nth-of-type(2)");
    ts::wait_for(|| ts::body_contains("Sam Owner")).await;
    assert_eq!(selected(2).as_deref(), Some("true"));
    assert_eq!(selected(1).as_deref(), Some("false"));
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
    // IDs saved in-app are what this form edits, so no override note shows.
    assert!(!ts::body_contains("overrides what you save here"));

    // The defaults' Save button doesn't follow the operator here — the two
    // saves write different files, and the wrong one silently does nothing.
    assert!(!ts::body_contains("Save defaults"));

    // Saving asks first (a restart drops the signed-in session) and names the
    // tenant it is about to sign in to.
    ts::click_button_labelled_in(".settings-tab", "Save & restart");
    ts::wait_for(|| ts::body_contains("Restart and sign in?")).await;
    assert!(ts::body_contains(&configured.tenant_id));

    // Confirming writes both IDs through, then relaunches. Scoped because the
    // form and the confirmation over it deliberately carry the same label — the
    // dialog's is the one that acts.
    ts::click_button_labelled_in(".modal", "Save & restart");
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

/// With an env var supplying the IDs, a saved change would be ignored after
/// the restart — the tab says so instead of letting the old tenant come back
/// unexplained.
#[wasm_bindgen_test]
async fn tenant_connection_tab_names_an_active_env_override() {
    ts::reset();
    ts::mock_ok("get_tenant_defaults", &fixtures::tenant_defaults());
    ts::mock_ok(
        "get_auth_config",
        &fixtures::configured_from(ConfigSource::Env),
    );

    let _m = ts::mount_view(|| view! { <SettingsView /> });
    ts::wait_for(|| ts::body_contains("App Registration Defaults")).await;
    ts::click(".ui-tabs button:nth-of-type(4)");
    ts::wait_for(|| ts::body_contains("overrides what you save here")).await;
    assert!(ts::body_contains(
        "AZAPPTOOLKIT_CLIENT_ID and AZAPPTOOLKIT_TENANT_ID"
    ));
}

/// Settings sits behind the sign-in that may be failing, so the Tenant
/// connection tab is one of several places the log folder and settings file
/// are shown — copyable, without knowing the per-OS layout.
#[wasm_bindgen_test]
async fn tenant_connection_tab_shows_where_the_logs_and_settings_live() {
    ts::reset();
    ts::mock_ok("get_tenant_defaults", &fixtures::tenant_defaults());
    ts::mock_ok("get_auth_config", &fixtures::configured());
    ts::mock_ok("get_support_paths", &fixtures::support_paths());
    let paths = fixtures::support_paths();

    let _m = ts::mount_view(|| view! { <SettingsView /> });
    ts::wait_for(|| ts::body_contains("App Registration Defaults")).await;
    ts::click(".ui-tabs button:nth-of-type(4)");
    ts::wait_for(|| ts::body_contains(&paths.log_dir)).await;
    assert!(ts::body_contains(&paths.settings_file));
    assert!(ts::body_contains("Logs folder"));
    assert_eq!(ts::query_all(".support-paths .copy-block").len(), 2);
}

/// A save over a damaged settings.json is refused (writing over it would lose
/// the tenant defaults) — and the hint says the file is the problem, not the
/// folder's permissions, with the paths to go and fix it.
#[wasm_bindgen_test]
async fn a_save_over_a_damaged_settings_file_says_to_fix_or_move_it() {
    ts::reset();
    ts::mock_err(
        "set_auth_config",
        &fixtures::ui_error(
            "settings_unreadable",
            "settings.json is damaged: /x/settings.json exists but could not be read (invalid \
             JSON at line 1, column 2); fix it or move it aside — it was left unchanged.",
        ),
    );
    ts::mock_ok("get_support_paths", &fixtures::support_paths());
    let configured = fixtures::configured();
    let (client, tenant) = (configured.client_id.clone(), configured.tenant_id.clone());

    let _m = ts::mount_view(move || {
        view! { <ConfigScreen client_id=client tenant_id=tenant /> }
    });
    ts::click_button_labelled("Save & restart");
    ts::wait_for(|| ts::body_contains("settings.json is damaged — fix the JSON or move it aside"))
        .await;
    assert!(ts::body_contains("/x/settings.json"));
    assert!(!ts::body_contains(
        "check that the app's config folder is writable"
    ));
    assert_eq!(
        ts::call_count("restart_app"),
        0,
        "a refused save never relaunches"
    );
    // The first-run screen has no Settings page behind it: the paths show here.
    ts::wait_for(|| ts::body_contains(&fixtures::support_paths().settings_file)).await;
}

/// A settings.json the app could not read at startup is named before anything
/// is typed or signed in — on both screens in front of Settings — instead of
/// the app silently running on defaults.
#[wasm_bindgen_test]
async fn a_damaged_settings_file_at_startup_is_named_on_both_screens() {
    ts::reset();
    ts::mock_ok("get_support_paths", &fixtures::support_paths());

    let config = ts::mount_view(|| {
        view! {
            <ConfigScreen
                client_id=String::new()
                tenant_id=String::new()
                settings_error=Some(SETTINGS_ERROR.to_string())
            />
        }
    });
    ts::wait_for(|| ts::query(".settings-error").is_some()).await;
    assert!(ts::text(".settings-error").contains("invalid JSON at line 3, column 5"));
    ts::wait_for(|| ts::body_contains(&fixtures::support_paths().log_dir)).await;
    drop(config);

    let sign_in = ts::mount_view(|| {
        view! {
            <SignInScreen
                tenant="test-tenant".to_string()
                on_reconfigure=Callback::new(|_| ())
                settings_error=Some(SETTINGS_ERROR.to_string())
            />
        }
    });
    sign_in.session.active_tenant.set(None);
    ts::wait_for(|| ts::query(".settings-error").is_some()).await;
    assert!(ts::text(".settings-error").contains("started without it"));
    assert!(ts::body_contains("Sign in with Entra ID"));
}
