//! The grant-expiry dialog (B3): Save writes the picked date, Clear expiry
//! writes none, and the dialog offers Clear only when a date is set.

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use std::sync::Arc;

use azapptoolkit_dto::permissions::PermissionKind;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::dialogs::grant_expiry_dialog::{ExpiryTarget, GrantExpiryDialog};
use azapptoolkit_web_rs::views::tabs::permissions_tab::PermissionsTab;

const SP: &str = "0f6a1c3e-58c4-4a8e-9a43-3f8a2c1d5e71";
const RES: &str = "00000003-0000-0000-c000-000000000000";
const ROLE: &str = "45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8";

fn target(current: Option<&str>) -> ExpiryTarget {
    ExpiryTarget {
        sp_object_id: SP.into(),
        resource_app_id: RES.into(),
        app_role_id: ROLE.into(),
        label: "CallRecords.Read.All".into(),
        current: current.map(|d| d.parse().unwrap()),
    }
}

fn date_value() -> String {
    ts::query(".grant-expiry__date")
        .map(|el| el.unchecked_into::<web_sys::HtmlInputElement>().value())
        .unwrap_or_default()
}

#[wasm_bindgen_test]
async fn the_expiry_dialog_sets_and_clears() {
    ts::reset();
    ts::mock_ok("set_grant_expiry", &());
    let saved = RwSignal::new(0_u32);
    let t = RwSignal::new(Some(target(Some("2026-12-24"))));
    let _m = ts::mount_view(move || {
        view! {
            <GrantExpiryDialog
                target=t
                on_close=Callback::new(move |()| t.set(None))
                on_saved=Callback::new(move |_| saved.update(|n| *n += 1))
            />
        }
    });
    ts::wait_for(|| ts::body_contains("Expiry for CallRecords.Read.All")).await;
    // Prefilled with the current date.
    ts::wait_for(|| date_value() == "2026-12-24").await;

    ts::set_input_value(".grant-expiry__date", "2027-01-31");
    ts::click_button_labelled("Save");
    ts::wait_for(|| ts::call_count("set_grant_expiry") == 1).await;
    let args = ts::last_call("set_grant_expiry").unwrap().args;
    assert_eq!(args["spObjectId"], SP);
    assert_eq!(
        args["grants"],
        serde_json::json!([{ "resourceAppId": RES, "appRoleId": ROLE }])
    );
    assert_eq!(args["expiresOn"], "2027-01-31");
    ts::wait_for(|| saved.get_untracked() == 1).await;
    ts::wait_for(|| !ts::body_contains("Expiry for")).await;

    t.set(Some(target(Some("2027-01-31"))));
    ts::wait_for(|| ts::has_button_labelled("Clear expiry")).await;
    ts::click_button_labelled("Clear expiry");
    ts::wait_for(|| ts::call_count("set_grant_expiry") == 2).await;
    let args = ts::last_call("set_grant_expiry").unwrap().args;
    assert!(args["expiresOn"].is_null(), "{args}");
    ts::wait_for(|| saved.get_untracked() == 2).await;

    t.set(Some(target(None)));
    ts::wait_for(|| ts::body_contains("Expiry for")).await;
    ts::wait_for(|| date_value().is_empty()).await;
    assert!(!ts::has_button_labelled("Clear expiry"), "nothing to clear");
}

/// The server judges dates in UTC, so the dialog says so and won't offer a
/// day already over (B3d).
#[wasm_bindgen_test]
async fn the_expiry_dialog_says_utc_and_starts_today() {
    ts::reset();
    let t = RwSignal::new(Some(target(None)));
    let _m = ts::mount_view(move || {
        view! {
            <GrantExpiryDialog
                target=t
                on_close=Callback::new(move |()| t.set(None))
                on_saved=Callback::new(|_| {})
            />
        }
    });
    ts::wait_for(|| ts::body_contains("Expiry for CallRecords.Read.All")).await;
    let today = jiff::tz::Offset::UTC
        .to_datetime(jiff::Timestamp::now())
        .date()
        .to_string();
    let min = ts::query(".grant-expiry__date")
        .and_then(|el| el.get_attribute("min"))
        .unwrap_or_default();
    assert_eq!(min, today);
    assert!(ts::body_contains("Dates are UTC"));
}

/// A granted Application row shows its expiry under the status badge, and
/// its Expiry button opens the dialog prefilled for that grant on the app's
/// service principal.
#[wasm_bindgen_test]
async fn the_permissions_tab_shows_and_edits_a_grants_expiry() {
    ts::reset();
    let mut detail = fixtures::application_detail("obj-1", "app-1", "Call Analytics");
    let row = fixtures::resolved_permission(
        fixtures::MICROSOFT_GRAPH_APP_ID,
        "Microsoft Graph",
        "CallRecords.Read.All",
        "Read all call records",
        PermissionKind::Application,
    );
    let tag = azapptoolkit_core::audit::encode_expiry_tag(&azapptoolkit_core::audit::GrantExpiry {
        resource_app_id: row.resource_app_id.clone(),
        app_role_id: row.permission_id.clone(),
        expires_on: "2099-12-24".parse().unwrap(),
    })
    .unwrap();
    detail.resolved_permissions = vec![row];
    detail.service_principal = Some(azapptoolkit_core::models::ServicePrincipal {
        id: SP.into(),
        app_id: "app-1".into(),
        tags: vec!["HideApp".into(), tag],
        ..Default::default()
    });
    let detail = Arc::new(detail);
    let _m = ts::mount_view(move || {
        let d = detail.clone();
        view! {
            <PermissionsTab detail=Signal::derive(move || d.clone()) on_changed=Callback::new(|()| {}) />
        }
    });
    ts::wait_for(|| ts::body_contains("Expires 2099-12-24")).await;
    let button: web_sys::HtmlElement =
        ts::query("[aria-label='Set expiry for CallRecords.Read.All on Microsoft Graph']")
            .expect("the row's Expiry button")
            .unchecked_into();
    button.click();
    ts::wait_for(|| ts::body_contains("Expiry for CallRecords.Read.All")).await;
    ts::wait_for(|| date_value() == "2099-12-24").await;
}
