//! GUI tests for the Network lock section on the Conditional Access tab: it
//! offers only the actions that are the toolkit's to take — create when no
//! lock exists, turn on / remove the toolkit's own lock in any state, nothing
//! for another policy's lock or an app Conditional Access can't target — and
//! shows what a report-only lock would have blocked before turning it on.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_core::conditional_access::{LockIneligible, NetworkLock};
use azapptoolkit_dto::conditional_access::{
    CreatedLock, NetworkLockStatus, ReportOnlyReadout, ToolkitLockDto,
};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::conditional_access_tab::NetworkLockSection;

const APP: &str = "11111111-1111-1111-1111-111111111111";
const CREATE: &str = "Lock to trusted locations…";

fn mount() -> ts::Mounted {
    ts::mount_view(|| {
        view! {
            <NetworkLockSection
                app_id=Signal::derive(|| APP.to_string())
                app_name=Signal::derive(|| "Payroll".to_string())
            />
        }
    })
}

fn status(
    toolkit_lock: Option<ToolkitLockDto>,
    other: NetworkLock,
    other_policy_name: Option<&str>,
    readout: Option<ReportOnlyReadout>,
) -> NetworkLockStatus {
    NetworkLockStatus {
        ineligible: None,
        toolkit_lock,
        other,
        other_policy_name: other_policy_name.map(str::to_string),
        readout,
    }
}

fn toolkit(state: &str) -> ToolkitLockDto {
    ToolkitLockDto {
        policy_id: "pol-1".into(),
        state: state.into(),
        excluded_locations: fixtures::named_locations()[..1].to_vec(),
    }
}

#[wasm_bindgen_test]
async fn none_offers_create_and_creates_report_only() {
    ts::reset();
    ts::mock_ok("get_network_lock", &fixtures::network_lock_status_none());
    ts::mock_ok("list_named_locations", &fixtures::named_locations());
    ts::mock_ok(
        "create_network_lock",
        &CreatedLock {
            policy_id: "pol-1".into(),
            created_location_id: None,
        },
    );
    let _m = mount();
    ts::wait_until("the create button", || ts::has_button_labelled(CREATE)).await;
    ts::click_button_labelled(CREATE);
    ts::wait_until("the named-location list", || ts::body_contains("Head office")).await;
    assert!(
        ts::body_contains("Created report-only"),
        "{}",
        ts::body_text()
    );
    // The first row is "Head office" (the fixture's first location).
    ts::click(".modal .checkbox-row input");
    ts::wait_until("a chosen location enables Create lock", || {
        ts::button_labelled_enabled("Create lock")
    })
    .await;
    ts::click_button_labelled_in(".modal", "Create lock");
    ts::wait_until("the create call", || ts::call_count("create_network_lock") == 1).await;
    let args = ts::last_call("create_network_lock").unwrap().args;
    assert_eq!(
        args["namedLocationIds"],
        serde_json::json!(["aaaaaaaa-0000-0000-0000-000000000001"])
    );
    assert!(args["newLocation"].is_null(), "{args}");
}

#[wasm_bindgen_test]
async fn report_only_shows_the_readout_in_the_turn_on_confirm() {
    ts::reset();
    ts::mock_ok(
        "get_network_lock",
        &status(
            Some(toolkit("enabledForReportingButNotEnforced")),
            NetworkLock::None,
            None,
            Some(ReportOnlyReadout {
                would_block: 3,
                sample_ips: vec!["203.0.113.7".into()],
                window_days: 7,
            }),
        ),
    );
    ts::mock_ok("enable_network_lock", &());
    let _m = mount();
    ts::wait_for(|| ts::body_contains("Report-only")).await;
    assert!(
        ts::body_contains("3 sign-ins would have been blocked"),
        "{}",
        ts::body_text()
    );
    ts::click_button_labelled("Turn on lock");
    ts::wait_for(|| ts::has_button_labelled("Turn on")).await;
    let modal = ts::text(".modal");
    assert!(modal.contains("Payroll"), "{modal}");
    assert!(
        modal.contains("3 sign-ins would have been blocked"),
        "{modal}"
    );
    ts::click_button_labelled("Turn on");
    ts::wait_for(|| ts::call_count("enable_network_lock") == 1).await;
    assert_eq!(
        ts::last_call("enable_network_lock").unwrap().args["policyId"],
        "pol-1"
    );
}

#[wasm_bindgen_test]
async fn a_foreign_lock_offers_no_buttons() {
    ts::reset();
    ts::mock_ok(
        "get_network_lock",
        &status(
            None,
            NetworkLock::Enforced {
                policy_ids: vec!["x".into()],
            },
            Some("Tenant workload lock"),
            None,
        ),
    );
    let _m = mount();
    ts::wait_for(|| ts::body_contains("Locked by Tenant workload lock")).await;
    for label in [CREATE, "Turn on lock", "Remove", "Remove lock"] {
        assert!(!ts::has_button_labelled(label), "{label}");
    }
}

#[wasm_bindgen_test]
async fn a_lock_turned_off_in_the_portal_offers_turn_on_and_remove() {
    ts::reset();
    ts::mock_ok(
        "get_network_lock",
        &status(Some(toolkit("disabled")), NetworkLock::None, None, None),
    );
    let _m = mount();
    ts::wait_for(|| ts::body_contains("Turned off outside the toolkit")).await;
    assert!(ts::has_button_labelled("Turn on lock"));
    assert!(ts::has_button_labelled("Remove"));
    assert!(!ts::has_button_labelled(CREATE));
}

#[wasm_bindgen_test]
async fn an_ineligible_app_says_why_and_offers_nothing() {
    ts::reset();
    ts::mock_ok(
        "get_network_lock",
        &NetworkLockStatus {
            ineligible: Some(LockIneligible::MultiTenantApp),
            toolkit_lock: None,
            other: NetworkLock::NotPossible {
                reason: LockIneligible::MultiTenantApp,
            },
            other_policy_name: None,
            readout: None,
        },
    );
    let _m = mount();
    ts::wait_for(|| ts::body_contains("multi-tenant app")).await;
    assert!(!ts::has_button_labelled(CREATE));
}
