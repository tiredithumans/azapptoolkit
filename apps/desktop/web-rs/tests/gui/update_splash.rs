//! GUI tests for the update splash's failure paths: a failure a retry cannot
//! clear (an update whose signature does not verify) disables "Update &
//! restart" and points at the manual install and the log folder; a transient
//! one leaves the button for another try.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::UiError;
use azapptoolkit_web_rs::bindings::updater::UpdateInfo;
use azapptoolkit_web_rs::components::update_splash::UpdateSplash;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

fn mount_splash() -> ts::Mounted {
    ts::mount_view(|| {
        let info = RwSignal::new(Some(UpdateInfo {
            version: "9.9.9".to_string(),
            current_version: "0.34.1".to_string(),
            notes: "### Fixed\n- A thing.".to_string(),
            pub_date: None,
        }));
        view! { <UpdateSplash open=RwSignal::new(true) info=info /> }
    })
}

#[wasm_bindgen_test]
async fn an_unverified_update_disables_retry_and_points_at_the_manual_install() {
    ts::reset();
    ts::mock_err(
        "perform_update",
        &fixtures::ui_error(
            "update_unverified",
            "The downloaded update failed its signature check, so it was not installed: bad sig",
        ),
    );
    ts::mock_ok("get_support_paths", &fixtures::support_paths());
    let _m = mount_splash();

    ts::wait_for(|| ts::has_button_labelled("Update & restart")).await;
    ts::click_button_labelled("Update & restart");
    ts::wait_for(|| ts::body_contains("failed its signature check")).await;
    assert!(ts::body_contains("Releases page"));
    // Not "install the same payload by hand": it may have been tampered with.
    assert!(ts::body_contains("may have been altered or corrupted"));
    assert!(ts::body_contains("ideally from another network"));
    assert!(!ts::body_contains("run its installer instead"));
    assert!(
        !ts::button_labelled_enabled("Update & restart"),
        "a retry would download the same unverifiable bytes"
    );
    assert!(ts::button_labelled_enabled("Later"));
    // The log folder only: the settings file has nothing to do with it.
    ts::wait_for(|| ts::body_contains(&fixtures::support_paths().log_dir)).await;
    assert!(!ts::body_contains(&fixtures::support_paths().settings_file));

    // A click on the disabled button does not try again.
    ts::click_button_labelled("Update & restart");
    ts::tick().await;
    assert_eq!(ts::call_count("perform_update"), 1);
}

#[wasm_bindgen_test]
async fn a_network_failure_leaves_update_and_restart_for_another_try() {
    ts::reset();
    ts::mock_err(
        "perform_update",
        &UiError::new(
            "network_error",
            "Couldn't reach the update server: operation timed out",
            true,
        ),
    );
    let _m = mount_splash();

    ts::wait_for(|| ts::has_button_labelled("Update & restart")).await;
    ts::click_button_labelled("Update & restart");
    ts::wait_for(|| ts::body_contains("Couldn't reach the update server")).await;
    assert!(!ts::body_contains("Releases page"));
    assert!(ts::button_labelled_enabled("Update & restart"));
}

/// An install that failed for another reason is not a tampering warning: it
/// points at the manual install of the same release.
#[wasm_bindgen_test]
async fn a_failed_install_points_at_the_manual_install_without_a_tampering_warning() {
    ts::reset();
    ts::mock_err(
        "perform_update",
        &fixtures::ui_error("updater", "invalid updater binary format"),
    );
    let _m = mount_splash();

    ts::wait_for(|| ts::has_button_labelled("Update & restart")).await;
    ts::click_button_labelled("Update & restart");
    ts::wait_for(|| ts::body_contains("invalid updater binary format")).await;
    assert!(ts::body_contains("run its installer instead"));
    assert!(!ts::body_contains("altered or corrupted"));
    assert!(!ts::button_labelled_enabled("Update & restart"));
}
