//! GUI tests for the Permission tester's seeded identity.
//!
//! A "Test access…" affordance seeds `tenant_ui.tester_app_id` and navigates
//! here. The view is keep-alive, so the seed is consumed by an Effect rather
//! than at mount — and consumed ONCE, so a later visit can't clobber an
//! identity the operator typed by hand.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::state::use_session;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::permission_tester_view::PermissionTesterView;

const GUID: &str = "11111111-2222-3333-4444-555555555555";
const PICKER: &str = ".tester-picker input";

fn picker_value() -> String {
    ts::query(PICKER)
        .expect("picker input")
        .dyn_into::<web_sys::HtmlInputElement>()
        .expect("input element")
        .value()
}

/// The keep-alive path: the view is already mounted when the seed arrives.
#[wasm_bindgen_test]
async fn seeded_app_id_fills_picker_once() {
    ts::reset();
    ts::mock_ok("global_search", &fixtures::global_search_apps(&[]));

    let m = ts::mount_view(|| view! { <PermissionTesterView /> });
    ts::tick().await;

    m.session.open_permission_tester_for(GUID.into());
    ts::tick().await;

    assert_eq!(picker_value(), GUID);
    assert_eq!(
        m.session.tenant_ui.tester_app_id.get_untracked(),
        None,
        "the seed is consumed"
    );

    // A manual edit afterwards survives: the one-shot does not re-fire.
    ts::set_input_value(PICKER, "manual");
    ts::tick().await;
    assert_eq!(picker_value(), "manual");
}

/// The first-mount path: the seed is set before the view mounts, so the
/// tenant-reset Effect and the seed Effect run in the same tick — the seed
/// must win.
#[wasm_bindgen_test]
async fn a_seed_set_before_first_mount_survives_the_tenant_reset() {
    ts::reset();
    ts::mock_ok("global_search", &fixtures::global_search_apps(&[]));

    let m = ts::mount_view(|| {
        use_session()
            .tenant_ui
            .tester_app_id
            .set(Some(GUID.to_string()));
        view! { <PermissionTesterView /> }
    });
    ts::tick().await;

    assert_eq!(picker_value(), GUID);
    assert_eq!(m.session.tenant_ui.tester_app_id.get_untracked(), None);
}
