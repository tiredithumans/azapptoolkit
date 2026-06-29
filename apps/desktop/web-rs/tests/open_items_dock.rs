//! GUI tests for the open-items workspace: the shared, cross-entity "working
//! set" dock + the 1-up / 2-up compare workspace. Mounts the dock + workspace
//! directly (they live in the shell in the real app) and drives the working set
//! through the session, asserting on the rendered chips and visible panes.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::open_items_dock::OpenItemsDock;
use azapptoolkit_web_rs::components::open_items_workspace::OpenItemsWorkspace;
use azapptoolkit_web_rs::state::OpenItemKind;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

wasm_bindgen_test_configure!(run_in_browser);

/// Count `.workspace__pane` elements that are actually visible (the hidden ones
/// are `display:none`, so they have no offset parent).
fn visible_panes() -> usize {
    ts::query_all(".workspace__pane")
        .into_iter()
        .filter(|el| {
            el.clone()
                .unchecked_into::<web_sys::HtmlElement>()
                .offset_parent()
                .is_some()
        })
        .count()
}

/// Mount the dock + workspace with the App Reg / Enterprise detail commands
/// mocked, so opened windows load and report their names back to the dock.
fn mount() -> ts::Mounted {
    ts::reset();
    ts::mock_ok(
        "get_application_detail",
        &fixtures::application_detail(
            "app-1",
            "11111111-1111-1111-1111-111111111111",
            "Contoso API",
        ),
    );
    ts::mock_ok(
        "get_enterprise_application_detail",
        &fixtures::enterprise_application_detail("sp-1", "Fabrikam Web"),
    );
    ts::mount_view(|| {
        view! {
            <OpenItemsWorkspace />
            <OpenItemsDock />
        }
    })
}

#[wasm_bindgen_test]
async fn open_focus_compare_close() {
    let m = mount();
    // Nothing open → no dock, no visible workspace pane.
    assert!(ts::query_all(".open-dock__chip").is_empty());
    assert_eq!(visible_panes(), 0);

    // Open an app registration → one chip, one visible pane.
    m.session.open_item(
        OpenItemKind::AppReg,
        "app-1".to_string(),
        "Contoso API".to_string(),
    );
    ts::wait_for(|| ts::query_all(".open-dock__chip").len() == 1).await;
    ts::wait_for(|| visible_panes() == 1).await;

    // Open an enterprise app (cross-entity) → two chips; focus replaces, so still
    // one pane shown.
    m.session.open_item(
        OpenItemKind::Enterprise,
        "sp-1".to_string(),
        "Fabrikam Web".to_string(),
    );
    ts::wait_for(|| ts::query_all(".open-dock__chip").len() == 2).await;
    ts::wait_for(|| visible_panes() == 1).await;

    // Dedupe: re-opening the app reg adds no third chip.
    m.session.open_item(
        OpenItemKind::AppReg,
        "app-1".to_string(),
        "Contoso API".to_string(),
    );
    assert_eq!(
        ts::query_all(".open-dock__chip").len(),
        2,
        "dedupe by (kind, entity_id) — no third chip"
    );

    let app_id = m.session.is_open(OpenItemKind::AppReg, "app-1").unwrap();
    let ent_id = m.session.is_open(OpenItemKind::Enterprise, "sp-1").unwrap();

    // Compare: pin both side-by-side → two visible panes + the two-up grid.
    m.session.focus_item(app_id, false);
    m.session.focus_item(ent_id, true);
    ts::wait_for(|| visible_panes() == 2).await;
    assert!(
        !ts::query_all(".workspace__panes--two").is_empty(),
        "side-by-side compare applies the two-up modifier"
    );

    // A third pin stays capped at two visible panes.
    m.session.focus_item(app_id, true);
    assert_eq!(visible_panes(), 2, "compare is capped at two panes");

    // Closing the app reg drops it from the dock and the shown set.
    m.session.close_item(app_id);
    ts::wait_for(|| ts::query_all(".open-dock__chip").len() == 1).await;
    ts::wait_for(|| visible_panes() == 1).await;
}

#[wasm_bindgen_test]
async fn chip_title_self_corrects_to_loaded_name() {
    let m = mount();
    // Open with a placeholder label (the id) — as pairing jumps / deep-links do.
    m.session.open_item(
        OpenItemKind::AppReg,
        "app-1".to_string(),
        "app-1".to_string(),
    );
    // Once the detail loads, the pane reports its real name to the dock chip.
    ts::wait_for(|| ts::text(".open-dock__chip-label") == "Contoso API").await;
}
