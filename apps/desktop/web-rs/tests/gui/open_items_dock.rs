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
use azapptoolkit_web_rs::hooks::use_shortcuts::use_shortcuts;
use azapptoolkit_web_rs::state::{OpenItemKind, use_session};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

/// Count elements matching `selector` that are actually visible (hidden ones are
/// `display:none`, so they have no offset parent).
fn visible_count(selector: &str) -> usize {
    ts::query_all(selector)
        .into_iter()
        .filter(|el| {
            el.clone()
                .unchecked_into::<web_sys::HtmlElement>()
                .offset_parent()
                .is_some()
        })
        .count()
}

fn visible_panes() -> usize {
    visible_count(".workspace__pane")
}

/// True when the focused element matches `selector`. Focus placement is the
/// whole property here and no DOM query expresses it.
fn focused_matches(selector: &str) -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element())
        .and_then(|el| el.matches(selector).ok())
        .unwrap_or(false)
}

/// The App Reg / Enterprise detail commands, so opened windows load and report
/// their names back to the dock.
fn mock_details() {
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
}

/// Mount the dock + workspace on their own.
fn mount() -> ts::Mounted {
    mock_details();
    ts::mount_view(|| {
        view! {
            <OpenItemsWorkspace />
            <OpenItemsDock />
        }
    })
}

/// The same pair plus the global keyboard layer the shell installs beside them,
/// and a stand-in for the list row that opened the item — the focus contract is
/// precisely about handing focus back to that row.
///
/// Deliberately no `provide_session()`: `mount_view` already provided one, and
/// re-providing would hand the test a different session than the view reads.
fn mount_with_shortcuts() -> ts::Mounted {
    mock_details();
    ts::mount_view(|| {
        use_shortcuts(use_session(), RwSignal::new(false));
        view! {
            <button class="probe-row" type="button">"Open Contoso API"</button>
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
    // The otherwise-invisible compare gesture is advertised on the chip tooltip.
    let title = ts::query(".open-dock__chip-main")
        .unwrap()
        .get_attribute("title")
        .unwrap_or_default();
    assert!(
        title.contains("Ctrl/Cmd-click to compare"),
        "chip title advertises the compare gesture: {title}"
    );
    // Single pane: the "Full" control would be a no-op, so it isn't shown.
    assert_eq!(
        visible_count(".workspace__pane-full"),
        0,
        "no Full button in single-pane view"
    );

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

    // Two items + not yet comparing → the inline compare hint shows in the bar.
    assert!(
        ts::query(".open-dock__hint").is_some(),
        "compare hint visible once a second item is open"
    );

    // Compare: pin both side-by-side → two visible panes + the two-up grid.
    m.session.focus_item(app_id, false);
    m.session.focus_item(ent_id, true);
    ts::wait_for(|| visible_panes() == 2).await;
    // The gesture has been found — the hint gets out of the way.
    assert!(
        ts::query(".open-dock__hint").is_none(),
        "compare hint hidden while a 2-up compare is active"
    );
    assert!(
        !ts::query_all(".workspace__panes--two").is_empty(),
        "side-by-side compare applies the two-up modifier"
    );
    // Comparing two panes: each shows a "Full" button to collapse to itself.
    ts::wait_for(|| visible_count(".workspace__pane-full") == 2).await;

    // A third pin stays capped at two visible panes.
    m.session.focus_item(app_id, true);
    assert_eq!(visible_panes(), 2, "compare is capped at two panes");

    // Closing the app reg drops it from the dock and the shown set.
    m.session.close_item(app_id);
    ts::wait_for(|| ts::query_all(".open-dock__chip").len() == 1).await;
    ts::wait_for(|| visible_panes() == 1).await;
}

#[wasm_bindgen_test]
async fn close_all_clears_the_dock() {
    let m = mount();
    // One open item: no "Close all" (its chip × already closes it).
    m.session.open_item(
        OpenItemKind::AppReg,
        "app-1".to_string(),
        "Contoso API".to_string(),
    );
    ts::wait_for(|| ts::query_all(".open-dock__chip").len() == 1).await;
    assert!(
        ts::query(".open-dock__clear").is_none(),
        "no Close all for one item"
    );

    // A second open item surfaces the "Close all" button.
    m.session.open_item(
        OpenItemKind::Enterprise,
        "sp-1".to_string(),
        "Fabrikam Web".to_string(),
    );
    ts::wait_for(|| ts::query(".open-dock__clear").is_some()).await;

    // Clicking it empties the dock and collapses the workspace.
    ts::click(".open-dock__clear");
    ts::wait_for(|| ts::query_all(".open-dock__chip").is_empty()).await;
    assert_eq!(
        visible_panes(),
        0,
        "workspace collapses when all items close"
    );
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

#[wasm_bindgen_test]
async fn dock_labels_name_the_chip_they_close() {
    let m = mount();
    m.session.open_item(
        OpenItemKind::AppReg,
        "app-1".to_string(),
        "Contoso API".to_string(),
    );
    ts::wait_for(|| ts::query_all(".open-dock__chip").len() == 1).await;

    // A bare `aria-label` on a plain `<div>` has no role to attach to and is
    // never announced — the same fix the workspace made for itself.
    let dock = ts::query(".open-dock").expect("the dock");
    assert_eq!(
        dock.get_attribute("role").as_deref(),
        Some("region"),
        "the dock's label needs a role to hang on"
    );
    // With six items open, six identical "Close"es tell a screen-reader user
    // nothing about which one is about to go.
    let close = ts::query(".open-dock__close").expect("a chip close button");
    assert_eq!(
        close.get_attribute("aria-label").as_deref(),
        Some("Close Contoso API")
    );
}

#[wasm_bindgen_test]
async fn focus_moves_into_the_pane_and_returns_on_collapse() {
    let m = mount_with_shortcuts();
    // Stand where the operator stands: on the list row that opens the item.
    ts::focus(".probe-row");
    m.session.open_item(
        OpenItemKind::AppReg,
        "app-1".to_string(),
        "Contoso API".to_string(),
    );
    // Without this the overlay opens with focus still on <body>, ~13 Tab
    // presses (the whole nav rail) away from the pane it just opened.
    ts::wait_for(|| focused_matches(".workspace__pane")).await;

    // Escape collapses the workspace; focus goes back to the row, so the
    // operator keeps their place in the list rather than restarting at <body>.
    ts::press_key("body", "Escape");
    ts::wait_for(|| focused_matches(".probe-row")).await;
}

#[wasm_bindgen_test]
async fn accelerators_step_the_dock_and_close_the_focused_item() {
    let m = mount_with_shortcuts();
    let a = m.session.open_item(
        OpenItemKind::AppReg,
        "app-1".to_string(),
        "Contoso API".to_string(),
    );
    let b = m.session.open_item(
        OpenItemKind::Enterprise,
        "sp-1".to_string(),
        "Fabrikam Web".to_string(),
    );
    ts::wait_for(|| visible_panes() == 1).await;

    // Escape is documented as "collapse the workspace" and used to be a one-way
    // door: the only route back was tabbing past the entire content slot to the
    // dock. Cmd/Ctrl-] is that route.
    ts::press_key("body", "Escape");
    ts::wait_for(|| visible_panes() == 0).await;
    ts::press_key_with_accel("body", "]");
    ts::wait_for(|| visible_panes() == 1).await;
    assert_eq!(
        m.session.shown_items.get_untracked(),
        vec![a],
        "collapsed, `]` re-opens at the first chip"
    );

    // Then it steps along the dock, and `[` steps back. Focus follows the
    // switch: the pane it was in is now `display:none`, so leaving it there
    // would drop the operator back on `<body>` with every step.
    ts::press_key_with_accel("body", "]");
    ts::wait_for(|| m.session.shown_items.get_untracked() == vec![b]).await;
    ts::wait_for(|| focused_matches(".workspace__pane")).await;
    ts::press_key_with_accel("body", "[");
    ts::wait_for(|| m.session.shown_items.get_untracked() == vec![a]).await;

    // Cmd/Ctrl-W closes the focused open item — the OS window is not this
    // binding's business, and on macOS the app menu has no Close Window item so
    // the accelerator reaches the webview at all.
    ts::press_key_with_accel("body", "w");
    ts::wait_for(|| ts::query_all(".open-dock__chip").len() == 1).await;
    assert!(
        m.session.is_open(OpenItemKind::AppReg, "app-1").is_none(),
        "the focused item is the one that closed"
    );
}
