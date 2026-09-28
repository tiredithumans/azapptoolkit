//! GUI tests for the global keyboard layer (`hooks::use_shortcuts`) and the
//! dialog/menu contracts it must respect.
//!
//! The property that matters most here is the *negative* one: a global
//! bare-key binding must never eat a keystroke while the operator is typing.
//! A regression there is invisible in a unit test and maddening in the app —
//! every `/` or `?` typed into a filter would vanish.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::components::export_menu::ExportMenu;
use azapptoolkit_web_rs::components::modal_shell::ModalShell;
use azapptoolkit_web_rs::components::shortcuts_help::ShortcutsHelp;
use azapptoolkit_web_rs::hooks::use_shortcuts::use_shortcuts;
use azapptoolkit_web_rs::state::{ActiveView, provide_session, use_session};
use azapptoolkit_web_rs::test_support as ts;

/// Mounts just the shortcut layer plus a text input, so the bindings can be
/// exercised without standing up the whole shell.
fn mount_shortcut_harness() -> ts::Mounted {
    ts::mount_view(|| {
        provide_session();
        let session = use_session();
        let open = RwSignal::new(false);
        use_shortcuts(session, open);
        view! {
            <div>
                <input class="probe-input" type="text" />
                <ShortcutsHelp open=open />
            </div>
        }
    })
}

#[wasm_bindgen_test]
async fn question_mark_toggles_the_shortcut_sheet() {
    ts::reset();
    let _m = mount_shortcut_harness();

    assert!(ts::query(".modal").is_none(), "the sheet starts closed");

    ts::press_key("body", "?");
    ts::wait_for(|| ts::query(".shortcuts").is_some()).await;

    // And it lists the bindings rather than being an empty shell.
    assert!(
        !ts::query_all(".shortcuts__row").is_empty(),
        "the sheet documents at least one binding"
    );
    // Each key renders as the shared `.ui-kbd` chip, not a bare `<kbd>` with
    // an ad-hoc rule (which once pointed at an undefined colour token).
    assert_eq!(
        ts::query_all(".shortcuts__keys kbd.ui-kbd").len(),
        ts::query_all(".shortcuts__row").len(),
        "every binding's key renders as a .ui-kbd chip"
    );
}

#[wasm_bindgen_test]
async fn bare_key_bindings_do_not_fire_while_typing() {
    ts::reset();
    let _m = mount_shortcut_harness();

    // Focus a text field, then "type" the bare-key bindings. Neither may act:
    // `?` must not open the sheet and `/` must not steal focus, or every filter
    // box in the app would silently swallow those characters.
    ts::focus(".probe-input");
    ts::press_key(".probe-input", "?");
    ts::press_key(".probe-input", "/");
    ts::tick().await;

    assert!(
        ts::query(".shortcuts").is_none(),
        "a bare-key binding must not fire while the operator is typing"
    );
}

#[wasm_bindgen_test]
async fn quick_nav_switches_the_active_view() {
    ts::reset();
    let view_seen = RwSignal::new(None::<ActiveView>);
    let _m = ts::mount_view(move || {
        provide_session();
        let session = use_session();
        let open = RwSignal::new(false);
        use_shortcuts(session, open);
        // Mirror the session's view into a probe we can assert on.
        Effect::new(move |_| view_seen.set(Some(session.view.get())));
        view! { <div class="probe" /> }
    });

    ts::tick().await;
    // Cmd/Ctrl-2 is App Registrations. Modified bindings fire even from a text
    // field, so they carry no typing guard to work around.
    ts::press_key_with_accel("body", "2");
    ts::wait_for(|| view_seen.get_untracked() == Some(ActiveView::Apps)).await;
}

/// The focused element, for asserting where a key sent focus.
fn active() -> Option<web_sys::Element> {
    web_sys::window()?.document()?.active_element()
}

/// Class list of the focused element (empty when nothing is focused).
fn active_class() -> String {
    active().map(|e| e.class_name()).unwrap_or_default()
}

/// Trimmed text of the focused element.
fn active_text() -> String {
    active()
        .and_then(|e| e.text_content())
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Polls until `pred` holds for the focused element, like [`ts::wait_for`], but
/// a timeout names what actually has focus — a focus regression is otherwise an
/// opaque "condition not met".
async fn wait_for_focus(what: &str, pred: impl Fn() -> bool) {
    for _ in 0..300 {
        if pred() {
            return;
        }
        ts::tick().await;
    }
    panic!(
        "focus never reached {what}; focused: <{}> class={:?} text={:?}",
        active().map(|e| e.tag_name()).unwrap_or_default(),
        active().map(|e| e.class_name()).unwrap_or_default(),
        active_text()
    );
}

/// Mounts the shortcut layer plus `extra`, so a test can add the probes it needs.
fn mount_with<V: IntoView + 'static>(extra: impl FnOnce() -> V + Send + 'static) -> ts::Mounted {
    ts::mount_view(move || {
        provide_session();
        let session = use_session();
        let open = RwSignal::new(false);
        use_shortcuts(session, open);
        let extra = extra();
        view! {
            <div>
                {extra}
                <ShortcutsHelp open=open />
            </div>
        }
    })
}

/// A focused bulk-select checkbox is not typing: after Space-toggling a row,
/// `?` and `/` must still work (the grid hook already agreed; the window layer
/// used to treat every `<input>` as a text field).
#[wasm_bindgen_test]
async fn question_mark_opens_the_sheet_from_a_focused_checkbox() {
    ts::reset();
    let _m = mount_with(|| view! { <input class="probe-check" type="checkbox" /> });

    ts::focus(".probe-check");
    ts::press_key(".probe-check", "?");
    ts::wait_for(|| ts::query(".shortcuts").is_some()).await;
}

/// Keep-alive panes stay in the DOM in declaration order, so the first
/// "Filter…" input is often a hidden pane's; `/` must skip it (and one under an
/// `inert` subtree, which can't take focus) for the one the operator can see.
#[wasm_bindgen_test]
async fn slash_focuses_the_visible_filter_not_the_first_in_the_dom() {
    ts::reset();
    let _m = mount_with(|| {
        view! {
            <div style="display:none">
                <input class="probe-hidden" placeholder="Filter hidden" />
            </div>
            <div inert="">
                <input class="probe-inert" placeholder="Filter inert" />
            </div>
            <input class="probe-visible" placeholder="Filter visible" />
        }
    });
    ts::tick().await;

    ts::press_key("body", "/");
    wait_for_focus("the visible filter", || {
        active_class().contains("probe-visible")
    })
    .await;
}

/// `?` from inside an open dialog must not stack the sheet on top (two modals,
/// two traps, one Escape closing both), and `/` must not pull focus out of the
/// dialog to a list filter behind the backdrop.
#[wasm_bindgen_test]
async fn question_mark_does_not_stack_the_sheet_over_an_open_dialog() {
    ts::reset();
    let _m = mount_with(|| {
        view! {
            <input class="probe-filter" placeholder="Filter probe" />
            <ModalShell
                open=Signal::derive(|| true)
                title="Probe".to_string()
                on_close=Callback::new(|_| ())
            >
                <button class="probe-modal-btn" type="button">"ok"</button>
            </ModalShell>
        }
    });
    ts::wait_for(|| ts::query(".probe-modal-btn").is_some()).await;

    ts::focus(".probe-modal-btn");
    ts::press_key(".probe-modal-btn", "?");
    ts::press_key(".probe-modal-btn", "/");
    ts::tick().await;

    assert!(
        ts::query(".shortcuts").is_none(),
        "`?` must not open the sheet over another dialog"
    );
    assert_eq!(
        ts::query_all(".modal-backdrop").len(),
        1,
        "exactly one dialog is shown"
    );
    assert!(
        active_class().contains("probe-modal-btn"),
        "`/` must not move focus out of the open dialog"
    );
}

/// The dialog gate must not break the toggle: the open sheet is itself a
/// modal, and `?` still closes it.
#[wasm_bindgen_test]
async fn question_mark_closes_the_sheet_it_opened() {
    ts::reset();
    let _m = mount_shortcut_harness();

    ts::press_key("body", "?");
    ts::wait_for(|| ts::query(".shortcuts").is_some()).await;
    ts::press_key("body", "?");
    ts::wait_for(|| ts::query(".shortcuts").is_none()).await;
}

/// Several `ModalShell`s can be mounted at once; each must label itself, not
/// whichever came first in the document.
#[wasm_bindgen_test]
async fn stacked_modal_shells_have_distinct_title_ids() {
    ts::reset();
    let _m = ts::mount_view(|| {
        view! {
            <div>
                <ModalShell
                    open=Signal::derive(|| true)
                    title="First".to_string()
                    on_close=Callback::new(|_| ())
                >
                    <button type="button">"a"</button>
                </ModalShell>
                <ModalShell
                    open=Signal::derive(|| true)
                    title="Second".to_string()
                    on_close=Callback::new(|_| ())
                >
                    <button type="button">"b"</button>
                </ModalShell>
            </div>
        }
    });
    ts::wait_for(|| ts::query_all(".modal-backdrop").len() == 2).await;

    let ids: Vec<String> = ts::query_all(".modal-backdrop")
        .iter()
        .map(|b| b.get_attribute("aria-labelledby").unwrap_or_default())
        .collect();
    assert_ne!(ids[0], ids[1], "each dialog needs its own title id");
    assert_eq!(ts::text(&format!("#{}", ids[0])), "First");
    assert_eq!(ts::text(&format!("#{}", ids[1])), "Second");
}

/// `ExportMenu` announces `role="menu"`, so it must behave like one: focus the
/// first item on open, Arrow/Home/End between items, Escape back to the button
/// — and the trigger says it opens a menu and whether it is open.
#[wasm_bindgen_test]
async fn export_menu_follows_the_menu_keyboard_contract() {
    ts::reset();
    let picked = RwSignal::new(None::<&'static str>);
    let _m = ts::mount_view(move || {
        view! {
            <ExportMenu
                disabled=false
                on_select=Callback::new(move |f| picked.set(Some(f)))
                options=vec![("csv", "Export as CSV…"), ("json", "Export as JSON…")]
            />
        }
    });
    let trigger = ".export-menu > button";
    ts::wait_for(|| ts::query(trigger).is_some()).await;
    let attr = |name: &str| ts::query(trigger).and_then(|b| b.get_attribute(name));
    assert_eq!(attr("aria-haspopup").as_deref(), Some("menu"));
    assert_eq!(attr("aria-expanded").as_deref(), Some("false"));

    // The keyboard route: Enter/Space on the focused button fires its click.
    // (A synthetic `click()` alone doesn't focus it, so there'd be no trigger
    // for the menu to hand focus back to.)
    ts::focus(trigger);
    ts::click(trigger);
    ts::wait_for(|| ts::query(".export-menu__panel").is_some()).await;
    assert_eq!(attr("aria-expanded").as_deref(), Some("true"));
    wait_for_focus("Export as CSV…", || active_text() == "Export as CSV…").await;

    let item = ".export-menu__panel [role=menuitem]";
    ts::press_key(item, "ArrowDown");
    wait_for_focus("Export as JSON…", || active_text() == "Export as JSON…").await;
    ts::press_key(item, "ArrowDown");
    wait_for_focus("Export as CSV…", || active_text() == "Export as CSV…").await;
    ts::press_key(item, "End");
    wait_for_focus("Export as JSON…", || active_text() == "Export as JSON…").await;

    ts::press_key("body", "Escape");
    ts::wait_for(|| ts::query(".export-menu__panel").is_none()).await;
    wait_for_focus("the Export button", || {
        active().is_some_and(|a| ts::query(trigger).is_some_and(|t| t == a))
    })
    .await;
    assert_eq!(picked.get_untracked(), None, "Escape selects nothing");
}
