//! GUI tests for the global keyboard layer (`hooks::use_shortcuts`).
//!
//! The property that matters most here is the *negative* one: a global
//! bare-key binding must never eat a keystroke while the operator is typing.
//! A regression there is invisible in a unit test and maddening in the app —
//! every `/` or `?` typed into a filter would vanish.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

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
