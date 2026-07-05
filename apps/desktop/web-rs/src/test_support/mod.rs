//! Browser test harness for the front-end. Mounts real Leptos+Thaw views into
//! a headless-browser DOM with the Tauri IPC bridge mocked, so GUI behaviour
//! (load → render, filter, error/empty states, "did the click call the right
//! command") is exercised with **no live tenant and no backend**.
//!
//! The mock IPC bridge itself — installing `window.__TAURI_INTERNALS__`, the
//! route registry, `mock_ok`/`mock_err`/`emit_event`, and the recorded-call
//! assertions — lives in [`crate::ipc_mock`] and is shared with the GitHub Pages
//! `demo` build; it's re-exported here so existing tests keep importing it from
//! `test_support`. This module adds the test-only pieces on top: mounting a view
//! into the DOM ([`mount_view`]) and the DOM query/interaction helpers.
//!
//! Behind the `test-support` feature so none of this ships in the Trunk bundle.

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::Promise;
use leptos::prelude::*;
use thaw::{ConfigProvider, Theme};
use wasm_bindgen::JsCast;

use crate::bindings::TenantContext;
use crate::ipc_mock::{document, ensure_installed, window};
use crate::state::{Session, provide_session, use_session};

// The mock IPC bridge + fixtures, re-exported so tests import them from
// `test_support` unchanged.
pub use crate::ipc_mock::fixtures;
pub use crate::ipc_mock::{
    RecordedCall, Unmocked, call_count, emit_event, last_call, mock_err, mock_ok, set_unmocked_mode,
};

/// Reset shared test state **and** clear the document body. Every test calls this
/// first. The GUI tests all run in ONE browser page (a single `wasm-pack` binary
/// — see `tests/gui.rs`), so unlike the old file-per-binary layout there is no
/// fresh document between tests: clearing the body here gives each test a clean
/// DOM and stops a prior test's mounted host — or any portaled/teleported overlay
/// (Thaw dialogs, toasts) — leaking into the next. Delegates the
/// mock-route/recorded-call/listener reset to [`crate::ipc_mock::reset`]; the mock
/// bridge lives on `window`, not in the body, so it survives the sweep.
pub fn reset() {
    crate::ipc_mock::reset();
    if let Some(body) = document().body() {
        while let Some(child) = body.first_child() {
            let _ = body.remove_child(&child);
        }
    }
}

/// A default signed-in tenant context, so views that guard on
/// `session.active_tenant` proceed to fetch.
pub fn test_tenant() -> TenantContext {
    TenantContext {
        tenant_id: "test-tenant".to_string(),
        account_oid: "00000000-0000-0000-0000-000000000001".to_string(),
        username: Some("admin@test.onmicrosoft.com".to_string()),
        display_name: Some("Test Admin".to_string()),
    }
}

/// A mounted view: holds the unmount handle and its host element, both torn
/// down on drop. `session` lets a test drive app-wide state (e.g. switch tenant).
pub struct Mounted {
    pub session: Session,
    element: web_sys::Element,
    _handle: Box<dyn std::any::Any>,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if let Some(parent) = self.element.parent_node() {
            let _ = parent.remove_child(&self.element);
        }
    }
}

/// Mount `view_fn` into a fresh element under the document body, inside the same
/// `Session` + Thaw `ConfigProvider` context the real app provides, with a
/// signed-in [`test_tenant`] preset. Returns a [`Mounted`] handle that unmounts
/// and removes its element on drop.
pub fn mount_view<F, V>(view_fn: F) -> Mounted
where
    // `Send` because Thaw's `ConfigProvider` children closure is `Send` (Leptos's
    // `Children` is `Box<dyn FnOnce() -> AnyView + Send>`). Test view closures
    // capture nothing, so they satisfy it.
    F: FnOnce() -> V + Send + 'static,
    V: IntoView + 'static,
{
    ensure_installed();
    let element = document().create_element("div").unwrap();
    document().body().unwrap().append_child(&element).unwrap();
    let host: web_sys::HtmlElement = element.clone().unchecked_into();

    let slot: Rc<RefCell<Option<Session>>> = Rc::new(RefCell::new(None));
    let slot_inner = slot.clone();
    let handle = leptos::mount::mount_to(host, move || {
        provide_session();
        let session = use_session();
        session.active_tenant.set(Some(test_tenant()));
        *slot_inner.borrow_mut() = Some(session);
        let theme = RwSignal::new(Theme::light());
        view! { <ConfigProvider theme>{view_fn()}</ConfigProvider> }
    });

    let session = slot.borrow().expect("session captured during mount");
    Mounted {
        session,
        element,
        _handle: Box::new(handle),
    }
}

// ----------------------------- DOM helpers ------------------------------

/// First element matching the CSS selector, if present.
pub fn query(selector: &str) -> Option<web_sys::Element> {
    document().query_selector(selector).unwrap()
}

/// All elements matching the CSS selector.
pub fn query_all(selector: &str) -> Vec<web_sys::Element> {
    let list = document().query_selector_all(selector).unwrap();
    (0..list.length())
        .filter_map(|i| list.item(i))
        .map(|node| node.unchecked_into())
        .collect()
}

/// Trimmed text content of the first element matching `selector` (empty string
/// if none).
pub fn text(selector: &str) -> String {
    query(selector)
        .and_then(|el| el.text_content())
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Whole-document text. Useful for asserting a message rendered *somewhere*
/// without coupling to a specific view's error/empty container markup.
pub fn body_text() -> String {
    document()
        .body()
        .and_then(|b| b.text_content())
        .unwrap_or_default()
}

/// True if the rendered page contains `needle` anywhere — the robust way to
/// assert an error/empty message surfaced regardless of which element holds it.
pub fn body_contains(needle: &str) -> bool {
    body_text().contains(needle)
}

/// Click the first element matching `selector` (no-op if absent).
pub fn click(selector: &str) {
    if let Some(el) = query(selector) {
        let el: web_sys::HtmlElement = el.unchecked_into();
        el.click();
    }
}

/// Set the value of an `<input>` and dispatch an `input` event so the bound
/// (Thaw / Leptos) signal updates, exactly as a keystroke would.
pub fn set_input_value(selector: &str, value: &str) {
    if let Some(el) = query(selector) {
        let input: web_sys::HtmlInputElement = el.unchecked_into();
        input.set_value(value);
        let event = web_sys::Event::new("input").unwrap();
        input.dispatch_event(&event).unwrap();
    }
}

/// Set the value of a `<textarea>` and dispatch an `input` event so the bound
/// (Thaw / Leptos) signal updates, exactly as typing would — the multi-line
/// twin of [`set_input_value`] (e.g. the Exchange scope panel's group field).
pub fn set_textarea_value(selector: &str, value: &str) {
    if let Some(el) = query(selector) {
        let area: web_sys::HtmlTextAreaElement = el.unchecked_into();
        area.set_value(value);
        let event = web_sys::Event::new("input").unwrap();
        area.dispatch_event(&event).unwrap();
    }
}

/// Focus an element (fires its `focus` event), as Tab/click would — e.g. to open
/// the global-search dropdown, which only shows while the input is focused.
pub fn focus(selector: &str) {
    if let Some(el) = query(selector) {
        let el: web_sys::HtmlElement = el.unchecked_into();
        let _ = el.focus();
    }
}

/// Dispatch a bubbling `keydown` for `key` (e.g. "ArrowDown", "Enter", "Escape")
/// on the element matching `selector`, as a keyboard user would.
pub fn press_key(selector: &str, key: &str) {
    if let Some(el) = query(selector) {
        let init = web_sys::KeyboardEventInit::new();
        init.set_key(key);
        init.set_bubbles(true);
        let event =
            web_sys::KeyboardEvent::new_with_keyboard_event_init_dict("keydown", &init).unwrap();
        let _ = el.dispatch_event(&event);
    }
}

/// Resolve after a short macrotask, flushing pending microtasks (mocked
/// Promises) and Leptos effects.
pub async fn tick() {
    let promise = Promise::new(&mut |resolve, _reject| {
        window()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 10)
            .unwrap();
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Poll `predicate` every ~10ms until it holds, up to ~3s. Panics on timeout so
/// a stuck resource fails the test instead of hanging.
pub async fn wait_for<F: Fn() -> bool>(predicate: F) {
    for _ in 0..300 {
        if predicate() {
            return;
        }
        tick().await;
    }
    panic!("wait_for: condition not met within timeout");
}
