//! Browser test harness for the front-end. Mounts real Leptos+Thaw views into
//! a headless-browser DOM with the Tauri IPC bridge mocked, so GUI behaviour
//! (load → render, filter, error/empty states, "did the click call the right
//! command") is exercised with **no live tenant and no backend**.
//!
//! How the mock works: every front-end → backend call, and every event stream,
//! bottoms out at `tauri-sys`'s bundled `core.js`, which calls three methods on
//! `window.__TAURI_INTERNALS__` — `invoke(cmd, args)`, `transformCallback`, and
//! `convertFileSrc`. We install our own `__TAURI_INTERNALS__` before mounting,
//! so the real bindings and the real serde wire format run unchanged; we just
//! answer `invoke()` from canned fixtures instead of Graph. Fixtures are built
//! from the shared DTO types and serialized with the *same* `serde-wasm-bindgen`
//! the bindings deserialize with, so a fixture that drifts from the wire format
//! fails the test.
//!
//! Behind the `test-support` feature so none of this ships in the Trunk bundle.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use js_sys::{Function, Object, Promise, Reflect};
use leptos::prelude::*;
use serde::Serialize;
use serde_wasm_bindgen as swb;
use thaw::{ConfigProvider, Theme};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};

use crate::bindings::TenantContext;
use crate::state::{provide_session, use_session, Session};

pub mod fixtures;

/// A single mocked command response: resolve (`Ok`) or reject (`Err`) the
/// Promise `__TAURI_INTERNALS__.invoke` returns. `tauri-sys`'s `invoke_result`
/// maps resolve → `Ok(T)` and reject → `Err(E)`, so `Err` drives the error-path
/// rendering tests.
enum RouteResult {
    Ok(JsValue),
    Err(JsValue),
}

/// One recorded `invoke` call, for asserting that a click fired the right
/// command with the right arguments.
pub struct RecordedCall {
    pub cmd: String,
    pub args: serde_json::Value,
}

impl RecordedCall {
    /// String value of a top-level (camelCase) argument key, e.g.
    /// `call.arg_str("tenantId")`.
    pub fn arg_str(&self, key: &str) -> Option<String> {
        self.args
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from)
    }
}

type IpcClosure = Closure<dyn Fn(JsValue, JsValue) -> JsValue>;

thread_local! {
    static ROUTES: RefCell<HashMap<String, RouteResult>> = RefCell::new(HashMap::new());
    static CALLS: RefCell<Vec<RecordedCall>> = const { RefCell::new(Vec::new()) };
    /// `transformCallback`-registered JS callbacks, keyed by the id we hand back.
    static CALLBACKS: RefCell<HashMap<u64, Function>> = RefCell::new(HashMap::new());
    /// Event name → the listener registered for it (via `plugin:event|listen`).
    static LISTENERS: RefCell<HashMap<String, Function>> = RefCell::new(HashMap::new());
    static CB_SEQ: RefCell<u64> = const { RefCell::new(1) };
    static EVENT_SEQ: RefCell<u64> = const { RefCell::new(1) };
    /// Keeps the installed closures alive for the lifetime of the test process.
    static KEEPALIVE: RefCell<Vec<IpcClosure>> = const { RefCell::new(Vec::new()) };
    static INSTALLED: RefCell<bool> = const { RefCell::new(false) };
}

fn window() -> web_sys::Window {
    web_sys::window().expect("no window")
}

fn document() -> web_sys::Document {
    window().document().expect("no document")
}

/// Install `window.__TAURI_INTERNALS__` once. Idempotent — the registry it reads
/// is cleared by [`reset`], so the closures stay valid across tests.
fn ensure_installed() {
    if INSTALLED.with(|f| *f.borrow()) {
        return;
    }

    let invoke = Closure::wrap(Box::new(move |cmd: JsValue, args: JsValue| -> JsValue {
        let cmd = cmd.as_string().unwrap_or_default();

        // Record every call (args as plain JSON) for later assertions.
        let json =
            swb::from_value::<serde_json::Value>(args.clone()).unwrap_or(serde_json::Value::Null);
        CALLS.with(|c| {
            c.borrow_mut().push(RecordedCall {
                cmd: cmd.clone(),
                args: json,
            })
        });

        // Event plumbing: `listen` registers a callback under an event name so
        // `emit_event` can drive it; emit/unlisten are inert.
        match cmd.as_str() {
            "plugin:event|listen" => {
                let event = Reflect::get(&args, &JsValue::from_str("event"))
                    .ok()
                    .and_then(|v| v.as_string());
                let handler = Reflect::get(&args, &JsValue::from_str("handler"))
                    .ok()
                    .and_then(|v| v.as_f64());
                if let (Some(event), Some(id)) = (event, handler) {
                    let func = CALLBACKS.with(|m| m.borrow().get(&(id as u64)).cloned());
                    if let Some(func) = func {
                        LISTENERS.with(|m| m.borrow_mut().insert(event, func));
                    }
                }
                let eid = EVENT_SEQ.with(|s| {
                    let mut s = s.borrow_mut();
                    let v = *s;
                    *s += 1;
                    v
                });
                return Promise::resolve(&JsValue::from_f64(eid as f64)).into();
            }
            "plugin:event|unlisten" | "plugin:event|emit" | "plugin:event|emit_to" => {
                return Promise::resolve(&JsValue::UNDEFINED).into();
            }
            _ => {}
        }

        match ROUTES.with(|r| {
            r.borrow().get(&cmd).map(|res| match res {
                RouteResult::Ok(v) => RouteResult::Ok(v.clone()),
                RouteResult::Err(e) => RouteResult::Err(e.clone()),
            })
        }) {
            Some(RouteResult::Ok(v)) => Promise::resolve(&v).into(),
            Some(RouteResult::Err(e)) => Promise::reject(&e).into(),
            None => {
                // Unmocked command — reject loudly so the test surfaces it
                // instead of hanging on a never-resolving resource.
                let err = swb::to_value(&fixtures::ui_error(
                    "unmocked",
                    &format!("test_support: no mock for command `{cmd}`"),
                ))
                .unwrap();
                Promise::reject(&err).into()
            }
        }
    }) as Box<dyn Fn(JsValue, JsValue) -> JsValue>);

    let transform = Closure::wrap(Box::new(move |cb: JsValue, _once: JsValue| -> JsValue {
        let func: Function = cb.unchecked_into();
        let id = CB_SEQ.with(|s| {
            let mut s = s.borrow_mut();
            let v = *s;
            *s += 1;
            v
        });
        CALLBACKS.with(|m| m.borrow_mut().insert(id, func));
        JsValue::from_f64(id as f64)
    }) as Box<dyn Fn(JsValue, JsValue) -> JsValue>);

    let convert = Closure::wrap(
        Box::new(move |path: JsValue, _proto: JsValue| -> JsValue { path })
            as Box<dyn Fn(JsValue, JsValue) -> JsValue>,
    );

    let internals = Object::new();
    Reflect::set(
        &internals,
        &JsValue::from_str("invoke"),
        invoke.as_ref().unchecked_ref(),
    )
    .unwrap();
    Reflect::set(
        &internals,
        &JsValue::from_str("transformCallback"),
        transform.as_ref().unchecked_ref(),
    )
    .unwrap();
    Reflect::set(
        &internals,
        &JsValue::from_str("convertFileSrc"),
        convert.as_ref().unchecked_ref(),
    )
    .unwrap();
    Reflect::set(
        &window(),
        &JsValue::from_str("__TAURI_INTERNALS__"),
        &internals,
    )
    .unwrap();

    KEEPALIVE.with(|k| k.borrow_mut().extend([invoke, transform, convert]));
    INSTALLED.with(|f| *f.borrow_mut() = true);
}

/// Clear all mocked routes, recorded calls, and event listeners. Call at the
/// top of every test so state never leaks between them.
pub fn reset() {
    ensure_installed();
    ROUTES.with(|r| r.borrow_mut().clear());
    CALLS.with(|c| c.borrow_mut().clear());
    LISTENERS.with(|l| l.borrow_mut().clear());
}

/// Mock `cmd` to resolve with `value` (serialized via the same serde path the
/// bindings deserialize with). Use `&()` for commands that return `()`.
pub fn mock_ok<T: Serialize>(cmd: &str, value: &T) {
    ensure_installed();
    let v = swb::to_value(value).expect("serialize mock value");
    ROUTES.with(|r| r.borrow_mut().insert(cmd.to_string(), RouteResult::Ok(v)));
}

/// Mock `cmd` to reject with `err` — drives the front-end's error-path
/// rendering (`invoke_result` maps a rejected Promise to `Err(UiError)`).
pub fn mock_err(cmd: &str, err: &azapptoolkit_dto::UiError) {
    ensure_installed();
    let e = swb::to_value(err).expect("serialize UiError");
    ROUTES.with(|r| r.borrow_mut().insert(cmd.to_string(), RouteResult::Err(e)));
}

/// How many times `cmd` has been invoked since the last [`reset`].
pub fn call_count(cmd: &str) -> usize {
    CALLS.with(|c| c.borrow().iter().filter(|call| call.cmd == cmd).count())
}

/// The most recent recorded invocation of `cmd`, if any.
pub fn last_call(cmd: &str) -> Option<RecordedCall> {
    CALLS.with(|c| {
        c.borrow()
            .iter()
            .rev()
            .find(|call| call.cmd == cmd)
            .map(|call| RecordedCall {
                cmd: call.cmd.clone(),
                args: call.args.clone(),
            })
    })
}

/// Deliver an event to a listener registered by the front-end (the 4
/// progress-stream panels listen via `events::*_progress`). The envelope shape
/// matches `tauri-sys`'s `Event<T>` (`event` / `id` / `payload`).
pub fn emit_event<T: Serialize>(name: &str, payload: &T) {
    if let Some(func) = LISTENERS.with(|m| m.borrow().get(name).cloned()) {
        let envelope = Object::new();
        Reflect::set(
            &envelope,
            &JsValue::from_str("event"),
            &JsValue::from_str(name),
        )
        .unwrap();
        Reflect::set(&envelope, &JsValue::from_str("id"), &JsValue::from_f64(1.0)).unwrap();
        Reflect::set(
            &envelope,
            &JsValue::from_str("payload"),
            &swb::to_value(payload).unwrap(),
        )
        .unwrap();
        let _ = func.call1(&JsValue::NULL, &envelope);
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
