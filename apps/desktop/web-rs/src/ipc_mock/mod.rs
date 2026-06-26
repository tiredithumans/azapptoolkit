//! Shared mock Tauri IPC bridge. Installs a fake `window.__TAURI_INTERNALS__`
//! and answers `invoke()` from canned fixtures, so the real bindings and the
//! real `serde-wasm-bindgen` wire format run unchanged with **no backend**.
//!
//! Two consumers, behind the `mock-ipc` feature:
//! - `test_support` (the headless-browser GUI tests) — registers per-test routes
//!   and asserts on recorded calls; an unmocked command rejects *loudly* so a
//!   missing fixture fails the test.
//! - `demo` (the GitHub Pages build) — registers curated sample data once at
//!   startup; an unmocked command degrades to a *friendly* "not in the demo"
//!   error (see [`Unmocked`]).
//!
//! How the mock works: every front-end → backend call, and every event stream,
//! bottoms out at `tauri-sys`'s bundled `core.js`, which calls three methods on
//! `window.__TAURI_INTERNALS__` — `invoke(cmd, args)`, `transformCallback`, and
//! `convertFileSrc`. We install our own before mounting; fixtures are built from
//! the shared DTO types and serialized with the *same* `serde-wasm-bindgen` the
//! bindings deserialize with, so a fixture that drifts from the wire format is
//! caught immediately.

use std::cell::RefCell;
use std::collections::HashMap;

use js_sys::{Function, Object, Promise, Reflect};
use serde::Serialize;
use serde_wasm_bindgen as swb;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};

pub mod fixtures;

/// What an unmocked command does. Tests want a loud reject (a missing fixture is
/// a test bug); the demo wants a friendly typed error so an unregistered read
/// degrades to a clean toast/empty state instead of hanging on a never-resolving
/// resource. [`reset`] restores the default (`LoudReject`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Unmocked {
    LoudReject,
    DemoFriendly,
}

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
    /// Keeps the installed closures alive for the lifetime of the process.
    static KEEPALIVE: RefCell<Vec<IpcClosure>> = const { RefCell::new(Vec::new()) };
    static INSTALLED: RefCell<bool> = const { RefCell::new(false) };
    /// How to answer a command with no registered route.
    static UNMOCKED: RefCell<Unmocked> = const { RefCell::new(Unmocked::LoudReject) };
}

pub fn window() -> web_sys::Window {
    web_sys::window().expect("no window")
}

pub fn document() -> web_sys::Document {
    window().document().expect("no document")
}

/// Install `window.__TAURI_INTERNALS__` once. Idempotent — the registry it reads
/// is cleared by [`reset`], so the closures stay valid across tests.
pub fn ensure_installed() {
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
            None => match UNMOCKED.with(|u| *u.borrow()) {
                // Test harness: surface the gap instead of hanging on a
                // never-resolving resource.
                Unmocked::LoudReject => {
                    let err = swb::to_value(&fixtures::ui_error(
                        "unmocked",
                        &format!("test_support: no mock for command `{cmd}`"),
                    ))
                    .unwrap();
                    Promise::reject(&err).into()
                }
                // Demo: every unregistered read (and every mutation) degrades to
                // a friendly error toast / empty state rather than a hang.
                Unmocked::DemoFriendly => {
                    let err = swb::to_value(&fixtures::ui_error(
                        "demo_unsupported",
                        "This action isn't available in the live demo — \
                         download the app to use it for real.",
                    ))
                    .unwrap();
                    Promise::reject(&err).into()
                }
            },
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

/// Clear all mocked routes, recorded calls, and event listeners, and restore the
/// `LoudReject` unmocked policy. Call at the top of every test so state never
/// leaks between them.
pub fn reset() {
    ensure_installed();
    ROUTES.with(|r| r.borrow_mut().clear());
    CALLS.with(|c| c.borrow_mut().clear());
    LISTENERS.with(|l| l.borrow_mut().clear());
    UNMOCKED.with(|u| *u.borrow_mut() = Unmocked::LoudReject);
}

/// Choose how an unmocked command is answered (see [`Unmocked`]). The demo build
/// sets `DemoFriendly`; tests stay on the `LoudReject` default.
pub fn set_unmocked_mode(mode: Unmocked) {
    ensure_installed();
    UNMOCKED.with(|u| *u.borrow_mut() = mode);
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
