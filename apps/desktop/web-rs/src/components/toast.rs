// The toast push API is intentionally complete (success/info/error); not every
// kind/helper has a call site yet, mirroring the icon catalog in `icon.rs`.
#![allow(dead_code)]

//! In-app toast notifications. A single `ToastHost` is mounted near the
//! shell root and renders the live stack from `Session::toasts`; toasts are
//! pushed from anywhere via the `Session` helpers (`toast_success`,
//! `toast_error`, …) and auto-dismiss after a timeout — errors linger longer
//! than successes/info so they aren't missed; error toasts that carry a retry
//! action stay until acted on or dismissed. Errors announce assertively
//! (`role="alert"`), the rest politely (`role="status"`).

use std::collections::HashMap;
use std::rc::Rc;

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::components::icon::{Icon, IconName};
use crate::state::use_session;

/// How long success / info toasts linger before auto-dismiss (ms).
const TOAST_TIMEOUT_MS: i32 = 5000;
/// Errors linger longer — a failure the user must read shouldn't vanish as
/// fast as a routine success confirmation.
const ERROR_TIMEOUT_MS: i32 = 10000;

/// Optional action attached to a toast (e.g. "Retry"). CSR-only, single-
/// threaded, so `Rc<dyn Fn()>` is used rather than Leptos `Callback`: the
/// handler is a plain `'static` closure that re-runs an IPC call and never
/// needs `Send`/`Sync` or the reactive arena. Cloning a `Toast` clones the
/// `Rc`, which is cheap.
pub type ToastAction = Rc<dyn Fn()>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Error,
    Info,
}

#[derive(Clone)]
pub struct Toast {
    pub id: u64,
    pub kind: ToastKind,
    pub message: String,
    /// Label + handler for an action button (only rendered when present).
    pub action_label: Option<String>,
    pub action: Option<ToastAction>,
}

impl ToastKind {
    fn class(self) -> &'static str {
        match self {
            ToastKind::Success => "toast toast--ok",
            ToastKind::Error => "toast toast--error",
            ToastKind::Info => "toast toast--info",
        }
    }

    fn icon(self) -> IconName {
        match self {
            ToastKind::Success => IconName::CheckCircle,
            ToastKind::Error => IconName::AlertTriangle,
            ToastKind::Info => IconName::Info,
        }
    }

    /// ARIA live role: errors interrupt (`alert` ⇒ assertive); successes/info
    /// wait their turn (`status` ⇒ polite).
    fn role(self) -> &'static str {
        match self {
            ToastKind::Error => "alert",
            _ => "status",
        }
    }

    /// Auto-dismiss delay (ms). Errors linger longer so they aren't missed.
    fn timeout_ms(self) -> i32 {
        match self {
            ToastKind::Error => ERROR_TIMEOUT_MS,
            _ => TOAST_TIMEOUT_MS,
        }
    }
}

/// Renders the toast stack and owns auto-dismiss timers. Mount once.
#[component]
pub fn ToastHost() -> impl IntoView {
    let session = use_session();
    let toasts = session.toasts;

    // id -> pending timeout handle, so a manual dismiss can cancel its timer
    // and `on_cleanup` can clear everything. A `StoredValue` (Copy, and
    // `Send + Sync` because it only holds `i32`s) reaches both the `Effect` and
    // the `on_cleanup` closure — an `Rc<RefCell<..>>` would satisfy neither.
    let handles: StoredValue<HashMap<u64, i32>> = StoredValue::new(HashMap::new());

    // Schedule auto-dismiss for any newly-seen toast that should expire.
    Effect::new(move |_| {
        let win = match web_sys::window() {
            Some(w) => w,
            None => return,
        };
        // Snapshot the (id, kind, has-action) of the currently-present toasts.
        let present: Vec<(u64, ToastKind, bool)> = toasts.with(|list| {
            list.iter()
                .map(|t| (t.id, t.kind, t.action.is_some()))
                .collect()
        });

        handles.update_value(|map| {
            // Cancel + drop timers for toasts that are gone.
            let present_ids: Vec<u64> = present.iter().map(|(id, _, _)| *id).collect();
            let stale: Vec<u64> = map
                .keys()
                .copied()
                .filter(|id| !present_ids.contains(id))
                .collect();
            for id in stale {
                if let Some(h) = map.remove(&id) {
                    win.clear_timeout_with_handle(h);
                }
            }
            // Schedule timers for new auto-dismissable toasts.
            for (id, kind, has_action) in present {
                // Errors with a retry action are sticky; everything else expires.
                let sticky = matches!(kind, ToastKind::Error) && has_action;
                if sticky || map.contains_key(&id) {
                    continue;
                }
                // Capture `session` (it is `Copy`) — never call `use_session()`
                // inside a JS callback, which runs outside any reactive owner.
                let cb = Closure::once_into_js(move || session.dismiss_toast(id));
                let cb_fn = cb.unchecked_ref::<js_sys::Function>();
                if let Ok(h) = win
                    .set_timeout_with_callback_and_timeout_and_arguments_0(cb_fn, kind.timeout_ms())
                {
                    map.insert(id, h);
                }
            }
        });
    });

    on_cleanup(move || {
        if let Some(win) = web_sys::window() {
            handles.update_value(|map| {
                for (_, h) in map.drain() {
                    win.clear_timeout_with_handle(h);
                }
            });
        }
    });

    let stack = move || {
        toasts
            .get()
            .into_iter()
            .map(|t| {
                let id = t.id;
                let action = t.action.clone();
                let action_label = t.action_label.clone();
                let dismiss = move |_| session.dismiss_toast(id);
                let retry = {
                    let action = action.clone();
                    move |_| {
                        if let Some(a) = action.clone() {
                            a();
                        }
                        session.dismiss_toast(id);
                    }
                };
                view! {
                    <div class=t.kind.class() role=t.kind.role()>
                        <span class="toast__icon">
                            <Icon name=t.kind.icon() size=16 />
                        </span>
                        <span class="toast__message">{t.message.clone()}</span>
                        {action
                            .is_some()
                            .then(|| {
                                let label = action_label
                                    .clone()
                                    .unwrap_or_else(|| "Retry".to_string());
                                view! {
                                    <button class="toast__action" type="button" on:click=retry>
                                        {label}
                                    </button>
                                }
                            })}
                        <button
                            class="toast__close"
                            type="button"
                            aria-label="Dismiss"
                            on:click=dismiss
                        >
                            "\u{00d7}"
                        </button>
                    </div>
                }
            })
            .collect_view()
    };

    // No `aria-live` on the host: each toast carries its own `role`
    // (alert ⇒ assertive, status ⇒ polite), so a wrapping live region would
    // just nest redundantly.
    view! { <div class="toast-host">{stack}</div> }
}
