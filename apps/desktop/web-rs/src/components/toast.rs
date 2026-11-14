//! In-app toast notifications. A single `ToastHost` is mounted near the
//! shell root and renders the live stack from `Session::toasts`; toasts are
//! pushed from anywhere via the `Session` helpers (`toast_success`,
//! `toast_error`, …). Successes and info auto-dismiss after a timeout; errors
//! stay until acted on or dismissed ([`Toast::is_sticky`]). Errors announce
//! assertively (`role="alert"`), the rest politely (`role="status"`).
//!
//! The stack is a keyed `<For>`: a push or dismiss touches only that toast's
//! node. Mapping the whole list rebuilt every toast on each change, which
//! replayed the entry animation, re-announced every `role="alert"`, and took
//! focus away from a Retry button the operator had tabbed to.

use std::collections::HashMap;
use std::rc::Rc;

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::components::icon::{Icon, IconName};
use crate::state::use_session;

/// How long success / info toasts linger before auto-dismiss (ms). Errors
/// never auto-dismiss ([`Toast::is_sticky`]).
const TOAST_TIMEOUT_MS: i32 = 5000;

/// The same, for a success / info toast that carries an action (Undo, Reopen,
/// View changelog): twice as long, because the toast is the only place the
/// action exists and five seconds is less than it takes to read the message
/// and decide.
const TOAST_ACTION_TIMEOUT_MS: i32 = 10_000;

/// Optional action attached to a toast (e.g. "Retry"). CSR-only, single-
/// threaded, so `Rc<dyn Fn()>` is used rather than Leptos `Callback`: the
/// handler is a plain `'static` closure that re-runs an IPC call and never
/// needs `Send`/`Sync` or the reactive arena. Cloning a `Toast` clones the
/// `Rc`, which is cheap.
pub type ToastAction = Rc<dyn Fn()>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Identity of a recovery toast (the lever plus what it recovers, e.g.
    /// `"reauth"`, `"consent:exchange"`): a second push with the same key while
    /// one is showing is a no-op, so a burst of failures raises one lever, not
    /// a stack of copies. `None` (every other toast) never merges — two Retry
    /// toasts with the same text re-run different operations.
    pub dedupe_key: Option<String>,
}

impl Toast {
    /// The one definition of "sticky": an error stays until acted on or
    /// dismissed — with an action (Retry, Re-authenticate, Grant consent, …) or
    /// without. `ToastHost` never auto-dismisses one, and the stack cap evicts
    /// one only once no transient toast is left to drop.
    ///
    /// A plain error used to expire after ten seconds, so a failure that landed
    /// while the operator was reading another window was simply gone, with no
    /// history to find it in.
    pub fn is_sticky(&self) -> bool {
        matches!(self.kind, ToastKind::Error)
    }
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
        // Snapshot the (id, sticky, has-action) of the currently-present toasts.
        let present: Vec<(u64, bool, bool)> = toasts.with(|list| {
            list.iter()
                .map(|t| (t.id, t.is_sticky(), t.action.is_some()))
                .collect()
        });

        handles.update_value(|map| {
            // Cancel + drop timers for toasts that are gone.
            let present_ids: Vec<u64> = present.iter().map(|(id, ..)| *id).collect();
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
            for (id, sticky, has_action) in present {
                // Sticky toasts (`Toast::is_sticky`) stay; everything else expires.
                if sticky || map.contains_key(&id) {
                    continue;
                }
                // Capture `session` (it is `Copy`) — never call `use_session()`
                // inside a JS callback, which runs outside any reactive owner.
                let cb = Closure::once_into_js(move || session.dismiss_toast(id));
                let cb_fn = cb.unchecked_ref::<js_sys::Function>();
                let timeout = if has_action {
                    TOAST_ACTION_TIMEOUT_MS
                } else {
                    TOAST_TIMEOUT_MS
                };
                if let Ok(h) =
                    win.set_timeout_with_callback_and_timeout_and_arguments_0(cb_fn, timeout)
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

    // Keyed by id, and the row looks its toast up: `Toast` holds an
    // `Rc<dyn Fn()>` action and so is not `Send`, which `<For>`'s item type
    // must be. A toast is immutable once pushed, so the untracked read is exact.
    let render = move |id: u64| {
        toasts
            .with_untracked(|list| list.iter().find(|t| t.id == id).cloned())
            .map(|t| {
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
    };

    // No `aria-live` on the host: each toast carries its own `role`
    // (alert ⇒ assertive, status ⇒ polite), so a wrapping live region would
    // just nest redundantly.
    view! {
        <div class="toast-host">
            <For
                each=move || toasts.with(|list| list.iter().map(|t| t.id).collect::<Vec<_>>())
                key=|id| *id
                children=render
            />
        </div>
    }
}

#[cfg(test)]
mod tests {
    /// The stylesheet, as shipped. The browser GUI tests mount views without
    /// it, so they cannot see a `white-space` rule; this reads the CSS itself.
    const STYLES: &str = include_str!("../../styles.css");

    /// The declarations of the top-level rule `selector { … }`, or `None` when
    /// the stylesheet has no such rule.
    fn rule_body(selector: &str) -> Option<&'static str> {
        let open = STYLES.find(&format!("\n{selector} {{"))?;
        let body = &STYLES[open..];
        let close = body.find('}')?;
        Some(&body[..close])
    }

    /// Backend `UiError`s put their actionable guidance after a blank line
    /// (`{err}\n\n{hint}`); HTML collapses that to a single space unless the
    /// sink preserves whitespace. The admin-consent 403 toasts its remediation
    /// steps, and they ran together into one paragraph because
    /// `.toast__message` — unlike `.form-error` — had no `pre-wrap`. Every
    /// class that renders a backend error message keeps the breaks.
    #[test]
    fn every_error_sink_keeps_the_guidance_on_its_own_lines() {
        for selector in [
            ".form-error",
            ".alert",
            ".signin-error",
            ".toast__message",
            ".app-detail__error",
        ] {
            let body = rule_body(selector)
                .unwrap_or_else(|| panic!("styles.css has no top-level `{selector} {{` rule"));
            assert!(
                body.contains("white-space: pre-wrap"),
                "`{selector}` renders backend error text but collapses its \\n\\n guidance: {body}"
            );
        }
    }
}
