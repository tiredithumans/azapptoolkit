//! The app's global keyboard layer.
//!
//! Everything here is *window*-level and view-independent. Anything scoped to a
//! surface (Escape closing a dialog, arrow keys inside a grid) belongs to that
//! surface's own hook — [`crate::hooks::use_escape`],
//! [`crate::hooks::use_grid_keynav`] — not here.
//!
//! **Typing must never be hijacked.** Every binding is skipped while focus is in
//! a text field or a `contenteditable` region, except the modified ones
//! (Cmd/Ctrl-…) that can't collide with typing. This is why `/` is safe as a
//! bare key: it reaches the handler only when the operator is not in an input.

use leptos::ev;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::HtmlElement;

use crate::state::{ActiveView, Session};

/// Nav destinations reachable by `Cmd/Ctrl-<n>`, in rail order. Deliberately the
/// *inventory and security* surfaces an operator moves between constantly —
/// not every view. Operations pages (Bulk Actions, DR, Key Vault) are
/// deliberate, low-frequency destinations and stay pointer/rail-only.
const QUICK_NAV: &[(char, ActiveView)] = &[
    ('1', ActiveView::Home),
    ('2', ActiveView::Apps),
    ('3', ActiveView::EnterpriseApps),
    ('4', ActiveView::ManagedIdentities),
    ('5', ActiveView::Security),
];

/// True when the event target is a text-entry context, where a bare-key binding
/// would eat the keystroke.
fn is_typing(ev: &ev::KeyboardEvent) -> bool {
    let Some(el) = ev.target().and_then(|t| t.dyn_into::<HtmlElement>().ok()) else {
        return false;
    };
    if el.is_content_editable() {
        return true;
    }
    matches!(
        el.tag_name().to_ascii_lowercase().as_str(),
        "input" | "textarea" | "select"
    )
}

/// Focuses the active surface's filter input, if it has one.
///
/// Matches on the shared `SearchInput` markup rather than threading a
/// `NodeRef` through every list — the lists mount and unmount independently
/// (keep-alive), so there is no single ref to hold, and the *visible* one is
/// whichever pane is displayed.
fn focus_list_filter() -> bool {
    let Ok(Some(node)) = document().query_selector(
        // `:not([style*='display:none'])` would not survive keep-alive's inline
        // style, so instead take the first filter input that is actually laid
        // out — a hidden pane's input has no offset parent.
        "input.search-input__field, .search-input input, input[placeholder^='Filter']",
    ) else {
        return false;
    };
    let Ok(el) = node.dyn_into::<HtmlElement>() else {
        return false;
    };
    if el.offset_parent().is_none() {
        return false;
    }
    let _ = el.focus();
    true
}

/// Installs the global shortcuts for the authenticated shell.
///
/// `show_help` is flipped by `?` so the shell can render the shortcut sheet.
pub fn use_shortcuts(session: Session, show_help: RwSignal<bool>) {
    let handle = window_event_listener(ev::keydown, move |ev| {
        let modified = ev.meta_key() || ev.ctrl_key();

        // ---- Modified bindings: safe even while typing. ----
        if modified && !ev.alt_key() {
            let key = ev.key();
            // Cmd/Ctrl-<n> — jump to a top-level view.
            if let Some(ch) = key.chars().next()
                && key.chars().count() == 1
                && let Some((_, view)) = QUICK_NAV.iter().find(|(c, _)| *c == ch)
            {
                ev.prevent_default();
                session.set_view(*view);
                return;
            }
            // Cmd/Ctrl-W — close the focused open item (the workspace's tab-like
            // working set), NOT the OS window.
            if key.eq_ignore_ascii_case("w") {
                let closed = session.shown_items.with_untracked(|s| s.first().cloned());
                if let Some(item) = closed {
                    ev.prevent_default();
                    session.close_item(item);
                }
                return;
            }
            return;
        }

        // ---- Bare-key bindings: only outside text entry. ----
        if is_typing(&ev) {
            return;
        }
        match ev.key().as_str() {
            // Focus this list's filter. Distinct from Cmd/Ctrl-K, which focuses
            // the tenant-wide Global Search — different tools, and conflating
            // them is a common annoyance in admin UIs.
            "/" => {
                if focus_list_filter() {
                    ev.prevent_default();
                }
            }
            "?" => {
                ev.prevent_default();
                show_help.update(|open| *open = !*open);
            }
            _ => {}
        }
    });
    on_cleanup(move || handle.remove());
}

/// The bindings, for the help sheet. Kept beside the handler so the two can't
/// drift.
pub const SHORTCUTS: &[(&str, &str)] = &[
    (
        "Cmd/Ctrl + K",
        "Focus global search (any app, tool, or GUID)",
    ),
    ("/", "Focus the current list's filter"),
    (
        "Cmd/Ctrl + 1…5",
        "Home · App Registrations · Enterprise Apps · Managed Identities · Security",
    ),
    ("Cmd/Ctrl + W", "Close the open item"),
    ("Esc", "Close a dialog, or collapse the open-item workspace"),
    ("↑ ↓ / Home / End", "Move between rows in a table"),
    ("←  →", "Move between tabs"),
    ("?", "Show this list"),
];
