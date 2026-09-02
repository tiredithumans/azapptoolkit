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

/// Move the workspace focus one entry along the dock, wrapping at both ends.
///
/// Focuses rather than splits: `focus_item` also re-expands a collapsed
/// workspace, so this is the keyboard route back in after Escape. Ordering is
/// the dock's own (open order), not focus recency, so repeated presses walk a
/// stable strip instead of ping-ponging between the last two items.
fn step_open_item(session: Session, forward: bool) {
    let items = session.open_items.get_untracked();
    let len = items.len();
    if len == 0 {
        return;
    }
    // Anchor on the pane the operator is reading (the last-focused of a 2-up
    // compare). Collapsed, there is no anchor — `]` then opens the first entry
    // and `[` the last, so either key gets the workspace back.
    let current = session
        .shown_items
        .with_untracked(|s| s.last().copied())
        .and_then(|id| items.iter().position(|it| it.id == id));
    let next = match (current, forward) {
        (Some(i), true) => (i + 1) % len,
        (Some(i), false) => (i + len - 1) % len,
        (None, true) => 0,
        (None, false) => len - 1,
    };
    session.focus_item(items[next].id, false);
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
            // working set), NOT the OS window. `prevent_default` runs FIRST,
            // unconditionally: with nothing shown — one Escape after a collapse
            // is enough — the keystroke would otherwise fall through to the OS
            // and take the whole window, the working set, the audit run and any
            // in-flight dialog with it. macOS needs the other half of this too:
            // an NSMenu key equivalent is consumed before the webview ever sees
            // the event, which is why `src-tauri/src/lib.rs` builds a menu with
            // no Close Window item.
            if key.eq_ignore_ascii_case("w") {
                ev.prevent_default();
                // The LAST shown pane is the most recently focused one
                // (`focus_item` pushes), so a 2-up compare closes the pane the
                // operator is reading rather than whichever is on the left.
                if let Some(item) = session.shown_items.with_untracked(|s| s.last().copied()) {
                    session.close_item(item);
                }
                return;
            }
            // Cmd/Ctrl-] / Cmd/Ctrl-[ — step forward/back through the dock. The
            // dock reads as a tab strip but had no keyboard route at all, and
            // `focus_item` re-expands a workspace collapsed with Escape — which
            // is what closes that one-way door.
            if key == "]" || key == "[" {
                ev.prevent_default();
                step_open_item(session, key == "]");
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
    ("Cmd/Ctrl + W", "Close the focused open item"),
    ("Cmd/Ctrl + ]", "Next open item"),
    (
        "Cmd/Ctrl + [",
        "Previous open item (either key re-opens a collapsed workspace)",
    ),
    ("Esc", "Close a dialog, or collapse the open-item workspace"),
    ("↑ ↓ / Home / End", "Move between rows in a table"),
    ("←  →", "Move between tabs"),
    ("?", "Show this list"),
];
