//! Shared "jump to the paired object" navigation, used by both the App
//! Registration and Enterprise Application list rows *and* detail-pane headers.
//!
//! Previously each of the four call sites hand-rolled `set_view` +
//! `set_selected_*`, and only the list-row enterprise→app jump scrolled the
//! target into view — so behaviour drifted. Centralizing it here keeps all four
//! consistent: every jump switches view, selects the paired object, brings the
//! selected list row into view, and lands the destination detail pane at its top.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::state::{ActiveView, Session};

/// Switch to the App Registrations view, select `app_obj_id`, and land at the top.
pub fn jump_to_paired_app(session: Session, app_obj_id: String) {
    session.set_view(ActiveView::Apps);
    session.set_selected_app(Some(app_obj_id));
    settle_scroll_after_jump();
}

/// Switch to the Enterprise Applications view, select `sp_id`, and land at the top.
pub fn jump_to_paired_enterprise(session: Session, sp_id: String) {
    session.set_view(ActiveView::EnterpriseApps);
    session.set_selected_enterprise_app(Some(sp_id));
    settle_scroll_after_jump();
}

/// Reset scroll for the just-switched view so the destination opens at its top.
///
/// Deferred a tick (timeout 0): the destination detail pane mounts behind a
/// `Suspense`, and the view swap/layout hasn't settled synchronously. It then
/// (1) brings the now-selected list row into view within its list scroller, and
/// (2) forces the page content scroller and the detail pane back to the top — a
/// kept-alive pane can otherwise retain its previous scroll position, and
/// `scroll_into_view` can pull an outer scroller down. Both lists/panes leave a
/// hidden copy mounted in the *other* kept-alive view; those have no offset
/// parent (`display:none`), so we act only on the visible one.
fn settle_scroll_after_jump() {
    let Some(win) = web_sys::window() else {
        return;
    };
    let cb = Closure::once_into_js(move || {
        let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
            return;
        };
        // 1. Show the selected row inside its list scroller (the visible list).
        if let Ok(rows) = doc.query_selector_all(".app-list__row--selected") {
            for i in 0..rows.length() {
                if let Some(row) = rows
                    .item(i)
                    .and_then(|n| n.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    if row.offset_parent().is_some() {
                        row.scroll_into_view_with_bool(true);
                    }
                }
            }
        }
        // 2. Land the destination at the top: reset the page content scroller…
        if let Ok(Some(content)) = doc.query_selector(".shell__content") {
            if let Some(content) = content.dyn_ref::<web_sys::HtmlElement>() {
                content.set_scroll_top(0);
            }
        }
        // …and the visible detail pane (after the row scroll, so this wins).
        if let Ok(panes) = doc.query_selector_all(".app-detail__pane") {
            for i in 0..panes.length() {
                if let Some(pane) = panes
                    .item(i)
                    .and_then(|n| n.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    if pane.offset_parent().is_some() {
                        pane.set_scroll_top(0);
                    }
                }
            }
        }
    });
    let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
        cb.unchecked_ref::<js_sys::Function>(),
        0,
    );
}
