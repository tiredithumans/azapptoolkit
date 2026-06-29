//! The workspace overlay: a detail "window" per open item (keep-alive), showing
//! the 1–2 named in `Session::shown_items` — one full-width, or two side-by-side
//! for compare. Mounted once by the shell, layered over the (now full-width)
//! list. Each `OpenItem.kind` maps to the matching self-contained detail pane.

use leptos::prelude::*;

use crate::hooks::use_escape::use_escape;
use crate::state::{OpenItem, OpenItemKind, Session, use_session};
use crate::views::application_detail_pane::ApplicationDetailPane;
use crate::views::enterprise_application_detail_pane::EnterpriseApplicationDetailPane;
use crate::views::managed_identities::ManagedIdentityDetailWindow;

#[component]
pub fn OpenItemsWorkspace() -> impl IntoView {
    let session = use_session();

    // Escape collapses the workspace back to the full-width list (the dock and
    // every window stay mounted). Gated to no-op while a modal is open, so
    // Escape there closes the modal — via its own handler — instead of both.
    use_escape(
        move || {
            session.shown_items.with_untracked(|s| !s.is_empty())
                && document()
                    .query_selector(".modal-backdrop")
                    .ok()
                    .flatten()
                    .is_none()
        },
        move || session.shown_items.set(Vec::new()),
    );

    // Hide (don't unmount) the overlay when nothing is shown, so the list below
    // stays clickable while the windows keep their loaded data + per-tab state.
    let overlay_style = move || {
        if session.shown_items.with(|s| s.is_empty()) {
            "display:none"
        } else {
            ""
        }
    };
    let panes_class = move || {
        let mut c = String::from("workspace__panes");
        if session.shown_items.with(|s| s.len() == 2) {
            c.push_str(" workspace__panes--two");
        }
        c
    };

    view! {
        // Mounted whenever the working set is non-empty, so every open window
        // survives chip switches and collapse/expand (no remount, no refetch).
        <Show when=move || session.open_items.with(|l| !l.is_empty())>
            <div class="workspace" style=overlay_style aria-label="Open item workspace">
                <div class=panes_class>
                    <For each=move || session.open_items.get() key=|it| it.id let:item>
                        {open_item_window(session, item)}
                    </For>
                </div>
            </div>
        </Show>
    }
}

fn open_item_window(session: Session, item: OpenItem) -> impl IntoView {
    let id = item.id;
    let entity_id = item.entity_id;
    let shown = move || session.shown_items.with(|s| s.contains(&id));
    // The pane corrects the dock chip's label to the real name once its detail
    // loads — so opens that lacked a name (pairing jumps, deep-links) self-fix.
    let on_title = Callback::new(move |t: String| session.set_open_item_title(id, t));
    let inner = match item.kind {
        OpenItemKind::AppReg => {
            let eid = entity_id.clone();
            view! {
                <ApplicationDetailPane
                    object_id=Signal::derive(move || eid.clone())
                    on_title=on_title
                />
            }
            .into_any()
        }
        OpenItemKind::Enterprise => {
            let eid = entity_id.clone();
            view! {
                <EnterpriseApplicationDetailPane
                    service_principal_id=Signal::derive(move || eid.clone())
                    on_title=on_title
                />
            }
            .into_any()
        }
        OpenItemKind::ManagedIdentity => {
            let eid = entity_id.clone();
            view! {
                <ManagedIdentityDetailWindow
                    mi_id=Signal::derive(move || eid.clone())
                    on_title=on_title
                />
            }
            .into_any()
        }
    };
    view! {
        <div class="workspace__pane" style:display=move || if shown() { "flex" } else { "none" }>
            <div class="workspace__pane-bar">
                <button
                    type="button"
                    class="workspace__pane-full"
                    title="Show full-width"
                    on:click=move |_| session.focus_item(id, false)
                >
                    "⤢ Full"
                </button>
                <button
                    type="button"
                    class="workspace__pane-close"
                    aria-label="Close pane"
                    title="Close pane"
                    on:click=move |_| {
                        session.shown_items.update(|s| s.retain(|x| *x != id));
                    }
                >
                    "✕"
                </button>
            </div>
            {inner}
        </div>
    }
}
