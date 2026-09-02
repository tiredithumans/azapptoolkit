//! The workspace overlay: a detail "window" per open item (keep-alive), showing
//! the 1–2 named in `Session::shown_items` — one full-width, or two side-by-side
//! for compare. Mounted once by the shell, layered over the (now full-width)
//! list. Each `OpenItem.kind` maps to the matching self-contained detail pane.

use leptos::html;
use leptos::prelude::*;

use crate::components::icon::{Icon, IconName};
use crate::components::open_items_dock::chip_kind;
use crate::components::type_chip::TypeChip;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_return::use_focus_return;
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

    // Move focus into the pane on the open edge and hand it back on collapse.
    // Without this, opening a row from the keyboard left focus on `<body>` —
    // ~13 Tab presses from the pane, past the whole nav rail — and Escape left
    // it there too, losing the operator's place in the list they came from.
    //
    // Which pane is being asked to take focus. Focus is routed through a signal
    // the target pane claims from its OWN effect — never a `.focus()` at the
    // mutation site, and never `request_animation_frame`.
    //
    // Both shortcuts are wrong here, and silently so. This runs in the component
    // body, *before* the `<Show>`/`<For>` below has put a pane in the document:
    // a direct `.focus()` finds nothing, and reading `open_items` for the retry
    // does not help, because that signal does not change again when the element
    // lands. rAF would paper over it while someone was watching and do nothing
    // in a hidden tab — exactly the flakiness `uri_list_editor` documents at its
    // own `focus_key`, and it would make the headless browser gate flaky too. A
    // pane claiming the request from an effect that tracks its own `NodeRef` has
    // no timer in it at all, and a pane that mounts a tick late still takes it.
    let pane_focus: RwSignal<Option<u64>> = RwSignal::new(None);
    // Ask the visible pane (the last-focused of a 2-up compare) to take focus.
    // Returns whether there was anything to ask, which is `use_focus_return`'s
    // cue to record the trigger — sound because the ask does not move focus, so
    // `document.activeElement` is still the row button the operator came from.
    let request_pane_focus = move || match session.shown_items.with_untracked(|s| s.last().copied())
    {
        Some(id) => {
            pane_focus.set(Some(id));
            true
        }
        None => false,
    };

    // MUST be created before the `inert` effect below: `inert` blurs whatever is
    // focused inside the covered content, and the element worth restoring is the
    // row button that opened this, not the `<body>` the browser falls back to.
    // Leptos runs effects in creation order, so this ordering is the guarantee.
    use_focus_return(
        Signal::derive(move || session.shown_items.with(|s| !s.is_empty())),
        request_pane_focus,
    );

    // The overlay is fully opaque over the list (`.workspace` is
    // `position:absolute; inset:0`), so the content it covers must also be
    // removed from the accessibility tree and the tab order — otherwise the
    // hidden list's rows, checkboxes and buttons stay reachable *behind* it,
    // and a keyboard or screen-reader user tabs into content they cannot see.
    // `inert` does both in one attribute.
    Effect::new(move |_| {
        let covered = session.shown_items.with(|s| !s.is_empty());
        if let Some(content) = document().query_selector(".shell__content").ok().flatten() {
            if covered {
                let _ = content.set_attribute("inert", "");
            } else {
                let _ = content.remove_attribute("inert");
            }
        }
    });

    // Stepping panes from the keyboard (`Cmd/Ctrl-[`/`]`) hides the pane focus
    // was in, and the browser drops focus to `<body>` when that happens — the
    // same dead end the open edge had. Re-place it, but ONLY when it was really
    // lost, so switching by clicking a dock chip leaves focus on that chip.
    // Created after the two effects above so it observes their result rather
    // than pre-empting the element `use_focus_return` needs to record.
    Effect::new(move |_| {
        if session.shown_items.with(|s| !s.is_empty()) && focus_is_lost() {
            request_pane_focus();
        }
    });

    view! {
        // Mounted whenever the working set is non-empty, so every open window
        // survives chip switches and collapse/expand (no remount, no refetch).
        <Show when=move || session.open_items.with(|l| !l.is_empty())>
            // `role="region"` + a label: a bare `aria-label` on a generic `div`
            // has no role to attach to, so it was never announced.
            <div
                class="workspace"
                style=overlay_style
                role="region"
                aria-label="Open item workspace"
            >
                <div class=panes_class>
                    <For each=move || session.open_items.get() key=|it| it.id let:item>
                        {open_item_window(session, item, pane_focus)}
                    </For>
                </div>
            </div>
        </Show>
    }
}

/// True when nothing meaningful holds focus — `<body>`, or nothing at all.
/// Hiding the element that had focus leaves exactly this state.
fn focus_is_lost() -> bool {
    document()
        .active_element()
        .map(|el| el.tag_name().eq_ignore_ascii_case("body"))
        .unwrap_or(true)
}

fn open_item_window(
    session: Session,
    item: OpenItem,
    pane_focus: RwSignal<Option<u64>>,
) -> impl IntoView {
    let id = item.id;
    let entity_id = item.entity_id;
    let app_kind = chip_kind(item.kind);
    // Live title from the session signal (same pattern as the dock chip) so the
    // pane label self-corrects when the detail loads with a real name — and so a
    // 2-up compare labels each pane with its kind + name.
    let title = move || {
        session
            .open_items
            .with(|l| l.iter().find(|it| it.id == id).map(|it| it.title.clone()))
            .unwrap_or_default()
    };
    let shown = move || session.shown_items.with(|s| s.contains(&id));
    // This pane claims the workspace's focus request once its element exists and
    // it is the one on screen. Tracking `pane_ref` is what makes a pane that
    // mounts after the request still take focus (the same shape `use_focus_trap`
    // uses for a dialog that mounts a tick after `active` flips); clearing the
    // request marks it served, so a later re-render doesn't yank focus back out
    // from under the operator.
    let pane_ref: NodeRef<html::Div> = NodeRef::new();
    Effect::new(move |_| {
        let wanted = pane_focus.get();
        let node = pane_ref.get();
        if wanted != Some(id) || !shown() {
            return;
        }
        if let Some(el) = node {
            let _ = el.focus();
            pane_focus.set(None);
        }
    });
    // Two panes are shown side-by-side — only then does "Full" (collapse to just
    // this pane) do anything, so it's hidden in the single-pane view.
    let comparing = move || session.shown_items.with(|s| s.len() == 2);
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
        // `tabindex="-1"` so the pane itself can take focus on open (see
        // `use_focus_return` above); it stays out of the Tab order, so the next
        // Tab from here lands on the pane's own first control.
        <div
            node_ref=pane_ref
            class="workspace__pane"
            tabindex="-1"
            style:display=move || if shown() { "flex" } else { "none" }
        >
            <div class="workspace__pane-bar">
                // Echoes the dock chip: kind glyph + the item's live title, so a
                // side-by-side compare labels which pane is which.
                <div class="workspace__pane-title">
                    <TypeChip kind=app_kind />
                    <span class="workspace__pane-name">{title}</span>
                </div>
                <div class="workspace__pane-actions">
                    <Show when=comparing>
                        <button
                            type="button"
                            class="workspace__pane-full"
                            aria-label="Collapse to just this pane"
                            title="Collapse to just this pane (full width)"
                            on:click=move |_| session.focus_item(id, false)
                        >
                            <Icon name=IconName::Maximize size=14 />
                        </button>
                    </Show>
                    <button
                        type="button"
                        class="workspace__pane-close"
                        aria-label="Hide this pane"
                        title="Hide this pane (it stays in the Open dock)"
                        on:click=move |_| {
                            session.shown_items.update(|s| s.retain(|x| *x != id));
                        }
                    >
                        <Icon name=IconName::Close size=14 />
                    </button>
                </div>
            </div>
            {inner}
        </div>
    }
}
