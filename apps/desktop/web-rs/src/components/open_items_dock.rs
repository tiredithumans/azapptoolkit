//! The "Open" dock — a persistent strip of chips for the shared, cross-entity
//! working set (`Session::open_items`). A chip click focuses its item in the
//! workspace (`Cmd`/`Ctrl`-click pins it for side-by-side compare); the ×
//! closes it. Mounted once by the shell so the set is visible from every view.
//! Modeled on `ToastHost` — it just renders a `Session`-owned `Vec`.

use leptos::prelude::*;

use crate::components::type_chip::{AppKind, TypeChip};
use crate::state::{OpenItem, OpenItemKind, Session, use_session};

#[component]
pub fn OpenItemsDock() -> impl IntoView {
    let session = use_session();
    view! {
        <Show when=move || session.open_items.with(|l| !l.is_empty())>
            <div class="open-dock" aria-label="Open items">
                // Chips scroll; the "Close all" control stays pinned beside them.
                <div class="open-dock__chips">
                    <For each=move || session.open_items.get() key=|it| it.id let:item>
                        {dock_chip(session, item)}
                    </For>
                </div>
                // Only meaningful with more than one open — a lone chip's × already
                // closes it.
                <Show when=move || session.open_items.with(|l| l.len() > 1)>
                    <button
                        type="button"
                        class="open-dock__clear"
                        title="Close all open items"
                        on:click=move |_| session.close_all_items()
                    >
                        "Close all"
                    </button>
                </Show>
            </div>
        </Show>
    }
}

/// The `AppKind` glyph for a dock chip. The dock doesn't carry an MI's subtype,
/// so a managed identity shows the generic chip.
fn chip_kind(kind: OpenItemKind) -> AppKind {
    match kind {
        OpenItemKind::AppReg => AppKind::AppRegistration,
        OpenItemKind::Enterprise => AppKind::EnterpriseApp,
        OpenItemKind::ManagedIdentity => AppKind::ManagedIdentityUnknown,
    }
}

fn dock_chip(session: Session, item: OpenItem) -> impl IntoView {
    let id = item.id;
    let app_kind = chip_kind(item.kind);
    // Read the title live from the signal (rather than capturing it) so a
    // re-open with a corrected name updates the chip — the keyed `<For>` won't
    // rebuild this row on a title-only change.
    let label = move || {
        session
            .open_items
            .with(|l| l.iter().find(|it| it.id == id).map(|it| it.title.clone()))
            .unwrap_or_default()
    };
    let is_active = move || session.shown_items.with(|s| s.contains(&id));
    let chip_class = move || {
        let mut c = String::from("open-dock__chip");
        if is_active() {
            c.push_str(" open-dock__chip--active");
        }
        c
    };
    view! {
        <div class=chip_class>
            <button
                type="button"
                class="open-dock__chip-main"
                aria-pressed=move || if is_active() { "true" } else { "false" }
                title=label
                on:click=move |ev: leptos::ev::MouseEvent| {
                    session.focus_item(id, ev.meta_key() || ev.ctrl_key());
                }
            >
                <TypeChip kind=app_kind compact=true />
                <span class="open-dock__chip-label">{label}</span>
            </button>
            <button
                type="button"
                class="open-dock__close"
                aria-label="Close"
                title="Close"
                on:click=move |ev: leptos::ev::MouseEvent| {
                    ev.stop_propagation();
                    session.close_item(id);
                }
            >
                "×"
            </button>
        </div>
    }
}
