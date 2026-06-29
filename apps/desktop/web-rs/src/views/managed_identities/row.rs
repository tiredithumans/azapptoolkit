//! Virtualized managed-identity list row: subtype-aware type chip + name +
//! app id, reusing the shared `app-list__*` classes so the MI list matches the
//! App Registration / Enterprise Application lists.

use std::sync::Arc;

use leptos::prelude::*;

use crate::bindings::managed_identity::{ManagedIdentityDto, MiSubtype};
use crate::components::type_chip::{AppKind, TypeChip};
use crate::constants::*;
use crate::state::{OpenItemKind, use_session};

pub(crate) fn chip_kind_for(subtype: MiSubtype) -> AppKind {
    match subtype {
        MiSubtype::SystemAssigned => AppKind::ManagedIdentitySystem,
        MiSubtype::UserAssigned => AppKind::ManagedIdentityUser,
        MiSubtype::Unknown => AppKind::ManagedIdentityUnknown,
    }
}

// Reuses the shared `app-list__*` row classes (and the VirtualList scroller)
// so the managed-identity list matches the App Registration / Enterprise
// Application lists exactly. Rows are absolutely positioned inside the sizer.
pub(super) fn render_row(idx: usize, mi: ManagedIdentityDto) -> impl IntoView {
    let session = use_session();
    // One shared allocation for the row id; the per-handler captures below are
    // refcount bumps instead of String clones.
    let id: Arc<str> = mi.id.into();
    let id_for_click = Arc::clone(&id);
    // Highlight every row open in the workspace (the working set). Class name
    // stays `--selected` so `pairing.rs`'s scroll-settle selector keeps matching.
    let row_class = move || {
        let mut c = String::from("app-list__row");
        if session
            .is_open(OpenItemKind::ManagedIdentity, &id)
            .is_some()
        {
            c.push_str(" app-list__row--selected");
        }
        c
    };
    let chip_kind = chip_kind_for(mi.mi_subtype);
    let top = idx as f64 * ROW_HEIGHT;
    let display_name = if mi.display_name.is_empty() {
        mi.app_id.clone()
    } else {
        mi.display_name
    };
    let title_name = display_name.clone();
    let name_for_open = display_name.clone();
    let app_id = mi.app_id;
    view! {
        <div
            class=row_class
            style:top=format!("{top}px")
            style:height=format!("{ROW_HEIGHT}px")
        >
            <button
                class="app-list__row-btn"
                type="button"
                on:click=move |_| {
                    session.open_item(
                        OpenItemKind::ManagedIdentity,
                        id_for_click.to_string(),
                        name_for_open.clone(),
                    );
                }
            >
                <span class="row-meta">
                    <TypeChip kind=chip_kind compact=true />
                    <span class="app-list__row-title" title=title_name>{display_name}</span>
                </span>
                <span class="app-list__row-appid">{app_id}</span>
            </button>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_kind_for_maps_each_subtype() {
        assert_eq!(
            chip_kind_for(MiSubtype::SystemAssigned),
            AppKind::ManagedIdentitySystem
        );
        assert_eq!(
            chip_kind_for(MiSubtype::UserAssigned),
            AppKind::ManagedIdentityUser
        );
        assert_eq!(
            chip_kind_for(MiSubtype::Unknown),
            AppKind::ManagedIdentityUnknown
        );
    }
}
