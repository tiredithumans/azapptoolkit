//! Shared header strip for a resource detail pane: a type chip, the title, a
//! copyable appId, an optional middle slot (pairing / foreign-tenant badges),
//! and a refresh + delete action row. The App Registration and Enterprise
//! Application detail panes built this identically and differed only in the chip
//! kind, the middle slot, and the delete-confirm dialog — which the caller still
//! owns (it just wires `on_delete` to open its own dialog).

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::components::icon::IconName;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{CopyIconButton, IconButton};

#[component]
pub fn DetailHeader(
    kind: AppKind,
    #[prop(into)] title: Signal<String>,
    #[prop(into)] app_id: Signal<String>,
    #[prop(into)] on_refresh: Callback<()>,
    /// Refresh busy state (the app-reg pane shows a spinner while its detail
    /// cache busts + refetches; the enterprise pane has none, so it defaults to
    /// never-busy).
    #[prop(optional, into, default = Signal::derive(|| false))]
    refreshing: Signal<bool>,
    /// Delete action. Optional: panes for objects that can't be deleted from
    /// here (e.g. managed identities, which are Azure resources) omit it and the
    /// Delete button isn't rendered.
    #[prop(optional, into)]
    on_delete: Option<Callback<()>>,
    /// Middle slot — pairing link, foreign-tenant badge, etc.
    #[prop(optional)]
    children: Option<Children>,
) -> impl IntoView {
    view! {
        <header class="row-between app-detail__header">
            <div class="detail-header">
                <TypeChip kind=kind />
                <div>
                    <h2 class="app-detail__title">{move || title.get()}</h2>
                    <span class="row-meta">
                        <Body1 class="mono">{move || app_id.get()}</Body1>
                        <CopyIconButton value=app_id aria_label="Copy app id".to_string() />
                    </span>
                </div>
                {children.map(|c| c())}
            </div>
            <div class="actions-row">
                <IconButton
                    icon=IconName::Refresh
                    aria_label="Refresh this application".to_string()
                    title="Refresh".to_string()
                    busy=refreshing
                    on_click=Callback::new(move |_| on_refresh.run(()))
                />
                {on_delete
                    .map(|cb| {
                        view! {
                            <Button
                                class="button--danger"
                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                on_click=Box::new(move |_| cb.run(()))
                            >
                                "Delete"
                            </Button>
                        }
                    })}
            </div>
        </header>
    }
}
