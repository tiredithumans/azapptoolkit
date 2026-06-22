//! Shared frame for a collapsible "scoping" section on a detail pane: a
//! `<section class="detail-section">` with a title, a capability-role hint, and a
//! Show/Hide toggle, plus a body that's only rendered while expanded. The
//! Exchange and SharePoint scoping sections share this frame (collapse state,
//! header, lazy body); only the title, capability key, and body differ.
//!
//! The caller owns the `open` signal so it can *also* gate its lazy resource
//! loads on it — a collapsed section then costs no Graph/Exchange round trips.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::components::requires_role::RequiresRole;

#[component]
pub fn CollapsibleScopingSection(
    title: &'static str,
    /// Capability-catalog key for the inline `RequiresRole` hint in the header.
    capability_key: &'static str,
    /// Collapse state — owned by the caller (see module docs).
    open: RwSignal<bool>,
    /// Section body, rendered only while expanded.
    children: ChildrenFn,
) -> impl IntoView {
    view! {
        <section class="detail-section">
            <header class="row-between">
                <strong>{title}</strong>
                <span class="detail-section__controls">
                    <RequiresRole capability_key=capability_key />
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                        on_click=Box::new(move |_| open.update(|o| *o = !*o))
                    >
                        {move || if open.get() { "Hide" } else { "Show" }}
                    </Button>
                </span>
            </header>
            {move || open.get().then(|| children())}
        </section>
    }
}
