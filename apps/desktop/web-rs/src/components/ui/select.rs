use leptos::html;
use leptos::prelude::*;

/// A dropdown bound two-way to a `RwSignal<String>`: a bare
/// `<select class="ui-select">` with its `<option>`s passed as children.
///
/// Replaces Thaw's `Select`, which wraps the `<select>` in a span and draws its
/// own chevron. The app's `.ui-select` rule was applied to that wrapper too, so
/// the control rendered as a box inside a box with two chevrons (the New app
/// dialog's "Sign-in audience"). One element, one rule.
///
/// `label` is the accessible name. A Thaw `Field` names only Thaw controls (it
/// injects an id into them), so a plain `<select>` under one would otherwise be
/// unnamed — the same reason the hand-written selects carry `aria-label`.
#[component]
pub fn Select(
    value: RwSignal<String>,
    /// Accessible name (`aria-label`); normally the enclosing `Field`'s label.
    #[prop(into)]
    label: String,
    #[prop(optional, into)] disabled: Signal<bool>,
    children: Children,
) -> impl IntoView {
    let node: NodeRef<html::Select> = NodeRef::new();
    // The options are children, so the element's own `value` can only be set
    // once they exist: an effect that tracks the node as well as the signal
    // writes it after mount and again on every outside change (a form reset).
    Effect::new(move |_| {
        let wanted = value.get();
        if let Some(el) = node.get()
            && el.value() != wanted
        {
            el.set_value(&wanted);
        }
    });
    view! {
        <select
            class="ui-select"
            node_ref=node
            aria-label=label
            disabled=move || disabled.get()
            on:change=move |ev| value.set(event_target_value(&ev))
        >
            {children()}
        </select>
    }
}
