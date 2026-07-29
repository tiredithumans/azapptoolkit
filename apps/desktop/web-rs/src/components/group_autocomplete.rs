//! Mail-enabled-group typeahead for the Exchange scope forms: a group-scoped
//! [`DirectorySearch`] that appends a picked group's **name** to a free-text
//! field (one identifier per line), keeping that field the source of truth and
//! the fallback for the raw mailbox identifiers Exchange also accepts.
//!
//! Two behaviours here differ from the other pickers and are deliberate: the
//! input is bare (no `<Field>` wrapper) because it sits inside the scope
//! wizard's flex column, and an empty result set renders **nothing** rather
//! than "No matches." — the field below is a perfectly good manual fallback, so
//! a miss is not a dead end worth announcing.

use leptos::prelude::*;
use thaw::ButtonAppearance;

use crate::components::directory_search::{DirectoryScope, DirectorySearch};

#[component]
pub fn GroupAutocomplete(
    /// The free-text group field this typeahead appends to (one per line).
    target: RwSignal<String>,
) -> impl IntoView {
    // Append the picked group's name on its own line, deduped.
    let on_pick = Callback::new(move |g: azapptoolkit_core::models::DirectoryObject| {
        let identifier = g.display_name.clone().unwrap_or_else(|| g.id.clone());
        target.update(|t| {
            if t.lines().any(|l| l.trim() == identifier) {
                return;
            }
            if !t.is_empty() && !t.ends_with('\n') {
                t.push('\n');
            }
            t.push_str(&identifier);
        });
    });

    view! {
        <DirectorySearch
            scope=Signal::derive(|| DirectoryScope::Groups)
            on_pick=on_pick
            placeholder="Search mail-enabled groups (2+ chars)…"
            action_appearance=Signal::derive(|| ButtonAppearance::Secondary)
            show_no_matches=false
        />
    }
}
