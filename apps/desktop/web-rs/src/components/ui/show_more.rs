use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::constants::RENDER_PAGE;

/// The universal "showing N of M, load another page" footer for a windowed
/// list.
///
/// Several views render only the first `render_limit` matches rather than the
/// whole result set (a tenant sweep can match thousands of rows, and the DOM
/// cost is what the window exists to bound). Each of them needs the same
/// footer, and each had grown its own copy: six of them, identical apart from
/// the noun, all hardcoding the same `audit-show-more` class — including in the
/// Key Vault, Sites and Mailboxes panels, which have nothing to do with the
/// audit. That class name travelling into unrelated views is the tell that the
/// pattern had no owner.
///
/// Renders nothing when everything already fits, so a caller does not wrap it
/// in its own `(total > limit).then(..)`.
///
/// Not for the virtualised lists ([`crate::components::VirtualList`] renders
/// every row and windows the DOM instead) — this is for the tables that cap the
/// *row set*.
#[component]
pub fn ShowMore(
    /// Rows that matched, before the render window is applied.
    total: usize,
    /// Rows currently rendered — `render_limit`'s value at the time the caller
    /// read it, passed in so the caller's own reactive closure stays the single
    /// place that tracks it.
    limit: usize,
    /// Raised by `RENDER_PAGE` on click.
    render_limit: RwSignal<usize>,
    /// Plural noun for what is being counted: "matching rows", "apps",
    /// "affected". Reads as "Showing 200 of 4812 {noun}".
    #[prop(into)]
    noun: String,
) -> impl IntoView {
    (total > limit).then(|| {
        let next = next_page_size(total, limit);
        view! {
            <div class="show-more">
                <Body1>{format!("Showing {limit} of {total} {noun}")}</Body1>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| render_limit.update(|n| *n += RENDER_PAGE))
                >
                    {format!("Show {next} more")}
                </Button>
            </div>
        }
    })
}

/// How many rows the next click will add: a full page, or whatever is left.
///
/// Split out from the component so it is testable on the host — the browser
/// suite is the only other gate the frontend has, and this is the one piece of
/// arithmetic here that can be wrong.
///
/// Saturating so the function is total on its own. The component's
/// `total > limit` guard already makes the subtraction safe there (as it did in
/// all six copies this replaced — no underflow was reachable), but a helper
/// that is only correct when its caller checks first is a trap for the next
/// caller.
fn next_page_size(total: usize, limit: usize) -> usize {
    RENDER_PAGE.min(total.saturating_sub(limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_page_is_offered_while_a_full_page_remains() {
        assert_eq!(next_page_size(RENDER_PAGE * 3, RENDER_PAGE), RENDER_PAGE);
    }

    #[test]
    fn the_last_page_offers_only_what_is_left() {
        // The footer must never say "Show 200 more" when 7 remain.
        assert_eq!(next_page_size(RENDER_PAGE + 7, RENDER_PAGE), 7);
        assert_eq!(next_page_size(RENDER_PAGE + 1, RENDER_PAGE), 1);
    }

    #[test]
    fn a_window_wider_than_the_row_set_does_not_underflow() {
        // Not reachable through `ShowMore`, which checks `total > limit` first.
        // This pins the helper's own contract: called directly with a window
        // wider than the row set — which a search narrowing the matches under an
        // already-grown window would produce — it returns 0 rather than panicking
        // in debug and wrapping to usize::MAX in release.
        assert_eq!(next_page_size(5, RENDER_PAGE), 0);
        assert_eq!(next_page_size(0, RENDER_PAGE), 0);
        assert_eq!(next_page_size(RENDER_PAGE, RENDER_PAGE), 0);
    }
}
