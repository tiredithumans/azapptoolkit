//! Repeatable one-URI-per-row editor for a set of reply (redirect) URIs.
//!
//! Replaces the newline-separated `<Textarea>` the Authentication tab rendered
//! per platform. A textarea is fine for three URIs and hostile at forty: no
//! entry can be removed without hand-editing the text around it (leaving a
//! stray fragment behind is one keystroke away), there is no count, and nothing
//! marks the one line the server is about to reject.
//!
//! **Pure presentation + state**, the same split as [`crate::components::claims_editor`]:
//! the parent builds one [`UriListState`] per platform from the loaded DTO,
//! renders one [`UriListEditor`] each, and reads [`UriListState::to_uris`] back
//! on save. This module never calls IPC and never gates the save.
//!
//! Four things here are load-bearing and easy to "simplify" into bugs:
//!
//! 1. **Validation is advisory; the backend stays the authority.** Rows are
//!    checked with `azapptoolkit_core::redirect::validate_redirect_uri` — the
//!    *same* function `commands/applications/authentication.rs` runs before its
//!    PATCH, ungated for wasm. It exists to point at the offending row *before*
//!    the round trip, because the backend `?`s out of a loop over all three
//!    platforms and therefore reports only the FIRST bad URI: three typos cost
//!    three saves. Save is deliberately **never disabled** — a client rule that
//!    ever drifted from the server's would make an app unsavable through the
//!    UI, which is strictly worse than a rejected save.
//! 2. **Rows are keyed, never indexed.** A keyed `<For>` patches one row instead
//!    of rebuilding every `<Input>`; an index-keyed list drops focus and the
//!    caret out from under whoever is typing.
//! 3. **Nothing splits on anything but a newline.** A redirect URI may legally
//!    contain a comma or a semicolon in a query string. One row is one URI,
//!    which makes that hazard structural rather than a rule a later sweep can
//!    quietly delete; the multi-line paste path uses the same restriction.
//! 4. **Focus is handed over through a signal, never scheduled on a frame.**
//!    See [`UriListState::focus_key`] — `request_animation_frame` is the obvious
//!    way to focus a row that does not exist yet, and it fails *invisibly* in a
//!    hidden tab (measured: focus simply never moved, and the browser gate would
//!    have inherited the flake).

use std::sync::atomic::{AtomicUsize, Ordering};

use leptos::ev;
use leptos::html;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, ButtonRef, ComponentRef};

use azapptoolkit_core::redirect::validate_redirect_uri;

use crate::components::icon::IconName;
use crate::components::ui::IconButton;

/// Distinguishes editors mounted at the same time so their generated element
/// ids can't collide. Three lists share one tab, and the open-items workspace
/// keeps a detail pane alive **per open item** — two App Registration panes are
/// routinely in the DOM together, so a hardcoded id would make one pane's
/// `aria-labelledby` resolve into the other pane's markup.
static NEXT_GROUP_ID: AtomicUsize = AtomicUsize::new(0);

/// One editable entry.
///
/// `key` is stable for the row's lifetime (the keyed `<For>` depends on it), and
/// `input` points at this row's control — focus moves through the ref rather
/// than `document.getElementById`, which would find the wrong pane's row
/// whenever two detail panes are open. *When* it moves is the row's own
/// business; see [`UriListState::focus_key`].
#[derive(Clone, Copy)]
struct UriRow {
    key: usize,
    value: RwSignal<String>,
    input: NodeRef<html::Input>,
}

/// What is wrong with one row. Neither variant blocks saving.
#[derive(Clone, PartialEq, Eq)]
enum RowIssue {
    /// The shared validator rejected it; carries the reason with the echoed URI
    /// stripped (see [`redirect_uri_reason`]).
    Rejected(String),
    /// Exact repeat of the entry at this 1-based position.
    Duplicate(usize),
}

impl RowIssue {
    fn message(&self) -> String {
        match self {
            Self::Rejected(reason) => reason.clone(),
            Self::Duplicate(at) => format!("Same as entry {at}."),
        }
    }
}

/// Returns the next monotonically increasing key and advances the counter. Keys
/// let us remove a specific row without index juggling across re-renders.
/// (A deliberate four-line twin of `claims_editor::next_key`: cheaper than
/// making one editor depend on the other's internals.)
fn next_key(seq: RwSignal<usize>) -> usize {
    let k = seq.get_untracked();
    seq.set(k + 1);
    k
}

fn new_row(seq: RwSignal<usize>, value: &str) -> UriRow {
    UriRow {
        key: next_key(seq),
        value: RwSignal::new(value.to_string()),
        input: NodeRef::new(),
    }
}

/// Splits pasted text into one entry per line, trimmed, blanks dropped.
/// Newlines **only** — see the module docs.
fn split_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Per-entry check: `Some(reason)` flags the row, `None` accepts it.
///
/// A plain `fn` pointer rather than a closure so [`UriListState`] stays `Copy`.
/// Which rules apply is the **caller's** call and must stay that way: these
/// lists look identical but are not interchangeable. Reply URLs are redirect
/// URIs and take [`redirect_uri_reason`]; SAML Entity IDs are not — a bare
/// `urn:contoso:saml:sp` is a perfectly ordinary identifier, and the redirect
/// rules reject `urn:` on purpose. Handing every list the same validator would
/// paint a red bar on a correct SAML config.
pub type UriValidator = fn(&str) -> Option<String>;

/// The redirect-URI rules the backend enforces, ready to pass to
/// [`UriListState::validated`]. `None` when the entry is blank (a row you have
/// not filled in yet is not an error — [`UriListState::to_uris`] drops it) or
/// acceptable.
///
/// The core validator interpolates the offending URI into its message because
/// the backend has no other channel to say *which* one failed. Inline, the row
/// **is** the pointer, so the echo is stripped; an unrecognised message shape
/// falls through unchanged. The trimmed value is passed so a stray leading
/// space isn't reported as a scheme error — `to_uris` trims before saving.
pub fn redirect_uri_reason(raw: &str) -> Option<String> {
    let uri = raw.trim();
    if uri.is_empty() {
        return None;
    }
    let msg = validate_redirect_uri(uri).err()?;
    Some(
        msg.strip_suffix(&format!(": {uri}"))
            .unwrap_or(&msg)
            .to_string(),
    )
}

/// `Copy` handle to one platform's rows. Built by the parent inside its render
/// (the inner signals need a reactive owner), handed to [`UriListEditor`], read
/// back with [`Self::to_uris`] on save.
#[derive(Clone, Copy)]
pub struct UriListState {
    group: usize,
    rows: RwSignal<Vec<UriRow>>,
    seq: RwSignal<usize>,
    /// One sentence for the list's `role="status"` region. Written only on
    /// discrete mutations (add / remove / paste) — never derived from row
    /// values, or a screen reader would re-announce on every keystroke.
    status: RwSignal<String>,
    /// Every row's problem, recomputed as a set. A `Memo` so a keystroke that
    /// doesn't change the verdict doesn't re-render any row.
    issues: Memo<Vec<(usize, RowIssue)>>,
    /// The row that should take focus, claimed by that row's own effect.
    ///
    /// A mutation cannot focus the row it just created: the element does not
    /// exist until Leptos has flushed the render. The first instinct —
    /// `request_animation_frame` — is **wrong here and silently so**: rAF does
    /// not fire in a background or hidden tab, so "Add, then type" would work
    /// when watched and do nothing when not, and the browser gate (which runs
    /// the page headless) would be flaky. Routing focus through a signal that
    /// the target row claims from its own effect has no timer in it at all.
    focus_key: RwSignal<Option<usize>>,
}

impl UriListState {
    /// Seeds one row per entry, with **no** per-entry validation — duplicates
    /// are still flagged. For a list whose entries have rules the app knows,
    /// use [`Self::validated`].
    pub fn new(uris: &[String]) -> Self {
        Self::build(uris, None)
    }

    /// [`Self::new`] plus a per-entry check. See [`UriValidator`] for why the
    /// rules are the caller's to choose.
    pub fn validated(uris: &[String], validate: UriValidator) -> Self {
        Self::build(uris, Some(validate))
    }

    /// An empty list still gets one blank row, so there is always somewhere to
    /// type — and, more importantly, always a paste target: pasting a block out
    /// of PowerShell into an empty list is the one thing the textarea was
    /// genuinely good at.
    fn build(uris: &[String], validate: Option<UriValidator>) -> Self {
        let seq = RwSignal::new(0_usize);
        let mut initial: Vec<UriRow> = uris.iter().map(|u| new_row(seq, u)).collect();
        if initial.is_empty() {
            initial.push(new_row(seq, ""));
        }
        let rows = RwSignal::new(initial);
        let issues = Memo::new(move |_| {
            let rows = rows.get();
            // Positions are 1-based and count blank rows, so "Same as entry 4"
            // names what the operator can actually see on screen.
            let mut seen: Vec<String> = Vec::with_capacity(rows.len());
            let mut out: Vec<(usize, RowIssue)> = Vec::new();
            for row in &rows {
                let trimmed = row.value.get().trim().to_string();
                if trimmed.is_empty() {
                    seen.push(String::new());
                    continue;
                }
                if let Some(reason) = validate.and_then(|v| v(&trimmed)) {
                    out.push((row.key, RowIssue::Rejected(reason)));
                } else if let Some(i) = seen.iter().position(|s| *s == trimmed) {
                    out.push((row.key, RowIssue::Duplicate(i + 1)));
                }
                seen.push(trimmed);
            }
            out
        });

        Self {
            group: NEXT_GROUP_ID.fetch_add(1, Ordering::Relaxed),
            rows,
            seq,
            status: RwSignal::new(String::new()),
            issues,
            focus_key: RwSignal::new(None),
        }
    }

    /// The list as it will be saved: trimmed, blank rows dropped, **order
    /// preserved** (Graph stores `redirectUris` as an ordered array). Reads
    /// untracked — call it from a save handler.
    pub fn to_uris(&self) -> Vec<String> {
        self.rows
            .get_untracked()
            .into_iter()
            .map(|r| r.value.get_untracked().trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
    }

    /// Reactive count of non-blank rows (the header counter).
    fn filled(&self) -> usize {
        self.rows.with(|rows| {
            rows.iter()
                .filter(|r| r.value.with(|v| !v.trim().is_empty()))
                .count()
        })
    }

    fn issue_for(&self, key: usize) -> Option<RowIssue> {
        self.issues
            .with(|v| v.iter().find(|(k, _)| *k == key).map(|(_, i)| i.clone()))
    }

    /// Ask `key`'s row to take focus once it has rendered. Claimed and cleared
    /// by that row's own effect — see the [`Self::focus_key`] field docs for why
    /// this is a signal rather than a direct `.focus()` call.
    fn request_focus(&self, key: usize) {
        self.focus_key.set(Some(key));
    }

    /// Append a blank row (`after` = `None`) or insert one below `after`, and
    /// give it focus so typing can start immediately.
    fn add_row(&self, after: Option<usize>, noun: &str) {
        let row = new_row(self.seq, "");
        self.rows.update(
            |rows| match after.and_then(|k| rows.iter().position(|r| r.key == k)) {
                Some(i) => rows.insert(i + 1, row),
                None => rows.push(row),
            },
        );
        let n = self.rows.with_untracked(Vec::len);
        self.status.set(format!("Added {noun} {n}."));
        self.request_focus(row.key);
    }

    /// Remove `key`, moving focus to whichever row takes its place. The last
    /// remaining row is cleared rather than removed, so the list never loses its
    /// only typing/paste target. Returns false when the row is already gone, so
    /// the caller can park focus somewhere that still exists.
    fn remove_row(&self, key: usize, noun: &str) -> bool {
        let rows_now = self.rows.get_untracked();
        if rows_now.len() <= 1 {
            let Some(only) = rows_now.first().copied() else {
                return false;
            };
            only.value.set(String::new());
            self.status.set(format!("Cleared. No {noun}s left."));
            self.request_focus(only.key);
            return true;
        }
        let Some(i) = rows_now.iter().position(|r| r.key == key) else {
            return false;
        };
        self.rows.update(|rows| {
            rows.remove(i);
        });
        let len = self.rows.with_untracked(Vec::len);
        self.status.set(match len {
            1 => format!("Removed. 1 {noun} left."),
            n => format!("Removed. {n} {noun}s left."),
        });
        // The row that shifted into this slot, or the new tail.
        if let Some(next) = self
            .rows
            .with_untracked(|rows| rows.get(i.min(len - 1)).copied())
        {
            self.request_focus(next.key);
        }
        true
    }

    /// Multi-line paste. A single-line `<input>` silently strips the newlines,
    /// so without this, pasting forty URLs lands one unusable concatenated
    /// string that is *valid* by the redirect rules and saves quietly. The
    /// lines fill `key`'s row when it is untouched, and are otherwise inserted
    /// below it so a paste never destroys something already typed.
    fn insert_lines(&self, key: usize, lines: Vec<String>, noun: &str) {
        if lines.is_empty() {
            return;
        }
        let count = lines.len();
        let seq = self.seq;
        let mut lines = lines.into_iter();

        let Some(target) = self
            .rows
            .with_untracked(|rows| rows.iter().find(|r| r.key == key).copied())
        else {
            return;
        };
        let mut last = target;
        if target.value.get_untracked().trim().is_empty()
            && let Some(first) = lines.next()
        {
            target.value.set(first);
        }
        let fresh: Vec<UriRow> = lines.map(|l| new_row(seq, &l)).collect();
        if let Some(r) = fresh.last() {
            last = *r;
        }
        self.rows.update(|rows| {
            let at = rows
                .iter()
                .position(|r| r.key == key)
                .map_or(rows.len(), |p| p + 1);
            for (n, row) in fresh.into_iter().enumerate() {
                rows.insert(at + n, row);
            }
        });
        self.status.set(match count {
            1 => format!("Pasted 1 {noun}."),
            n => format!("Pasted {n} {noun}s."),
        });
        self.request_focus(last.key);
    }
}

/// One labelled, add/remove-able list of redirect URIs.
///
/// `noun` is the singular thing this list holds ("web redirect URI"). Every
/// generated control name derives from it — "Add web redirect URI", "Remove web
/// redirect URI", "Removed. 3 web redirect URIs left." — because three of these
/// stack on one tab and identical button labels would be indistinguishable to a
/// screen reader. Deriving them from one prop is what stops the button label and
/// the announcement drifting apart.
#[component]
pub fn UriListEditor(
    state: UriListState,
    /// Visible group label, e.g. `"Web redirect URIs"`.
    #[prop(into)]
    label: String,
    /// Singular noun for generated names, e.g. `"web redirect URI"`.
    #[prop(into)]
    noun: String,
    /// Placeholder shown in an empty row.
    #[prop(optional, into)]
    placeholder: String,
    /// Extra class on the root (call sites add `uri-list--<platform>` as a
    /// stable hook for layout and GUI tests).
    #[prop(optional, into)]
    class: String,
) -> impl IntoView {
    let label_id = format!("uri-list-{}-label", state.group);
    let labelled_by = label_id.clone();
    let root_class = if class.is_empty() {
        "uri-list".to_string()
    } else {
        format!("uri-list {class}")
    };
    let noun = StoredValue::new(noun);
    let placeholder = StoredValue::new(placeholder);
    let add_label = noun.with_value(|n| format!("Add {n}"));
    // Focus target of last resort — the only control left if a list is ever
    // emptied; focus must never be dropped onto <body>.
    let add_ref = ComponentRef::<ButtonRef>::new();

    let add = move |_| noun.with_value(|n| state.add_row(None, n));

    view! {
        // `role="group"` + `aria-labelledby`: a bare `aria-label` on a generic
        // div has no role to attach to. NOT a thaw `<Field>` — Field mints one
        // id and injects it into EVERY descendant input, so N rows inside one
        // Field would all share a DOM id.
        <section class=root_class role="group" aria-labelledby=labelled_by>
            // `row-between` + a bold "Title (N)" is the tab-section header the
            // Credentials / API-permissions tabs use ("Secrets (2)"). The count
            // rides inside the title rather than in a separate chip so this reads
            // as one more section of the detail pane, not as a form control.
            <header class="row-between">
                <strong class="uri-list__label" id=label_id>
                    {move || format!("{label} ({})", state.filled())}
                </strong>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    comp_ref=add_ref
                    on_click=Box::new(add)
                >
                    {add_label}
                </Button>
            </header>

            // A real <ul>/<li>: a screen reader announces "list, 7 items" and
            // "item 3 of 7" for free, which is the orientation the flat textarea
            // never gave — and the reason seven identical Remove buttons don't
            // each need a stale position baked into the label.
            <ul class="uri-list__rows">
                // Keyed on the stable row id so adding or removing one entry
                // patches only that <li>; a positional key would tear down the
                // <input> being typed in.
                <For each=move || state.rows.get() key=|row| row.key let:row>
                    <UriRowView
                        row=row
                        state=state
                        noun=noun
                        placeholder=placeholder
                        add_ref=add_ref
                    />
                </For>
            </ul>

            // Always present, empty at rest: a live region has to exist BEFORE
            // its text changes or the change is not announced. Implicit-live via
            // `role`, never a hand-added `aria-live` — see `components/toast.rs`.
            <p class="uri-list__status" role="status">
                {move || state.status.get()}
            </p>
        </section>
    }
}

#[component]
fn UriRowView(
    row: UriRow,
    state: UriListState,
    noun: StoredValue<String>,
    placeholder: StoredValue<String>,
    add_ref: ComponentRef<ButtonRef>,
) -> impl IntoView {
    let key = row.key;
    let issue = Memo::new(move |_| state.issue_for(key));
    let issue_id = StoredValue::new(format!("uri-list-{}-issue-{key}", state.group));

    // Claim focus when the list hands it to this row. An effect rather than a
    // `.focus()` at the mutation site: a row created by that mutation does not
    // exist yet when it returns, and the obvious fix — `request_animation_frame`
    // — does not fire in a hidden tab, so it would work only while someone was
    // watching. Tracking the `NodeRef` too means a row that mounts *after* being
    // asked for focus still takes it when its element lands.
    Effect::new(move |_| {
        let wanted = state.focus_key.get();
        let node = row.input.get();
        if wanted != Some(key) {
            return;
        }
        if let Some(el) = node {
            let _ = el.focus();
            state.focus_key.set(None);
        }
    });

    let remove = move |_| {
        if !noun.with_value(|n| state.remove_row(key, n))
            && let Some(b) = add_ref.get_untracked()
        {
            // Nothing left to focus — park on Add rather than dropping to <body>.
            b.focus();
        }
    };

    // Enter inserts the next entry — the newline the textarea used to give you.
    // Bound to the input itself (not the row) so it can't intercept Enter on the
    // Remove button, where `prevent_default` would cancel the button's own
    // activation and hand a keyboard user a NEW row instead of removing one.
    let on_keydown = move |e: ev::KeyboardEvent| {
        if e.key() != "Enter" {
            return;
        }
        e.prevent_default();
        noun.with_value(|n| state.add_row(Some(key), n));
    };

    let on_paste = move |e: ev::ClipboardEvent| {
        let Some(text) = e
            .clipboard_data()
            .and_then(|d| d.get_data("text/plain").ok())
        else {
            return;
        };
        // A single-line paste is the browser's job; only a multi-line one needs
        // intercepting.
        if !text.contains('\n') && !text.contains('\r') {
            return;
        }
        e.prevent_default();
        noun.with_value(|n| state.insert_lines(key, split_lines(&text), n));
    };

    view! {
        <li class=move || match issue.get() {
            Some(RowIssue::Rejected(_)) => "uri-list__row uri-list__row--rejected",
            Some(RowIssue::Duplicate(_)) => "uri-list__row uri-list__row--duplicate",
            None => "uri-list__row",
        }>
            // A plain `<input>`, not thaw's — deliberately. thaw's `Input` is a
            // bordered, rounded box with an animated brand underline: right for a
            // standalone field, wrong for forty stacked rows, which read as a
            // form wall rather than the flat separated rows every other tab uses.
            // Overriding that chrome means out-specificity-ing rules thaw injects
            // into <head> at runtime, so the row owns its own control instead.
            // The bonus is that `aria-invalid` / `aria-describedby` are ordinary
            // attributes here — on thaw's wrapper markup they had to be poked
            // onto the inner element from an effect.
            <input
                class="uri-list__input"
                type="text"
                node_ref=row.input
                prop:value=move || row.value.get()
                on:input=move |e| row.value.set(event_target_value(&e))
                on:keydown=on_keydown
                on:paste=on_paste
                placeholder=placeholder.get_value()
                spellcheck="false"
                autocapitalize="none"
                autocomplete="off"
                aria-invalid=move || {
                    matches!(issue.get(), Some(RowIssue::Rejected(_))).then_some("true")
                }
                aria-describedby=move || issue.get().map(|_| issue_id.get_value())
            />
            <IconButton
                icon=IconName::Trash
                aria_label=noun.with_value(|n| format!("Remove {n}"))
                title="Remove".to_string()
                class="uri-list__remove button--danger".to_string()
                on_click=Callback::new(remove)
            />
            {move || {
                issue
                    .get()
                    .map(|i| {
                        view! {
                            <span class="uri-list__issue" id=issue_id.get_value()>
                                {i.message()}
                            </span>
                        }
                    })
            }}
        </li>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uris(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The reactive state methods allocate signals, which need an owner.
    fn with_owner<T>(f: impl FnOnce() -> T) -> T {
        let owner = Owner::new();
        let out = owner.with(f);
        owner.cleanup();
        out
    }

    #[test]
    fn split_lines_splits_on_newlines_only_and_trims() {
        // Ported from the `lines_to_uris` test this replaces.
        assert_eq!(
            split_lines("https://a/cb\n  https://b/cb  \n"),
            ["https://a/cb", "https://b/cb"]
        );
        // A comma/semicolon in a query string must NOT split one URI into two.
        assert_eq!(
            split_lines("https://a/cb?x=1,2;3"),
            ["https://a/cb?x=1,2;3"]
        );
        // Windows line endings survive.
        assert_eq!(
            split_lines("https://a/cb\r\nhttps://b/cb"),
            ["https://a/cb", "https://b/cb"]
        );
        assert!(split_lines("\n  \n").is_empty());
    }

    #[test]
    fn redirect_uri_reason_mirrors_the_backend_and_drops_the_echoed_uri() {
        assert_eq!(redirect_uri_reason("https://app.contoso.com/auth"), None);
        assert_eq!(redirect_uri_reason("   "), None);
        assert_eq!(
            redirect_uri_reason("https://*.contoso.com/auth").as_deref(),
            Some("wildcard redirect URIs are not allowed")
        );
        assert_eq!(
            redirect_uri_reason("http://app.contoso.com/cb").as_deref(),
            Some("insecure http redirect URIs are not allowed (use https)")
        );
        // A row the operator is still typing into isn't an error yet.
        assert_eq!(redirect_uri_reason("  https://ok.contoso.com/cb  "), None);
        // Loopback http is fine; a host that merely starts "localhost" is not.
        assert_eq!(redirect_uri_reason("http://localhost:5173/cb"), None);
        assert!(redirect_uri_reason("http://localhost.evil.com/cb").is_some());
    }

    #[test]
    fn to_uris_trims_drops_blanks_and_preserves_order() {
        with_owner(|| {
            let s = UriListState::new(&uris(&["  https://b/cb  ", "", "https://a/cb?x=1,2;3"]));
            assert_eq!(s.to_uris(), ["https://b/cb", "https://a/cb?x=1,2;3"]);
        });
    }

    #[test]
    fn an_empty_list_still_has_one_row_to_type_or_paste_into() {
        with_owner(|| {
            let s = UriListState::new(&[]);
            assert_eq!(s.rows.get_untracked().len(), 1);
            assert!(s.to_uris().is_empty());
        });
    }

    #[test]
    fn removing_the_only_row_clears_it_instead_of_emptying_the_list() {
        with_owner(|| {
            let s = UriListState::new(&uris(&["https://a/cb"]));
            let key = s.rows.get_untracked()[0].key;
            assert!(s.remove_row(key, "web redirect URI"));
            assert_eq!(s.rows.get_untracked().len(), 1);
            assert!(s.to_uris().is_empty());
            // Focus stays on the row that's still there, not on nothing.
            assert_eq!(s.focus_key.get_untracked(), Some(key));
        });
    }

    #[test]
    fn remove_drops_only_the_named_row() {
        with_owner(|| {
            let s = UriListState::new(&uris(&["https://a/cb", "https://b/cb", "https://c/cb"]));
            let keys: Vec<usize> = s.rows.get_untracked().iter().map(|r| r.key).collect();
            s.remove_row(keys[1], "web redirect URI");
            assert_eq!(s.to_uris(), ["https://a/cb", "https://c/cb"]);
        });
    }

    #[test]
    fn add_inserts_below_the_named_row_not_at_the_end() {
        with_owner(|| {
            let s = UriListState::new(&uris(&["https://a/cb", "https://c/cb"]));
            let first = s.rows.get_untracked()[0].key;
            s.add_row(Some(first), "web redirect URI");
            let added = s.rows.get_untracked()[1];
            added.value.set("https://b/cb".to_string());
            assert_eq!(
                s.to_uris(),
                ["https://a/cb", "https://b/cb", "https://c/cb"]
            );
            // The new row is the one that gets focus, so typing starts there.
            assert_eq!(s.focus_key.get_untracked(), Some(added.key));
        });
    }

    #[test]
    fn multiline_paste_fills_a_blank_row_then_inserts_below_it() {
        with_owner(|| {
            let s = UriListState::new(&uris(&["https://a/cb", ""]));
            let keys: Vec<usize> = s.rows.get_untracked().iter().map(|r| r.key).collect();
            s.insert_lines(
                keys[1],
                split_lines("https://b/cb\nhttps://c/cb\n\n"),
                "web redirect URI",
            );
            assert_eq!(
                s.to_uris(),
                ["https://a/cb", "https://b/cb", "https://c/cb"]
            );

            // Pasting into a row that already has content inserts *after* it,
            // so a paste never overwrites something already typed.
            let a = s.rows.get_untracked()[0].key;
            s.insert_lines(a, split_lines("https://x/cb"), "web redirect URI");
            assert_eq!(
                s.to_uris(),
                [
                    "https://a/cb",
                    "https://x/cb",
                    "https://b/cb",
                    "https://c/cb"
                ]
            );
        });
    }

    #[test]
    fn an_unvalidated_list_flags_duplicates_but_accepts_any_scheme() {
        with_owner(|| {
            // SAML Entity IDs are not redirect URIs: `urn:` is ordinary there,
            // and `redirect_uri_reason` rejects it. A list built with `new`
            // must not borrow those rules.
            let s = UriListState::new(&uris(&[
                "urn:contoso:saml:sp",
                "https://saml.contoso.com/sp",
                "urn:contoso:saml:sp",
            ]));
            let issues = s.issues.get_untracked();
            assert!(
                !issues
                    .iter()
                    .any(|(_, i)| matches!(i, RowIssue::Rejected(_)))
            );
            // Duplicates are structural, so they are still caught.
            assert!(
                issues
                    .iter()
                    .any(|(_, i)| matches!(i, RowIssue::Duplicate(1)))
            );
        });
    }

    #[test]
    fn every_offender_is_marked_not_just_the_first() {
        with_owner(|| {
            let s = UriListState::validated(
                &uris(&[
                    "https://ok.contoso.com/cb",
                    "https://*.bad.com/cb",
                    "http://app.contoso.com/cb",
                    "https://ok.contoso.com/cb",
                ]),
                redirect_uri_reason,
            );
            let issues = s.issues.get_untracked();
            // The backend reports one rejection per round trip; the editor marks
            // both — plus the exact repeat, which it only warns about.
            assert_eq!(
                issues
                    .iter()
                    .filter(|(_, i)| matches!(i, RowIssue::Rejected(_)))
                    .count(),
                2
            );
            assert!(
                issues
                    .iter()
                    .any(|(_, i)| matches!(i, RowIssue::Duplicate(1)))
            );
        });
    }
}
