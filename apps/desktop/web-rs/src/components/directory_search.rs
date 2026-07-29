//! One debounced tenant-directory search-and-pick list.
//!
//! Every "type 2+ characters, get `DirectoryObject`s back, click a row to act on
//! one" surface in the app is this component with different props: the Settings
//! default-owner editors, the Settings SSO-notification distribution-list
//! picker, the Exchange scope forms' group typeahead, and both search blocks on
//! the enterprise Access tab. Before this there were four hand-rolled copies of
//! the same 60 lines — same 300 ms debounce, same 2-char gate, same
//! `Suspense` + "Searching…" spinner, same `.candidates` markup — which had
//! already drifted apart in three ways (see below).
//!
//! **The primitive never mutates anything.** It hands the picked
//! `DirectoryObject` to the caller through `on_pick`. That is deliberately the
//! more general of the two contracts it replaced: a caller holding the whole
//! object can derive a display name (the group typeahead), an object id (the
//! Access tab), or a mail address (the DL picker) — none of which can
//! reconstruct the object. It is also what lets one component back three
//! different follow-ups: a direct callback, a text-field append, and a
//! set-pending-then-confirm dialog flow.

use std::collections::HashSet;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::applications;
use crate::hooks::use_debounced::use_debounced;
use crate::state::use_session;

/// Trimmed **byte** length a query must reach before a search fires — which is
/// what all four extracted copies used. (`gallery_dialog.rs` deliberately counts
/// `chars()` instead, to match a backend char gate; that search is a different
/// shape and is not folded in here.)
const MIN_QUERY_LEN: usize = 2;
const DEBOUNCE_MS: i32 = 300;

/// Which directory the search hits, and how a result row is subtitled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DirectoryScope {
    #[default]
    Users,
    Groups,
    /// Mail-enabled groups only. Rows without a `mail` address are dropped
    /// *before* the empty check, so a page of mailless groups reads "No
    /// matches." rather than rendering an empty list.
    DistributionLists,
}

impl DirectoryScope {
    /// Second line of a result row — the disambiguator for objects whose
    /// display names collide.
    fn subtitle(self, o: &DirectoryObject) -> String {
        match self {
            Self::Users => o
                .user_principal_name
                .clone()
                .unwrap_or_else(|| o.id.clone()),
            Self::Groups => o.id.clone(),
            Self::DistributionLists => o.mail.clone().unwrap_or_else(|| o.id.clone()),
        }
    }

    /// Rows this scope refuses to show at all.
    fn admits(self, o: &DirectoryObject) -> bool {
        match self {
            Self::DistributionLists => o.mail.is_some(),
            Self::Users | Self::Groups => true,
        }
    }
}

#[component]
pub fn DirectorySearch(
    /// Fired with the picked object. The **caller** owns the mutation.
    on_pick: Callback<DirectoryObject>,

    /// A `Signal`, not a plain value, so the Access tab can drive it from its
    /// Users/Groups `TabBar` and have the search re-run. Pass
    /// `Signal::derive(|| DirectoryScope::Groups)` for a fixed scope.
    #[prop(into, optional, default = Signal::derive(|| DirectoryScope::Users))]
    scope: Signal<DirectoryScope>,

    /// Ids hidden from results so they can't be picked twice. Reactive, so the
    /// list re-filters without the parent re-rendering.
    #[prop(into, optional, default = Signal::derive(HashSet::new))]
    exclude: Signal<HashSet<String>>,

    /// The text-box signal. Defaults to a private one; pass your own when the
    /// box must be cleared from **outside** — both Access-tab blocks clear only
    /// after their mutation round trip returns `Ok`.
    #[prop(optional)]
    query: Option<RwSignal<String>>,

    /// `Some` wraps the input in a `<Field label=…>`; `None` renders a bare
    /// `<Input>` — the shape the scope wizard's typeahead needs, where an extra
    /// wrapper would break the surrounding flex column.
    #[prop(optional, into)]
    label: Option<String>,

    #[prop(optional, into, default = String::from("Search the directory…"))] placeholder: String,

    /// Row action button text: "Add" everywhere except the Access tab's
    /// "Assign".
    #[prop(optional, into, default = String::from("Add"))]
    action_label: String,

    #[prop(optional, into, default = Signal::derive(|| ButtonAppearance::Primary))]
    action_appearance: Signal<ButtonAppearance>,

    /// Per-row disable, given the candidate's id. Covers both in-tree shapes:
    /// the assignments block compares the id against its in-flight signal, the
    /// group-membership block ignores the id and returns one global flag.
    #[prop(optional)]
    row_disabled: Option<Callback<String, bool>>,

    /// Clear the box the moment a row is picked. `true` for callers that act
    /// synchronously; `false` for the two that clear only on mutation success
    /// (those pass their own `query` and clear it themselves).
    #[prop(optional, default = true)]
    clear_on_pick: bool,

    /// Render "No matches." when a long-enough query returns nothing. `false`
    /// reproduces the group typeahead's render-nothing behaviour.
    #[prop(optional, default = true)]
    show_no_matches: bool,

    /// Optional wrapper class. `None` emits no wrapper element at all.
    #[prop(optional)]
    class: Option<&'static str>,
) -> impl IntoView {
    let session = use_session();
    let raw_query = query.unwrap_or_else(|| RwSignal::new(String::new()));
    let debounced = use_debounced(raw_query.into(), DEBOUNCE_MS);
    // Captured by the row closure, which must be `Fn`.
    let action_label = StoredValue::new(action_label);

    // Switching scope clears the box. The resource already re-runs on `scope`,
    // so this is not for correctness — searching the group directory for a
    // half-typed person's name returns nothing useful, so the box starts clean.
    // Single-scope callers pass a constant signal and never see this fire.
    Effect::new(move |prev: Option<DirectoryScope>| {
        let s = scope.get();
        // Skip the first run: there is nothing to reset on mount, and clearing
        // would discard a query the caller may have seeded.
        if prev.is_some_and(|p| p != s) {
            raw_query.set(String::new());
        }
        s
    });

    // The scope travels *with* the results, so a row rendered from an in-flight
    // request is never subtitled using a scope the user has since switched away
    // from.
    let candidates = LocalResource::new(move || {
        let q = debounced.get();
        let tenant = session.active_tenant.get();
        let scope = scope.get();
        async move {
            let q = q.trim().to_string();
            if q.len() < MIN_QUERY_LEN {
                return Ok::<(DirectoryScope, Vec<DirectoryObject>), String>((scope, Vec::new()));
            }
            let Some(t) = tenant else {
                return Ok((scope, Vec::new()));
            };
            let found = match scope {
                DirectoryScope::Users => applications::search_users(&t.tenant_id, &q).await,
                DirectoryScope::Groups => applications::search_groups(&t.tenant_id, &q).await,
                DirectoryScope::DistributionLists => {
                    applications::search_distribution_lists(&t.tenant_id, &q).await
                }
            };
            found.map(|v| (scope, v)).map_err(|e| e.message)
        }
    });

    let input = match label {
        Some(l) => view! {
            <Field label=l>
                <Input value=raw_query placeholder=placeholder />
            </Field>
        }
        .into_any(),
        None => view! { <Input value=raw_query placeholder=placeholder /> }.into_any(),
    };

    let results = move || {
        // Gated on the RAW query, not the debounced one, for two reasons: the
        // result region disappears the instant the box is cleared instead of
        // leaving a stale list up for 300 ms, and an *empty* box renders
        // nothing at all. Two of the copies this replaced showed a bare "No
        // matches." under an untouched search field, because their empty-check
        // could not tell "searched and found none" from "hasn't searched yet".
        if raw_query.get().trim().len() < MIN_QUERY_LEN {
            return ().into_any();
        }
        view! {
            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Searching…" /> }
            }>
                {move || Suspend::new(async move {
                    let (scope, found) = match candidates.await {
                        Ok(v) => v,
                        Err(msg) => {
                            return view! {
                                <Body1 class="form-error">{format!("Search failed: {msg}")}</Body1>
                            }
                                .into_any();
                        }
                    };
                    let ex = exclude.get();
                    let found: Vec<DirectoryObject> = found
                        .into_iter()
                        .filter(|o| scope.admits(o) && !ex.contains(&o.id))
                        .collect();
                    if found.is_empty() {
                        return if show_no_matches {
                            view! { <Body1>"No matches."</Body1> }.into_any()
                        } else {
                            ().into_any()
                        };
                    }
                    view! {
                        // `.candidates li` is `justify-content: space-between`
                        // over exactly two flex children — the identity block
                        // and the action. Keep it at two.
                        <ul class="candidates">
                            {found
                                .into_iter()
                                .map(|o| {
                                    let picked = o.clone();
                                    let id = o.id.clone();
                                    let display = o
                                        .display_name
                                        .clone()
                                        .unwrap_or_else(|| o.id.clone());
                                    let subtitle = scope.subtitle(&o);
                                    view! {
                                        <li>
                                            <div>
                                                <div>{display}</div>
                                                <div class="mono small">{subtitle}</div>
                                            </div>
                                            <Button
                                                appearance=action_appearance
                                                disabled=Signal::derive(move || {
                                                    row_disabled.is_some_and(|f| f.run(id.clone()))
                                                })
                                                on_click=Box::new(move |_| {
                                                    on_pick.run(picked.clone());
                                                    if clear_on_pick {
                                                        raw_query.set(String::new());
                                                    }
                                                })
                                            >
                                                {action_label.get_value()}
                                            </Button>
                                        </li>
                                    }
                                })
                                .collect_view()}
                        </ul>
                    }
                        .into_any()
                })}
            </Suspense>
        }
        .into_any()
    };

    match class {
        Some(c) => view! {
            <div class=c>
                {input}
                {results}
            </div>
        }
        .into_any(),
        None => view! {
            {input}
            {results}
        }
        .into_any(),
    }
}
