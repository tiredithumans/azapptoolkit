//! Top-bar search bar. A debounced query hits the `global_search` Tauri command
//! for directory record hits (App Registrations / Enterprise Applications /
//! Managed Identities, each tagged with a [`TypeChip`]). Clicking a record — or
//! Arrow Up/Down + Enter — navigates to it and opens it in the workspace; the
//! record's name also seeds that list's filter (the search↔filter bridge).
//!
//! Cmd/Ctrl-K focuses the bar from anywhere. Above the record groups sits the
//! **"Go to" group**: a static, client-side table of the app's ~25 named
//! destinations (rail rows, account-menu items, and the Security / Resource
//! Access / Settings sub-tabs). Half of them — "Credential expiry", "SSO
//! certificates", "Delegated grants", "Mailboxes", "Vault access" — exist only
//! as a strip revealed *after* you already picked the right rail row, so
//! nothing in the app could find them by name. Each row routes through the
//! `Session` helper that already owns that destination (`set_view`,
//! `open_security`, `open_resource_access`, `open_settings`,
//! `open_credentials_with_facet`), so this adds no second way to get anywhere.
//! Actions are still deliberately absent: this is a jump list, not a command
//! palette.
//!
//! The dropdown says what it left out. The backend caps each kind at ten rows
//! and filters a corpus built from the capped service-principal index, so
//! without the per-group "10 of 47" footer and the index-cap `Callout` this is
//! the fastest input in the app *and* the one that can quietly lie: ten rows
//! reads as "there are ten", and a bare "No matches." reads as "not in this
//! tenant". Neither annotation is focusable or part of the roving selection —
//! see `render_group`.
//!
//! **The roving index spans both kinds.** Destinations are selectable, so
//! unlike the group footers they *do* enter `flatten_hits`, and the record
//! groups' indices shift by however many destination rows are on screen. Both
//! the rendered ids and the flattened list derive that shift from the same
//! `goto_rows` call over the same signal, so a keystroke can never leave
//! `aria-activedescendant` pointing at a row Enter won't open.

use leptos::ev;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::HtmlInputElement;

use crate::bindings::search::{self, GlobalSearchResults, SearchHit};
use crate::components::icon::{Icon, IconName};
use crate::components::index_cap_notice::index_cap_message;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::Callout;
use crate::hooks::use_debounced::use_debounced;
use crate::state::{ActiveView, OpenItemKind, use_session};

/// How many "Go to" rows the group renders before the footer takes over.
///
/// Bounded on purpose: a one-letter query matches most of the table, and a jump
/// list that buries the record hits under twenty destinations has swapped one
/// problem for another. The floor is the widest *deliberate* query — a parent's
/// name, which must show the parent plus all six of its sub-tabs rather than
/// silently dropping one. The footer names whatever is left over, exactly as a
/// capped record group does.
const GOTO_LIMIT: usize = 8;

#[component]
pub fn GlobalSearch() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 250);
    let focused = RwSignal::new(false);
    // Keyboard roving selection over the destination + record hits (Arrow/Enter).
    let selected = RwSignal::new(0usize);
    let input_ref = NodeRef::<leptos::html::Input>::new();

    // Reset the highlight whenever the query changes.
    Effect::new(move |_| {
        raw_query.track();
        selected.set(0);
    });

    // Window-level Cmd/Ctrl-K focuses the bar from anywhere.
    let handle = window_event_listener(ev::keydown, move |evt| {
        if (evt.meta_key() || evt.ctrl_key()) && evt.key().eq_ignore_ascii_case("k") {
            evt.prevent_default();
            if let Some(el) = input_ref.get() {
                let _ = el.focus();
            }
        }
    });
    on_cleanup(move || handle.remove());

    let results: LocalResource<Option<Result<GlobalSearchResults, String>>> =
        LocalResource::new(move || {
            let tenant = tenant.get();
            let q = query.get();
            async move {
                let trimmed = q.trim();
                if trimmed.is_empty() {
                    return None;
                }
                let t = tenant?;
                Some(
                    search::global_search(&t.tenant_id, trimmed)
                        .await
                        .map_err(|e| e.message),
                )
            }
        });

    // How many "Go to" rows are on screen — the record groups' roving base.
    // The destinations match the RAW query (a static table needs no round trip,
    // and a jump list that lagged the keystroke by a debounce would be the
    // wrong tool), while the records lag by the debounce plus the IPC. That is
    // fine and even expected, but it means the offset must be reactive: baking
    // it in at record-render time froze it at the query the *records* were
    // fetched for, and every keystroke after that pointed the ids at the wrong
    // rows until the next result landed.
    let goto_n = Memo::new(move |_| goto_rows(&raw_query.get()).0.len());

    // Flattened selectable rows (destinations → apps → enterprise → managed
    // identities, matching render order) for the keyboard roving selection —
    // read synchronously by the keydown handler. Derived from the same two
    // sources the rows render from (the raw query and the async `results`
    // resource), so it can never drift out of sync with what's on screen.
    // Mirrored into a plain signal via an Effect (rather than a derive the
    // keydown handler reads) so the handler always sees the current list
    // synchronously. Neither `hits` nor `goto_n` is a dependency of the
    // `results` resource, so setting them can't re-trigger the search.
    let hits: RwSignal<Vec<Pick>> = RwSignal::new(Vec::new());
    Effect::new(move |_| hits.set(flatten_hits(&raw_query.get(), results.get())));

    // Warm the search corpus when the bar takes focus (click or Cmd/Ctrl-K).
    // It is TTL'd and dropped by every app mutation, so a cold one made the
    // FIRST query wait on two full directory scans — the lag that reads as
    // "search hung". Warming here overlaps that rebuild with the operator
    // typing. Best-effort and idempotent: warm returns immediately, and the
    // backend single-flights the build, so a re-focus mid-build joins it rather
    // than starting a second one.
    let warm_corpus = move || {
        let Some(t) = tenant.get_untracked() else {
            return;
        };
        leptos::task::spawn_local(async move {
            let _ = search::prefetch_search_corpus(&t.tenant_id).await;
        });
    };

    let on_input = move |ev: ev::Event| {
        if let Some(target) = ev.target()
            && let Ok(input) = target.dyn_into::<HtmlInputElement>()
        {
            raw_query.set(input.value());
        }
    };

    let clear = move || raw_query.set(String::new());
    let blur = move || {
        if let Some(el) = input_ref.get() {
            let _ = el.blur();
        }
    };

    // Arrow keys rove destinations then records; Enter activates the highlight.
    let on_keydown = move |evt: ev::KeyboardEvent| match evt.key().as_str() {
        "ArrowDown" => {
            evt.prevent_default();
            let total = hits.with(Vec::len);
            if total > 0 {
                selected.update(|i| *i = (*i + 1) % total);
            }
        }
        "ArrowUp" => {
            evt.prevent_default();
            let total = hits.with(Vec::len);
            if total > 0 {
                selected.update(|i| *i = if *i == 0 { total - 1 } else { *i - 1 });
            }
        }
        "Enter" => {
            let sel = selected.get_untracked();
            if let Some(pick) = hits.with(|r| r.get(sel).cloned()) {
                evt.prevent_default();
                activate(session, &pick, raw_query);
                blur();
            }
        }
        "Escape" => {
            evt.prevent_default();
            clear();
            blur();
        }
        _ => {}
    };

    let dropdown_visible = Memo::new(move |_| !raw_query.get().trim().is_empty() && focused.get());

    view! {
        <div class="global-search">
            <label class="global-search__input">
                <span class="global-search__icon">
                    <Icon name=IconName::Search size=14 />
                </span>
                <input
                    node_ref=input_ref
                    type="text"
                    class="global-search__field"
                    role="combobox"
                    aria-autocomplete="list"
                    aria-controls="global-search-listbox"
                    aria-expanded=move || dropdown_visible.get().to_string()
                    aria-activedescendant=move || {
                        // The active row is whichever hit the roving index is on
                        // — a destination or a record; the two id prefixes are
                        // resolved from the flattened list, never guessed.
                        hits.with(|h| active_option_id(h, selected.get()))
                    }
                    placeholder="Search apps or jump to a page…"
                    prop:value=move || raw_query.get()
                    on:input=on_input
                    on:focus=move |_| {
                        focused.set(true);
                        warm_corpus();
                    }
                    on:blur=move |_| {
                        let win = web_sys::window();
                        if let Some(w) = win {
                            let cb = wasm_bindgen::closure::Closure::once_into_js(move || {
                                focused.set(false);
                            });
                            let _ = w
                                .set_timeout_with_callback_and_timeout_and_arguments_0(
                                    cb.unchecked_ref::<js_sys::Function>(),
                                    150,
                                );
                        }
                    }
                    on:keydown=on_keydown
                />
                // Clear (×) — shown only when the field has text. `mousedown` +
                // `prevent_default` so the click doesn't blur the input (which
                // would close the dropdown before the clear lands).
                {move || {
                    (!raw_query.get().is_empty())
                        .then(|| {
                            view! {
                                <button
                                    class="global-search__clear"
                                    type="button"
                                    tabindex="-1"
                                    aria-label="Clear search"
                                    title="Clear search"
                                    on:mousedown=move |ev| {
                                        ev.prevent_default();
                                        clear();
                                    }
                                >
                                    <Icon name=IconName::Close size=14 />
                                </button>
                            }
                        })
                }}
            </label>
            {move || {
                if !dropdown_visible.get() {
                    return ().into_any();
                }
                view! {
                    <div class="global-search__results" role="listbox" id="global-search-listbox">
                        // Destinations first, and outside the `Suspense`: they
                        // are a local table match, so making them wait on the
                        // directory search would be latency for nothing.
                        {move || {
                            let (rows, total) = goto_rows(&raw_query.get());
                            render_goto_group(rows, total, session, raw_query, selected)
                        }}
                        // Record hits (App Registrations / Enterprise Applications /
                        // Managed Identities), resolved from the async search.
                        <Suspense fallback=move || {
                            view! { <div class="global-search__empty">"Searching…"</div> }
                        }>
                            {move || Suspend::new(async move {
                                match results.await {
                                    None => view! {
                                        <div class="global-search__empty">
                                            "Type a name or GUID."
                                        </div>
                                    }
                                        .into_any(),
                                    Some(Err(msg)) => view! {
                                        <div class="global-search__empty">
                                            {format!("Search failed: {msg}")}
                                        </div>
                                    }
                                        .into_any(),
                                    Some(Ok(r)) => {
                                        view_results(r, session, raw_query, selected, goto_n)
                                    }
                                }
                            })}
                        </Suspense>
                    </div>
                }
                    .into_any()
            }}
        </div>
    }
}

fn view_results(
    results: GlobalSearchResults,
    session: crate::state::Session,
    raw_query: RwSignal<String>,
    selected: RwSignal<usize>,
    // Destination rows on screen above these groups — the roving base. A `Memo`
    // rather than a number because the destinations track the raw query while
    // these rows track the (debounced, async) search result.
    goto_n: Memo<usize>,
) -> leptos::prelude::AnyView {
    // The corpus this query filtered is itself a truncated view of the tenant,
    // so every answer below — "No matching records." emphatically included — is
    // a claim about a subset. Same cap, same warning, same wording as the three
    // inventory lists (`IndexCapNotice`); the sizing class is theirs too, so the
    // two truncation notices read as one thing said twice, not two things.
    let cap_notice = results.corpus_truncated.then(|| {
        view! {
            <Callout tone="warn" class="app-list__cap-notice">
                {index_cap_message(results.corpus_cap, "record")}
            </Callout>
        }
    });

    let empty = results.app_registrations.is_empty()
        && results.enterprise_apps.is_empty()
        && results.managed_identities.is_empty();
    if empty {
        // "records", not a bare "No matches": the "Go to" group above may well
        // have matched, and a flat denial over a list of visible hits is the
        // one thing worse than an over-broad claim.
        return view! {
            {cap_notice}
            <div class="global-search__empty">"No matching records."</div>
        }
        .into_any();
    }

    // Roving indices run across the groups: destinations, then apps, then
    // enterprise, then MIs. They count *rendered rows* only, so the group
    // footers below stay outside them by construction.
    let apps_n = results.app_registrations.len();
    let ent_n = results.enterprise_apps.len();
    view! {
        {cap_notice}
        {render_group(
            "App Registrations",
            AppKind::AppRegistration,
            results.app_registrations,
            results.app_registrations_total,
            session,
            raw_query,
            SelectionKind::AppReg,
            selected,
            goto_n,
            0,
        )}
        {render_group(
            "Enterprise Applications",
            AppKind::EnterpriseApp,
            results.enterprise_apps,
            results.enterprise_apps_total,
            session,
            raw_query,
            SelectionKind::EntApp,
            selected,
            goto_n,
            apps_n,
        )}
        {render_group(
            "Managed Identities",
            AppKind::ManagedIdentityUnknown,
            results.managed_identities,
            results.managed_identities_total,
            session,
            raw_query,
            SelectionKind::Mi,
            selected,
            goto_n,
            apps_n + ent_n,
        )}
    }
    .into_any()
}

/// The muted footer line for a group the backend capped, or `None` when every
/// match is already on screen.
///
/// `total` is the pre-cap match count; a stale or absent one (the field is
/// `#[serde(default)]`) reads as `0`, which is `<= shown` and so renders
/// nothing — the honest failure direction.
fn more_matches_label(shown: usize, total: usize) -> Option<String> {
    (total > shown).then(|| format!("{shown} of {total} — keep typing to narrow"))
}

// ------------------------------ Destinations ------------------------------

/// Where a "Go to" row lands.
///
/// Every variant routes through the [`crate::state::Session`] helper that
/// already owns that destination — the helpers encode ordering that matters
/// (`set_view` collapses the workspace overlay before the view swaps, and each
/// tab helper sets its tab *before* navigating), so a table that poked signals
/// directly would be a second, subtly different way to arrive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Route {
    /// A rail row or account-menu item.
    View(ActiveView),
    /// A Security workbench sub-tab.
    Security(&'static str),
    /// The Security workbench's Credential-expiry sub-tab, **unfiltered**. It
    /// is the one sub-tab that carries a facet across visits (Home's Credential
    /// Health metrics set it), and a destination reached by its name promises
    /// the whole tab — a leftover "≤ 7 days" chip would quietly answer a
    /// different question than the one that was typed.
    Credentials,
    /// A Resource Access tab.
    ResourceAccess(&'static str),
    /// A Settings tab.
    Settings(&'static str),
}

/// One named destination the operator can reach by typing its name.
struct Destination {
    /// The destination's on-screen label. Kept in step by hand: there is no
    /// shared constant to read a rail row's or `TabBarItem`'s label from, and
    /// drift here costs a missed match, never a wrong jump (the `route` is the
    /// address). One deliberate departure — "Key Vault (secrets)" — carries a
    /// disambiguating parenthetical the rail row itself has no room for.
    label: &'static str,
    /// The surface that contains it, or `""` for a top-level destination —
    /// rendered muted after the label. This is what makes "Mailboxes" and
    /// "Sites" addressable without knowing they live under Resource Access.
    context: &'static str,
    /// Extra match terms, **lowercase** (pinned by test — `match_rank` compares
    /// them without normalizing). Synonyms plus the question the destination
    /// answers, so the reverse lookups are findable by what they do and not
    /// only by what they are called.
    keywords: &'static str,
    icon: IconName,
    route: Route,
}

/// Every named destination, in rail → account-menu → sub-tab order. Equal-rank
/// matches keep this order (the sort is stable), so a rail row always precedes
/// the sub-tabs it contains.
///
/// The two Key Vaults are the reason this table needs a `context` at all: the
/// rail row is the secret *browser* and the Resource Access tab answers "who
/// can reach this vault?". They are now named apart on screen ("Vault access")
/// **and** here, and both still answer to the words "key vault".
const DESTINATIONS: &[Destination] = &[
    Destination {
        label: "Home",
        context: "",
        keywords: "overview dashboard start",
        icon: IconName::Home,
        route: Route::View(ActiveView::Home),
    },
    Destination {
        label: "App Registrations",
        context: "",
        keywords: "apps applications registrations inventory",
        icon: IconName::AppWindow,
        route: Route::View(ActiveView::Apps),
    },
    Destination {
        label: "Enterprise Applications",
        context: "",
        keywords: "service principals sso gallery inventory",
        icon: IconName::Building,
        route: Route::View(ActiveView::EnterpriseApps),
    },
    Destination {
        label: "Managed Identities",
        context: "",
        keywords: "mi msi system assigned user assigned inventory",
        icon: IconName::Server,
        route: Route::View(ActiveView::ManagedIdentities),
    },
    Destination {
        label: "Security",
        context: "",
        keywords: "audit posture risk scan workbench",
        icon: IconName::ShieldCheck,
        route: Route::View(ActiveView::Security),
    },
    Destination {
        label: "Permission Tester",
        context: "",
        keywords: "test access effective can this app reach",
        icon: IconName::Search,
        route: Route::View(ActiveView::PermissionTester),
    },
    Destination {
        label: "Resource Access",
        context: "",
        keywords: "reverse lookup who can reach this resource",
        icon: IconName::Database,
        route: Route::View(ActiveView::ResourceAccess),
    },
    Destination {
        label: "Bulk Actions",
        context: "",
        keywords: "batch multiple selection",
        icon: IconName::Wrench,
        route: Route::View(ActiveView::BulkActions),
    },
    Destination {
        label: "Disaster Recovery",
        context: "",
        keywords: "dr backup restore manifest estate",
        icon: IconName::Download,
        route: Route::View(ActiveView::DisasterRecovery),
    },
    Destination {
        label: "Key Vault (secrets)",
        context: "",
        keywords: "key vault secret browser reveal rotate",
        icon: IconName::Key,
        route: Route::View(ActiveView::KeyVault),
    },
    Destination {
        label: "Access Readiness",
        context: "",
        keywords: "roles scopes checklist what can i do consent",
        icon: IconName::CheckCircle,
        route: Route::View(ActiveView::Readiness),
    },
    Destination {
        label: "Settings",
        context: "",
        keywords: "preferences defaults options configuration",
        icon: IconName::Settings,
        route: Route::View(ActiveView::Settings),
    },
    // Security workbench sub-tabs.
    Destination {
        label: "Findings",
        context: "Security",
        keywords: "audit issues remediation groups",
        icon: IconName::ShieldAlert,
        route: Route::Security("findings"),
    },
    Destination {
        label: "All apps",
        context: "Security",
        keywords: "audit scores risk table every application",
        icon: IconName::ShieldCheck,
        route: Route::Security("apps"),
    },
    Destination {
        label: "Credential expiry",
        context: "Security",
        keywords: "secrets certificates expiring expired rotation",
        icon: IconName::Clock,
        route: Route::Credentials,
    },
    Destination {
        label: "SSO certificates",
        context: "Security",
        keywords: "saml signing certificate rollover",
        icon: IconName::Lock,
        route: Route::Security("sso-certificates"),
    },
    Destination {
        label: "Delegated grants",
        context: "Security",
        keywords: "consent oauth2 permission grants on behalf of a user",
        icon: IconName::ShieldCheck,
        route: Route::Security("grants"),
    },
    Destination {
        label: "Application permissions",
        context: "Security",
        keywords: "app roles app only assignments granted",
        icon: IconName::ShieldCheck,
        route: Route::Security("app-permissions"),
    },
    // Resource Access tabs.
    Destination {
        label: "Mailboxes",
        context: "Resource Access",
        keywords: "exchange who can read this mailbox reachers",
        icon: IconName::Database,
        route: Route::ResourceAccess("mailboxes"),
    },
    Destination {
        label: "Sites",
        context: "Resource Access",
        keywords: "sharepoint sites.selected who can touch this site",
        icon: IconName::Database,
        route: Route::ResourceAccess("sites"),
    },
    Destination {
        label: "Vault access",
        context: "Resource Access",
        keywords: "key vault azure rbac role assignments who can read this vault",
        icon: IconName::Database,
        route: Route::ResourceAccess("keyvault"),
    },
    // Settings tabs.
    Destination {
        label: "App Registration Defaults",
        context: "Settings",
        keywords: "default owners app registration",
        icon: IconName::Settings,
        route: Route::Settings("app-reg"),
    },
    Destination {
        label: "Enterprise Application Defaults",
        context: "Settings",
        keywords: "default owners sso notification emails",
        icon: IconName::Settings,
        route: Route::Settings("enterprise"),
    },
    Destination {
        label: "Naming Defaults",
        context: "Settings",
        keywords: "scope name pattern group name convention",
        icon: IconName::Settings,
        route: Route::Settings("naming"),
    },
    Destination {
        label: "Tenant connection",
        context: "Settings",
        keywords: "client id tenant id sign in endpoint",
        icon: IconName::Settings,
        route: Route::Settings("connection"),
    },
];

/// How well `d` matches `needle` (already trimmed, lowercased and non-empty),
/// lowest first, or `None` when it doesn't match at all.
///
/// Three tiers, because a shared word must not scramble the obvious answer:
/// "key" reaches "Key Vault (secrets)" by its label and "Vault access" only by
/// a keyword, so the label match has to sort first.
fn match_rank(d: &Destination, needle: &str) -> Option<u8> {
    let label = d.label.to_lowercase();
    if label.starts_with(needle) {
        return Some(0);
    }
    if label.contains(needle) {
        return Some(1);
    }
    if d.context.to_lowercase().contains(needle) || d.keywords.contains(needle) {
        return Some(2);
    }
    None
}

/// The "Go to" group's rows: the capped list actually rendered, plus the total
/// number of matches so the footer can name what was left off.
///
/// ONE definition on purpose. The roving index, `aria-activedescendant` and the
/// record groups' base offset are all derived from the capped list's *length*;
/// a second cap applied anywhere else would point Enter at a row that isn't on
/// screen.
fn goto_rows(query: &str) -> (Vec<&'static Destination>, usize) {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return (Vec::new(), 0);
    }
    let mut ranked: Vec<(u8, &'static Destination)> = DESTINATIONS
        .iter()
        .filter_map(|d| match_rank(d, &needle).map(|rank| (rank, d)))
        .collect();
    // Stable, so equal-rank destinations keep the table's order.
    ranked.sort_by_key(|(rank, _)| *rank);
    let total = ranked.len();
    ranked.truncate(GOTO_LIMIT);
    (ranked.into_iter().map(|(_, d)| d).collect(), total)
}

fn render_goto_group(
    rows: Vec<&'static Destination>,
    total: usize,
    session: crate::state::Session,
    raw_query: RwSignal<String>,
    selected: RwSignal<usize>,
) -> impl IntoView {
    if rows.is_empty() {
        return ().into_any();
    }
    let more = more_matches_label(rows.len(), total);
    view! {
        <div class="global-search__group-label">"Go to"</div>
        {rows
            .into_iter()
            .enumerate()
            .map(move |(idx, dest)| {
                // Destinations render first, so their roving index IS their
                // position in the group — the record groups are the ones that
                // shift.
                let route = dest.route;
                view! {
                    <button
                        class="global-search__row"
                        class:global-search__row--active=move || selected.get() == idx
                        type="button"
                        id=format!("gs-goto-{idx}")
                        role="option"
                        aria-selected=move || (selected.get() == idx).to_string()
                        on:mousedown=move |_| go_to(session, route, raw_query)
                        on:mouseenter=move |_| selected.set(idx)
                    >
                        <span class="global-search__row-icon">
                            <Icon name=dest.icon size=14 />
                        </span>
                        <span class="global-search__row-title">{dest.label}</span>
                        {(!dest.context.is_empty())
                            .then(|| {
                                view! {
                                    <span class="global-search__row-hint">{dest.context}</span>
                                }
                            })}
                    </button>
                }
            })
            .collect_view()}
        // Capped-group footer — same construction (and the same reason) as the
        // record groups': a plain `role="presentation"` div, outside the option
        // set, because `flatten_hits` never sees it.
        {more
            .map(|text| {
                view! {
                    <div class="global-search__empty global-search__more" role="presentation">
                        {text}
                    </div>
                }
            })}
    }
    .into_any()
}

#[derive(Clone, Copy)]
enum SelectionKind {
    AppReg,
    EntApp,
    Mi,
}

/// One selectable dropdown row, in render order: the "Go to" destinations, then
/// the three record groups. Group footers and the cap `Callout` are deliberately
/// not representable here — they are not activatable, so they must not occupy a
/// roving index.
#[derive(Clone)]
enum Pick {
    Goto(&'static Destination),
    Record(SelectionKind, SearchHit),
}

/// The DOM id of the row the roving index is on, for `aria-activedescendant`,
/// or `""` when nothing is selectable.
///
/// Resolved from the flattened list rather than assumed: the two row kinds carry
/// different id prefixes, and formatting one prefix unconditionally (as this did
/// when records were the only rows) would announce a `gs-rec-…` element that
/// doesn't exist as soon as a destination is highlighted.
fn active_option_id(hits: &[Pick], selected: usize) -> String {
    match hits.get(selected) {
        Some(Pick::Goto(_)) => format!("gs-goto-{selected}"),
        Some(Pick::Record(..)) => format!("gs-rec-{selected}"),
        None => String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn render_group(
    label: &'static str,
    chip_kind: AppKind,
    hits: Vec<SearchHit>,
    // Matches in this bucket BEFORE the backend's per-kind cap, so the footer
    // can name what was left off.
    total: usize,
    session: crate::state::Session,
    raw_query: RwSignal<String>,
    selection: SelectionKind,
    selected: RwSignal<usize>,
    // Destination rows above every record group (reactive — they track the raw
    // query, these rows track the resolved search).
    goto_n: Memo<usize>,
    // This group's offset among the record groups (apps = 0, then enterprise,
    // then MIs).
    offset: usize,
) -> impl IntoView {
    if hits.is_empty() {
        return ().into_any();
    }
    let more = more_matches_label(hits.len(), total);
    view! {
        <div class="global-search__group-label">{label}</div>
        {hits
            .into_iter()
            .enumerate()
            .map(move |(i, hit)| {
                // Roving index: destinations, then this group's offset, then the
                // row. Computed per read rather than captured, so a keystroke
                // that changes the destination count re-labels these rows in the
                // same tick `flatten_hits` re-indexes them.
                let idx = move || goto_n.get() + offset + i;
                let app_id = hit.app_id.clone();
                let display = hit.display_name.clone();
                let hit_for_pick = hit.clone();
                view! {
                    <button
                        class="global-search__row"
                        class:global-search__row--active=move || selected.get() == idx()
                        type="button"
                        id=move || format!("gs-rec-{}", idx())
                        role="option"
                        aria-selected=move || (selected.get() == idx()).to_string()
                        on:mousedown=move |_| pick_hit(session, &hit_for_pick, selection, raw_query)
                        on:mouseenter=move |_| selected.set(idx())
                    >
                        <TypeChip kind=chip_kind compact=true />
                        <span class="global-search__row-title">{display}</span>
                        <span class="global-search__row-appid">
                            {app_id.unwrap_or_default()}
                        </span>
                    </button>
                }
            })
            .collect_view()}
        // Capped-group footer. Deliberately a plain div, not a `<button
        // role="option">`: the combobox drives `aria-activedescendant` and its
        // Arrow/Enter roving index off `flatten_hits`, which sees only the
        // destination table and the hit vectors, so anything that entered the
        // option set here would either desynchronize the two or hand the
        // operator an "Enter" that opens nothing. `role="presentation"` states
        // that to assistive tech as well, while leaving the text itself readable.
        {more
            .map(|text| {
                view! {
                    <div class="global-search__empty global-search__more" role="presentation">
                        {text}
                    </div>
                }
            })}
    }
    .into_any()
}

/// Flattens the dropdown's selectable rows into one ordered list — the capped
/// "Go to" destinations for `query`, then apps, enterprise apps and managed
/// identities (matching render order) — for the keyboard roving selection.
fn flatten_hits(
    query: &str,
    results: Option<Option<Result<GlobalSearchResults, String>>>,
) -> Vec<Pick> {
    let (destinations, _) = goto_rows(query);
    let mut out: Vec<Pick> = destinations.into_iter().map(Pick::Goto).collect();
    let Some(Some(Ok(r))) = results else {
        return out;
    };
    out.reserve(r.app_registrations.len() + r.enterprise_apps.len() + r.managed_identities.len());
    out.extend(
        r.app_registrations
            .into_iter()
            .map(|h| Pick::Record(SelectionKind::AppReg, h)),
    );
    out.extend(
        r.enterprise_apps
            .into_iter()
            .map(|h| Pick::Record(SelectionKind::EntApp, h)),
    );
    out.extend(
        r.managed_identities
            .into_iter()
            .map(|h| Pick::Record(SelectionKind::Mi, h)),
    );
    out
}

/// Activates the highlighted row, whichever kind it is. Shared by the keyboard
/// Enter dispatch and (via the two `mousedown` handlers) the pointer, so both
/// behave identically.
fn activate(session: crate::state::Session, pick: &Pick, raw_query: RwSignal<String>) {
    match pick {
        Pick::Goto(dest) => go_to(session, dest.route, raw_query),
        Pick::Record(kind, hit) => pick_hit(session, hit, *kind, raw_query),
    }
}

/// Navigates to a "Go to" destination through the `Session` helper that owns it.
fn go_to(session: crate::state::Session, route: Route, raw_query: RwSignal<String>) {
    match route {
        Route::View(view) => session.set_view(view),
        Route::Security(tab) => session.open_security(tab),
        Route::Credentials => session.open_credentials_with_facet("all"),
        Route::ResourceAccess(tab) => session.open_resource_access(tab),
        Route::Settings(tab) => session.open_settings(tab),
    }
    raw_query.set(String::new());
}

/// Opens a picked record: switches to its list view, opens it in the workspace,
/// and seeds that list's filter with its name (the search↔filter bridge). Shared
/// by the row mouse handler and the keyboard Enter dispatch so both behave
/// identically.
fn pick_hit(
    session: crate::state::Session,
    hit: &SearchHit,
    selection: SelectionKind,
    raw_query: RwSignal<String>,
) {
    let id = hit.id.clone();
    let name = hit.display_name.clone();
    match selection {
        SelectionKind::AppReg => {
            session.set_view(ActiveView::Apps);
            session.tenant_ui.apps_search.set(name.clone());
            session.open_item(OpenItemKind::AppReg, id, name);
        }
        SelectionKind::EntApp => {
            session.set_view(ActiveView::EnterpriseApps);
            session.tenant_ui.enterprise_search.set(name.clone());
            session.open_item(OpenItemKind::Enterprise, id, name);
        }
        SelectionKind::Mi => {
            session.set_view(ActiveView::ManagedIdentities);
            session.tenant_ui.mi_search.set(name.clone());
            session.open_item(OpenItemKind::ManagedIdentity, id, name);
        }
    }
    raw_query.set(String::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(name: &str) -> SearchHit {
        SearchHit {
            id: name.into(),
            app_id: None,
            display_name: name.into(),
        }
    }

    /// Names of the destinations `query` would render, in order.
    fn goto_labels(query: &str) -> Vec<&'static str> {
        goto_rows(query).0.iter().map(|d| d.label).collect()
    }

    fn record_results() -> Option<Option<Result<GlobalSearchResults, String>>> {
        Some(Some(Ok(GlobalSearchResults {
            query: String::new(),
            looked_up_as_guid: false,
            app_registrations: vec![hit("a-app")],
            enterprise_apps: vec![hit("b-ent")],
            managed_identities: vec![hit("c-mi")],
            ..Default::default()
        })))
    }

    #[test]
    fn flatten_hits_orders_apps_then_enterprise_then_mi() {
        // A query matching no destination leaves the record order — and the
        // record roving indices — exactly as they were before the "Go to" group.
        let flat = flatten_hits("zqx", record_results());
        let names: Vec<&str> = flat
            .iter()
            .map(|p| match p {
                Pick::Record(_, h) => h.display_name.as_str(),
                Pick::Goto(d) => d.label,
            })
            .collect();
        assert_eq!(names, ["a-app", "b-ent", "c-mi"]);
        assert!(matches!(&flat[0], Pick::Record(SelectionKind::AppReg, _)));
        assert!(matches!(&flat[1], Pick::Record(SelectionKind::EntApp, _)));
        assert!(matches!(&flat[2], Pick::Record(SelectionKind::Mi, _)));
    }

    #[test]
    fn flatten_hits_puts_destinations_before_every_record() {
        // Render order is destinations → apps → enterprise → MIs, and the
        // roving index is that order: a destination can never sort below a
        // record, or Arrow would walk the dropdown in an order the eye doesn't
        // see. "Naming Defaults" is a single-destination match, so the record
        // rows shift by exactly one.
        let flat = flatten_hits("naming", record_results());
        assert!(matches!(&flat[0], Pick::Goto(d) if d.label == "Naming Defaults"));
        assert_eq!(flat.len(), 4);
        assert!(
            flat[1..].iter().all(|p| matches!(p, Pick::Record(..))),
            "records must follow the destinations, never interleave",
        );
    }

    #[test]
    fn flatten_hits_ignores_the_capped_group_footers() {
        // The footers are not hits: they must never enter the flattened list the
        // roving index and `aria-activedescendant` are driven from, or Arrow
        // would stop on a row Enter can't open. Totals far above the rendered
        // counts is exactly the capped case.
        let results = Some(Some(Ok(GlobalSearchResults {
            query: String::new(),
            looked_up_as_guid: false,
            app_registrations: vec![hit("a-app")],
            enterprise_apps: vec![hit("b-ent")],
            managed_identities: Vec::new(),
            app_registrations_total: 47,
            enterprise_apps_total: 12,
            corpus_truncated: true,
            corpus_cap: 10_000,
            ..Default::default()
        })));
        assert_eq!(flatten_hits("zqx", results).len(), 2);
    }

    #[test]
    fn flatten_hits_caps_the_goto_group_and_drops_its_footer_too() {
        // "s" matches most of the table; the flattened list must hold exactly
        // the rows that render — the cap — and not the footer that names the
        // rest.
        let (rows, total) = goto_rows("s");
        assert_eq!(rows.len(), GOTO_LIMIT);
        assert!(
            total > GOTO_LIMIT,
            "the fixture query must actually overflow"
        );
        assert_eq!(flatten_hits("s", None).len(), GOTO_LIMIT);
        let footer = format!("{GOTO_LIMIT} of {total} — keep typing to narrow");
        assert_eq!(
            more_matches_label(rows.len(), total).as_deref(),
            Some(footer.as_str()),
        );
    }

    #[test]
    fn more_matches_label_only_speaks_when_rows_were_dropped() {
        // The finding: ten rows and a full stop is read as "there are ten", so a
        // capped group must say so — and an uncapped one must stay silent rather
        // than adding noise to every search.
        assert_eq!(
            more_matches_label(10, 47).as_deref(),
            Some("10 of 47 — keep typing to narrow"),
        );
        assert_eq!(more_matches_label(3, 3), None);
        // A missing total (`#[serde(default)]`, e.g. an older payload) reads as
        // 0 and stays silent — the honest direction to fail.
        assert_eq!(more_matches_label(3, 0), None);
    }

    #[test]
    fn flatten_hits_holds_only_destinations_for_loading_and_error_states() {
        // The destination table is local, so it answers while the directory
        // search is still in flight — or has failed outright, which is exactly
        // when being able to jump somewhere else matters most.
        assert!(flatten_hits("zqx", None).is_empty()); // resource still loading
        assert!(flatten_hits("zqx", Some(None)).is_empty()); // empty query
        assert!(flatten_hits("zqx", Some(Some(Err("boom".into())))).is_empty());
        assert_eq!(flatten_hits("naming", None).len(), 1);
        assert_eq!(
            flatten_hits("naming", Some(Some(Err("boom".into())))).len(),
            1,
        );
    }

    #[test]
    fn a_label_match_outranks_a_keyword_match() {
        // "key" names the rail's secret browser outright; Resource Access's
        // "Vault access" answers to it only through its keywords, so it must
        // sort second — otherwise a shared word buries the obvious answer.
        let labels = goto_labels("key");
        assert_eq!(labels.first().copied(), Some("Key Vault (secrets)"));
        assert!(labels.contains(&"Vault access"));
    }

    #[test]
    fn the_two_key_vault_destinations_are_named_apart() {
        // The finding: one rail row and one Resource Access tab were both called
        // "Key Vault", with nothing on screen to say which answered which
        // question. Both must still be reachable by the words "key vault", and
        // no two destinations may share a rendered identity.
        let labels = goto_labels("key vault");
        assert!(labels.contains(&"Key Vault (secrets)"));
        assert!(labels.contains(&"Vault access"));
        let mut identities: Vec<(&str, &str)> =
            DESTINATIONS.iter().map(|d| (d.label, d.context)).collect();
        identities.sort_unstable();
        let before = identities.len();
        identities.dedup();
        assert_eq!(
            before,
            identities.len(),
            "two destinations read identically"
        );
    }

    #[test]
    fn a_sub_tab_is_reachable_by_its_own_name_and_by_its_parents() {
        // The whole point of NAV-04: these six existed only as a strip revealed
        // after the operator had already guessed the right rail row.
        for (name, context) in [
            ("Credential expiry", "Security"),
            ("SSO certificates", "Security"),
            ("Delegated grants", "Security"),
            ("Mailboxes", "Resource Access"),
            ("Sites", "Resource Access"),
            ("Tenant connection", "Settings"),
        ] {
            assert!(
                goto_labels(name).contains(&name),
                "{name} is not reachable by its own name",
            );
            assert!(
                goto_labels(context).contains(&name),
                "{name} is not reachable by its parent, {context}",
            );
        }
    }

    #[test]
    fn every_destination_keyword_is_lowercase() {
        // `match_rank` lowercases the needle and the label/context but compares
        // `keywords` raw (they are hand-authored, so normalizing them at every
        // keystroke would be work for nothing) — a capitalized keyword would
        // silently never match.
        for d in DESTINATIONS {
            assert_eq!(
                d.keywords,
                d.keywords.to_lowercase(),
                "{} has a non-lowercase keyword",
                d.label,
            );
        }
    }

    #[test]
    fn active_option_id_names_the_row_kind_it_points_at() {
        // `aria-activedescendant` must name an element that exists: the two row
        // kinds carry different id prefixes, and the index is global across both.
        let hits = flatten_hits("naming", record_results());
        assert_eq!(active_option_id(&hits, 0), "gs-goto-0");
        assert_eq!(active_option_id(&hits, 1), "gs-rec-1");
        assert_eq!(active_option_id(&hits, 99), "");
        assert_eq!(active_option_id(&[], 0), "");
    }

    #[test]
    fn every_destination_routes_somewhere_a_session_helper_owns() {
        // A route is the destination's real address (the label is only what the
        // operator types), so an empty tab key would navigate to the parent
        // view's default tab and quietly answer the wrong question.
        for d in DESTINATIONS {
            match d.route {
                Route::View(_) | Route::Credentials => {}
                Route::Security(tab) | Route::ResourceAccess(tab) | Route::Settings(tab) => {
                    assert!(!tab.is_empty(), "{} routes to an unnamed tab", d.label);
                }
            }
        }
    }
}
