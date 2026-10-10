# Frontend workspace, session state & UI primitives

Deep-dive companion to the frontend gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `web-rs/src/state/` (the `Session` struct in `mod.rs`, its impl split by concern into
`tenant.rs` / `navigation.rs` / `open_items.rs` / `toasts.rs` / `errors.rs`), the shell, the list
views, the open-items workspace, or the Security workbench's panes.

## Reactivity conventions

Leptos reactivity is closure-based: `{move || sig.get()}` inside `view!` for tracking,
`.get()`/`.with()` to read. Shared state is `RwSignal<T>` fields on a context-provided `Session`
(`web-rs/src/state/mod.rs`). CSS is one plain global `styles.css` with BEM-ish class names — no
CSS-in-Rust, no per-component stylesheets. Every class selector in it must be rendered somewhere in
`src/` (or be a `thaw-*` override, or a modifier built by `format!("{base}--{…}")`), and every
`var(--token)` it uses must be declared in it — a fallback does not excuse an undefined token, which
renders transparent. Both are pinned by `web-rs/tests/stylesheet_coverage.rs`, so a rule whose
component is gone is deleted with it.

**A command's result can land after its component is gone.** Sign-out clears the tenant and
unmounts the whole authed shell; closing a pane disposes its tabs. Reading a disposed signal or
`.run(`-ing a disposed `Callback` panics the window, so after an await: check the tenant the call
started for (`Session::is_active_tenant`) and land nothing if it changed, since a toast would
otherwise carry into the next sign-in; on the same tenant, skip the component-local writes once
it is disposed but keep the session-level effects (toasts, re-auth prompts, a session-owned
selection), and call callbacks with `try_run`. `CommandState::land` does this for every
`use_command` runner (an `on_err` whose view is gone goes to the session's sink); the bulk bar's
`Landing` does it for its runs. Hand-spawned tasks use `.try_run(` after an await, pinned by
`web-rs/tests/post_await_callbacks.rs`.

## One primitive per UI pattern

The design-consistency invariant: every recurring UI pattern has exactly one primitive, and new
surfaces reuse it rather than re-implementing the markup.

- **Page header** — `components::ui::SectionHeader` (uppercase category crumb + title), app-wide.
  There is no `.view-header` class. The two list views own their `SectionHeader` above a titleless
  `ListScaffold` — `ListScaffold` takes no `title`/`actions` props; the card starts at its search
  box.
- **Loading** — skeletons for content regions (`SkeletonList` / `DetailSkeleton`); spinners are
  reserved for in-button / inline busy states only.
- **Load failure** — `DetailLoadError`, the universal "message + Retry" block (detail panes and
  their tabs/sections, all three list views, dashboard cards). Pass `on_retry: Callback<()>` plus a
  context `class`. A `Suspend` `Err` arm never renders `form-error` / `FormError` directly — pinned
  by `repo_invariants/commands.rs`, with a reasoned exemption list for the typed searches whose
  `String` error it cannot take.
- **Inline error** — `components::ui::FormError` (`.form-error` + `role="alert"`, so an error that
  appears after an action is announced); `DetailLoadError` uses it for its message. Never write
  `<Body1 class="form-error">` by hand — pinned by `repo_invariants/commands.rs`.
- **Notices/alerts** — `components::ui::Callout` (`info`/`ok`/`warn`/`danger`, reusing the `.alert`
  classes). New alert markup goes through it; migrate any raw `<div class="alert alert--…">` you
  touch.
- **Status pills** — `components::ui::Badge` with a typed `BadgeTone` (`Neutral`/`Ok`/`Info`/
  `Warning`/`Danger`/`Critical`/`Unknown`); a status helper returns a `BadgeTone`, never a class
  string. The `.badge` classes are spelled only in `badge.rs`, whose test proves every tone has a
  stylesheet rule (`badge--info` once shipped without one); pinned by `repo_invariants/commands.rs`.
- **Tables** — `DataTable`, which brings keyboard row navigation (roving tabindex, ↑ ↓ / Home /
  End, Enter on the row's first button) plus the empty state; pass `""` for an action column. A
  keyed `<For>` table that can't use it wires `use_grid_keynav` on its `<tbody>` (the Permissions
  tab, `resource_access/sites.rs`). Every `<table` in `web-rs/src` needs its own keynav call —
  pinned by `repo_invariants/commands.rs`, with a reasoned exemption list for non-grid tables.
- **Empty states** — a table's empty is `DataTable`'s `empty_message`; a whole section/pane with
  nothing to show is `EmptyState`; never a bare `<Body1>`. `.muted` (colour only) and `.hint`
  (smaller field-hint size) are different jobs — don't merge them.
- **Repeatable list-of-values field** — `components::uri_list_editor::UriListEditor`, backed by a
  `Copy` `UriListState` the parent builds from its DTO and reads back with `to_uris()` (pure
  presentation + state; the caller owns the save). One plain `<input>` per entry inside a
  `<ul>`/`<li>` under `role="group"` + `aria-labelledby` — **not** a thaw `<Field>`, which mints
  one id and injects it into every descendant input, so N rows would share a DOM id, and **not**
  a thaw `<Input>`: its bordered/rounded box with an animated brand underline is right for a
  standalone field and wrong for forty stacked rows, and overriding it means out-specificity-ing
  rules thaw injects into `<head>` at runtime. The row owns its control, styled flat like a
  `.data-table` row with the affordance revealed on hover/focus. Rows are keyed by a stable
  `usize`, never by index, or an insert next to the caret drops focus mid-keystroke. A multi-line
  paste splits into rows — newlines only, because a redirect URI may legally contain `,` or `;`.
  **Validation is per-list and opt-in** (`UriListState::validated` + a `UriValidator` fn pointer):
  reply URLs and redirect URIs take `redirect_uri_reason` (the backend's own
  `core::redirect::validate_redirect_uri`); SAML **identifiers do not** — a bare `urn:` Entity ID
  is ordinary there and the redirect rules reject `urn:` on purpose, so one shared validator would
  red-bar a correct SAML config. It is **advisory** either way: it points at the offender before
  the round trip — the backend `?`s out of its loop and reports only the first — but never gates
  Save, because a client rule that drifted from the server's would make an object unsavable
  through the UI. Focus after add/remove/paste is handed over via a `focus_key` signal the target
  row claims from its own effect, **never** `request_animation_frame` — rAF does not fire in a
  hidden tab, so it works only while someone is watching and would flake the headless browser
  gate. Add/remove/paste announce through one `role="status"` line per list; the entry count is
  deliberately NOT live (it tracks row values, so it would fire on every keystroke). Used by the
  App Registration Authentication tab (3 lists) and the enterprise SSO tab (5); don't reintroduce
  a newline-separated `<Textarea>` for a set of values. `sso_wizard_dialog.rs` is the one
  remaining migration.
- **Large copyable value (certificate / one-time secret)** — `components::ui::CopyBlock`: label,
  optional hint, `pre.secret-reveal`, and a Copy button that rides `util::write_clipboard` and
  reports a failed clipboard write instead of claiming "Copied". Used by the SSO owner summaries
  and the SSO tab's staged / rotated certificate reveals; don't hand-roll a `pre` plus a clipboard
  call.
- **Select / dropdown** — `.ui-select` (a class, not a component: these are bare `<select>`s
  inside a thaw `Field`). Metrics match the thaw input/button they sit beside, chevron is an
  inline-SVG data URI because the CSP forbids fetching one, and the stroke colour is baked into
  the URI so the dark-mode override swaps the whole image — keep the two in sync. `:root` also
  sets `color-scheme`, which is the only thing that reaches the OS-drawn popup list and the
  scrollbars; without it they render light on a dark page.
- **Pick-one-of-N (tabs and segmented choice)** — `components::ui::TabBar` + `TabBarItem`, bound
  to one `RwSignal<String>`. **The** tab implementation: both detail panes, Security / Settings /
  Bulk Actions sub-tabs, the audit dashboard's facet bar, Resource Access, the permission picker's
  Application/Delegated choice, and the Access tab's Users/Groups. Do **not** reach for thaw's
  `TabList` — it was removed app-wide because `thaw::Tab` has no roving `tabindex` and no keydown
  handler, so a 10-tab strip is ten Tab presses with no arrow keys; `.ui-tabs` also scrolls
  natively where `.thaw-tab-list` needed an app-side `overflow-x` patch. Don't hand-roll a pair of
  buttons whose selected state is a Primary `appearance` either. `TabBar` only writes its bound
  signal, so a side effect on change (clearing a search box) belongs in an `Effect` that skips its
  first run. **Every true/false ARIA state is bound to a *string*** — `aria-selected`,
  `aria-expanded`, `aria-pressed`, `aria-checked`, … (`(sel == v).to_string()`): bound to a bare
  `bool`, Leptos renders a boolean attribute — `aria-selected=""` when true, absent when false —
  and neither is a valid ARIA value. Pinned by `web-rs/tests/aria_state_bindings.rs`, a source scan
  under `just web-test`. A **combobox**'s listbox holds only `role="option"`s or `role="group"`s of
  them (one group per heading, named by `aria-labelledby`); its loading / empty / error text
  lives in a sibling `role="status"` region, never among the options (`GlobalSearch`, the
  Permission Tester's picker). A notice that qualifies the results (`GlobalSearch`'s index-cap and
  failed-lookup `Callout`s) goes in its own `role="status"` region *before* the listbox, so it
  leads the scrolling panel instead of sitting below the fold.
  Two things legitimately stay different, and "consolidate" must not eat them: `FilterChip` keeps
  its count badge and zero-count disabled state (thaw's `Tab` takes only `class`/`value`/`children`
  and could not express either), and `.ui-select` stays where the option list is long or open-ended.
- **Dropdown menu** — a plain-DOM disclosure (`ExportMenu`, the shell's account menu), **not** a
  thaw `Menu`: an export opens the native Save dialog, and doing that from inside a teleported thaw
  overlay froze the webview on WebView2 as the overlay tore down. Its `role="menu"` panel wires
  `hooks::use_menu_keynav` — focus the first enabled item on open, Arrow Up/Down (wrapping) and
  Home/End between items, and focus back to the trigger however it closes (through
  `use_focus_return`); Escape itself stays with the caller's `use_escape`. Tab is not handled —
  closing on Tab would race the focus return against the browser's own move. The trigger carries
  `aria-haspopup="menu"` and a *string* `aria-expanded` (see `aria-selected` above); on a thaw
  `Button` both go on as `attr:`. An item that opens a dialog closes the menu **first**, so the
  menu's focus return runs before the dialog's trap records and places focus. Never ship
  `role="menu"` without the hook — the role promises keys that would otherwise not exist.
- **Modal** — `components::modal_shell::ModalShell` (backdrop, `role="dialog"`, focus trap,
  Escape). It mints a per-instance title id (`modal-shell-title-{n}`): the shell alone mounts four
  shells at once, so a fixed id labelled every one of them with the first. Global bare keys (`?`,
  `/`) no-op while any `.modal-backdrop` is present (`hooks::modal_is_open`, which the workspace's
  Escape also gates on), so `?` can't stack the sheet over a dialog and `/` can't pull focus out of
  its trap; the one exception is `?` closing the sheet it opened.
- **Directory search-and-pick** — `components::directory_search::DirectorySearch`, the single
  debounced "type 2+ chars, pick a `DirectoryObject`" control (`OwnerPicker`, `GroupAutocomplete`
  and the Settings DL picker are thin named wrappers over it). It **never mutates** — it hands the
  whole picked object to `on_pick`, which is what lets one component back a direct callback, a
  text-field append, and a stage-then-confirm dialog flow; a caller with the object can derive a
  name, an id, or a mail address, and none of those can reconstruct the object. `scope` is a
  `Signal<DirectoryScope>` so a caller can drive it from a `TabBar`; `DirectoryScope::Applications`
  searches apps through the cached global search and returns the **appId** as the row's `id` (the
  Expose an API tab's client picker). Both Owners tabs and the audit's add-owner dialog use it too
  (the app-registration tab mounts one instance per Add/Stage mode). Pass your own `query` +
  `clear_on_pick=false` when the box should clear only after a mutation succeeds. The results
  region gates on the **raw** query, not the debounced one, so an untouched box renders nothing
  rather than "No matches." — the bug two of the four copies had.
- **Form field labels** — thaw `<Field label=…>`, demoted app-wide by a single
  `.thaw-field__label` rule (medium weight, `--text-muted`). Thaw's default renders a label
  identical to body text, which flattens every form; don't re-specify label typography per view.
- **Table row actions** — a control in a `.data-table` cell needs `class="cell-mid"`, because the
  base rule is `vertical-align: top` and a 32px button sits ~7px below a single line of text.
  Multi-line *identity* cells deliberately stay top-aligned — the name should start where you read
  it — so classify the control columns, not the whole row.
- **Detail-tab roots** must appear in the tab-grid selector in `styles.css` (`display: grid;
  gap: var(--space-4)`), or the tab's rhythm silently falls back to UA `<h4>`/`<p>` margin
  collapse. `.ent-access`/`.ent-owners` had no rule at all for exactly this reason. If a root also
  contains `<h4>`s, zero their UA margin or the grid gap and the margin stack.
- **Destructive actions** — `button--danger`, on every control that destroys or revokes. Labeled
  buttons get border + red text + faint fill; icon-only ones (`.ui-icon-btn`, chip `×`) get the
  red glyph alone with the tint deferred to `:hover`, so a per-row trash repeated down a long list
  reads as actions rather than errors. Do **not** re-add `border-color` to the icon-only rule — a
  `.ui-icon-btn` has a transparent 1px border, so colouring it paints the heavy red square that
  rule exists to avoid. Reversible actions (Disable sign-in) stay un-reddened on purpose; bulk
  actions derive it from `BulkAction::is_destructive()` rather than per-call-site match arms.
  A per-row destructive control's accessible name names its row, starting with the visible verb
  (`Remove Application ID URI api://…`): `IconButton` via `aria_label`, a thaw `Button` via
  `attr:aria-label` (it also survives the label being swapped for a spinner), as the dock's Close
  chips do. An action column's header is `""` in `DataTable`, which renders a `.visually-hidden`
  "Actions"; a hand-built table writes the same span into its empty `<th>`.

## The open-items workspace (one shared working set)

The three list views (App Registrations / Enterprise Apps / Managed Identities) render full-width;
there is no side detail pane. Opening a row calls `session.open_item(kind, entity_id, title)`,
which adds it to ONE shared, cross-entity working set:

- **State shape** — `Session.open_items: RwSignal<Vec<OpenItem>>` plus `open_seq` (one monotonic
  clock: it mints ids *and* stamps `focused_at`) and `shown_items: Vec<u64>` (the 1–2 items
  currently displayed). Cap `MAX_OPEN_ITEMS = 8` (`state/open_items.rs`); overflow evicts the
  **least-recently-focused** item (min `focused_at`, stamped by `focus_item`), not the oldest
  opened — drain-oldest threw away a parked reference app. The eviction raises an `Info` toast
  ("Open dock is full (8) — closed "…"") with a **Reopen** action. Pinned by
  `open_item_cap_evicts_the_least_recently_focused` (`state/mod.rs` tests).
- **Helpers** — `open_item` (dedupes by `(kind, entity_id)`, re-focuses an existing entry),
  `focus_item(id, split)` (split mode caps `shown` at 2, drop-oldest), `close_item` /
  `close_item_by_entity` / `close_all_items`, `set_open_item_title`, `is_open`.
- **Cross-tenant footgun** — the same one as the lifted searches/facets below: `open_items` +
  `shown_items` MUST reset in `set_active_tenant`, or a stale open item leaks the prior tenant's
  data.
- **Persistence (tenant-keyed)** — the working set is parked in `localStorage` under
  `azapptoolkit:workspace:{tenant_id}` (`workspace_key`). Every in-session mutation goes through
  `Session::update_open_items`, the one write path, which also saves the snapshot. The only other
  writes are deliberate raw `set`s: the clear in `set_active_tenant` (not persisted — by then
  `active_tenant` is already the new tenant) and `restore_open_items`, the only reader, which
  `set_active_tenant` calls *after* the clear. Restore fast-forwards `open_seq` past the
  snapshot's ids and stamps (so a new item can't reuse a restored id) and never repopulates
  `shown_items` — the dock comes back, the overlay doesn't. `OpenItemKind` variant names are a
  stored format: renaming one silently drops parked docks (an undecodable snapshot is discarded
  whole). Restore dedupes the snapshot by `(kind, entity_id)` and by id and clamps it to
  `MAX_OPEN_ITEMS` by dropping the least recently focused (removing, never sorting, so dock order
  holds), so a snapshot cannot violate the in-memory model (`sanitize_restored`, pinned by the
  `state/open_items.rs` tests). Never add an unkeyed snapshot or a second write path; pinned by
  `restore_open_items_never_crosses_tenants`.
- **Mounting** — `OpenItemsDock` (the chip strip) + `OpenItemsWorkspace` (the overlay, 1-up or
  `--two` side-by-side) are mounted **once in `shell.rs`** so the set is shared, cross-entity, and
  survives nav. Never mount them per-view — keep-alive would duplicate them.
- **Keep-alive rendering** — the workspace mounts a window shell per open item (keyed `<For>`
  over `open_items`) and toggles visibility by `shown`; collapse is `style:display:none`, not
  unmount, so pane state survives chip switches. The pane *body* mounts on the window's first show,
  via a per-window latch seeded from `shown_items` (an interactive open is already shown, so it
  mounts eagerly), and is then kept alive. A restored dock therefore fetches nothing for a chip
  that has not been opened. Pinned by `restored_chips_fetch_nothing_until_opened` (`gui_1`).
- **Pane chrome** — each pane's `workspace__pane-bar` shows the dock chip's `TypeChip` kind glyph
  plus the item's **live** title (read from the `open_items` signal, self-correcting like the
  chip), so a 2-up compare is legible; Full (`Icon::Maximize`) and close (`Icon::Close`) are icon
  buttons on the right.
- **Pane contents** — the app-reg and enterprise detail panes are self-contained and reused
  directly. The MI detail is split: `ManagedIdentityDetailWindow` owns the resources, signals, and
  `ConfirmDialog` (keyed off one `mi_id`) and feeds the pure-presenter
  `ManagedIdentityDetailPane`.
- **Title self-correction** — each pane takes an optional `on_title` callback. Opens that lack a
  real name (pairing jumps, `open_*_on_tab` deep-links — they pass the id as a placeholder)
  correct the chip label once the detail loads.
- **Row highlight** — the "open" highlight reuses `app-list__row--selected` (so the `pairing.rs`
  scroll-settle selector still matches) but keys off `is_open`, not a single selection.
- **No per-list selected-id signals.** Global search, pairing jumps, and deep-links all route
  through `open_item` / `close_item_by_entity` — do not reintroduce
  `selected_*_id`-style signals on `Session`.

## Tenant-scoped UI state: `TenantScopedUi`

Per-list filter state that an outside surface can seed — or that would silently narrow the next
tenant's list if it survived a switch (the lists stay mounted via `util::keep_alive`) — lives on
`Session.tenant_ui` (the `TenantScopedUi` substruct) — the front-end mirror of the backend's cross-tenant cache-leakage
footgun, with the reset enforced **by structure, not vigilance**:

- **What lives there** — the searches (`apps_search` / `enterprise_search` / `mi_search`); the
  facet of every drill target (`enterprise_facet`, `mi_facet`, `credentials_facet`, the audit's
  `audit_severity`, the Findings pane's `audit_expanded_group`); the two lists' creation-date
  ranges (`apps_created_*` / `enterprise_created_*`); both bulk selections
  (`selected_app_ids`, `selected_audit_ids`); the pending deep-link tabs; and the shell dialog
  flags (`cache_open` / `create_open` / `sso_wizard_open`).
- **Who seeds it** — Global Search seeds the list search; the Home dashboard's clickable metrics
  seed the facet via `open_enterprise_with_facet` / `open_managed_identities_with_facet` /
  `open_posture_with_facet` / `open_credentials_with_facet` before navigating.
  `open_posture_with_facet` routes severity keys (`critical|high|medium|low`) to the All-apps
  pane's `audit_severity` and every finding key to `audit_expanded_group` + the Findings pane.
  A view binds its chip signal *to* the session field
  (`let ent_filter = session.tenant_ui.enterprise_facet;`).
- **The structural reset** — `set_active_tenant` calls `TenantScopedUi::reset()`, whose body sits
  directly under the field declarations, and the
  `tenant_switch_resets_every_tenant_scoped_field` pinning test asserts every field resets. A new
  tenant-scoped signal goes INTO `TenantScopedUi` with a `reset()` line + a test assertion —
  never as a bare `Session` field with a hand-added reset.
- **Exceptions/nuances** — the App Registrations credential facet (`apps_facet`) keeps its
  historical `"any"` show-all sentinel so saved views stay valid; Home's "With secrets" / "With
  certs" drill into it via `open_apps_with_facet`. Drilling into the App Registrations or
  Enterprise list also trips the one-shot `pending_open_filters`, which names its destination
  (`Some(ActiveView::Apps | EnterpriseApps)`) because both lists stay mounted and a bare flag
  would be consumed by whichever list's effect ran first; the named list expands its collapsed
  filter drawer once to reveal the active chip.

## Security workbench layout

Filtering **the audit scan** has exactly **two** homes: the Findings accordion and the All-apps
`audit_severity` control. Anything else that filters is a third home and will
drift out of step with them.

`BulkActionBar` is the single home of bulk command-calling. There is **no Grant
consent on audit surfaces** — consent is a Permissions-tab action, and offering
it beside a finding invites granting the very permission the finding is about.

A row shows only its own section's Fix and tab (`GroupSpec`); `on_remediated`
clears just that remediation kind, so fixing one finding does not blank the row's
unrelated findings.

**Load-bearing asymmetry:** `scoped_mailbox` matches
`.contains(SCOPED_VIA_RBAC)` while its siblings use `.starts_with`. That is
deliberate, not an oversight — pinned by the `filter.rs` tests.


The Security tab is a findings-first workbench: one controller, one strip, six keep-alive
sub-tabs (the two audit panes plus four inventory lenses). (Finding
*semantics* — the group catalog, key matching, and bulk-action pairing — live in
[audit-findings-and-remediation.md](./audit-findings-and-remediation.md#finding-groups-filters--bulk-action-pairing); this section is the view structure.)

- **One controller** — `SecurityView` constructs a single `audit_view::AuditController`
  (run/cancel/export/progress/consent + the cached-run hydration with its tenant-race guard) and
  provides it via context to every pane.
- **Read-only posture strip** — it renders severity counts, never filter controls. Do not
  reintroduce a severity TabBar, finding-chip drawer, or clickable scorecard as filters, and no
  `SavedViews` on the two audit panes (Findings / All apps) — filtering the scan has exactly two
  homes (below). The four inventory lenses (Credential expiry, SSO certificates, Delegated grants,
  Application permissions) keep their own facets + `SavedViews` via
  `components::audit_dashboard::AuditDashboard`, because they filter their own datasets, not the
  scan. The strip also carries the run's coverage caveats (cancelled / truncated / degraded) as
  non-interactive callouts, above both audit panes and in the export's `coverage_sentences` wording;
  the Findings pane keeps only the empty-state qualification of a partial run.
- **Sub-tabs** — `security_tab`: `"findings" | "apps" | "credentials" | "sso-certificates" |
  "grants" | "app-permissions"`, keep-alive.
  **Findings** (default) renders the grouped accordion; expansion state is
  `Session.tenant_ui.audit_expanded_group`. **All apps** is the ranked table with ONE severity
  control (`audit_severity`) + search (`filter_indices(items, severity, "all", query)`).
- **One shared selection** — `tenant_ui.selected_audit_ids` (distinct from `selected_app_ids`;
  both live in `TenantScopedUi`, so the tenant-switch reset is structural), cleared on
  group-expansion change and on the findings↔apps tab switch.
- **One bulk-action home** — `components/bulk_action_bar.rs::BulkActionBar` owns all
  selection-driven bulk command-calling logic. It mounts per expanded Findings group (actions
  from the finding catalog), on the All-apps pane (`[RemoveExpired, Delete]`), on the App
  Registrations list, and on the Bulk Actions page. **No bulk admin consent (`BulkAction::Grant`)
  on audit surfaces** — consent is a Permissions-tab action, and offering it beside a finding
  invites granting the very permission the finding is about; the operator's own AuditLog.Read.All
  consent on the posture strip (`grant_reports_consent`) is not that. Pinned by
  `groups.rs::no_audit_surface_offers_bulk_admin_consent`.
  "Fix all N" only seeds `selected_audit_ids` with the group's *eligible* (Application-kind) ids —
  the bar's typed-confirm / target forms still gate execution.
  **One run at a time:** `TenantScopedUi.bulk_running` is set by every bar's run and Undo and by
  the Bulk Actions Create, and cleared by the landing on every exit; every bar's chips, confirm and
  Undo wait on it (`blocked = busy || bulk_running`) and the Create buttons disable. The bars share
  their selection and the backend's single `bulk_cancel` flag, and the App Registrations list and
  the Bulk Actions page both stay mounted, so a second run on the very same ids was one click away.
  **Footgun (App Registrations list):** the bar mounts in `ApplicationList` *above* the
  `<Suspense>` body, not inside `LoadedApps`. The bar's own `on_done` bumps `apps_reload`, whose
  refetch remounts the whole Suspense body — a bar mounted inside it wipes its run summary (and
  the post-delete Undo state) on the very refetch the run triggers. Its app-name map therefore
  reads `tenant_ui.app_names` (published per fetch by `LoadedApps`) instead of a local signal.

## Browser GUI tests: sharding and its constraints

`just web-itest` mounts real Leptos views in a headless browser with the Tauri
IPC mocked. It is the frontend's only behavioural gate, and CI runs it
unconditionally.

Tests are `tests/gui/<view>.rs` **modules**, grouped into shard binaries
(`tests/gui_N.rs`) via `#[path] mod`; the harness lives in
`web-rs/src/test_support/`.

**Why shards.** Each served test wasm must stay under the ceiling headless Chrome
will instantiate (at opt-level 0 one merged binary exceeded it), and each binary
gets its own 60 s runner budget (`WASM_BINDGEN_TEST_TIMEOUT`, justfile).
`just web-itest-size` enforces the per-shard wasm ceiling and prints how to
split when a shard grows past it. It runs in CI and in `just verify-full`
(Unix; the Windows variant loud-skips).

**Grouping rule.** Group modules by the **view subtree they mount**, not by
count — the linker keeps only referenced views, so a shard's size tracks the
subtree it pulls in rather than the number of tests in it.

**What makes the ceiling reachable.** `[profile.test] strip = "debuginfo"` plus
`opt-level = 1`. Never `strip = true`: it removes the `name` section, and every
panic trace becomes anonymous.

**Do NOT make `test_support::reset()` clear `document.body`.** The runner
scrapes results from the page DOM, so wiping it makes the shard report nothing —
a green run that tested nothing.

**Renaming breaks tests silently at edit time.** A CSS class, `aria-label`, or
on-screen string a GUI test references is part of that test's contract.
`web-test-strings-check.sh` warns when an edit removes one; `just verify`
catches it locally given a browser, `just verify-ui` always.
