# Frontend workspace, session state & UI primitives

Deep-dive companion to the frontend gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `web-rs/src/state.rs`, the shell, the list views, the open-items workspace, or the
Security workbench's panes.

## Reactivity conventions

Leptos reactivity is closure-based: `{move || sig.get()}` inside `view!` for tracking,
`.get()`/`.with()` to read. Shared state is `RwSignal<T>` fields on a context-provided `Session`
(`web-rs/src/state.rs`). CSS is one plain global `styles.css` with BEM-ish class names — no
CSS-in-Rust, no per-component stylesheets.

## One primitive per UI pattern

The design-consistency invariant: every recurring UI pattern has exactly one primitive, and new
surfaces reuse it rather than re-implementing the markup.

- **Page header** — `components::ui::SectionHeader` (uppercase category crumb + title), app-wide.
  There is no `.view-header` class. The two list views own their `SectionHeader` above a titleless
  `ListScaffold` — `ListScaffold` takes no `title`/`actions` props; the card starts at its search
  box.
- **Loading** — skeletons for content regions (`SkeletonList` / `DetailSkeleton`); spinners are
  reserved for in-button / inline busy states only.
- **Load failure** — `DetailLoadError`, the universal "message + Retry" block (detail panes, all
  three list views, dashboard cards). Pass `on_retry: Callback<()>` plus a context `class`.
- **Notices/alerts** — `components::ui::Callout` (`info`/`ok`/`warn`/`danger`, reusing the `.alert`
  classes). New alert markup goes through it; migrate any raw `<div class="alert alert--…">` you
  touch.
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
  first run. **`aria-selected` must be a *string*** (`(sel == v).to_string()`): bound to a bare
  `bool`, Leptos renders a boolean attribute — `aria-selected=""` when true, absent when false —
  and neither is a valid ARIA value.
  Two things legitimately stay different, and "consolidate" must not eat them: `FilterChip` keeps
  its count badge and zero-count disabled state (thaw's `Tab` takes only `class`/`value`/`children`
  and could not express either), and `.ui-select` stays where the option list is long or open-ended.
- **Directory search-and-pick** — `components::directory_search::DirectorySearch`, the single
  debounced "type 2+ chars, pick a `DirectoryObject`" control (`OwnerPicker`, `GroupAutocomplete`
  and the Settings DL picker are thin named wrappers over it). It **never mutates** — it hands the
  whole picked object to `on_pick`, which is what lets one component back a direct callback, a
  text-field append, and a stage-then-confirm dialog flow; a caller with the object can derive a
  name, an id, or a mail address, and none of those can reconstruct the object. `scope` is a
  `Signal<DirectoryScope>` so a caller can drive it from a `TabBar`. Pass your own `query` +
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

## The open-items workspace (one shared working set)

The three list views (App Registrations / Enterprise Apps / Managed Identities) render full-width;
there is no side detail pane. Opening a row calls `session.open_item(kind, entity_id, title)`,
which adds it to ONE shared, cross-entity working set:

- **State shape** — `Session.open_items: RwSignal<Vec<OpenItem>>` plus `open_seq` (monotonic id
  source) and `shown_items: Vec<u64>` (the 1–2 items currently displayed). Modeled on the toast
  stack: `Vec` + seq + cap `MAX_OPEN_ITEMS = 8` + drain-oldest on overflow.
- **Helpers** — `open_item` (dedupes by `(kind, entity_id)`, re-focuses an existing entry),
  `focus_item(id, split)` (split mode caps `shown` at 2, drop-oldest), `close_item` /
  `close_item_by_entity`, `set_open_item_title`, `is_open`.
- **Cross-tenant footgun** — the same one as the lifted searches/facets below: `open_items` +
  `shown_items` MUST reset in `set_active_tenant`, or a stale open item leaks the prior tenant's
  data.
- **Mounting** — `OpenItemsDock` (the chip strip) + `OpenItemsWorkspace` (the overlay, 1-up or
  `--two` side-by-side) are mounted **once in `shell.rs`** so the set is shared, cross-entity, and
  survives nav. Never mount them per-view — keep-alive would duplicate them.
- **Keep-alive rendering** — the workspace mounts ALL open windows (keyed `<For>` over
  `open_items`) and toggles visibility by `shown`; collapse is `style:display:none`, not unmount,
  so pane state survives chip switches.
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

Per-list filter state that an outside surface can seed lives on `Session.tenant_ui` (the
`TenantScopedUi` substruct) — the front-end mirror of the backend's cross-tenant cache-leakage
footgun, with the reset enforced **by structure, not vigilance**:

- **What lives there** — the searches (`apps_search` / `enterprise_search` / `mi_search`); the
  facet of every drill target (`enterprise_facet`, `mi_facet`, `credentials_facet`, the audit's
  `audit_severity`, the Findings pane's `audit_expanded_group`); both bulk selections
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
- **Exceptions/nuances** — the App Registrations credential facet stays local to the view (no
  metric drills into it). Drilling into the Enterprise list also trips the one-shot
  `pending_open_filters` so the list expands its collapsed filter drawer and reveals the active
  chip.

## Security workbench layout

Filtering has exactly **two** homes: the Findings accordion and the All-apps
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


The Security tab is a findings-first workbench: one controller, one strip, four panes. (Finding
*semantics* — the group catalog, key matching, and bulk-action pairing — live in
[scoping-and-audit.md](./scoping-and-audit.md); this section is the view structure.)

- **One controller** — `SecurityView` constructs a single `audit_view::AuditController`
  (run/cancel/export/progress/consent + the cached-run hydration with its tenant-race guard) and
  provides it via context to every pane.
- **Read-only posture strip** — it renders severity counts, never filter controls. Do not
  reintroduce a severity TabBar, finding-chip drawer, or clickable scorecard as filters, and no
  `SavedViews` on this view — filtering has exactly two homes (below).
- **Sub-tabs** — `security_tab`: `"findings" | "apps" | "credentials" | "grants"`, keep-alive.
  **Findings** (default) renders the grouped accordion; expansion state is
  `Session.tenant_ui.audit_expanded_group`. **All apps** is the ranked table with ONE severity
  control (`audit_severity`) + search (`filter_indices(items, severity, "all", query)`).
- **One shared selection** — `tenant_ui.selected_audit_ids` (distinct from `selected_app_ids`;
  both live in `TenantScopedUi`, so the tenant-switch reset is structural), cleared on
  group-expansion change and on the findings↔apps tab switch.
- **One bulk-action home** — `components/bulk_action_bar.rs::BulkActionBar` owns all
  selection-driven bulk command-calling logic. It mounts per expanded Findings group (actions
  from the finding catalog), on the All-apps pane (`[RemoveExpired, Delete]`), on the App
  Registrations list, and on the Bulk Actions page. **No Grant consent on audit surfaces.**
  "Fix all N" only seeds `selected_audit_ids` with the group's *eligible* (Application-kind) ids —
  the bar's typed-confirm / target forms still gate execution.

## Browser GUI tests: sharding and its constraints

`just web-itest` mounts real Leptos views in a headless browser with the Tauri
IPC mocked. It is the frontend's only behavioural gate, and CI runs it
unconditionally.

Tests are `tests/gui/<view>.rs` **modules**, grouped into shard binaries
(`tests/gui_N.rs`) via `#[path] mod`; the harness lives in
`web-rs/src/test_support/`.

**Why shards.** One merged binary exceeds what headless Chrome will instantiate.
`just web-itest-size` enforces the per-shard wasm ceiling and prints how to
split when a shard grows past it. It runs in CI and in `just verify-full`.

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
