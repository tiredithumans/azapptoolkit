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
