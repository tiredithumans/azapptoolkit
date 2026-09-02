---
paths:
  - "apps/desktop/web-rs/**"
---

# Frontend (Leptos/WASM) — the detail behind the AGENTS.md one-liners

Deep-dive: `docs/architecture/frontend-workspace.md` (sharding + the `strip`/`reset()` footguns included).

- **Reactivity is closure-based.** `{move || sig.get()}` for tracking; `.get()`/`.with()` to read. State is `RwSignal<T>` on a context-provided `Session`. CSS: plain global `styles.css` with BEM-ish names. Global keys live in `hooks::use_shortcuts`; a **bare-key** binding MUST no-op in a text field or it eats typing.
- **One primitive per UI pattern (design-consistency invariant).** Page header = `components::ui::SectionHeader`; loading = skeletons (`SkeletonList`/`DetailSkeleton`), spinners only in-button/inline; load failure = `DetailLoadError`; notices/alerts = `components::ui::Callout`; windowed-list footer = `components::ui::ShowMore`. Reuse the primitive; don't re-implement the markup (a repo_invariants test scans for hand-rolled callouts).
- **Open-items workspace = full-width lists + ONE shared cross-entity working set.** `session.open_item(kind, entity_id, title)` fills `Session.open_items`; no side detail pane, and the dock + workspace mount **once in `shell.rs`**. **Footgun:** `open_items` + `shown_items` MUST reset in `set_active_tenant`, or a stale item leaks the prior tenant's data. No `selected_*_id` signals.
- **Per-list filter state lives on `Session.tenant_ui` (`TenantScopedUi`) and resets on tenant switch by structure.** A new tenant-scoped signal goes INTO the substruct with a `reset()` line + an assertion in the `tenant_switch_resets_every_tenant_scoped_field` pinning test — never a bare `Session` field with a hand-added reset.
- **Bindings mirror commands.** The command-name string is the flat snake_case fn name; args structs are snake_case Rust with `#[serde(rename_all = "camelCase")]`; reuse the shapes in `bindings/common.rs`; use `invoke_result` for `Result<T, UiError>` commands. `Application` + `AuditItem` cross IPC as-is.
- **WASM gating.** `web-rs` compiles to `wasm32-unknown-unknown`. Server deps (tokio, reqwest, rustls) must be gated `#[cfg(not(target_arch = "wasm32"))]` in shared crates, or excluded from `web-rs`. `web-rs` is outside the workspace, so it declares its own `[lints.rust] unsafe_code = "deny"` — keep it in sync with the root block (pinned by test).
- **GitHub Pages demo = the WASM frontend with the Tauri backend mocked.** `just web-build-pages` builds with the `demo` feature (off in `web-build`/desktop, so the mock never ships). **Footgun:** any infallible `invoke()` must be in `demo::register_fixtures` or it **panics the whole page** — enforced by `web-rs/tests/demo_fixture_coverage.rs`.
- **Auto-update is interactive (not silent).** The front-end checks once on launch and toasts a notification whose action opens `UpdateSplash` (explicit **Update & restart**). **Don't reintroduce a silent background `download_and_install` in `lib.rs` setup** — it would race the prompt.
- **Browser GUI tests are sharded** (`tests/gui_N.rs`, `#[path] mod` per module) because one binary exceeds what headless Chrome will instantiate; `just web-itest-size` enforces the per-shard ceiling. Renaming a CSS class / aria-label / on-screen text a test references fails CI — the `web-test-strings-check.sh` hook flags it at edit time.
