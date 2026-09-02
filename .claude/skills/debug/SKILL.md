---
name: debug
description: Debug issues in the azapptoolkit Tauri + Leptos WASM app. Use when the user says "debug X" where X is a symptom (e.g., "token refresh failing", "list not loading", "WASM build error"), or asks for help diagnosing a problem.
argument-hint: "[symptom] — e.g., 'token refresh failing', 'list not loading'"
---

# Debug — diagnose Tauri + Leptos WASM issues

Start from the symptom, form one hypothesis, then check the layers in order. Read the matching
`docs/architecture/` deep-dive (linked from AGENTS.md) before touching a subsystem.

## 0. Pin the symptom

- Which surface: sign-in/token, a list, a detail tab, the audit, Search, a bulk action, the updater?
- Native (`just dev`) only, WASM build only, or the GitHub Pages demo?
- Exact error text / `ui_code` (the toast and `DetailLoadError` show it) and the log line
  (`README.md → Logs` says where the file is).

## 1. Fast checks (never hand-typed `cargo`)

| Need | Recipe |
|---|---|
| Does it compile at all (both trees)? | `just check` |
| One crate's tests, optionally filtered | `just test-crate <crate> [-- <filter>]` |
| Frontend unit tests / WASM build | `just web-test` / `just web-build` |
| Frontend behaviour in a real browser (IPC mocked) | `just web-itest` |
| Everything CI runs | `just verify` |

## 2. Backend (`crates/` + `apps/desktop/src-tauri/`)

- `src-tauri/src/state.rs` — `AppState`: auth singleton, per-tenant clients, cache, cancel flags.
- `src-tauri/src/commands/<domain>.rs` (or the `applications/`, `sso/`, `exchange/` subdirs) —
  the failing handler. Is it in `generate_handler![]` (`lib.rs`)? The `command-parity-check.sh`
  hook names a missing leg.
- Cache: key carries `{tenant_id}|`? Invalidated only on `Ok`? A pinned index read through its
  accessor? → [caching-and-search.md](../../../docs/architecture/caching-and-search.md).
- `src-tauri/src/token_adapter.rs` — `ScopedTokenAdapter` mints extra-scope tokens; a missing
  admin consent must degrade to `consent_required`, never a hard error.

## 3. Auth (`crates/azapptoolkit-auth/`)

- Token refresh: `src/token_cache.rs` (~60 s early, behind a shared mutex). A dead refresh token
  surfaces as `refresh_missing` / `not_signed_in` and must trigger **re-auth in place**, not
  sign-out → [auth-and-consent.md](../../../docs/architecture/auth-and-consent.md).
- Keyring: refresh tokens are chunked (Windows caps an entry at 2560 UTF-16 bytes) — a partial
  chunk set reads as "no token".
- Consent: AADSTS65001/65004 → `AuthError::ConsentRequired`; the command must pre-acquire via
  `AppState::ensure_*` for the "Grant consent" button to appear.

## 4. Frontend (`apps/desktop/web-rs/`)

- `src/bindings/<domain>.rs` — command-name string and args struct match the handler
  (`#[serde(rename_all = "camelCase")]`; Graph models are camelCase, DTOs snake_case)?
- `src/state/` — `Session` `RwSignal`s; tenant-scoped filter state lives in `tenant_ui` and must
  reset on tenant switch.
- `src/views/`, `src/components/` — the rendering; loading/error surfaces use the `ui` primitives.
- Demo/Pages only: an infallible `invoke()` with no fixture panics the whole page — check
  `src/demo/mod.rs::register_fixtures`.

## 5. Common symptoms

| Symptom | Quick check | Likely culprit |
|---|---|---|
| "Session expired" / silent failures after idle | log for `refresh_missing` | re-auth path not taken; see §3 |
| List empty or stale after a tenant switch | key prefix, `set_active_tenant` resets | unscoped cache key or a `Session` field outside `tenant_ui` |
| Command "not found" from the UI | parity hook output | handler missing from `generate_handler![]` or the binding string differs |
| Args rejected (`invalid args`) | binding args struct | camelCase/snake_case mismatch |
| WASM build error | `just web-build` | server-only dep (tokio/reqwest/rustls) not `cfg(not(wasm32))`-gated |
| Frontend `fetch` blocked | `tauri.conf.json` `connect-src` | only WASM-side fetches need CSP; backend reqwest never does |
| Audit score looks wrong | `AppPermissions.mail_scopes` | empty map = org-wide by design; check the scope probe |
| Long write ignores Cancel | `claim()` before first await? | `CancelToken` claimed late / no `SessionDead` latch |

## 6. Report

```
# Debug — <symptom>
## Hypothesis · ## Evidence (file:line) · ## Fix (or next probe) · ## Verified by (recipe run)
```

If `just verify` passes but the symptom persists, it is a runtime/logic bug: reproduce it in a
`web-itest` GUI test or a crate unit test before fixing, so the fix carries its regression test.
