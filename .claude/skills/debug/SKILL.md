---
name: debug
description: Debug issues in the azapptoolkit Tauri + Leptos WASM app. Use when the user says "debug X" where X is a symptom (e.g., "token refresh failing", "list not loading", "WASM build error"), or asks for help diagnosing a problem.
argument-hint: "[symptom] — e.g., 'token refresh failing', 'list not loading'"
---

# Debug — diagnose Tauri + Leptos WASM issues

Walk through the app's architecture layers to pinpoint the root cause. Start with a hypothesis from the symptom, then check each layer systematically.

## 0. Clarify the symptom

Ask for / confirm:
- Which component is affected? (auth token, app list, audit scoring, Search, etc.)
- Is it happening in `just dev` (native) or only after a WASM rebuild?
- Is there an error message or console output?

## 1. Check the Rust backend (`crates/` + `src-tauri/`)

If Rust source changed:
- `just clippy` — often the fastest check for compile-time issues.
- `cargo test --lib -p <crate>` — targeted crate tests.

If backend code is responsible:
- Check `src-tauri/src/state.rs` — AppState singleton, auth state, cache status.
- Check `src-tauri/src/commands/<domain>.rs` — the handler that's failing.
- Check for cache invalidation issues (tenant-scoped? invalidated only on Ok?).
- Look at `src-tauri/src/token_adapter.rs` — ScopedTokenAdapter for extra-scope tokens.

## 2. Check the WASM frontend (`web-rs/`)

- `just web-build` — quick rebuild to see if the issue is in WASM.
- Check `web-rs/src/bindings/` — do the stubs match backend handlers?
- Check `web-rs/src/state.rs` — RwSignal state for the affected feature.
- Look at `web-rs/src/hooks/` — debounced signals, ReusableEffect patterns.
- Check `web-rs/src/views/` — the view/component that renders the feature.

## 3. Check auth layers (common source of bugs)

For token/consent/auth issues:
- **Token refresh** (`crates/azapptoolkit-auth/src/token_cache.rs`): is the token expired? Check `~60s before expiry` behavior.
- **Keyring chunking**: Windows Credential Manager caps at 2560 UTF-16 bytes. If refresh tokens are chunked, check all chunks exist.
- **Silent grants**: AADSTS65001/65004 → `ConsentRequired`. Check `AppState::ensure_*` pre-acquisition.
- **Extra-scope tokens**: Admin-consent scopes (AuditLog, Policy.Read.All) ride ScopedTokenAdapter. If missing → `unavailable` message.

## 4. Check the WASM native boundary (`src-tauri/src/lib.rs`)

- Are commands in `generate_handler![]`?
- Is the typed stub in `web-rs/src/bindings/` correct (camelCase vs snake_case)?
- Is the `connect-src` in `tauri.conf.json` correct for new origins?

## 5. Output format

Produce a debugging report:
```
# Debug Report — Token Refresh Failing

## Symptom
Token refresh failing after ~1 hour of idle time. Works fine on fresh start.

## Hypothesis
Keyring chunking issue — Windows Credential Manager may have dropped a chunk.

## Evidence
- Checked `src-tauri/src/token_cache.rs:47` — chunked read pattern.
- Checked `AppState.refresh()` in `state.rs:156` — shares mutex with refresh.
- Verified keyring entries exist via `keyring::Entry`.

## Next steps
1. Run `just dev` — observe token expiry in logs.
2. Check keyring: `keyring list`
3. If chunk missing → fix in `token_cache.rs:47-63`.

## Files changed
- src-tauri/src/token_cache.rs (suggested fix)
```

## Common symptoms and quick checks

| Symptom | Quick check | Likely culprit |
|---------|-------------|----------------|
| Token refresh failing after idle | `just clippy` → run in background ~60s | Shared mutex deadlock in token_cache.rs |
| List not loading | `app_name_index` + `sp_index` present? | Cache key missing `{tenant_id}\|` prefix |
| WASM build error | `just web-build` (runs Trunk) | Server dep in wasm subtree (tokio, reqwest) |
| CSP error on fetch | `tauri.conf.json` → web-rs fetch URL | Missing `connect-src` entry |
| Command not found in frontend | Check bindings + handler list | command-parity-check.sh warning missed |
| Wrong camelCase in UI | Check bindings vs backend | Graph models = camel, DTOs = snake |
| Audit scores wrong | Check `score_application` + Exchange scopes | Mail scopes not scoped, org-wide assumed |

## Failure handling

- If `just verify` passes but the issue persists → it's likely a runtime/logic bug.
- If `just verify` fails → fix the failing gate first, then re-check if original issue remains.
- If WASM only → check Trunk logs (`web-rs/dist/`), `console.log`, and WASM-specific errors.
