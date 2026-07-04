---
name: feature
description: Scaffold a new feature branch and command stub for azapptoolkit. Use when the user says "feature X", "add feature X", or asks to create a new command/stub.
argument-hint: "[feature description] — e.g., 'add feature batch approve apps'"
---

# Feature — scaffold branches, commands, and stubs for new features

Create a complete feature scaffolding: branch → backend command + handler → frontend binding → wiring. Follow the repo's conventions and run verification at each step.

## 0. Determine scope & naming

- From the argument (or ask): what is the feature?
  - New domain command → the right module under `src-tauri/src/commands/` + a binding in `web-rs/src/bindings/<domain>.rs`. Note `commands/` has domain **subdirectories** (`applications/`, `sso/`) as well as single files — extend the existing module for the domain rather than adding a parallel file.
  - New WASM component → new file in `web-rs/src/components/` or `web-rs/src/views/`.
  - New crate → new dir in `crates/` + update workspace Cargo.toml.
- Conventional-commit scope: use the canonical list in AGENTS.md (Git & version control — exactly 9 scopes, enforced by the commit-validator hook). Don't invent scopes.
- Suggest branch name: `<type>/<short-slug>` where `<type>` is the conventional-commit type (e.g., `feat/batch-approve`, `fix/token-refresh`).

## 1. Branch

- Create feature branch:
```bash
git checkout -b <type>/<short-slug> origin/main
```
- If on `main`, this creates a clean branch. If already on one, suggest rebasing.

## 2. Scaffolding — backend command (`src-tauri/src/commands/`)

Create or extend the domain's handler module. Use this pattern:
```rust
use tauri::State;

use crate::dto::UiError;
use crate::state::AppState;

#[tauri::command]
pub async fn <name>(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<ReturnType, UiError> {
    // ... implementation
}
```

- Use `#[tauri::command] async fn`, `State<'_, AppState>` first, `Result<T, UiError>` return.
- Rust params stay snake_case — the Tauri macro maps the camelCase arg keys the frontend sends.
- New module file? Register it in `src-tauri/src/commands/mod.rs`.
- Check token scopes if the feature needs extra-scope tokens (e.g., `AppState::ensure_audit_log()`).

## 3. Register the handler (`src-tauri/src/lib.rs`)

Add to `tauri::generate_handler![]`:
```rust
let builder = tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
        // ... existing handlers
        <domain>::name,
    ]);
```

## 4. Create the frontend binding (`web-rs/src/bindings/<domain>.rs`)

Typed Rust stub over `tauri_sys` — mirror `bindings/activity.rs`:
```rust
use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NameArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
}

pub async fn <name>(tenant_id: &str, object_id: &str) -> Result<ReturnType, UiError> {
    invoke_result(
        "<name>",
        NameArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}
```

- The command name string is the **flat snake_case fn name** (`"<name>"`, no domain prefix).
- Args struct fields are snake_case Rust; `#[serde(rename_all = "camelCase")]` produces the camelCase wire keys the Tauri macro expects. Common shapes (`TenantArg`, `ObjectIdArgs`, `AppIdArgs`, …) already exist in `bindings/common.rs` — reuse before defining a new one.
- New module file? Add `pub mod <domain>;` to `web-rs/src/bindings/mod.rs`.
- Use `invoke_result` for `Result<T, UiError>` commands (not bare `invoke`, which panics on a rejected promise).

The command fn + `generate_handler![]` entry + binding are the 3-step parity contract; the advisory `command-parity-check.sh` hook warns if one leg is missing.

## 5. If WASM component — add to views/components

If this feature includes a UI component:
- Add to `web-rs/src/components/<component>.rs` (BEM-ish naming).
- Import and use in the appropriate view (`web-rs/src/views/<view>.rs`).

## 6. Verify scaffolding passes

Run `just verify` and report any issues:
- If Rust/WASM source changed, require full verification.
- If the feature is purely frontend (WASM only), `just web-build` suffices.

## 7. Output format

```
feature: created scaffold for <type>/<short-slug>

## Changes
- ✅ Branch created: `<type>/<short-slug>` from `origin/main`
- ✅ Backend handler: `src-tauri/src/commands/<domain>.rs` (or the domain subdirectory)
- ✅ Handler registered in `src-tauri/src/lib.rs` (`generate_handler![]`)
- ✅ Frontend binding: `web-rs/src/bindings/<domain>.rs` (calls `invoke_result`)
- ✅ Scopes checked: uses `AppState::ensure_<scope>()` for extra-scope tokens

## Next steps
Write the implementation in `src-tauri/src/commands/<domain>.rs` and update the binding.
```

## Failure handling

- If `generate_handler![]` already has the handler → warn (skip duplicate).
- If command-parity-check.sh warns about missing binding → add one.
- If the backend uses a new dependency → check `Cargo.lock` for conflicts before adding to `[workspace.dependencies]`.
