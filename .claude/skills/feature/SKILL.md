---
name: feature
description: Scaffold a new feature branch and command stub for azapptoolkit. Use when the user says "feature X", "add feature X", or asks to create a new command/stub.
argument-hint: "[feature description] — e.g., 'add feature batch approve apps'"
---

# Feature — scaffold branches, commands, and stubs for new features

Create a complete feature scaffolding: branch → backend command + handler → frontend stub → wiring. Follow the repo's conventions and run verification at each step.

## 0. Determine scope & naming

- From the argument (or ask): what is the feature?
  - New domain command → new file in `src-tauri/src/commands/<domain>.rs` + stub in `web-rs/src/bindings/<domain>.rs`.
  - New WASM component → new file in `web-rs/src/components/` or `web-rs/src/views/`.
  - New crate → new dir in `crates/` + update workspace Cargo.toml.
- Determine the scope for Conventional Commits: `desktop`, `core`, `auth`, `graph`, `exchange`.
- Suggest branch name: `<scope>/<short-slug>` (e.g., `desktop/batch-approve`).

## 1. Branch

- Create feature branch:
```bash
git checkout -b <scope>/<short-slug> origin/main
```
- If on `main`, this creates a clean branch. If already on one, suggest rebasing.

## 2. Scaffolding — backend command (`src-tauri/src/commands/<domain>.rs`)

Create or extend the handler file. Use this pattern:
```rust
use crate::state::{AppState, UiError};

#[tauri::command]
pub async fn <name>(state: State<AppState>, args: <ArgType>) -> Result<ReturnType, UiError> {
    // ... implementation
}
```

- Use `#[tauri::command] async fn`.
- Accept `State<'_, AppState>` as first param.
- Return `Result<T, UiError>`.
- Frontend args use `#[serde(rename_all = "camelCase")]` in `web-rs`.
- Check token scopes if the feature needs extra-scope tokens (e.g., `AppState.ensure_audit_log()`).

## 3. Register the handler (`src-tauri/src/lib.rs`)

Add to `tauri::generate_handler![]`:
```rust
let builder = tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
        // ... existing handlers
        <domain>::name,
    ]);
```

## 4. Create the frontend stub (`web-rs/src/bindings/<domain>.rs`)

Create or extend the typed stub:
```typescript
import { invoke_result } from "$lib/ipc";

interface <ArgType> {
  // ...
}

export interface <ReturnType> {
  // ...
}

export async function <name>(args: <ArgType>): Promise<<ReturnType>> {
  return invoke_result("<domain>.name", args);
}
```

- Arguments are camelCase (from frontend).
- Return type matches backend.
- Use `invoke_result` for typed results (not `invoke`, which is generic).

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
feature: created scaffold for <scope>/<short-slug>

## Changes
- ✅ Branch created: `<scope>/<short-slug>` from `origin/main`
- ✅ Backend handler: `src-tauri/src/commands/<domain>.rs`
- ✅ Handler registered in `src-tauri/src/lib.rs` (`generate_handler![]`)
- ✅ Frontend stub: `web-rs/src/bindings/<domain>.rs` (calls `invoke_result`)
- ✅ Scopes checked: uses `AppState.ensure_<scope>()` for extra-scope tokens

## Next steps
Write the implementation in `src-tauri/src/commands/<domain>.rs` and update the stub.
```

## Failure handling

- If `generate_handler![]` already has the handler → warn (skip duplicate).
- If command-parity-check.sh warns about missing binding → add one.
- If the backend uses a new dependency → check `Cargo.lock` for conflicts before adding to `[workspace.dependencies]`.
