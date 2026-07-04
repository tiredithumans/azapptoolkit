---
name: repo-review
description: Review PRs and commits for this repo — diff base → head, run verify gates on the right branches, check conventional-commits, flag scope/tenant-cache footguns. Use when the user says "repo review", "review this PR", "approve this PR", or asks for a review of their changes.
argument-hint: "[PR number, commit sha, or branch name]"
---

# Review — inspect diffs, run gates, suggest fixes

Review work in progress before it lands on `main`. Use the repo's exact verification pipeline and conventions. If arguments were passed, treat them as guidance (PR number, commit SHA, or branch).

## 0. Find the work

- **Argument given:**
  - PR number → `gh pr view <num>` for diffs + status.
  - Branch name → `git fetch origin && git diff origin/main...<branch>`.
  - Commit SHA → `git show <sha>` + `gh pr search --head <sha>`.
- **No argument:** diff working tree → `main` via `git status --short` + `git diff origin/main`.

## 1. Inspect the diffs

- **rust backend (crates/ + src-tauri):** Check that new commands follow the 3-step pattern:
  1. `#[tauri::command] async fn` in `src-tauri/src/commands/<domain>.rs`.
  2. Added to `tauri::generate_handler![]` in `src-tauri/src/lib.rs`.
  3. Typed stub in `web-rs/src/bindings/<domain>.rs` calling `invoke_result`.
- **Frontend (web-rs):** Check that added bindings actually match backend handlers. Look for stale `#[tauri::command]` handlers without corresponding bindings (the `command-parity-check.sh` hook catches this; mention which one).
- **Tenant cache footgun:** New cache reads/writes must include `{tenant_id}|` prefix. Flag any that look unscoped.
- **cache invalidation:** After mutation, is the relevant list cache busted? On failure is it left alone? (See [caching-and-search.md](docs/architecture/caching-and-search.md)).
- **WASM gates:** Any server-only dep used in web-rs? Should be `#[cfg(not(target_arch = "wasm32"))]`.
- **camelCase vs snake_case:** Graph models are camel; DTOs/bindings are snake. Core types crossing IPC (`Application`, `AuditItem`) must stay as-is for wire format.

## 2. Run the gates

- **Backend:** `just verify` on the current branch (or `origin/main` if reviewing a PR). If Rust/WASM source changed, this is required.
- **Quick variant (for large PRs):** `just clippy` + `just test` if the frontend is known stable.
- **Dependency audit** (if new deps): `just deny` + `cargo audit`.

## 3. Check conventions

- Commits follow Conventional Commits (`<type>[(scope)][!]: <description>`).
- Scopes match: `desktop`, `core`, `auth`, `graph`, `exchange`, `keyvault`, `permissions`, `ci`, `docs`.
- CHANGELOG.md `[Unreleased]` has entries for user-facing changes.

## 4. Produce output

Review result in PR body form when reviewing via `gh`:
```markdown
## Review Notes ✅ / ⚠️

### Changes reviewed:
- `src-tauri/src/commands/foo.rs` — new command, handler and stub aligned.
- `web-rs/src/bindings/foo.rs` — matches backend (camelCase → snake_case).
- `crates/azapptoolkit-core/src/cache.rs` — cache key now scoped by tenant.

### Issues:
- [ ] ⚠️ `_stub_frontend_dist` recipe missing from justfile (clippy warns on fresh checkout).
- [ ] Missing CHANGELOG entry for new `audit_remediation` feature.

### Gates:
- ✅ fmt-check, clippy (0 warnings), test — passed on this PR.
```

## Failure handling

- `just verify` fails → report the failing gate's output; do not approve.
- Unmatched command/stub pair → flag it (check `command-parity-check.sh`).
- Tenant cache not scoped → high-priority warning.
