---
name: release
description: Cut and publish a release — bump the 3 guarded manifests, sync both lockfiles, finalize CHANGELOG.md [Unreleased] → [X.Y.Z], release PR, tag the merge commit, verify the 3-OS draft, publish on human sign-off. Use when the user says "release", "bump version", or asks to publish a new release.
argument-hint: "[version bump type: patch, minor, major]"
---

# Release — bump → lockfiles → changelog → PR → tag → draft → publish

The pipeline: release PR onto `main` → annotated tag on the **merge commit** →
`release.yml` builds a 3-OS **draft** with one aggregated `latest.json` → a human publishes.
Publishing is the only step that reaches users: it flips `/releases/latest`, so NSIS and
AppImage users auto-update on next launch. `main` is strictly protected — never commit to it
directly; everything lands via the release PR.

## 0. Determine the bump type

- If argument given: use it (`patch`, `minor`, or `major`).
- If no argument, look at commits since the last release tag:
  - `feat:` → minor bump.
  - Breaking changes (`!` types or CHANGELOG notes) → major bump.
  - Only `fix:` / `chore:` / `docs:` → patch bump.

## 1. Bump the 3 guarded manifests

`release.yml`'s `guard` job fails the whole build unless ALL THREE equal the tag:

- `apps/desktop/src-tauri/tauri.conf.json` — `"version"`
- root `Cargo.toml` — `[workspace.package] version`
- `apps/desktop/web-rs/Cargo.toml` — `version` (also feeds the in-app version line)

These three are the complete set — there is no other version manifest in the repo.

## 2. Sync BOTH lockfiles

Every verify/CI gate runs `--locked`, so a stale lockfile fails CI after a version bump:

```bash
cargo update --workspace                                # root Cargo.lock
(cd apps/desktop/web-rs && cargo update --workspace)    # web-rs Cargo.lock (workspace-excluded)
```

This touches only the `azapptoolkit-*` member version lines — no dep churn. Don't
`cargo build`/`check` just to refresh a lock (needs the frontend-dist stub); `cargo update -w`
is clean.

## 3. Finalize the changelog

- Roll `## [Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD` — **no `v` prefix, ASCII hyphen**
  (e.g. `## [0.15.0] - 2026-07-04`). This exact shape is load-bearing: `release.yml` (line
  ~229) extracts the updater's in-app changelog notes by matching the `## [X.Y.Z]` header —
  a `v` prefix or an em-dash silently ships fallback notes instead of the changelog. It also
  matches every existing entry in `CHANGELOG.md`.
- Re-add an empty `## [Unreleased]` stub above the new section.

## 4. Verify, commit, PR

- `just verify` (lockfiles now match). Prefer `just verify-full` for full CI parity
  (adds audit/web-audit/deny/web-deny/web-itest) — the guard job re-runs the RustSec scan
  against this exact lockfile, so catching a fresh advisory locally saves a full cut cycle.
- Branch `release/vX.Y.Z`, commit `chore: release vX.Y.Z` — the type must be `chore`:
  a `release` commit type is not in the validator hook's accepted list.
- Push, then `gh pr create --base main` with the usual Summary/Test-plan body.

## 5. Wait for the required checks, merge

- 7 required checks: Rust workspace (ubuntu/windows/macos), Frontend (Leptos/WASM),
  actionlint, cargo-audit, cargo-deny. Watch with `gh pr checks <num> --watch`, or a
  background poll loop on `gh pr view <num> --json statusCheckRollup` (sleep ~45s between
  polls) so a ~7-minute CI run doesn't burn a tool timeout.
- Strict protection: if another merge lands first, this PR goes "behind" →
  `gh pr update-branch <num>` and re-wait (a fresh CI cycle).
- `gh pr merge <num> --merge --delete-branch`. Auto-merge is not enabled on this repo;
  never merge with `--admin`.

## 6. Tag the merge commit

```bash
git checkout main && git pull origin main
git tag -a vX.Y.Z -m "vX.Y.Z" <merge-sha>   # the MERGE COMMIT on main, not the branch head
git push origin vX.Y.Z
```

The tag push triggers `release.yml`: guard (version/pubkey/audit) → 3-OS build matrix
(`just build-windows-updater` · `build-macos-updater` · `build-linux-updater`) → a **draft**
release with ONE aggregated `latest.json` + `SHA256SUMS`.

## 7. Verify the draft

`gh release view vX.Y.Z --json isDraft,isPrerelease,assets` — expect:

- Windows: `*-setup.exe` (NSIS) + its `.sig`, plus the `.msi`
- macOS: `*.dmg` + `*.app.tar.gz` + its `.sig` (Apple Silicon only, unsigned — Gatekeeper
  bypass is documented in the README)
- Linux: `*.AppImage` + its `.sig`, plus the `.deb`
- `latest.json` — sanity-check it: `version` correct, all three platform `url`s point at
  their updater payloads, every `signature` non-empty
- `SHA256SUMS`

## 8. Pre-publish checklist (human gates — surface, never skip silently)

- Surface the open walkthrough backlog: `gh issue list --label walkthrough` → the issue
  titled **"Live walkthrough backlog"**. Put its contents in front of the human alongside
  the draft.
- The `just dev` UI eyeball is a **human-only** gate (GUI + Entra sign-in — cannot run
  headless). Remind the human it's outstanding; publishing auto-updates users, so skipping
  it must be their explicit call, never a silent omission.

## 9. Publish — ONLY on explicit human instruction

```bash
gh release edit vX.Y.Z --draft=false --latest
```

Never `gh release create` — the workflow already made the draft; creating a second release
bypasses the assembled `latest.json`/assets and confuses the updater endpoint.

## Re-cut pattern (broken draft, not yet published)

Validated on v0.11.0, where pre-publish testing caught a bug:

1. Fix on a **new** release branch, PR + merge as usual (steps 4–5).
2. Delete the stale draft + tag: `gh release delete vX.Y.Z --yes`, then
   `git push origin :refs/tags/vX.Y.Z` and `git tag -d vX.Y.Z`.
3. Re-tag the new merge commit (step 6). The same version number is fine — the first draft
   never published.

## Optional local packaging checks

Per-host only (each recipe builds its own OS's leg) and each needs the updater signing key
in `TAURI_SIGNING_PRIVATE_KEY[_PASSWORD]`: `just build-windows-updater` /
`just build-macos-updater` / `just build-linux-updater`. Not required for a release — the
matrix builds all three legs from the tag.

## Output format

```
release: v0.15.0 (minor)

✅ manifests bumped (tauri.conf.json · Cargo.toml [workspace.package] · web-rs Cargo.toml)
✅ lockfiles synced (root + web-rs) · verify green
✅ PR #NNN merged · tagged v0.15.0 on <merge-sha> · release.yml running
✅ draft verified: 3 platform payloads + 3 .sig + latest.json + SHA256SUMS

⏸ awaiting human: walkthrough backlog + `just dev` eyeball, then publish with
   gh release edit v0.15.0 --draft=false --latest
```

## Failure handling

- `just verify` fails → stop, report the failing gate's output.
- `guard` job fails (tag/manifest drift, placeholder updater pubkey, fresh RustSec
  advisory) → fix on a new branch and follow the re-cut pattern; never re-point a pushed
  tag with a force-push.
- Tag already exists → re-cut pattern (delete draft + tag, re-tag); never overwrite
  silently.
- Tag push 403s (the SSH remote can resolve to a no-write account) → per-command token
  workaround, without touching the saved remote:
  `git -c url."https://x-access-token:$(gh auth token)@github.com/".insteadOf="git@github.com:" push origin vX.Y.Z`.
