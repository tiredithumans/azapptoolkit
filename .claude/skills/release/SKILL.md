---
name: release
description: Prepare and publish a new release — bump version, finalize CHANGELOG.md [Unreleased] → [vX.Y.Z], tag and push. Use when the user says "release", "bump version", or asks to publish a new release.
argument-hint: "[version bump type: patch, minor, major]"
---

# Release — version bump → changelog → tag → push

Prepare a released build and publish it. If arguments were passed, treat them as guidance for the bump type (`major` / `minor` / `patch`; default is `patch`).

## 0. Determine the bump type

- If argument given: use it (`patch`, `minor`, or `major`).
- If no argument, look at the most recent commits since last release tag:
  - `feat:` → minor bump.
  - Breaking changes in commit messages or CHANGELOG → major bump.
  - Only `fix:` / `chore:` → patch bump.

## 1. Finalize the changelog

- Read `CHANGELOG.md`, find `[Unreleased]`.
- Convert it to a versioned section: `## [vX.Y.Z] — YYYY-MM-DD`.
- Move each `[Unreleased]` entry into the versioned section.
- Update `CHANGELOG.md` with a new `[Unreleased]` header below the versioned section.
- Check for entries that need `file:line` references (porting from legacy PowerShell).

## 2. Bump the version

- Update `apps/desktop/web-rs/package.json` `version` field.
  - Also update `apps/desktop/src-tauri/tauri.conf.json` version.
- Update `Cargo.toml` workspace root and any crate that publishes independently (check for `[package].version`).
- Update `apps/desktop/Cargo.toml` if it has its own version.

## 3. Verify the release build

- Run `just verify` (fmt → clippy → test → web-fmt-check → web-test → web-build).
- Ensure `_stub_frontend_dist` is current (so Tauri's `generate_context!` doesn't panic).
- Run `just build-windows` if releasing for Windows (MSI + NSIS installers).
- Check `tauri.conf.json` updater config and release notes.

## 4. Tag and push

- `git checkout main`
- `git pull origin main` (ensure up-to-date).
- Commit changelog + version bump: `git commit -m "release(vX.Y.Z): bump to vX.Y.Z"`.
- Tag: `git tag -a v0.1.2 -m "release(vX.Y.Z): version bump to vX.Y.Z"`.
- Push: `git push origin main --tags`.

## 5. Create the release on GitHub (optional, if not using gh)

- `gh release create v0.1.2 --generate-notes` if you want auto-generated notes from commits.
- Attach any release artifacts (e.g., `.msi`, installers) if they exist locally.

## Output format

```
release: bumping to v0.1.2 (patch)

## [v0.1.2] — 2026-06-18
- Show app version beneath Sign Out button (#47)
- Cache moved to bottom of nav rail in sidebar

✅ verify passed (fmt, clippy, test, web-fmt-check, web-test, web-build)
✅ tagged v0.1.2 and pushed to origin/main

🔗 https://github.com/tiredithumans/azapptoolkit/releases/tag/v0.1.2
```

## Failure handling

- `just verify` fails → stop, report the failing gate's output.
- Conflict on pull → suggest resolving before tagging.
- Tag already exists → report and ask whether to overwrite (never force-push silently).
