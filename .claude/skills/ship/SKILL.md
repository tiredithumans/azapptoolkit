---
name: ship
description: Land the current working-tree changes on main — branch, conventional commits, push, PR, merge, branch cleanup. Use when the user says "ship", "ship this/it", "land this", or asks for the full commit → PR → merge flow.
argument-hint: "[optional scope hint or PR title]"
---

# Ship — commit → push → PR → merge → cleanup

Land the current changes on `main` using this repo's exact flow, end to end, without stopping to
ask between steps. If arguments were passed, treat them as guidance (what to include, scope hint,
or PR title). Stop and ask only if the working tree mixes clearly unrelated work and the split is
ambiguous, or if a gate fails.

## 0. Preflight

- `git status --short` and `git log origin/main..HEAD --oneline`. Nothing to commit **and**
  nothing unpushed → report "nothing to ship" and stop.
- **Gate check:** if any Rust/WASM source changed (`crates/`, `apps/desktop/src-tauri/`,
  `apps/desktop/web-rs/`), run `just verify` (fmt-check → clippy → test → web-fmt-check →
  web-clippy → web-test → web-build) and stop on failure. For full CI parity, `just verify-full`
  adds audit/web-audit/deny/web-deny/web-itest (web-itest needs a browser). Changes limited to
  docs, `.claude/`, or `.github/` skip verify — say so in the PR test plan. Remote CI still runs
  the required checks on the PR; the merge waits on them (step 4).
- **Changelog check:** if the changes include a user-facing feature, fix, or behavior change, make
  sure `CHANGELOG.md` `[Unreleased]` has an entry for it (add one proactively — the advisory
  `changelog-check.sh` hook only nudges after the fact). Internal/docs/CI-only changes don't need
  one.

## 1. Branch

- On `main`? Create `git checkout -b <type>/<short-slug>`, where `<type>` matches the dominant
  conventional-commit type (`feat`/`fix`/`docs`/`chore`/`refactor`/…). Already on a topic branch?
  Stay on it.

## 2. Commit

- Group the changes into one or more **logical** commits — one concern per commit — each following
  Conventional Commits (AGENTS.md → Git & version control). Pass multi-line bodies with the
  `-m "$(cat <<'EOF' … EOF)"` heredoc form; the commit-validator hook understands it, including
  double quotes inside the body.
- Stage explicitly (`git add <paths>`), never a blind `git add -A` — leave unrelated files behind.

## 3. Push + PR

- `git push -u origin <branch>`
- `gh pr create --base main --title "<conventional subject>" --body …` — body is `## Summary`
  (what + why, bulleted) and `## Test plan` (checkboxes for what was *actually* run; an unchecked
  box is better than a false one).

## 4. Wait on CI, then merge + cleanup

- Branch protection on `main` is **strict** with required checks — the merge waits on remote CI.
  Watch with `gh pr checks <num> --watch`, or for long runs a background poll loop on
  `gh pr view <num> --json statusCheckRollup` (sleep ~45s between polls).
- If strict mode marks the branch behind (another PR merged first): `gh pr update-branch <num>`,
  then re-wait — that spawns a fresh CI cycle. With multiple PRs open, merges are therefore
  **sequential**, one CI cycle each (every merge re-behinds the others) — batch related changes
  into fewer PRs.
- **Stacked-PR footgun:** before merging, check `gh pr list --base <branch>` — deleting a branch
  that another open PR bases on CLOSES that PR. If anything bases on it, merge **without**
  `--delete-branch` and clean the branch up after the stack lands.
- `gh pr merge <num> --merge --delete-branch` — this repo uses merge commits. The command also
  checks out `main`, fast-forwards it, and deletes the local branch.
- `git fetch --prune` to drop the stale remote-tracking ref it leaves behind.
- Confirm `git status` is clean on the updated `main`, then report the PR URL and merge commit.

## Failure handling

- Commit blocked by the validator hook → fix the message; never bypass with `--no-verify`.
- `just verify` fails → stop, report the failing gate's output, do not push.
- A required remote check goes red → fix on the branch and push (CI re-runs); never merge over
  failing checks.
- PR not mergeable (conflict, branch protection) → stop and report; never force-push or merge with
  admin overrides.
