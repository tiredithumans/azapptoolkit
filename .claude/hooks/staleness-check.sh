#!/usr/bin/env bash
# PostToolUse hook for `Write` / `Edit`. Reads the hook payload from stdin and
# prints one-line staleness reminders to stderr when the agent edited a file
# whose documentation counterpart tends to lag behind:
#
#   * structural files (manifests, workflows, justfile, …) → AGENTS.md
#   * user-facing surfaces (commands, packaging, auth, frontend, updater/demo)
#     → the matching prose doc (README.md, docs/DEVELOPMENT.md,
#     docs/architecture/…)
#   * AGENTS.md itself → its 28 000-byte size budget (the file is an
#     invariant-plus-pointer index; deep detail belongs in docs/architecture/)
#
# Merged from agents-md-staleness-check.sh + docs-staleness-check.sh so the
# payload is parsed once and the path→doc map lives in one place. Reminders
# show up in the agent's next-turn context so it can decide whether to update
# the docs.
#
# Exits 0 always — this hook never blocks. The agent makes the judgment call.

set -uo pipefail

payload=$(cat 2>/dev/null || true)
[ -z "$payload" ] && exit 0

# Need jq to read the edited path out of the payload. If absent, skip silently
# rather than blocking edits.
if ! command -v jq >/dev/null 2>&1; then
  exit 0
fi

file=$(printf '%s' "$payload" \
  | jq -r '.tool_response.filePath // .tool_input.file_path // empty' 2>/dev/null)
[ -z "$file" ] && exit 0

project="${CLAUDE_PROJECT_DIR:-$PWD}"
# Compute repo-relative path so glob matches work regardless of cwd.
case "$file" in
  /*) rel="${file#"$project"/}" ;;
  *)  rel="$file" ;;
esac

# AGENTS.md edits get exactly one check: the size budget. Past the budget the
# invariant + pointer diet applies — move deep detail to docs/architecture/.
if [ "$rel" = "AGENTS.md" ]; then
  size=$(wc -c < "$project/AGENTS.md" 2>/dev/null | tr -d ' ')
  if [ "${size:-0}" -gt 28000 ] 2>/dev/null; then
    printf '[staleness-check] AGENTS.md is %s bytes — over its 28000-byte budget. Keep the invariant + pointer here; move deep detail to docs/architecture/.\n' "$size" >&2
  fi
  exit 0
fi
[ "$rel" = "CLAUDE.md" ] && exit 0

cd "$project" 2>/dev/null || exit 0
in_git=0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 && in_git=1

# True when the given doc is already modified (staged or unstaged) — the agent
# is already updating it, so stay silent.
dirty() {
  [ "$in_git" -eq 1 ] && git status --porcelain -- "$1" 2>/dev/null | grep -q .
}

# --- AGENTS.md reminder: structural surfaces. Editing any of these is the
# trigger for "consider updating AGENTS.md". Keep this list in sync with the
# "Keeping this file up to date" section of AGENTS.md.
match=0
case "$rel" in
  Cargo.toml) match=1 ;;
  Cargo.lock) match=1 ;;
  rust-toolchain.toml) match=1 ;;
  .claude/settings.json) match=1 ;;
  crates/*/Cargo.toml) match=1 ;;
  apps/*/*/Cargo.toml) match=1 ;;
  justfile) match=1 ;;
  apps/desktop/src-tauri/tauri.conf.json) match=1 ;;
  apps/desktop/src-tauri/build.rs) match=1 ;;
  apps/desktop/src-tauri/capabilities/*) match=1 ;;
  apps/desktop/web-rs/Trunk.toml) match=1 ;;
  .github/workflows/*.yml|.github/workflows/*.yaml) match=1 ;;
esac
if [ "$match" -eq 1 ] && ! dirty AGENTS.md; then
  printf '[staleness-check] Edited %s. If this affects repo map / commands / conventions, update AGENTS.md in this change.\n' "$rel" >&2
fi

# --- Prose-doc reminder: map the edited path to the doc most likely to lag
# behind. Order matters: the first match wins, so narrower patterns go ahead
# of broader ones. The hint string is the doc surface the agent should
# re-skim — a suggestion, not an assertion that the doc is wrong. Doc files,
# tests, generated artifacts, and lockfiles never trigger.
hint=""
case "$rel" in
  README.md|docs/*) ;;
  *_test.rs|*/tests/*|tests/*) ;;
  target/*|*/target/*|dist/*|*/dist/*|*.lock) ;;
  apps/desktop/src-tauri/src/commands/updater*)
    hint="docs/architecture/release-updater-demo.md"
    ;;
  apps/desktop/src-tauri/src/commands/*)
    hint="README.md (Features)"
    ;;
  apps/desktop/web-rs/src/components/update_splash.rs)
    hint="docs/architecture/release-updater-demo.md"
    ;;
  .github/workflows/release.yml|.github/workflows/pages.yml)
    hint="docs/architecture/release-updater-demo.md"
    ;;
  apps/desktop/web-rs/src/views/*|apps/desktop/web-rs/src/components/*)
    hint="docs/architecture/frontend-workspace.md"
    ;;
  apps/desktop/src-tauri/tauri.conf.json|apps/desktop/src-tauri/build.rs)
    hint="docs/DEVELOPMENT.md (packaging / updater / CI)"
    ;;
  apps/desktop/src-tauri/capabilities/*)
    hint="docs/DEVELOPMENT.md"
    ;;
  justfile)
    hint="docs/DEVELOPMENT.md (Quick setup / Testing)"
    ;;
  .github/workflows/ci.yml)
    hint="docs/DEVELOPMENT.md (CI)"
    ;;
  crates/azapptoolkit-auth/src/*)
    hint="README.md (First-run configuration / Security)"
    ;;
  Cargo.toml|rust-toolchain.toml)
    hint="docs/DEVELOPMENT.md (Prerequisites)"
    ;;
esac
if [ -n "$hint" ]; then
  # Strip the trailing " (...)" annotation to get the file path for the
  # dirty check.
  primary="${hint%% (*}"
  if ! dirty "$primary"; then
    printf '[staleness-check] Edited %s. If user-facing behavior changed, re-skim %s.\n' "$rel" "$hint" >&2
  fi
fi

exit 0
