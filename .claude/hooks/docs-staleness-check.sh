#!/usr/bin/env bash
# PostToolUse hook for `Write` / `Edit`. Reads the hook payload from stdin and
# prints a one-line reminder to stderr when the agent edited a user-facing
# surface (Tauri commands, packaging / updater config, setup scripts, the auth
# flow, …) without also touching the matching prose doc (README.md or
# docs/DEVELOPMENT.md). The reminder shows up in the agent's next-turn
# context so it can decide whether to update the prose docs.
#
# This is the docs/README counterpart to `agents-md-staleness-check.sh`.
# AGENTS.md is the agent contract; the prose docs go stale a different way (a
# new command → README feature gap, a tauri.conf.json change → packaging-doc
# gap, etc.).
#
# Exits 0 always — this hook never blocks. The agent makes the judgment call.

set -uo pipefail

payload=$(cat 2>/dev/null || true)
[ -z "$payload" ] && exit 0

if ! command -v jq >/dev/null 2>&1; then
  exit 0
fi

file=$(printf '%s' "$payload" \
  | jq -r '.tool_response.filePath // .tool_input.file_path // empty' 2>/dev/null)
[ -z "$file" ] && exit 0

project="${CLAUDE_PROJECT_DIR:-$PWD}"
case "$file" in
  /*) rel="${file#"$project"/}" ;;
  *)  rel="$file" ;;
esac

# Doc files themselves and the agent-contract files don't trigger a docs
# reminder — AGENTS.md has its own hook.
case "$rel" in
  README.md|AGENTS.md|CLAUDE.md) exit 0 ;;
  docs/*) exit 0 ;;
esac

# Skip tests, generated artifacts, and lockfiles. Editing these almost never
# requires a prose-doc update.
case "$rel" in
  *_test.rs|*/tests/*|tests/*) exit 0 ;;
  target/*|*/target/*) exit 0 ;;
  dist/*|*/dist/*) exit 0 ;;
  *.lock) exit 0 ;;
esac

# Map the edited path to the doc most likely to lag behind. Order matters: the
# first match wins, so put narrower patterns ahead of broader ones. The hint
# string is the doc surface the agent should re-skim — it's a suggestion, not
# an assertion that the doc is wrong.
hint=""
mention_readme=0
case "$rel" in
  apps/desktop/src-tauri/src/commands/*)
    hint="README.md (Features)"
    ;;
  apps/desktop/src-tauri/tauri.conf.json|apps/desktop/src-tauri/build.rs|.github/workflows/release.yml)
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
  *)
    exit 0
    ;;
esac

cd "$project" 2>/dev/null || exit 0

# Stay silent if the matched doc (or README.md, when relevant) is already
# modified — the agent is already updating prose.
docs_dirty=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  # Strip the trailing " (...)" annotation to get the file path prefix.
  primary="${hint%% (*}"
  primary="${primary%% and *}"
  if [ -n "$primary" ] && git status --porcelain -- "$primary" 2>/dev/null | grep -q .; then
    docs_dirty=1
  fi
  if [ "$mention_readme" -eq 1 ] && [ "$docs_dirty" -eq 0 ]; then
    if git status --porcelain -- README.md 2>/dev/null | grep -q .; then
      docs_dirty=1
    fi
  fi
fi
[ "$docs_dirty" -eq 1 ] && exit 0

if [ "$mention_readme" -eq 1 ]; then
  printf '[docs-check] Edited %s. If user-facing behavior changed, re-skim %s and README.md.\n' \
    "$rel" "$hint" >&2
else
  printf '[docs-check] Edited %s. If user-facing behavior changed, re-skim %s.\n' \
    "$rel" "$hint" >&2
fi
exit 0
