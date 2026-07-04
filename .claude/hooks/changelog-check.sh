#!/usr/bin/env bash
# PostToolUse hook for `Bash`. After a `git commit`, nudges when the new HEAD
# touches code paths but carries no CHANGELOG.md change — AGENTS.md requires an
# [Unreleased] entry per change, and amending now is cheaper than a review
# round trip later. Release commits are exempt (the release flow rewrites the
# changelog itself).
#
# Exits 0 always — this hook never blocks. The agent makes the judgment call.

set -uo pipefail

payload=$(cat 2>/dev/null || true)

# Cheap pre-filter: this hook fires after every Bash call, so the common path
# must be fast.
case "$payload" in
  *'git commit'*) ;;
  *) exit 0 ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  exit 0
fi

cmd=$(printf '%s' "$payload" | jq -r '.tool_input.command // empty' 2>/dev/null)
case "$cmd" in
  *'git commit'*) ;;
  *) exit 0 ;;
esac

project="${CLAUDE_PROJECT_DIR:-$PWD}"
cd "$project" 2>/dev/null || exit 0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

# The command mentioned `git commit` but may have failed; if HEAD is
# unreadable there is nothing to inspect.
subject=$(git log -1 --format=%s 2>/dev/null)
[ -z "$subject" ] && exit 0
case "$subject" in
  'chore: release'*|'chore(release)'*) exit 0 ;;
esac

files=$(git show --name-only --format= HEAD 2>/dev/null)
[ -z "$files" ] && exit 0
printf '%s\n' "$files" | grep -q '^CHANGELOG\.md$' && exit 0
printf '%s\n' "$files" | grep -qE '^(crates/|apps/desktop/|justfile$|\.claude/)' || exit 0

printf '[changelog-check] HEAD (%s) touches code but not CHANGELOG.md — add a [Unreleased] entry (e.g. via `git commit --amend`).\n' "$subject" >&2
exit 0
