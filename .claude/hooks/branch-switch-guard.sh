#!/usr/bin/env bash
# PreToolUse hook for `Bash`. Blocks `git checkout <branch>` / `git switch
# <branch>` while the shared checkout has uncommitted tracked changes — a
# background agent switching branches mid-session silently carries (or
# clobbers) another workstream's dirty state. New-branch forms (`-b`/`-B`/
# `-c`/`-C`/`--orphan`) and path checkouts (`-- <path>`) are allowed: starting
# a branch from dirty work is the normal flow, and path checkouts don't
# switch.
#
# Override for a deliberate switch: prefix the command with
# `AZAPP_ALLOW_BRANCH_SWITCH=1` (stash or commit first).
#
# Exit codes follow Claude Code's hook contract:
#   0 — allow (not a branch switch / clean tree / override present)
#   2 — block and surface stderr to Claude for self-correction

set -uo pipefail

payload=$(cat 2>/dev/null || true)

# Cheap pre-filter: this hook fires on every Bash call, so the common path
# must be fast.
case "$payload" in
  *'git checkout'*|*'git switch'*) ;;
  *) exit 0 ;;
esac

case "$payload" in
  *AZAPP_ALLOW_BRANCH_SWITCH=1*) exit 0 ;;
esac
[ "${AZAPP_ALLOW_BRANCH_SWITCH:-}" = "1" ] && exit 0

# Need python3 for reliable JSON + shell-quoted argument parsing. If absent,
# fail open — the agent still has the hazard note from AGENTS.md.
if ! command -v python3 >/dev/null 2>&1; then
  exit 0
fi

switch_target=$(PAYLOAD="$payload" python3 <<'PY'
import json, os, re, shlex, sys

try:
    payload = json.loads(os.environ.get("PAYLOAD", "") or "{}")
except (json.JSONDecodeError, ValueError):
    sys.exit(0)

cmd = (payload.get("tool_input") or {}).get("command", "") or ""
if "git" not in cmd:
    sys.exit(0)

NEW_BRANCH_FLAGS = {"-b", "-B", "-c", "-C", "--orphan"}

# Approximate split on chained shell separators — same trade-off as the
# commit validator: backs up the prompt rule, not a security boundary.
for segment in re.split(r"&&|\|\||;|\|", cmd):
    if "checkout" not in segment and "switch" not in segment:
        continue
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        continue
    for i in range(len(tokens) - 1):
        if tokens[i] != "git" or tokens[i + 1] not in ("checkout", "switch"):
            continue
        args = tokens[i + 2:]
        # `-- <path>` anywhere = path checkout, not a branch switch.
        if "--" in args:
            continue
        if any(a in NEW_BRANCH_FLAGS for a in args):
            continue
        targets = [a for a in args if not a.startswith("-")]
        if targets:
            print(targets[0])
            sys.exit(0)
sys.exit(0)
PY
)

[ -z "$switch_target" ] && exit 0

project="${CLAUDE_PROJECT_DIR:-$PWD}"
cd "$project" 2>/dev/null || exit 0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

# Untracked files survive a branch switch; only tracked modifications carry.
dirty=$(git status --porcelain --untracked-files=no 2>/dev/null)
[ -z "$dirty" ] && exit 0

count=$(printf '%s\n' "$dirty" | grep -c .)
{
  printf '[branch-switch-guard] Blocked `git checkout/switch %s`: %s tracked file(s) have uncommitted changes in this shared checkout.\n' "$switch_target" "$count"
  printf 'Commit or `git stash` first. For a deliberate switch carrying the changes, prefix the command with AZAPP_ALLOW_BRANCH_SWITCH=1.\n'
} >&2
exit 2
