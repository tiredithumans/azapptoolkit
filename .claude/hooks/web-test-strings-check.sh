#!/usr/bin/env bash
# PostToolUse hook for `Write` / `Edit`. When an Edit removes a string literal
# (CSS class, aria-label, on-screen text) from web-rs source, checks whether
# the browser GUI tests still reference it. `just web-itest` runs ONLY in CI —
# not in `just verify` — so a rename passes local verify and then fails CI;
# this hook surfaces the test dependency at edit time instead.
#
# Only Edit payloads carry old_string/new_string; Write payloads (whole-file
# replace) have no cheap before/after diff, so they exit silently.
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

# Only web-rs source can break the GUI tests; the tests themselves don't count.
case "$rel" in
  apps/desktop/web-rs/src/test_support/*) exit 0 ;;
  apps/desktop/web-rs/src/*) ;;
  *) exit 0 ;;
esac

old=$(printf '%s' "$payload" | jq -r '.tool_input.old_string // empty' 2>/dev/null)
[ -z "$old" ] && exit 0
new=$(printf '%s' "$payload" | jq -r '.tool_input.new_string // empty' 2>/dev/null)

tests_dir="$project/apps/desktop/web-rs/tests"
support_dir="$project/apps/desktop/web-rs/src/test_support"
search_dirs=""
[ -d "$tests_dir" ] && search_dirs="$tests_dir"
[ -d "$support_dir" ] && search_dirs="$search_dirs $support_dir"
[ -z "$search_dirs" ] && exit 0

# Candidate literals: double-quoted strings (>= 4 chars) in the removed text,
# plus the individual tokens of class="..." values (tests grep single class
# names out of multi-class attributes). aria-label="..." values are plain
# double-quoted literals, so the first extraction already covers them.
candidates=$( {
  printf '%s\n' "$old" | grep -oE '"[^"\\]{4,}"' | sed 's/^"//; s/"$//'
  printf '%s\n' "$old" | grep -oE 'class="[^"]+"' | sed 's/^class="//; s/"$//' | tr ' ' '\n'
} | awk 'length >= 4' | sort -u | head -20)
[ -z "$candidates" ] && exit 0

out=""
while IFS= read -r lit; do
  [ -z "$lit" ] && continue
  # Still present after the edit → not a removal, skip.
  case "$new" in *"$lit"*) continue ;; esac
  # shellcheck disable=SC2086  # search_dirs is intentionally word-split
  hits=$(grep -rlF -- "$lit" $search_dirs 2>/dev/null)
  [ -z "$hits" ] && continue
  hits_rel=$(printf '%s\n' "$hits" | sed "s|^$project/||" | paste -sd, -)
  out="${out}[web-test-strings] Removed \"$lit\" from $rel but it is still referenced by: $hits_rel\n"
done <<EOF
$candidates
EOF

[ -z "$out" ] && exit 0
printf '%b' "$out" | head -10 >&2
printf '[web-test-strings] web-itest runs ONLY in CI (not `just verify`) — update the tests with the rename or CI fails.\n' >&2
exit 0
