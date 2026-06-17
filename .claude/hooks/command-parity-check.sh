#!/usr/bin/env bash
# PostToolUse hook for `Write` / `Edit`. Reads the hook payload from stdin and,
# when the edited file is part of the Tauri command chain (a command handler,
# the lib.rs handler registry, or a frontend IPC binding), cross-checks the
# three halves of the "Adding a new Tauri command" pattern from AGENTS.md:
#
#   1. `#[tauri::command]` fns declared under src-tauri/src/commands/
#   2. entries in the `tauri::generate_handler![]` list in src-tauri/src/lib.rs
#   3. a `"command_name"` string literal in web-rs/src/bindings/ (invoke_result)
#
# Any gap is printed to stderr so it lands in the agent's next-turn context.
# Mid-edit gaps are expected (the steps land one file at a time) — the output
# is the escort through the remaining steps, not an error.
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
case "$file" in
  /*) rel="${file#"$project"/}" ;;
  *)  rel="$file" ;;
esac

# Only fire for files in the command chain.
case "$rel" in
  apps/desktop/src-tauri/src/commands/*.rs) ;;
  apps/desktop/src-tauri/src/lib.rs) ;;
  apps/desktop/web-rs/src/bindings/*.rs) ;;
  *) exit 0 ;;
esac

commands_dir="$project/apps/desktop/src-tauri/src/commands"
lib_rs="$project/apps/desktop/src-tauri/src/lib.rs"
bindings_dir="$project/apps/desktop/web-rs/src/bindings"
[ -d "$commands_dir" ] && [ -f "$lib_rs" ] && [ -d "$bindings_dir" ] || exit 0

# 1. Declared: fn name within a few lines after a #[tauri::command] attribute.
declared=$(grep -h -A4 '#\[tauri::command' "$commands_dir"/*.rs 2>/dev/null \
  | grep -oE 'fn [a-z_0-9]+' | sed 's/^fn //' | sort -u)

# 2. Registered: `commands::module::name` entries inside generate_handler![].
registered=$(sed -n '/generate_handler!\[/,/\]/p' "$lib_rs" 2>/dev/null \
  | tr -d ' ,' | grep '^commands::' | sed 's/.*:://' | sort -u)

[ -z "$declared" ] && [ -z "$registered" ] && exit 0

out=""

# Declared but never registered → the UI can't reach it.
for c in $(comm -23 <(printf '%s\n' "$declared") <(printf '%s\n' "$registered")); do
  out="${out}[command-parity] \`$c\` has #[tauri::command] but is not in generate_handler![] (src-tauri/src/lib.rs).\n"
done

# Registered but no declaration found → stale registry entry (or a renamed fn).
for c in $(comm -13 <(printf '%s\n' "$declared") <(printf '%s\n' "$registered")); do
  out="${out}[command-parity] \`$c\` is in generate_handler![] but no #[tauri::command] fn with that name was found under src-tauri/src/commands/.\n"
done

# Declared but no frontend binding string → no typed stub calls it.
for c in $declared; do
  if ! grep -rqF "\"$c\"" "$bindings_dir" 2>/dev/null; then
    out="${out}[command-parity] \`$c\` has no \"$c\" invoke string in web-rs/src/bindings/ — add the typed stub.\n"
  fi
done

[ -z "$out" ] && exit 0
printf '%b' "$out" | head -20 >&2
exit 0
