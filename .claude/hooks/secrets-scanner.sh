#!/usr/bin/env bash
# SessionEnd hook. Scans for committed secrets and warns the user.
# Wraps `gitleaks` if installed; otherwise applies a small set of high-signal
# regexes so the hook still produces useful output out of the box.
#
# Env:
#   SCAN_MODE=warn|block   (default warn)  warn = print and exit 0; block = exit 2
#   SCAN_SCOPE=diff|all    (default diff)  diff = changed/staged/untracked; all = whole tree

mode="${SCAN_MODE:-warn}"
scope="${SCAN_SCOPE:-diff}"
project="${CLAUDE_PROJECT_DIR:-$PWD}"

cd "$project" 2>/dev/null || exit 0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

emit_and_exit() {
  printf '[secrets-scanner] Potential secrets detected (mode=%s, scope=%s):\n' "$mode" "$scope" >&2
  printf '%s\n' "$1" >&2
  if [ "$mode" = "block" ]; then
    exit 2
  fi
  exit 0
}

if command -v gitleaks >/dev/null 2>&1; then
  if ! output=$(gitleaks detect --no-banner --redact 2>&1); then
    emit_and_exit "$output"
  fi
  exit 0
fi

# Regex fallback over the configured scope.
if [ "$scope" = "all" ]; then
  files=$(git ls-files)
else
  files=$( {
    git diff --name-only HEAD 2>/dev/null
    git diff --cached --name-only 2>/dev/null
    git ls-files --others --exclude-standard 2>/dev/null
  } | sort -u )
fi
[ -z "$files" ] && exit 0

# High-signal patterns only — false positives in a SessionEnd warning are noisy.
pattern='(AKIA|ASIA)[0-9A-Z]{16}'
pattern="$pattern"'|AIza[0-9A-Za-z_-]{35}'                  # Google API key
pattern="$pattern"'|ghp_[A-Za-z0-9]{36}'                    # GitHub PAT
pattern="$pattern"'|gho_[A-Za-z0-9]{36}'                    # GitHub OAuth
pattern="$pattern"'|github_pat_[A-Za-z0-9_]{82}'            # GitHub fine-grained PAT
pattern="$pattern"'|glpat-[A-Za-z0-9_-]{20}'                # GitLab PAT
pattern="$pattern"'|xox[baprs]-[A-Za-z0-9-]+'               # Slack token
pattern="$pattern"'|sk-[A-Za-z0-9]{32,}'                    # OpenAI / Anthropic-style key
pattern="$pattern"'|-----BEGIN [A-Z ]*PRIVATE KEY-----'     # PEM private key

hits=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || continue
  if line=$(grep -EnH --binary-files=without-match "$pattern" "$f" 2>/dev/null); then
    redacted=$(printf '%s\n' "$line" | sed -E 's/(:[0-9]+:).*$/\1<redacted>/')
    hits="${hits}${redacted}
"
  fi
done <<EOF
$files
EOF

if [ -n "$hits" ]; then
  emit_and_exit "$hits"
fi
exit 0
