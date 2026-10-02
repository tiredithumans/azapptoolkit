#!/usr/bin/env bash
# Release step 2 in one command (SKILL.md steps 1-2 defer to this; the
# changelog roll comes FIRST because the tail test compares against it).
# Rewrites the three guarded version literals (tauri.conf.json, root [workspace.package],
# web-rs [package]), resyncs BOTH lockfiles, then runs the release-identity
# tests. Lockfile sync uses `cargo update --workspace` (workspace members only,
# no dep churn, and never --locked — the whole point is to rewrite the locks).
# Usage: just bump X.Y.Z
set -euo pipefail
V="${1:?usage: just bump X.Y.Z}"
[[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bump: '$V' is not X.Y.Z" >&2; exit 1; }
cd "$(cd "$(dirname "$0")/.." && pwd)"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# tauri.conf.json carries exactly one "version" key — replace it anywhere.
sed 's/"version": *"[^"]*"/"version": "'"$V"'"/' apps/desktop/src-tauri/tauri.conf.json >"$tmp"
mv "$tmp" apps/desktop/src-tauri/tauri.conf.json

# Root Cargo.toml: only the [workspace.package] block. Dependency entries
# declare versions too and must not move, so the edit is scoped to the block.
awk -v v="$V" '
  /^\[workspace\.package\]/ { blk = 1; print; next }
  /^\[/                     { blk = 0 }
  blk && /^version = /      { print "version = \"" v "\""; next }
                            { print }' Cargo.toml >"$tmp"
mv "$tmp" Cargo.toml

# web-rs Cargo.toml: only the [package] block, for the same reason.
awk -v v="$V" '
  /^\[package\]/            { blk = 1; print; next }
  /^\[/                     { blk = 0 }
  blk && /^version = /      { print "version = \"" v "\""; next }
                            { print }' apps/desktop/web-rs/Cargo.toml >"$tmp"
mv "$tmp" apps/desktop/web-rs/Cargo.toml

# Fail loudly if any manifest did not end up stating the new version — a
# silently non-matching rewrite would ship a partial bump.
grep -q "\"version\": \"$V\"" apps/desktop/src-tauri/tauri.conf.json || { echo "bump: tauri.conf.json does not state $V — the rewrite matched nothing" >&2; exit 1; }
for f in Cargo.toml apps/desktop/web-rs/Cargo.toml; do
  grep -q "^version = \"$V\"" "$f" || { echo "bump: $f does not state $V — the rewrite matched nothing" >&2; exit 1; }
done

# Lockfile resync (SKILL.md §2): both trees, workspace-only update.
cargo update --workspace
(cd apps/desktop/web-rs && cargo update --workspace)

# Release-identity smoke: the release.rs invariant suite (three-manifest
# version parity, CHANGELOG header format, the verify-full gate list).
cargo test --locked -p desktop -- release