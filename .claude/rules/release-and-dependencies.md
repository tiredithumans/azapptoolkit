---
paths:
  - ".github/**"
  - "CHANGELOG.md"
  - "Cargo.toml"
  - "crates/*/Cargo.toml"
  - "apps/desktop/**/Cargo.toml"
  - "deny.toml"
  - "justfile"
  - "apps/desktop/src-tauri/tauri.conf.json"
  - "apps/desktop/src-tauri/build.rs"
  - "apps/desktop/web-rs/build.rs"
---

# Release, updater & dependencies — the detail behind the AGENTS.md one-liners

Deep-dive: `docs/architecture/release-updater-demo.md`. Pinned by `repo_invariants/release.rs` and `tests/dependency_policy.rs`.

- **Release is a 3-OS matrix → one aggregated `latest.json`.** `guard` → `build` matrix → `release` assembles one draft; a human publishes. CHANGELOG headers are `## [X.Y.Z] - YYYY-MM-DD` (**no `v` prefix, ASCII hyphen, one space**) — **two** parsers depend on it (PowerShell in `release.yml`, Rust in `web-rs/build.rs`). The three version manifests (`tauri.conf.json`, root `Cargo.toml`, `web-rs/Cargo.toml`) must agree with the tag.
- **`web-rs/build.rs` bakes this version's CHANGELOG section** but deliberately does NOT `rerun-if-changed` on `CHANGELOG.md` (an `[Unreleased]` entry would otherwise recompile the whole frontend crate three times per verify); a version bump re-runs it on its own.
- **Crypto/encoding deps — no `rsa`; the `sha2` major and `p12-keystore` 0.2.x pinned on purpose.** `cert.rs` uses `rcgen` on the `aws_lc_rs` backend specifically to keep `rsa` (RUSTSEC-2023-0071) out of the graph. The rule is narrow — **don't move a crypto/encoding dep we declare onto a major nothing else in the tree is on** — so it is a claim about the graph, to be re-derived there rather than inherited. `sha2` (transitive-only) still qualifies: oauth2 5 + Tauri 2 hold the 0.10 line, and 0.11 is Linux-only via the keyring store. `rand` and `base64` did NOT survive that re-derivation and were taken on 2026-09-14 — `p12-keystore` already pulled `rand 0.10` and `rcgen`→`pem` already pulled `base64 0.23`, so both bumps added zero crates; `base64` is declared `default-features = false, features = ["std"]` because 0.23 defaults `simd-unsafe` on. Rationale + drop conditions live in `dependabot.yml`'s `ignore` blocks and `docs/architecture/release-updater-demo.md`.
- **Workspace dependency** — add to `[workspace.dependencies]`, use `"name".workspace = true`, check `Cargo.lock` for a duplicate major. `web-rs` has its own lockfile, so the root `audit`/`deny` never reach it — `web-audit`/`web-deny` do; every verify/CI gate runs `--locked`, so bump both lockfiles with `cargo update --workspace` after a version bump.
- **CI gating.** Docs-only changes (`*.md`, `docs/`, `.claude/`) skip the compile jobs but every required check still reports; the secrets + hooks job is never gated (a docs-only diff can commit a key). `verify-full` must run every `just` recipe `ci.yml` runs (pinned by `verify_full_runs_every_gate_ci_runs`).
- **Auto-update is interactive**, and the updater is keyed: `*-updater` recipes need `TAURI_SIGNING_PRIVATE_KEY[_PASSWORD]`; `build-windows` is keyless for local packaging.
