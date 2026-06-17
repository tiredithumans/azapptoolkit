# Contributing to azapptoolkit

Thanks for your interest in improving azapptoolkit. Issues and pull requests are
welcome — **please open an issue first to discuss non-trivial changes** so we can
agree on the approach before you invest time.

By participating you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).

## Getting set up

Everything you need to build, run, and package the app lives in
[docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md). The short version:

```bash
cargo install just      # one-time: the task runner (or brew/winget)
just setup              # idempotent toolchain + dependency bootstrap
just dev                # daily dev loop (= cargo tauri dev)
```

Running locally needs `AZAPPTOOLKIT_CLIENT_ID` + `AZAPPTOOLKIT_TENANT_ID` for a
single-tenant public-client Entra app registration you control — see
[First-run configuration](./README.md#first-run-configuration) and `.env.example`.

## Working agreements

The single source of truth for how code is structured and the conventions every
contributor (human or AI assistant) follows is **[AGENTS.md](./AGENTS.md)**. Read it
before your first change — it covers the Tauri command pattern, tenant-scoped cache
rules, WASM gating, the incremental-consent token model, and the project's other
load-bearing gotchas.

## Before you open a pull request

Run the same gates CI runs, and make sure they pass:

```bash
just verify            # fmt-check → clippy → test → web-fmt-check → web-test → web-build
```

- **Keep changes focused.** Solve one logical thing per PR; smaller diffs review
  faster and break less.
- **Test what you change.** Add or update tests alongside behavior changes; keep
  `cargo test --workspace` green. Audit-scoring rules need a table-driven test that
  cites the legacy PowerShell `file:line` they were ported from.
- **Don't log or persist secrets.** Preserve the keyring / incremental-consent
  boundaries described in AGENTS.md.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) are required:
`<type>[(scope)][!]: <description>`.

- **types:** `feat fix docs chore refactor test build ci perf style revert deps`
- **scopes seen in this repo:** `desktop`, `core`, `auth`, `graph`, `exchange`,
  `keyvault`, `permissions`, `ci`, `docs`

Changes that port behavior from the legacy PowerShell module should reference the
source `file:line` range in the commit body.

## Reporting security issues

**Do not** open a public issue for vulnerabilities — follow
[SECURITY.md](./.github/SECURITY.md) instead.
