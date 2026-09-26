# Self-verified notes (main session, before workflow results)

## Unused dependency declarations (cargo-machete + grep confirmation)
Genuinely unused (0 references in src/, tests/, build.rs):
- crates/azapptoolkit-arm/Cargo.toml:19  `tracing`
- crates/azapptoolkit-keyvault/Cargo.toml:20  `tracing`
- crates/azapptoolkit-exchange/Cargo.toml:18  `url`
- apps/desktop/src-tauri/Cargo.toml:42  `anyhow`
- apps/desktop/src-tauri/Cargo.toml:43  `thiserror`
- apps/desktop/web-rs/Cargo.toml:63  `tracing`

FALSE POSITIVES (needed by macro expansion): `thiserror` in arm/graph/keyvault — core's
`http_error_enum!` (crates/azapptoolkit-core/src/http_error.rs:65) expands `#[derive(Debug, ::thiserror::Error)]`
in the CALLER crate, so callers must declare thiserror even though their source never names it.
Cleanup option: have core depend on thiserror, `pub use thiserror as __thiserror;` (or a `__private` module) and
make the macro derive `$crate::__thiserror::Error`, then drop the three caller declarations; or add
`[package.metadata.cargo-machete] ignored = ["thiserror"]` to the three crates and wire `cargo machete` into `just verify-full`/CI.

## Policy drift candidate
- AGENTS.md: "One definition per policy: HTTP error taxonomy from core::http_error_enum!" — but
  crates/azapptoolkit-exchange/src/error.rs:1-30 hand-rolls `ExchangeError` with `thiserror` instead of the macro
  (macro callers: arm, graph, keyvault only). Check whether documented as deliberate (exchange has extra variants like
  Forbidden{had_diagnostics}). If not, it's a taxonomy-drift risk the invariants don't pin.

## Environment
- Desktop crate cannot compile here (webkit2gtk-4.1 missing); shared crates + web-rs host tests can.

Update: `.claude/rules/backend-commands-and-caches.md:24` scopes the macro rule to "Graph/ARM/Key Vault", so Exchange's
hand-rolled enum is semi-deliberate; but AGENTS.md:108 states the rule without that qualifier. Either qualify AGENTS.md
or migrate ExchangeError onto the macro's `extra { ... }` arm (it supports client-specific variants) so all four HTTP
clients share one taxonomy and the dto `is_reauth_fatal` agreement test covers Exchange identically. Severity low/medium.

## Toolchain baseline (salvaged from the toolchain-runner's logs; commands ran to completion)
- `cargo test --locked -p <8 shared crates>`: ALL PASS. 1 ignored: the doctest for `http_error_enum!` (crates/azapptoolkit-core/src/http_error.rs:35, ignored by design).
- `cargo test --locked --manifest-path apps/desktop/web-rs/Cargo.toml` (host target): ALL PASS (197 + 3). 1 ignored doctest (src/hooks/use_command.rs:6).
- `cargo check --target wasm32 --all-targets --features test-support` for web-rs: OK in 1m20s, with the warning
  "packages contain code that will be rejected by a future version of Rust: proc-macro-error2 v2.0.1" (transitive via leptos_macro
  toolchain). Worth tracking: a future rustc bump could break the WASM build with no change in this repo.
- Pedantic/nursery clippy over the shared crates (actionable subset; the 137 `too_long_first_doc_paragraph` hits are style noise):
  - `future_not_send` x8: keyvault/src/client.rs:118, graph/src/client/applications.rs:586-587, service_principals.rs:617-618,
    transport.rs:91-92 — public async fns returning non-Send futures; matters if any caller ever `tokio::spawn`s them.
  - `significant_drop_tightening` x4: core/src/cache.rs:841, 914, 1059 (lock guards held longer than needed).
  - `unused_async` x2: auth/src/service/mod.rs:561 (sign_out) and :679 — async fns with no await.
  - `wildcard_imports` x12: `use super::*` at the top of every graph client submodule and the core audit submodules (a documented
    re-export pattern in graph/src/client.rs, so likely deliberate; still hides what each module actually uses).
  - `redundant_closure` x12, `derive_partial_eq_without_eq` x7, `ref_option` x4, `needless_continue` x3, `redundant_clone` x1.
  Candidate `[workspace.lints.clippy]` additions that the tree nearly passes already: `unused_async`, `redundant_clone`,
  `derive_partial_eq_without_eq`, `ref_option`, `needless_continue`, `future_not_send` (after fixing the 8).

## Lead-session spot-checks of judge-ranked items (read directly in the code, 2026-09-26)
Agree with the verified finding:
- F036/F139 updater opt-out inert: `UserSettings::load` (the only reader of `AZAPPTOOLKIT_AUTO_UPDATE`) has no production caller; `auto_update` is never read by updater.rs or the frontend.
- F105 domain-form tenant: config_screen.rs:125/176 accepts "contoso.onmicrosoft.com"; auth service/mod.rs:313 compares the id-token `tid` GUID to the configured string.
- F151/F251 mailbox advisory: scoping.rs:194 `mailbox_named` covers only Mail./MailboxSettings./Calendars./Contacts.; no MailboxItem/MailboxFolder/Mail-Advanced anywhere in scoping.rs or audit/permissions.rs.
- F178 list_all_sites: sharepoint.rs:105 `out.truncate(max); Ok(out)` returns no truncation signal.
- F295 setup.sh:131-136 runs `cargo check --workspace` before `trunk build`; dist/ is gitignored.
- F394 exchange_scoping_section.rs:324 gate is `if dry_run || !r.failures.is_empty()`; a partial report toasts "Migrated".
- F424 dr.rs:502 callout says a re-run "recreates only what is missing"; restore.rs:218 calls `create_application_core` with no existence check.
- F488 release.yml:105/109 Linux leg `runs-on: ubuntu-latest` (floating glibc baseline for the AppImage/.deb).
- F440-F442 audit_cancel is claimed by audit.rs:147, aap_migration.rs:52 and bulk.rs:156/319/418/541/616; bulk.rs:125-135 doc claims the loops "never run at once"; `CancelFlag::cancel` stops every older generation.
- F039 backup.rs:668-700 (pass 3) uses `batch_or_serial` with no `session` clone / `is_dead` check / `skipped` record, unlike passes 1-2 (backup.rs:205-215).
- F002 permissions_resolve.rs:276-278 `.ok().flatten()` swallows SP-lookup errors; mod.rs:292 caches the resulting detail under CacheKind::Lists.
- F371 sso/mod.rs:509-513 `Err(err) => { tracing::debug!(..); (None, None) }` collapses a failed claims-policy read into "no policy".
Not independently confirmed (left to the agents' verification): F054 (EWS verdict), F055-F057 (permission tester paths), F070 (claims codec).
