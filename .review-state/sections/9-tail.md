## Appendix A: refuted and downgraded claims

What was checked and cleared, so the reader knows the verification was adversarial and not a rubber stamp.

### Refuted (excluded from every section)

- **F205 · `Subscription` drops the `state` field, so Disabled/Warned/Deleted subscriptions are fanned out to and their failures counted as coverage gaps** (`crates/azapptoolkit-arm/src/models.rs:14`). The premise that reads against a Disabled or Deleted subscription fail is contradicted by Microsoft Learn: Disabled, Warned, Expired and Past Due subscriptions all allow GET (only PUT, PATCH and POST are blocked), and Deleted is not a persistent listing state. The fan-outs therefore pay no failed round trips for non-Enabled subscriptions and `skipped` is not inflated. Worse, the proposed partition on `state != "Enabled"` would hide genuine role assignments and vaults on disabled subscriptions, grants that become live again on reactivation, which is a regression for a security-posture tool.

### Downgraded or narrowed by the judges

Each id keeps its entry in the sections; the clause says how the judges weighed it.

- **F140**: the retry-loop mechanism is real, but the headline harm (a duplicate role assignment surviving removal) was refuted by the verifier, since Exchange rejects the duplicate and removal sweeps every assignment; folded into F164's false-failure framing.
- **F251**: the `graph_mail_role` half is a documented deliberate gap (AAP parity); only the advisory-membership half is a defect, reported under F151.
- **F393**: degraded-with-findings is disclosed on the default pane and the unmarked case needs more than 10,000 app registrations; kept as a one-line S fix inside the coverage theme.
- **F266**: the single-app delete dialog already says soft-delete; only the bulk bar copy is wrong, and the "Recently deleted" view is a feature, not a defect.
- **F001**: narrowed by the verifier; the partial-write shape is real but smaller than first reported.
- **F043**: partially confirmed low; regenerating a secret for an expired credential is arguably intended restore semantics and the report already lists them.
- **F216**: several proposed pedantic lints are nursery or fight Leptos's by-value style; keep a non-gating `just clippy-pedantic` recipe and the tiny low-false-positive subset.
- **F232**: HTTP/2 being off is confirmed but unmeasured; an experiment to run, not a finding.
- **F214 and F226**: the `$crate` re-export idiom for thiserror is refuted (thiserror hard-codes `::thiserror::__private` paths); reduced to a manifest comment plus a cargo-machete ignore, folded into F212 and F213.
- **F220**: rests on an open, unconfirmed upstream issue; a watch item next to F219.
- **F130**: the finder itself calls the `deduped()` clone cost negligible at current throughput.
- **F257**: the Key Vault api-version retires on 2027-02-27; a dated maintenance ticket, nothing is wrong today.
- **F272**: single-tenant-per-instance is a documented invariant; a feature request rather than a defect.
- **F305**: stale `.gitignore` template entries are harmless noise.
- **F241**: AGENTS.md sitting 2 bytes under its budget is a hint to dedupe when a rule is next added, not a defect.
- **F109**: text-only message injection on an abortable sign-in; kept as a low hardening line under auth.
- **F003**: sign-out sweeps the cache, so the exposure is the mid-flight switch and dead-session window only; low.
- **F286**: CSP over-allowlisting is harmless for a webview that never contacts those hosts; duplicate of F044 and F156.
- **F295**: high severity but developer-only (`just setup` on a fresh clone); no operator impact, so it belongs in tooling, not the headline.
- **F420**: an enhancement to demo variety, not a violated rule.
- **Feature requests moved to the product backlog rather than the headline**: F259 (appCredentialSignInActivities), F260 (app management policies), F264 (servicePrincipalRiskDetections), F265 (requestSignatureVerification), F267 (#109 posture snapshot; large and product-owned), F274 (tenant consent settings tile), F275 (SCIM job control), F277 (headless mode), F283 (bulk create from CSV), F392 (operator-supplied PFX).
- **Duplicates collapsed into one entry each**: F284 into F105; F139 into F036; F245 into F014; F091 into F019; F143 into F047; F211 into F119; F210 into F118 and F121; F286 and F156 into F044; F362 into F313; F358 into F331; F445 into F046; F351 into F335; F294 into F204; F224 into F209; F212 absorbs F173; F226 into F214; F225 into F213; F428 into F042; F276 into F264; F255 into F163; F287 into F252; F431 and F346 into F093; F379 into F319; F289 into F109; F401 partially into F127.
- **Doc-drift and a11y groups**: the roughly forty documentation-drift items (F014, F015, F030, F051, F067, F082, F099 to F101, F120, F131, F132, F137, F144, F145, F169, F175, F191, F237 to F246, F249, F282, F302 to F304, F344, F356, F409, F421, F446) are worth one sweep PR, with F239 and F169 the two that could mislead a maintainer into reintroducing a bug; the accessibility group (F312 to F328, F349, F360 to F363, F386, F438) is real and shippable but sits below correctness in the ranking and is presented as its own sub-section.

## Appendix B: minor nits

Every minor nit the slices recorded, grouped by slice, verbatim apart from punctuation (each carries its own `file:line`). These are below the finding bar: wording, comments, tiny inconsistencies and one-line tidy-ups. 302 items across 33 slices.

### backend-crates/core-audit (7)

- crates/azapptoolkit-core/src/audit/scoring.rs:160: "Mixed credential status: {names} are expired but {n} credentials are active" reads as "expired are expired but 1 credentials are active" in the snapshot (tests.rs:1300); pluralize and rephrase.
- crates/azapptoolkit-core/src/audit/permissions.rs:162-165: HIGH_RISK_DELEGATED_PERMISSIONS cites `Constants.ps1:104-130`, the union of the two app-permission spans (104-115, 123-130); looks copy-pasted rather than a delegated-list citation.
- crates/azapptoolkit-core/src/audit/permissions.rs:83-92: "Both scored ZERO." past-tense change narrative inside a constant table; move to the CHANGELOG/commit and keep the table comment declarative.
- crates/azapptoolkit-core/src/audit/scoring.rs:1009-1012: orphaned refactor note "(No resource-stripped value list any more: ...)" in `score_application`; it documents a removed line, not the code that remains.
- crates/azapptoolkit-core/src/audit/types.rs:562: `issue` module doc says `emitted_issue_markers_are_stable` "asserts the scorer still emits each"; the test covers 10 of the 17 markers.
- crates/azapptoolkit-core/src/audit/scoring.rs:1112-1118: `join_refs<S: AsRef<str>>` is now used by exactly one caller (`rule_high_risk_delegated`); could be inlined or `join_values`/`join_names` could share it.
- crates/azapptoolkit-core/src/audit/types.rs:275-282: `mail_scopes` doc says "every read goes through `AppPermissions::is_scoped`" while the single read is actually `scope_mechanism` (line 385); point the doc at the real gate.

### backend-crates/core-infra-a (10)

- crates/azapptoolkit-core/src/cache.rs:1046-1051: the doc comment for `release_watch` ("Drops one reference to a watch...") sits directly above `peek_watch`, which then has its own one-line doc; the two blocks are merged and `release_watch` (line 1058) is undocumented.
- crates/azapptoolkit-core/src/cache.rs:793-800: `store_if_current` returns `true` when `store` returned `None` (caching disabled / serialize failure) although the doc says it returns `false` when the store was skipped; return `stamp.is_some()` on the success arm (callers currently ignore the bool).
- crates/azapptoolkit-core/src/cache.rs:697: the poisoned-entry eviction in `get` uses `remove(key)` after the bucket lock was dropped in `lookup`, so it can evict an entry a concurrent writer just replaced; `lookup` could hand back the stamp and use the existing `remove_if_stamp` for consistency with `store_if_current`.
- crates/azapptoolkit-core/src/cache.rs:189: `Bucket::touch` allocates `key.to_string()` on every cache hit under the bucket lock; storing LRU keys as `Arc<str>` (shared with `entries`) would make the hot-path row a refcount clone.
- crates/azapptoolkit-core/src/http_retry.rs:61-72: `parse_retry_after_seconds(Some("0"))` → `retry_after_millis(0)` = 0 ms, so a `Retry-After: 0` yields MAX_RETRIES back-to-back attempts with no backoff or jitter; consider flooring the explicit header at e.g. 500 ms.
- crates/azapptoolkit-core/src/token.rs:63-73: `From<String>` and `From<&str>` for `TokenError` have no users (every site uses `TokenError::new`/`opaque` explicitly) and exist only to let a `?`/`.into()` silently flatten to `token_error`, the anti-pattern the type's doc warns about; remove them.
- crates/azapptoolkit-core/src/cache/tests.rs:53 and crates/azapptoolkit-core/src/defaults.rs:217: `use super::*;` appears mid-module after tests that already rely on it; move to the top of each test module.
- crates/azapptoolkit-core/src/settings.rs:404-429 and crates/azapptoolkit-core/src/private_file.rs:95-112: two identical hand-rolled `TempDir` helpers (the no-`tempfile` decision is documented); a `#[cfg(test)] pub(crate) mod test_support` would hold one copy.
- crates/azapptoolkit-core/src/cache.rs:42: comment "matches enum declaration order" is the only thing tying `ALL` to `idx()`; see the CacheKind::idx finding.
- docs/DEVELOPMENT.md:314: refers to "the settings toggle" for auto-update; no such toggle exists in web-rs (no `auto_update` binding or view).

### backend-crates/core-infra-b (8)

- crates/azapptoolkit-core/src/azure_roles.rs:36: the `"Contributor" => &[CONTRIBUTOR, OWNER]` arm is unreachable: no capability lists Contributor as a required role (grep `"Contributor"` in capabilities.rs finds none).
- crates/azapptoolkit-core/src/cloud.rs:155: `token_exchange_audience()` is the one accessor with no per-cloud test, although its own comment says a wrong value 'fails, silently, at exchange time'.
- crates/azapptoolkit-core/src/scoping.rs:1146-1154: test `the_ews_scope_is_scopable_only_on_the_resource_that_defines_it` repeats the assertion from lines 1133-1140 verbatim under a comment about 'the display-only form', a value-only helper that no longer exists.
- crates/azapptoolkit-core/src/thumbprint.rs:57-61: `canonical` hex-encodes any base64 payload; a hand-set `customKeyIdentifier` that is not 20 bytes yields a 'thumbprint' of the wrong length that can never match `preferredTokenSigningKeyThumbprint` (consider returning None unless `bytes.len() == 20`).
- crates/azapptoolkit-core/src/models.rs:3-4: module doc says '`Option` wraps anything Graph may omit' but the file's actual convention (lines 11-17) is `#[serde(default)]` + `null_to_default` on `String`/`Vec`; update the doc.
- docs/architecture/exchange-scoping.md:46-47: says 'the rest of the ~22 supported application roles (MailboxFolder.*, MailboxItem.*, SMTP.SendAsApp, MailboxConfigItem.*, MailTips.ReadBasic.All)'; Microsoft's table now has 24 and also includes `Mail-Advanced.ReadWrite.All` and `MailboxItem.Export.All`.
- crates/azapptoolkit-core/src/capabilities.rs:24: doc comment cites '`OPERATOR-ROLES.md` table, lines 13-17'; hard-coded line references into another file drift silently: cite the heading instead.
- crates/azapptoolkit-core/src/redirect.rs:340: `rest.split('/')` treats `?`/`#` as part of the authority, so `http://localhost?x@evil.com` is read with authority `localhost?x@evil.com` → host `evil.com` (rejected, fine), but `http://127.0.0.1#@evil.com` also rejects a technically loopback URI; splitting on `['/', '?', '#']` like federation.rs:115 would make the two validators consistent.

### backend-crates/auth (9)

- crates/azapptoolkit-auth/src/service/mod.rs:254: `tracing::info!("opening system browser…")` lacks `target: "auth"` unlike every other auth event in the file (174, 191, token_cache.rs:365), so log filtering on the target misses the authorize step.
- crates/azapptoolkit-auth/src/error.rs:14: doc says `interaction_required` means "the refresh token is no longer usable"; see the interaction_required finding: the doc encodes the wrong premise.
- crates/azapptoolkit-dto/src/lib.rs:168: `AuthError::Keyring` maps to `retryable: false`, but a locked keychain / Credential Manager is exactly the case that succeeds on retry after unlock (the sign-in hint even says "unlock … then retry").
- apps/desktop/src-tauri/src/commands/auth.rs:89-99: `reauthenticate` does not call `state.remember_account(&outcome.tenant)`; if the settings write failed at the original sign-in (best-effort by design), a later reauth never re-persists the restore pointer.
- crates/azapptoolkit-auth/src/service/loopback.rs:99-101: `error_description` is parsed out of the redirect query and discarded, so the AADSTS code Entra puts there never reaches `redacted_aad_error`/`aadsts_hint` for redirect-time failures.
- apps/desktop/web-rs/src/bindings/auth.rs:1: module doc lists `current_tenants`, a command that `generate_handler!` (src-tauri/src/lib.rs:45-50) does not register.
- crates/azapptoolkit-auth/src/service/mod.rs:5-6: module header says the authorize URL uses "read-only scopes … plus `offline_access`" but omits `openid`/`profile`, which `graph_scopes` always appends (scopes.rs:93-95).
- crates/azapptoolkit-auth/src/token_cache.rs:22: comment says the native store on Linux is "keyutils"; the registered store (line 67) is the zbus Secret Service.
- docs/architecture/auth-and-consent.md:12: the list of error codes omits `refresh_missing`, `authorization`, `loopback`, `state_mismatch`, `cancelled` that `From<AuthError> for UiError` emits (dto lib.rs:158-172).

### backend-crates/graph (9)

- crates/azapptoolkit-graph/src/client/transport.rs:711: `batch_sub_url` doc says it 'mirrors the single-call encoding the SP prewarm (`prewarm_sps`) does inline', but `prewarm_sps` now calls `batch_sub_url` itself (service_principals.rs:366); stale.
- crates/azapptoolkit-graph/src/client/transport.rs:216: `collect_all_pages_capped` doc has a truncated sentence: '... The cap also bounds a' then jumps to 'Returns `(items, truncated)`'.
- crates/azapptoolkit-graph/src/client/transport.rs:714: `batch_sub_url` would emit `path?existing?new` if `path` already carried a query (it `format!`s `{path}?{q}` after parsing); currently no caller does, but `batch_list_site_permissions` (sharepoint.rs:55) hand-formats `?$top=` instead of using the helper, so the two batched URL builders have drifted.
- crates/azapptoolkit-graph/src/client/directory.rs:220: `add_group_member` builds `@odata.id` from `self.base_url` untrimmed while `add_owner` (applications.rs:410), `add_service_principal_owner` and `assign_claims_mapping_policy` use `trim_end_matches('/')`.
- crates/azapptoolkit-graph/src/client.rs:49 vs client/applications.rs:217: `MAX_PAGE_SIZE: &str = "999"` and `DEFAULT_APP_PAGE_SIZE: u32 = 999` are two constants for one value with different types; derive one from the other so they cannot drift.
- crates/azapptoolkit-graph/src/client/roles_grants.rs:35: missing blank line between `invalidate_grant_cache` and `list_app_role_assignments`.
- crates/azapptoolkit-graph/src/client/batch.rs:293: the throttle observer is notified only when a re-batch happens; the final inner 429 that surfaces as `Throttled` after the budget is exhausted never reaches `on_throttle`, unlike the single-request path (transport.rs:626-632 notifies on every 429).
- crates/azapptoolkit-graph/src/client/sharepoint.rs:77: `$top=200` literal for `/sites?search=*` with no comment on why it differs from `MAX_PAGE_SIZE`.
- crates/azapptoolkit-graph/src/client/batch.rs:69: inner sub-response 401 is mapped to `Unauthorized` without checking the sub-response `WWW-Authenticate` for a CAE `insufficient_claims` challenge, so a CAE event mid-batch surfaces as a session-expired error instead of the single re-mint the unbatched path performs.

### backend-crates/exchange (7)

- crates/azapptoolkit-exchange/src/targets.rs:38 uses `std::collections::HashMap` fully qualified although `HashMap` is imported at line 19.
- crates/azapptoolkit-exchange/src/targets.rs:487-488 `folded_dns` and aap.rs:125 `SourceMember::key` fold with `to_ascii_lowercase`, so a DN/SMTP with non-ASCII letters (the `CN=Zürich` case the tests already exercise for non-panic) still compares case-sensitively on those letters; `to_lowercase()` is the safer fold.
- crates/azapptoolkit-exchange/src/client/transport.rs:316-321 `compose_error_detail` takes `&Option<String>` twice; `Option<&str>` is the idiomatic shape (clippy::ref_option under pedantic).
- crates/azapptoolkit-exchange/Cargo.toml:25 re-declares `serde_json` under [dev-dependencies] although it is already a normal dependency at line 16.
- crates/azapptoolkit-exchange/src/verdict.rs:3 says "These seven functions" - correct today, but the count will silently rot; name the functions or drop the number.
- crates/azapptoolkit-exchange/src/client/groups.rs:137-138 doc says list_group_members 'Returns an empty list when the group doesn't exist' - true, but aap.rs:175 then treats that empty list as 'unreadable', so a missing group and an empty group are indistinguishable to the planner; worth a sentence in the doc.
- apps/desktop/src-tauri/src/commands/exchange/aap_migration.rs:290-292 hand-folds `wanted_dns` with `to_ascii_lowercase` instead of building a `ScopeGroups` and calling `folded_dns()` - the same helper that rbac.rs uses.

### backend-crates/small-crates (11)

- crates/azapptoolkit-keyvault/src/client.rs:53-58: `with_base_url` builds a fresh `reqwest::Client` (own pool + TLS setup) per vault; `AppState::kv_for` caches per `(tenant, vault)`, so N vaults = N pools. Share one client via `Arc<reqwest::Client>` or a crate `OnceLock`.
- crates/azapptoolkit-keyvault/src/models.rs:21-23: `SecretItem::name()` returns `Some("")` for a trailing-slash id; `commands/keyvault.rs:38` then renders an empty row name. Use `rsplit('/').find(|s| !s.is_empty())` like `core::azure_roles::role_id_tail`.
- crates/azapptoolkit-keyvault/src/models.rs:165-170: `Paged<T>` derives `Serialize` (never serialised) and, unlike ARM's `Paged` (arm models.rs:8), has no `#[serde(default)]` on `value`.
- crates/azapptoolkit-arm/src/models.rs:8: `#[serde(default = "Vec::new")]` is just `#[serde(default)]`.
- crates/azapptoolkit-permissions/src/lib.rs:92-98: `from_root` clones every `ResourceEntry` into the `HashMap` while also keeping `ordered`; index by position (`HashMap<String, usize>`) instead of storing each entry twice.
- crates/azapptoolkit-permissions/src/lib.rs:41-46: `CatalogRoot.generated` ("directory") and `version` are deserialised and never read anywhere.
- crates/azapptoolkit-keyvault/src/lib.rs:3-5: "`2016-10-01`-compatible ... (we use `7.4`: the general-availability API version)" is stale phrasing; 7.5/7.6 are GA too. Say "pinned to 7.4" and why.
- crates/azapptoolkit-arm/src/loganalytics.rs:30: 120 s client timeout with no `Prefer: wait=<secs>` header; the Logs API accepts an explicit wait budget, and a slow 90-day `summarize` currently fails as `Network` (POST → not retried) with no service-side hint. Align the two or send the header.
- crates/azapptoolkit-arm/src/client.rs:67-70: `principal_id` is quote-escaped for OData but not shape-checked; a GUID check (see the security finding) would make the escape moot.
- crates/azapptoolkit-arm/tests/error_conformance.rs:8: "`azapptoolkit-arm` had 19 inline tests across 1121 lines": the count is now 21 across ~1.7k lines; consider dropping the numbers from the rationale so they cannot rot.
- apps/desktop/src-tauri/src/commands/keyvault.rs:89-92: the rotation comment says "exactly one copy exists" of the minted secret, but `send_json` copies it into a `serde_json::Value` and the retry closure clones that per attempt (client.rs:123-125, 178); models.rs:84-85 already documents this as an accepted limit: soften the command's claim to match.

### backend-crates/toolchain-runner (13)

- crates/azapptoolkit-core/src/constants.rs:49-55: four `Duration::from_secs(60 * 60)` could be `Duration::from_hours(1)` (stable since 1.91; MSRV is 1.98); clippy `duration_suboptimal_units`.
- crates/azapptoolkit-auth/src/service/mod.rs:453: `Duration::seconds(token.expires_in as i64)` with `expires_in: u64` (wire.rs:20) wraps on an absurd value; use `i64::try_from(..).unwrap_or(i64::MAX / 1000)` or clamp (clippy `cast_possible_wrap`).
- crates/azapptoolkit-exchange/src/client/transport.rs:319-320: `compose_error_detail` takes `&Option<String>` twice; `Option<&str>` is the idiomatic shape (clippy `ref_option`); :330 `out.push_str(&format!(..))` -> `write!(out, ..)` (clippy `format_push_string`).
- crates/azapptoolkit-graph/src/client.rs:326-332: `require_token` takes `&self` it never reads (clippy `unused_self`); make it an associated fn or free fn.
- crates/azapptoolkit-core/src/http_error.rs:35: the `http_error_enum!` doctest is ```` ```ignore ```` although the macro is `#[macro_export]` and core depends on thiserror; it could compile as a real doctest and pin the macro's public syntax.
- crates/azapptoolkit-core/src/audit/permissions.rs:920: `ews.clone()` on its last use in a test (clippy `redundant_clone`).
- crates/azapptoolkit-exchange/src/verdict.rs:627 and :641: `[x].into_iter().collect::<HashSet<_>>()` -> `HashSet::from([x])` (clippy `iter_on_single_items`).
- crates/azapptoolkit-exchange/src/targets.rs:1284: test helper `managed() -> Option<&'static str>` always returns Some (clippy `unnecessary_wraps`).
- crates/azapptoolkit-exchange/src/client/rbac.rs:185: clippy `default_trait_access`/`with_capacity(0)`-style construction where `HashSet::default()` is clearer.
- apps/desktop/web-rs/src/state/mod.rs:275-342: `Session` is a 468-byte `#[derive(Clone, Copy)]` struct copied at every by-value pass (19 sites flagged by `large_types_passed_by_value`; `AuditController` at views/audit_view/controller.rs:25-27 is 624 bytes because it embeds one). Idiomatic Leptos, but if Session keeps growing a `StoredValue<Session>`/`Arc` handle would shrink every closure capture.
- apps/desktop/web-rs/src/components/global_search.rs:949: function always returns `Some` (clippy `unnecessary_wraps`).
- crates/azapptoolkit-arm/tests/error_conformance.rs:7-8: header says graph has "a dedicated `tests/` tree"; `crates/azapptoolkit-graph/tests` does not exist (tests live in src/client/tests/).
- Cargo.toml [workspace.dependencies]: root duplicate majors are fully accounted for (RustCrypto 0.10 = p12-keystore hold vs 0.11 = secret-service 5.2 via zbus-secret-service-keyring-store; rand 0.8/getrandom 0.2 = oauth2 5 + ring; rest = GTK3/Tauri upstream); no local bump unifies any of them, and deny.toml `multiple-versions = "warn"` is the right posture.

### backend-app/cmd-apps (9)

- apps/desktop/src-tauri/src/commands/app_roles.rs:314: `serde_json::from_value(Value::Array(raw)).unwrap_or_default()` turns one malformed role into an empty App roles tab while the raw write path still works; log at warn or deserialize per element.
- crates/azapptoolkit-dto/src/expose_api.rs:30: `scope_type: String` validated at runtime against "Admin"|"User" (expose_api.rs:81); an enum would make the invalid state unrepresentable.
- apps/desktop/src-tauri/src/commands/search.rs:314,364: `SearchHit.app_id: Option<String>` is always `Some` from both branches; the Option is vestigial.
- apps/desktop/src-tauri/src/commands/credentials.rs:182-184: `PAGE_SIZE`/`MAX_APPS` re-alias `DEFAULT_APP_PAGE_SIZE`/`APPS_MAX` under new names; use the shared constants directly as applications/mod.rs does.
- apps/desktop/src-tauri/src/commands/credentials.rs:269: `save_credentials_to_file` takes a `format` arg but routes through CSV-only `save_csv_via_dialog`, while `save_applications_to_file` supports JSON via `save_export_via_dialog`; unify on the latter.
- apps/desktop/src-tauri/src/commands/applications/owners.rs:92-137: `search_users`/`search_groups`/`search_distribution_lists` are three identical directory-picker wrappers unrelated to owners (also used by the SSO wizard); a `directory.rs` module or one generic helper.
- apps/desktop/src-tauri/src/commands/applications/permissions_resolve.rs:151: `#[allow(clippy::too_many_arguments)]` on an 8-arg fn; a small `ResourceCtx { resource_app_id, display_name, cataloged, live_sp }` struct removes the allow.
- apps/desktop/src-tauri/src/commands/applications/mod.rs:142-155 and permissions.rs:55-58: duplicated cache hit/miss `tracing::debug!` blocks; a `cache_get_logged` helper on AppState would absorb them.
- apps/desktop/src-tauri/src/commands/guid.rs:76: hand-rolled v4 GUID formatter while `uuid` is already in Cargo.lock (transitively); fine to keep, but note it if a direct `uuid` dep ever arrives.

### backend-app/cmd-audit (7)

- apps/desktop/src-tauri/src/commands/bulk.rs:6-8: module doc says the expired-credential sweep is 'the exception' that runs its own concurrent loop; bulk_delete_applications (:311) and bulk_grant_permissions (:410) also fan out through dispatch_capped.
- apps/desktop/src-tauri/src/commands/bulk.rs:759-760: bulk_add_owner doc claims it reuses 'add_application_owner's core'; no such core exists: both it and owners.rs:14-24 call client.add_owner directly.
- apps/desktop/src-tauri/src/commands/bulk.rs:79-82: BulkOutcome impls for AppRemovalSummary and BulkGrantOutcome are never exercised (both outcomes are produced only on dispatch_capped paths; run_bulk_seq is the sole consumer of the trait).
- apps/desktop/src-tauri/src/commands/bulk.rs:172: `Some(10_000)` literal duplicates applications::APPS_MAX, which audit.rs:84 references by name.
- crates/azapptoolkit-dto/src/bulk.rs:56: BulkProgress.in_flight_cap doc says it is `None` for the bulk-credential/create/delete flows; the credential sweep, delete and grant now send `Some(meter.limit())`.
- docs/architecture/release-updater-demo.md:111: lists `export_audit_csv` among the infallible invoke() commands that need demo fixtures; it is no longer a command.
- apps/desktop/src-tauri/src/commands/audit.rs:1-14: module doc still says 'Cancellation is signalled via AppState.audit_cancel; the loop polls it' without mentioning the claimed CancelToken, the two-phase run or the degraded/coverage model that the rest of the file documents at length.

### backend-app/cmd-scoping (8)

- apps/desktop/src-tauri/src/commands/exchange/grants.rs:330-331: comment "busted unconditionally on success below (line ~450)" points at a line that no longer exists; the invalidation is apply_exchange_mailbox_scope at 294.
- apps/desktop/src-tauri/src/commands/exchange/grants.rs:22: remove_unscoped_grants issues the list_app_role_assignments GET even when `targets` is empty (every scoped role failed); an early `if targets.is_empty() { return Vec::new(); }` saves a round trip.
- apps/desktop/src-tauri/src/commands/exchange/mail_scopes.rs:306 and :52: get_mail_permission_scopes resolves mailbox_resource_roles and then held_orgwide_mail_grants resolves it again; passing `&resources` in would avoid the second (cached, so cheap) lookup.
- apps/desktop/src-tauri/src/commands/permission_tester.rs:386: the fallback detail "Exchange administrator rights are required." is also shown for exchange_client's `not_signed_in` / `no_anchor_mailbox` codes, where rights are not the problem.
- apps/desktop/src-tauri/src/commands/exchange/aap_migration.rs:238-242: on a real run consolidate_scope_group creates and populates the managed group before reconcile_scope_filter may refuse the app (scope_filter_mismatch); the refusal text does not mention the group left behind.
- apps/desktop/src-tauri/src/commands/sharepoint.rs:1013 and :1043: cache-only commands prove the session with `state.auth.tenant_context(&tenant_id)?` while mail_scopes.rs:289/405 use `commands::session::prove_tenant_session`; one spelling would let the repo_invariants grep pin a single idiom.
- apps/desktop/src-tauri/src/commands/sharepoint.rs:870: `let mut cancelled = false;` is immediately overwritten by `cancelled = cancelled || stopped_early` (933); fold into one `let`.
- apps/desktop/src-tauri/src/commands/exchange/scope_group.rs:75-77: add_exchange_scope_group_members computes `group_created` from a get_distribution_group read and then discards ensure_security_group's return value; returning a created flag from ensure_security_group would remove the double read and the TOCTOU.

### backend-app/cmd-sso-ent (12)

- apps/desktop/src-tauri/src/commands/sso/mod.rs:1002: `let (sps, _truncated)` discards the flag while crates/azapptoolkit-graph/src/client/service_principals.rs:239 documents it is returned "so the caller can tell the operator its coverage is partial"; either surface it on the board or correct the client docstring.
- apps/desktop/src-tauri/src/commands/enterprise_application.rs:457: "Only users can own a service principal (groups can't)": service principals can also own service principals; reword to "users or service principals (groups can't)".
- apps/desktop/src-tauri/src/commands/sso/mod.rs:906-912: `retire_saml_signing_certificate` docstring claims it refuses "the last usable one" and "the sole remaining fallback while a rollover is still in flight"; the code guards only `is_active` and `Staged`: align the docstring with the arch doc's precise wording.
- apps/desktop/src-tauri/src/commands/sso/mod.rs:1285: `metadata_http_client` `.build().unwrap_or_default()`: `reqwest::Client::default()` panics on the same TLS-init failure, so this is not a fallback; use `expect` with a message or return an error from the probe.
- apps/desktop/src-tauri/src/commands/sso/mod.rs:833: `probe_federation_metadata` interpolates the caller's `app_id` into the metadata URL query unvalidated (fixed host, so low risk); reject anything that is not a GUID before building the URL.
- apps/desktop/src-tauri/src/commands/sso/mod.rs:238-246: the create path runs `sanitize_notification_emails` but not the 5-address cap / `@` check that `set_notification_emails` enforces (lines 1677-1690); extract one `validate_notification_emails` used by both writers.
- apps/desktop/src-tauri/src/commands/sso/mod.rs:1103: `Some(d) if d < 0 => CredentialStatus::Expired` is unreachable after the preceding `CertStatus::Expired` check (both derive from the same `end`); keep as defence but comment it as such.
- apps/desktop/src-tauri/src/commands/keyvault.rs:198: `state.ensure_arm_token(&tenant_id).await?;` vs `.map_err(UiError::from)?` at every other ensure_* call site; pick one style.
- apps/desktop/src-tauri/src/commands/usage.rs:183: `where AppId == @'{app}'` is case-sensitive KQL; `=~` would tolerate an uppercase appId pasted from elsewhere.
- apps/desktop/src-tauri/src/commands/enterprise_application.rs:193-198: `AppAssignmentDto` drops `AppRoleAssignment.principal_id`, so the Access tab cannot dedupe a principal assigned to two roles or deep-link to the user/group; carry it through.
- crates/azapptoolkit-core/src/cache.rs:716 (outside slice, noticed while cross-checking): the `put_index` docstring names "the credential-expiry roll-up" as a pinned index, but both expiry boards (`credentials.rs:96`, `sso/mod.rs:1043`) store with plain `put`; fix the docstring or pin both boards via `put_index_if_current`.
- apps/desktop/web-rs/src/bindings/sso.rs:68-69: binding doc says `""` disables SSO; the tab actually sends "disabled"; update alongside the SsoMode enum.

### backend-app/cmd-platform (12)

- apps/desktop/src-tauri/src/state.rs:216,220,225: cancel-flag field docs still say 'Reset to `false` at the top of every run' / 'Reset at the top of every sweep'; `CancelFlag::claim` doc (line 70) says it 'Replaces the old `reset()`'. Update to 'claimed at the top of every run'.
- apps/desktop/src-tauri/src/state.rs:3-6: module doc frames a multi-tenant singleton ('covering all tenants', 'dedupe across tenant swaps') while the app is single-tenant-bound (backup-and-restore.md, auth service `tid` check).
- apps/desktop/src-tauri/src/commands/backup.rs:337-345: `backup_app_chunk`'s doc comment ('Backs up one chunk ... Returns the assembled backups for the chunk.') is attached to `note_graph_failures`; move it down to line 356.
- apps/desktop/src-tauri/src/commands/restore.rs:370-374: `wire_application` carries two glued doc paragraphs ('Pass-2 work for one created app ...' and 'Wires one freshly-created app ...'); keep one.
- apps/desktop/src-tauri/src/commands/restore.rs:436,559: Expose-an-API and federated-credential failures push a warning without `session.note_code(e.ui_code())`, unlike every other step in `wire_application` (419, 505, 574, 604).
- apps/desktop/src-tauri/src/commands/restore.rs:276-287: Pass 3 indexes `report.apps[idx]` by `created` index; safe only because cancel/dead are monotonic latches that also broke Pass 2 at the same point. `created.iter().zip(report.apps.iter_mut())` would make it structurally safe.
- apps/desktop/src-tauri/src/commands/updater.rs:70: comment 'On Windows (NSIS, passive) the installer has run; relaunch applies it' is inaccurate: tauri-plugin-updater 2.12 exits the process itself via `std::process::exit(0)` on Windows after spawning the installer (its `on_before_exit` doc), so `app.restart()` is reached only on macOS/Linux. Consider registering `on_before_exit` to flush the non-blocking log writer.
- apps/desktop/src-tauri/src/commands/export.rs:25: `csv_field` quotes on `,` `"` `\n` but not a lone `\r` mid-field (RFC 4180 requires quoting CR); leading `\r` is neutralised, embedded is not.
- apps/desktop/src-tauri/capabilities/default.json:7-8: `core:window:default` and `core:app:default` are already members of `core:default` (Tauri 2 docs); redundant entries.
- apps/desktop/src-tauri/Cargo.toml:333,335: `rand = "0.10"` and `time = "0.3"` are declared crate-locally rather than in `[workspace.dependencies]` as AGENTS.md asks; only this crate uses them, so low priority, but a comment saying so would stop the next reader 'fixing' it.
- apps/desktop/src-tauri/src/lib.rs:410-417: Linux `config_directory()` ignores `$XDG_DATA_HOME`/`$XDG_CONFIG_HOME` and puts settings.json (config) under the data dir; Tauri's `PathResolver` (`app_config_dir`/`app_log_dir`) is already available in-tree if `AppState::new` moved into `setup`.
- apps/desktop/src-tauri/src/lib.rs:394-420 / README.md:424-428: the README's log-path list matches the code, but neither mentions the 14-day `max_log_files` retention or that `RUST_LOG` also applies to the file appender (same filter layer).

### backend-app/invariants-dto-ipc (14)

- crates/azapptoolkit-dto/src/lib.rs:9: header says "Kept dependency-light (just `serde`)" but Cargo.toml also depends on `chrono` and `azapptoolkit-core`.
- crates/azapptoolkit-dto/src/bulk.rs:55: rustdoc link `[`ConcurrencyThrottle`](../../desktop)` does not resolve; use plain backticks.
- crates/azapptoolkit-dto/src/bulk.rs:38: `BulkError::is_reauth_fatal` builds a throwaway `UiError` (two String clones) to call `is_reauth_fatal`; call `azapptoolkit_core::reauth::is_reauth_fatal(&self.code)` directly like `UiError` does.
- apps/desktop/web-rs/src/demo/mod.rs:265: `mock_ok("current_tenants", ...)` fixtures a command that no longer exists (not in generate_handler!, no binding); `the_not_demo_reachable_allowlist_stays_honest` does not check fixtures against real commands, so add the reverse check or delete the line.
- apps/desktop/web-rs/src/bindings/auth.rs:1: module header lists `current_tenants`, which is not a function in the file.
- apps/desktop/src-tauri/tests/repo_invariants/sources.rs:138: `commands()` matches only the exact literal `#[tauri::command]`; a `#[tauri::command(rename_all = ...)]` form (none today) would be silently excluded from every rule. Match the `#[tauri::command` prefix like the hook does.
- apps/desktop/src-tauri/tests/repo_invariants/cache.rs:79-91: `is_fn_header` does not recognise `pub(in path) fn`, so such a header would not end the back-walk.
- apps/desktop/src-tauri/tests/repo_invariants/cache.rs:425: `first_session_proof` scans the flattened body including `//` comments, so a comment naming `graph_for(` before the cache read counts as proof; strip comments (as `balanced_block` already does for braces).
- apps/desktop/src-tauri/tests/repo_invariants/cache.rs:218-223: `in_async_fn` uses `src[..at].rfind("fn ")`, which can land on a comment or string containing `fn `.
- apps/desktop/src-tauri/tests/repo_invariants/cache.rs:371-380: two consecutive comment paragraphs say the same thing about the old `found >= 1` floor; keep one.
- apps/desktop/src-tauri/tests/repo_invariants/release.rs:244: assertion message contains a 10-space run from a missing `\` (test-only instance of the string-continuation bug).
- .claude/hooks/command-parity-check.sh:59: `grep -A4` after `#[tauri::command` misses a handler whose `fn` is more than four lines below the attribute (extra attributes + `pub async`); use `-A8` or the brace-aware extractor's logic.
- crates/azapptoolkit-dto/src/applications.rs:98-101 and elsewhere: `#[serde(default)]` on `Option<T>` fields (e.g. `AddPasswordInput.start_date_time`, `AddFederatedCredentialInput.audiences`) is redundant: serde already treats a missing `Option` field as `None`; harmless but inconsistent with the un-annotated `Option`s beside them.
- crates/azapptoolkit-dto/src/exchange.rs:283-284: test comment says the Exchange DTOs are snake_case "mirrors the other Exchange DTOs in this module", but `PrincipalPermission` (line 27) in the same module is `rename_all = "camelCase"`.

### frontend/fe-core (11)

- apps/desktop/web-rs/styles.css:182 and :1094: `.nav__item:focus-visible` is defined twice with identical bodies; drop one.
- apps/desktop/web-rs/styles.css:1957 and :2291: `.audit-view` is split across two rules (grid at 1957, `padding: 0` at 2291); merge.
- apps/desktop/web-rs/styles.css:1595: `var(--surface-hover, var(--surface))` and :325 `var(--border-subtle, rgba(128,128,128,0.2))` reference tokens that are never defined; define them in :root or inline the fallback.
- apps/desktop/web-rs/styles.css:3809: `var(--shadow-2, 0 4px 16px rgba(0,0,0,0.18))` carries a fallback for a token that is always defined; drop the fallback (it is the only non-token rgba outside the token/skeleton blocks).
- apps/desktop/web-rs/src/state/mod.rs:325-326 and src/state/navigation.rs:100-101: `security_tab` comments list four sub-tabs; the workbench has six (`sso-certificates`, `app-permissions` missing).
- apps/desktop/web-rs/src/hooks/use_shortcuts.rs:173-174: SHORTCUTS claims to sit 'beside the handler so the two can't drift', but Cmd/Ctrl-K is implemented in global_search.rs:78 and ←/→ in ui/tab_bar.rs; soften the comment or add a test that each SHORTCUTS row has an owner.
- apps/desktop/web-rs/src/constants.rs:21: comment cites `commands/applications.rs`; the file is `commands/applications/mod.rs`.
- apps/desktop/web-rs/src/views/shell.rs:~690: test comment says 'shell.rs is 679 lines'; it is 745. Drop the number.
- apps/desktop/web-rs/src/util.rs:218-353 then :355-434: the `tests` module sits between `created_in_range` and `contains_ignore_case`, with a second `contains_ignore_case_tests` module after; move `contains_ignore_case` above the first tests block so the file reads top-down.
- apps/desktop/web-rs/src/components/toast.rs:1-3: the `#![allow(dead_code)]` inner attribute precedes the `//!` module doc; conventional order is doc first (also see the stale-allow finding).
- docs/architecture/frontend-workspace.md:4 and :11: `web-rs/src/state.rs` should read `web-rs/src/state/` (folded into the docs finding).

### frontend/fe-apps (14)

- apps/desktop/web-rs/src/views/tabs/credentials_tab.rs:745: the Upload-certificate button does not clear the shared `error` signal, unlike its siblings at 649-651 and 736-738, so a stale inline error persists into the dialog
- apps/desktop/web-rs/src/views/tabs/credentials_tab.rs:1020-1022: thumbprint SHA-1/SHA-256 in the generated-certificate reveal are plain `Body1.mono` while the PFX password beside them uses `CopyableId`; make them copyable too
- apps/desktop/web-rs/src/views/tabs/credentials_tab.rs:360-366: `expired_count`/`remove_expired_passwords` sweep only secrets; expired certificates have no sweep affordance (feature gap)
- apps/desktop/web-rs/src/views/tabs/overview_tab.rs:59-70: the 'mirrors React useEffect' reset Effect is dead after mount today (`detail_signal` never changes) and would clobber in-progress edits once the pane keeps `detail` alive; guard it with `!editing.get_untracked()`
- apps/desktop/web-rs/src/views/tabs/permissions_tab.rs:133-134 + 762: `run_grant` reports the same error twice (toast_error and inline `consent_error`)
- apps/desktop/web-rs/src/views/tabs/permissions_tab.rs:945: a granted Delegated row with `permission_value == None` gets no Trash button at all, so it has no way out
- apps/desktop/web-rs/src/views/application_detail_pane.rs:72-73: `refreshing.set(false)` runs right after `reload.update`, before the refetch resolves, so the Refresh spinner stops early
- apps/desktop/web-rs/src/views/dialogs/confirm_dialog.rs:87: inline `style="display:block;margin-top:4px;"` contradicts the global-CSS-only convention; move to `.confirm-dialog__keyword input`
- apps/desktop/web-rs/src/views/dialogs/upload_certificate_dialog.rs:686-691: no client-side check that `pem` is non-empty before dispatch, unlike every other dialog in the slice
- apps/desktop/web-rs/src/views/tabs/federated_tab.rs:216-221: the edit form keeps only `audiences.first()`, so saving drops any additional audiences Graph returned
- apps/desktop/web-rs/src/views/tabs/federated_tab.rs:91-93: the creds resource returns `Ok(Vec::new())` for a missing tenant while sibling tabs return `no_tenant()`
- apps/desktop/web-rs/src/components/permission_picker.rs:76-84: an `Effect` with no tracked signal wraps a one-shot `spawn_local`; a plain `spawn_local` at mount reads clearer
- apps/desktop/web-rs/src/views/tabs/owners_tab.rs:17-28: `owner_kind` classifies by substring on `odata_type` (`contains("user")`), fragile for e.g. `#microsoft.graph.userFlow`-style types; match the full `#microsoft.graph.*` string
- apps/desktop/web-rs/src/views/tabs/credentials_tab.rs:220: `display_name` for a new secret is never reset after creation, so the second secret is also named `client-secret` by default

### frontend/fe-enterprise (10)

- apps/desktop/web-rs/src/views/enterprise_application_detail_pane/sso_tab.rs:257-258: two match arms (`d < 0` and `d <= 7`) both yield `badge badge--danger`; collapse to one.
- apps/desktop/web-rs/src/views/enterprise_application_detail_pane/access.rs:607: `resolve_role` detects default access with `id.chars().all(|c| c == '0' || c == '-')` (matches "0" or "-"); compare against the existing `DEFAULT_ACCESS_ROLE` const instead.
- apps/desktop/web-rs/src/components/sso_summary.rs:97: `RwSignal::new(value.clone()).into()` allocates a writable signal for a static string; `Signal::stored(value.clone())` is enough.
- apps/desktop/web-rs/src/views/managed_identities/detail_window.rs:204-206: `refreshing.set(false)` runs right after bumping `reload`/`arm_reload`, so the header spinner stops before any refetch resolves.
- apps/desktop/web-rs/src/views/enterprise_application_detail_pane/app_roles.rs:392-394: hint says "No spaces; it must be unique for this app" but `save` (111-132) checks neither; a `contains(char::is_whitespace)` / duplicate-value check against `roles_res` would pre-empt the Graph 400.
- apps/desktop/web-rs/src/views/enterprise_application_detail_pane/overview.rs:232: label promises "max 1024 characters" but the Textarea has no counter/limit; the backend rejects at 1025 (enterprise_application.rs:439).
- apps/desktop/web-rs/src/views/enterprise_application_detail_pane/owners.rs:243,307: error text uses `class="app-detail__error"` while every sibling tab uses `form-error`.
- apps/desktop/web-rs/src/views/sso_certificates_dashboard.rs:29-30 and views/credentials_dashboard.rs:20-21 and views/tabs/credentials_tab.rs:30-31: `CRITICAL_DAYS = 7` / `WARNING_DAYS = 30` declared three times in the frontend; core already exports `EXPIRY_WARNING_DAYS`.
- apps/desktop/web-rs/src/views/dialogs/sso_wizard_dialog.rs:6-8: module doc indentation drifts (three-space continuation) and still says step state is matched "in the view (the codebase has no Thaw stepper)": fine, but the `//!   ` lines are misaligned.
- apps/desktop/web-rs/src/views/enterprise_application_detail_pane/sso_tab.rs:439: the `(None, None)` probe arm is unreachable per the DTO contract (`http_status: None ⇒ error: Some`); a comment or `unreachable!`-free fold into the error arm would clarify.

### frontend/fe-security (9)

- apps/desktop/web-rs/src/components/scope_wizard.rs:183-193: the doc comment for `apply_sharepoint_scoped` ("SharePoint scoped path: grant Sites.Selected...") is glued onto `apply_sharepoint_item_scoped`; `apply_sharepoint_scoped` at 220 has no doc.
- apps/desktop/web-rs/src/components/scope_wizard.rs:486: `site_write.set(sel.permission_value != "Sites.Read.All")` duplicates `sites_need_write(&[sel])`; call the helper.
- apps/desktop/web-rs/src/views/audit_view/mod.rs:296,313: both the Risk and Score `<th>` carry `aria-sort` for `SortCol::Score`; ARIA expects one sorted column per table, so announce it on Score only.
- apps/desktop/web-rs/src/views/credentials_dashboard.rs:81-82: `r.app_display_name.to_lowercase().contains(q)` allocates per row per keystroke; sibling lenses use `contains_ignore_case`.
- apps/desktop/web-rs/src/views/bulk_actions_view.rs:183: Create-flow summary `<Callout tone=tone>` lacks the `role="status"` the bar's identical summary has (bulk_action_bar.rs:657); the whole summary+failures block (331-370) is a copy of the bar's and could be a shared `BulkRunSummary`.
- apps/desktop/web-rs/src/components/app_site_access_panel.rs:70-73: `get_app_site_access(...).await.ok().flatten()` swallows a real error (403/consent) as "no sweep cached" and offers a scan that will then fail; surface the error instead.
- apps/desktop/web-rs/src/components/retired_scope_groups.rs:144: `type_prompt` is an `RwSignal<String>` that is never written; a plain `String` placeholder suffices.
- apps/desktop/web-rs/src/components/aap_migration_report.rs:420,505 and views/dialogs/migrate_legacy_scope.rs:84: `status == "migrated"` compared as a string in three places; `AapMigrationItem.status`, `AppPermissionGrantDto.risk` and `OAuth2GrantDto.consent_type` are stringly-typed DTO fields matched by the Security surfaces (structured-signals rule); an enum with serde rename is an in-repo IPC change.
- apps/desktop/web-rs/src/components/exchange_scoping_section.rs:327: toast says "policy(ies)" but `r.items` is per application (see AapMigrationItem.removed_policies).

### frontend/fe-tools (10)

- apps/desktop/web-rs/src/bindings/backup.rs:2: module doc says "The restore side is added with the restore slices" but the restore bindings are already in this file (lines 190-233); stale.
- apps/desktop/web-rs/src/views/readiness_view.rs:100-101: `show_remediation` re-implements `is_gap(&item)` (line 55) inline.
- apps/desktop/web-rs/src/components/global_search.rs:641-649: `match_rank` allocates `label.to_lowercase()` and `context.to_lowercase()` per destination per keystroke while the test at 1119-1131 justifies pre-lowercased keywords as avoiding exactly that; either precompute or use ASCII case-insensitive `starts_with`/`contains` helpers.
- apps/desktop/web-rs/src/components/global_search.rs:707,816: `on:mousedown` navigates on any mouse button (right/middle click included); guard with `ev.button() == 0`.
- apps/desktop/web-rs/src/views/dr.rs:262-275: backup/restore progress never shows "(cancelling…)" although `BulkProgress.cancelled` (dto/bulk.rs:53) carries it; the Resource Access panels do.
- apps/desktop/web-rs/src/views/dr.rs:70-77: the backup success toast omits the skipped count even when the Callout below lists skipped objects; append ": N object(s) could not be read" when `b.skipped` is non-empty.
- apps/desktop/web-rs/src/views/dr.rs:104: `captured.get()` deep-clones the whole `TenantBackup` (potentially MBs) on every Save click; hold `Option<Arc<TenantBackup>>` and pass `&*b`.
- apps/desktop/web-rs/src/views/dialogs/cache_diagnostics_dialog.rs:35-38,142-154: `secs / 60` integer division renders a 90 s TTL as "1 min" (backend accepts any 60..=86400 s); round or show seconds when not a whole minute.
- apps/desktop/web-rs/src/views/permission_tester_view.rs:27-34 vs resource_access/mod.rs:309-316: two `verdict_badge` fns for the same verdict strings with different labels; if the wording difference is intended, document it in one place.
- apps/desktop/web-rs/src/bindings/audit.rs:28: `ExportArgs` is declared but never constructed (adjacent slice, same `#![allow(dead_code)]` symptom).

### frontend/fe-tests (8)

- apps/desktop/web-rs/src/demo/mod.rs:314,317: `mock_each` handlers for `resolve_sharepoint_resource` / `list_selected_item_permissions` wrap the value in `Some(...)` although both bindings return a non-Option `Result<T, UiError>`; harmless on the wire (serde `Some` is transparent) but misleading: drop the `Some`.
- apps/desktop/web-rs/src/ipc_mock/mod.rs:257-264: `reset()` clears ROUTES/FN_ROUTES/CALLS/LISTENERS but never CALLBACKS or CB_SEQ, so transformCallback registrations accumulate across a shard's tests; add `CALLBACKS.with(|m| m.borrow_mut().clear())`.
- apps/desktop/web-rs/tests/gui/dr.rs:29-30: two blind `tick()`s to 'let use_progress_stream register its listener'; the mock registers synchronously inside `plugin:event|listen` so this is deterministic today, but `ts::wait_for(|| ts::call_count("plugin:event|listen") >= 1)` states the actual precondition.
- apps/desktop/web-rs/tests/gui/app_site_access.rs:49: `mock_ok("list_site_permissions", &Vec::<serde_json::Value>::new())` is the only untyped fixture in the suite; use the real `Vec<SitePermissionRow>` (or whatever the binding returns) so a DTO change fails to compile.
- apps/desktop/web-rs/tests/gui_3.rs:10-11: header says the shard holds 'everything that mounts the ScopeWizard / permission picker', but gallery.rs (GalleryDialog) and managed_identities.rs (list only) mount neither.
- apps/desktop/web-rs/src/ipc_mock/mod.rs:106-107: recorded args that fail `from_value::<serde_json::Value>` silently become `Null`, so a later `arg_str` assertion fails as 'None' rather than 'args unrecordable'; log or panic with the command name.
- apps/desktop/web-rs/tests/gui/view_smoke.rs:1-3: header still says 'until those land' for interaction-heavy views; DR has landed (dr.rs), update or delete the DR smoke.
- apps/desktop/web-rs/src/ipc_mock/fixtures.rs:1189-1192: `distribution_list_search`'s doc comment sits above `application_templates` (the two `///` blocks were merged when the templates helper was inserted); move the DL comment down to line ~1350.

### frontend/fe-a11y-ux (12)

- apps/desktop/web-rs/src/hooks/use_focus_trap.rs:25-26: FOCUSABLE's `[tabindex]:not([tabindex="-1"])` clause does not exclude `button[tabindex="-1"]` (matched by `button:not([disabled])`), so a TabBar's inactive tabs or a SearchInput clear × inside a modal can be chosen as the wrap edge; add `:not([tabindex="-1"])` to each element clause.
- apps/desktop/web-rs/src/views/permission_tester_view.rs:288-294: aria-activedescendant is set to "" when there are no rows; omit the attribute (`then_some`) instead of an empty string.
- apps/desktop/web-rs/src/components/ui/skeleton.rs:23/45 and home_dashboard.rs:546: aria-busy="true" on a plain div is not announced; a visually-hidden "Loading…" (needs the .sr-only utility) or role="status" would be.
- apps/desktop/web-rs/src/components/virtual_list.rs:185-206: windowed rows expose no aria-rowcount/aria-setsize, so AT hears only the ~20 rendered rows of a 4,000-row list; the count label in select_all_bar.rs:77 partly compensates.
- apps/desktop/web-rs/src/views/shell.rs:463: "Sign Out" is Title Case while every other action label is sentence case ("Check for updates", "Cache diagnostics").
- Dialog close labels vary: "Done" (credentials_tab.rs:1070, sso_wizard_dialog.rs:425, secret_reveal_dialog.rs:67) vs "Close" (cache_diagnostics_dialog.rs:219, release_notes.rs:59); pick one for informational dialogs.
- apps/desktop/web-rs/src/views/security_view.rs:190-196: progress text "{done} / {total} apps (cap: N)" exposes the internal concurrency cap as operator-facing jargon; keep the rate-limit notice, drop "cap".
- apps/desktop/web-rs/src/views/readiness_view.rs:220, components/tenant_defaults_hint.rs:35, components/global_search.rs:828: <button> without type="button" (harmless today: there are 0 <form> elements, but the rest of the tree is consistent).
- apps/desktop/web-rs/styles.css:19-22: comment says --text-faint is "4.6:1 on --surface"; computed 5.10:1 on #fff, and the dark value #888 lands at 4.05:1 on --surface-raised (#2a2a2a), just under AA if ever used on a raised card (today it backs .filter-chip:disabled and .saved-view-chip__remove on --surface, 4.65:1).
- apps/desktop/web-rs/src/views/sign_in.rs:44-47: stale comment cites a 'detail-pane `error [code]: message` convention' that DetailLoadError replaced.
- apps/desktop/web-rs/src/components/ui/copyable_id.rs:24: truncated GUID's full value is only on `title` (hover); keyboard users rely on the copy button, acceptable but worth a visible expand on focus.
- apps/desktop/web-rs/src/components/global_search.rs:194-196: the wrapping <label class="global-search__input"> has no text, so the combobox's only name is its placeholder; add aria-label="Global search".

### cross-cutting/tooling (15)

- justfile:195: comment says "The committed dist/ stub is left alone" but `dist/` is gitignored (.gitignore:32) and `git ls-files` has no dist; the stub is created by `_stub-frontend-dist`, never committed.
- .claude/skills/repo-review/SKILL.md:16: `gh pr search --head <sha>` is not a gh subcommand (`gh search prs <sha>` or `gh pr list --search <sha>`); :54 spells the recipe `_stub_frontend_dist` (actual: `_stub-frontend-dist`).
- .claude/skills/release/SKILL.md:49: "release.yml (line ~229)": the CHANGELOG extraction loop is at release.yml:232-241; prefer naming the step ("Assemble update manifest") over a line number.
- .claude/skills/feature/SKILL.md:107: "If the feature is purely frontend (WASM only), `just web-build` suffices" contradicts the gate set (web-clippy, web-test, web-itest); say `just verify`.
- .cargo/audit.toml:1-2: header cites "the rustsec/audit-check CI action"; CI runs `just audit` via taiki-e/install-action, no such action is used.
- deny.toml:3: "Run locally with `cargo deny check`" should be `just deny` / `just web-deny` (AGENTS.md: never hand-type cargo; the recipe adds the check list and the web-rs `--config`).
- .github/workflows/ci.yml:75: `LICENSE|LICENSE.*` never matches the actual files `LICENSE-MIT` / `LICENSE-APACHE`, so a license-only edit runs the full matrix.
- .github/workflows/release.yml: none of guard/build/release set `timeout-minutes` (ci.yml sets one on every job); default is 360 min.
- scripts/setup.sh:80 says "~46k lines of frontend", justfile:91 says "~41k lines", apps/desktop/web-rs/build.rs:28 says "50k-line crate"; `find web-rs/src -name '*.rs' | xargs cat | wc -l` = 50 463 today.
- .claude/hooks/web-test-strings-check.sh:67: `grep -rlF -- "$lit" $search_dirs` word-splits `$project` paths; a checkout under a directory with a space (macOS "My Projects") breaks the search. Use a bash array.
- .claude/settings.json:9: the rustfmt PostToolUse hook is the only one without a `timeout`; give it the same 5-10 s the others have.
- .github/workflows/ci.yml:197,229: actionlint v1.7.12 and gitleaks v8.30.1 are checksum-pinned `curl` downloads Dependabot cannot see (install-action manifests verified absent); add a `# renovate`-style note or a quarterly check so the pins do not rot silently.
- scripts/setup.sh:132 / scripts/setup.ps1:74,79: `cargo check --workspace` and `trunk build` run without `--locked`, unlike every recipe in the justfile.
- .claude/hooks/staleness-check.sh:86-100: the AGENTS.md trigger list omits `scripts/setup.*`, `deny.toml`, `.cargo/audit.toml`, `.github/dependabot.yml` and `.claude/{rules,skills}/*`, all of which AGENTS.md's Quick reference / Repo map describe.
- CONTRIBUTING.md:43: "keep `cargo test --workspace` green": should be `just test` (the recipe adds `--locked` and the dist stub).

### cross-cutting/docs-drift (14)

- docs/DEVELOPMENT.md:4 "packaging a release MSI": the doc now covers Windows/macOS/Linux packaging; say "packaging installers".
- docs/DEVELOPMENT.md:20 "pins the channel (1.98)": rust-toolchain.toml:5 is `channel = "1.98.1"`; say "the 1.98.x patch release".
- docs/DEVELOPMENT.md:37-38 "installs the Tauri CLI and trunk if missing": scripts/setup.sh:70-76 and setup.ps1:56-62 also install wasm-pack (and chromedriver via Homebrew on macOS, setup.sh:98-103).
- docs/DEVELOPMENT.md:73 "(or `cargo tauri build` for your host target)" and README.md (Baked into a team build) "run `cargo tauri build`": AGENTS.md says never hand-type `cargo`; point at the `just build-*` recipes.
- README.md:150 Quick start step 1 "Download the latest Windows installer" while Install covers three OSes; say "the installer for your platform".
- CONTRIBUTING.md:43 "keep `cargo test --workspace` green": should be `just test` (and note it never reaches web-rs; `just web-test` does).
- docs/architecture/frontend-workspace.md:219 "CI runs it unconditionally": .github/workflows/ci.yml:137 skips the `web` job on the weekly cron and on docs-only changes (`if: github.event_name != 'schedule' && needs.changes.outputs.code == 'true'`).
- docs/architecture/frontend-workspace.md:54-55 "`sso_wizard_dialog.rs` is the one remaining migration" is still open: apps/desktop/web-rs/src/views/dialogs/sso_wizard_dialog.rs:298/310/313 still render `<Textarea value=notification_emails|redirect_uris|spa_uris />`.
- docs/architecture/auth-and-consent.md:34-43 optional-scope table lists ARM and Log Analytics `.default` rows but omits `Exchange.Manage` and Key Vault `.default`, both acquired the same lazy way (state.rs:543-546).
- docs/architecture/scoping-and-audit.md is a 14-line redirect stub with zero inbound references in the repo (grep for `scoping-and-audit` in *.md/*.rs/*.sh/*.json finds none); keep only if external links are known to exist.
- crates/azapptoolkit-keyvault/src/lib.rs:10 doc comment lists `delete_secret`, which does not exist in client.rs (only list/get/set).
- .github/SECURITY.md:19 "the app auto-updates from its configured endpoint": only NSIS/.app/.AppImage do; MSI and .deb do not (README Updates).
- docs/operator-rbac/entra-custom-role.ps1:51 comment "# tags / HideApp toggle" on `servicePrincipals/basic/update`: Microsoft lists `servicePrincipals/tag/update` as the separate permission for the tag property.
- apps/desktop/src-tauri/src/commands/restore.rs:292/307 section markers say Pass 4/Pass 5 while fn docs at :623/:723 say Pass-5/Pass-6 (docs-in-code inconsistency mirrored by backup-and-restore.md:184/197).

### cross-cutting/security (7)

- crates/azapptoolkit-keyvault/src/client.rs:96: `get_secret` interpolates `version` into `/secrets/{name}/{v}` without the `validate_secret_name`-style check the module header promises for path components (only caller passes `None`, so latent).
- apps/desktop/src-tauri/src/commands/export.rs:25: `csv_field` quotes on `,`/`"`/`\n` but not on a bare `\r` inside a field, so an embedded CR (Graph display names can carry one) can split a row in some CSV readers.
- apps/desktop/src-tauri/src/commands/sso/mod.rs:1279-1286: `metadata_http_client` uses `.build().unwrap_or_default()`, so a builder failure silently yields a reqwest client with no timeout; the other clients `.expect(...)` instead.
- apps/desktop/src-tauri/src/commands/auth.rs:54-55: `sign_out` drops `graph_clients`/`exchange_clients` but leaves `kv_clients`, `arm_clients`, `la_clients` for the tenant; harmless (adapters re-resolve via `known_tenants`) but inconsistent with the 'sweep everything tenant-scoped' comment beside it.
- apps/desktop/src-tauri/src/commands/sso/mod.rs:92-94: `app_id` from IPC is interpolated into `?appid={app_id}` for the public metadata GET without `is_guid`; `&`/`#` would alter the query (no bearer attached, host fixed).
- crates/azapptoolkit-auth/src/service/loopback.rs:99: the raw `error` query value from the redirect is surfaced verbatim in `AuthError::Authorization` and hence the toast; consider mapping known OAuth error codes to fixed text.
- README.md:387-401 vs apps/desktop/web-rs/src/views/config_screen.rs:125: README says to copy the Tenant ID GUID, the config screen advertises a domain; align once the domain-tenant bug above is resolved.

### cross-cutting/deps-hygiene (9)

- apps/desktop/src-tauri/Cargo.toml:19 and :31: `features = []` on tauri-build and tauri is noise; drop the empty arrays.
- Cargo.toml:20-21: `[workspace.package] authors` and `repository` are inherited by no member (no `authors.workspace`/`repository.workspace` anywhere); either inherit them or delete the dead keys.
- apps/desktop/web-rs/Cargo.toml:90: `lto = true` while the root profile says `lto = "fat"`; identical semantics, but say it the same way in both trees.
- apps/desktop/web-rs/Cargo.toml:62: chrono feature `wasmbind` is already in chrono 0.4.45's default set (`default = ["clock", "std", "oldtime", "wasmbind"]`), so listing it is redundant.
- apps/desktop/web-rs/Cargo.toml:58-60: comment says serde-wasm-bindgen is "Pinned to the version tauri-sys deserializes with", but `"0.6.5"` is a caret requirement; it unifies because tauri-sys also asks `^0.6.5`, not because it is pinned. Reword or use `=0.6.5`.
- apps/desktop/web-rs/Cargo.lock:1467-1485: two copies of `reactive_stores` (0.2.5 via thaw_utils 0.2.0-beta, 0.4.3 via tachys) ship in the wasm bundle; thaw 0.5.0-beta (2025-08-03) is still the newest release so nothing to bump, but worth a note next to the thaw line so it is not re-investigated.
- .github/dependabot.yml:46-47: the sha2 ignore targets a transitive-only dependency (the comment says so); harmless, but its drop condition duplicates docs/architecture/release-updater-demo.md:156-166: keep one canonical rationale and link to it.
- Cargo.lock: `cargo update --dry-run` shows zerocopy/zerocopy-derive 0.8.58 → 0.8.59 available; release-updater-demo.md:168-170 says a plain `cargo update` was a no-op as of 2026-09-14: trivial expected drift, Dependabot will take it.
- crates/azapptoolkit-auth/Cargo.toml:26: `webbrowser = "1"` is the only non-workspace-managed crates.io dep besides `bytes`; acceptable for a single consumer, but a workspace entry would keep the manifest style uniform.

### cross-cutting/graph-api-currency (6)

- crates/azapptoolkit-exchange/src/client.rs:26-28: pre-launch 'NOTE (verify during the live transport spike)' is stale on production transport code (also covered by the InvokeCommand docs finding).
- crates/azapptoolkit-exchange/src/client/transport.rs:129: doc link cites admin-api-get-started#pagination, a page that describes the v2.0 REST endpoints, not the beta InvokeCommand route the code calls.
- crates/azapptoolkit-keyvault/src/client.rs:25: DEFAULT_API_VERSION "7.4" predates Key Vault's switch to date-based data-plane versions (2025-07-01 on the current Get Secret reference).
- crates/azapptoolkit-core/src/capabilities.rs:213-218: audit_reports lists Global Reader; the Learn least-privilege lists for directoryAudits and servicePrincipalSignInActivities name only Reports Reader / Security Reader / Security Administrator (Global Reader works via its read-all actions, so this is wording not correctness).
- crates/azapptoolkit-graph/src/client/applications.rs:539: doc comment hardcodes the global custom template GUID; make it cloud-aware alongside the sso/mod.rs fix.
- crates/azapptoolkit-exchange/src/client.rs:50-53: X-AnchorMailbox uses the `UPN:` prefix; Learn's v2.0 table prefers `AAD-UPN:` but also documents `UPN:admin@contoso.com` for delegated org-level calls, so no change needed, just note both forms in the comment.

### cross-cutting/product-gaps (6)

- apps/desktop/web-rs/src/state/mod.rs:57: `DisasterRecovery` doc says restore comes 'in later slices'; `restore_tenant` is registered in lib.rs (covered in the docs finding).
- apps/desktop/web-rs/src/views/credentials_dashboard.rs:6: 'fetched fresh on open (no cache)' contradicts the read-through cache in apps/desktop/src-tauri/src/commands/credentials.rs:9.
- apps/desktop/src-tauri/src/commands/restore.rs:4: 'This slice restores app registrations' while passes 4/5 (restore.rs:292, 307) restore enterprise apps and managed identities.
- docs/DEVELOPMENT.md:174: RPM is 'omitted for now'; it is a single `--bundles appimage,deb,rpm` addition to `build-linux-updater` for RHEL/Fedora shops (documented deferral, not re-litigated).
- README.md:130: the Conditional Access claim should say 'target an application as a resource'; workload-identity policies are not evaluated (see the CA finding).
- crates/azapptoolkit-core/src/scoping.rs:459-460: the `ScopeKind` 'Future: AdministrativeUnit, AzureRbac, ResourceSpecificConsent' comment is the only record of those roadmap items; consider tracking them as issues so they are discoverable outside the enum.

### gap-critic/gap-cancel-flag-sharing (6)

- apps/desktop/web-rs/src/hooks/use_progress_stream.rs:3-5 says 'The four long-running panels (security audit, bulk actions, SharePoint site sweep, mailbox probe)': there are now eight subscribers (plus KV sweep, DR backup, DR restore, per-app site panel, updater).
- apps/desktop/src-tauri/src/commands/gallery.rs:127-135 justifies the unguarded `put_typed_index` with 'nothing invalidates this key', but the key is `{tenant_id}|gallery_corpus` (gallery.rs:45-47) and `sign_out` -> `cache.invalidate_tenant` does sweep it; harmless because the catalog is static, but the exemption's stated reason is inaccurate: say 'no mutation in this app changes the data' instead.
- apps/desktop/web-rs/src/bindings/audit.rs:20 and bindings/bulk.rs:13 call bare `invoke::<()>` for cancel_audit/cancel_bulk while cancel_resource_sweep and cancel_dr use `invoke_result`; the backend fns are infallible so it cannot reject today, but the rules file says never bare `invoke`: align the four cancel bindings.
- apps/desktop/src-tauri/src/commands/bulk.rs:12-13 'Progress events ride the same bulk-progress channel so the frontend can share a single listener': the frontend in fact mounts one listener per BulkActionBar (up to one per expanded Findings group plus the All-apps pane plus other views), so the stated benefit does not exist while the interleaving cost does; consider a run_id in BulkProgress.
- single_flight (state.rs:395-420): all four gate keys are tenant-prefixed (sp_index, app_name_index, search_corpus, gallery_corpus) and sign_out/clear_cache bump watched generations so holders' `*_if_current` refuse: no race found; the MAX_INFLIGHT_GATES sweep's `Arc::strong_count > 1` test is correct because a caller clones the Arc under the same map lock.
- throttle.rs:60-82 recovery loop: confirmed it exits within one RECOVERY_SECS tick after the last tracker Arc drops (Weak upgrade fails), so a short run leaves a task sleeping for up to 30 s but never leaks.

### gap-critic/gap-error-code-to-screen (7)

- GUI fixtures use `fixtures::ui_error("throttled", "Too many requests")` (tests/gui/credentials_dashboard.rs:36, tests/gui/managed_identities.rs:68): a message the backend never emits: so the tests pin a rendering the operator never sees; use the real Display string once finding 1 lands.
- apps/desktop/src-tauri/src/commands/graph_err.rs:88-91 `GraphError::Unauthorized => … "Your session expired. Sign in again to view {feature}."` is shown in a warn Callout with only the tab's Refresh button; the in-app remedy is "Refresh token", not a sign-in (fold into finding 4).
- apps/desktop/web-rs/src/views/sign_in.rs:169 fallback hint "Check your network and try again" is also what `state_mismatch` ("possible CSRF"), `url`, `serde`, `io` and `unknown_auth` receive; a CSRF/state error telling the operator to check their network is a confidently wrong instruction the file's own comment (line 176) says to avoid.
- DetailLoadError always renders Retry regardless of `retryable`: documented as deliberate (detail_load_error.rs:6-9, frontend-workspace.md:25), so not a finding, but for `forbidden` / `*_not_found` / `*_unavailable` it is a button that reproduces the same failure; passing `retryable` through to relabel it ("Retry" vs "Reload") would cost one prop.
- A 429 with `Retry-After: 300` is honoured verbatim up to three times inside `with_retries` (http_retry.rs:48,70-72), so one command can legitimately block for ~15 minutes; that is a documented decision, but the only in-flight throttle cue is the audit/DR progress notice: single-object loads show a bare skeleton for the whole wait.
- crates/azapptoolkit-graph/src/client/transport.rs:497 comment says "A 401 is non-retryable and surfaces to the caller to re-auth" but no caller performs or offers re-auth for `unauthorized` (see finding 4); either the comment or the UI should change.
- The `updater` code carries `retryable: true` (commands/updater.rs:20) and `UiError::io` is retryable by construction (dto lib.rs:70-72), but both render through `toast_error(.., None)` / `error.set(..)`: consistent with finding 3 that the flag has no consumer.

### gap-critic/gap-launch-sequence-perf (5)

- crates/azapptoolkit-dto/src/enterprise_application.rs:28-35: the list path serialises four always-empty Vecs (`password_credentials`, `key_credentials`, `app_roles`, `oauth2_permission_scopes`) per row because the SP index `$select` omits them (documented as 'non-empty for the detail view'); `#[serde(skip_serializing_if = "Vec::is_empty", default)]` would drop ~40 bytes x 4 x 10k rows from the IPC payload and cache JSON for free.
- apps/desktop/web-rs/src/views/home_dashboard.rs:58-66: the `managed` card tracks only its local `reload`, while `apps`/`enterprise` also track a session-level bump; there is no `mi_reload`, so an MI created/deleted outside the app shows a stale count for the 60-minute Lists TTL (acceptable since MIs are made in Azure, but inconsistent with its siblings).
- .github/workflows/ci.yml:152, release.yml:131, pages.yml:44: `tool: just,trunk` installs whatever Trunk is latest, so wasm-opt/minify/asset-hashing behaviour of the shipped bundle can change between two releases built from the same commit.
- apps/desktop/src-tauri/src/commands/audit.rs:504: `get_cached_audit` reads the run via the untyped `cache.get::<CachedAuditRun>`, walking the whole 10k-item `Value` tree on every call (two callers at sign-in, plus every `audit_reload`); the typed `put_typed_index_if_current` / `get_typed` path the indexes use would make it a refcount clone.
- apps/desktop/web-rs/src/views/shell.rs:42-50: `get_organization` is uncached and refetched on every shell mount; trivial today (one small GET per sign-in) but it is the only launch-path read with no cache entry.

### gap-critic/gap-updater-install-format-platforms (5)

- apps/desktop/src-tauri/src/commands/updater.rs:70: the comment 'On Windows (NSIS, passive) the installer has run; relaunch applies it' is wrong: the vendored plugin calls `std::process::exit(0)` right after `ShellExecuteW` (tauri-plugin-updater/src/updater.rs:880) and NSIS relaunches via `/R`, so `app.restart()` executes only on macOS/Linux. Because `process::exit` skips destructors, the `LogGuards` non-blocking writer is never flushed and the last 'installing update' lines can be lost on Windows (the plugin's `on_before_exit` only runs `cleanup_before_exit`).
- apps/desktop/src-tauri/src/commands/updater.rs:33: `pub_date: update.date.map(|d| d.to_string())` formats `time::OffsetDateTime` with `Display` (not RFC 3339), and the frontend never reads `pub_date` (update_splash.rs uses only `version`, `current_version`, `notes`); either drop the field or format it deliberately.
- apps/desktop/src-tauri/src/lib.rs:412-421: the Linux branch hardcodes `~/.local/share` instead of honouring `$XDG_DATA_HOME`, and the final fallback `PathBuf::from(".")` writes settings.json and logs into the process CWD when `APPDATA`/`HOME` are unset (e.g. a service/MDM launch context).
- README.md:231-232: 'Needs a WebKitGTK runtime (`libwebkit2gtk-4.1`) … pulled in automatically by the `.deb`' sits under both Linux formats, leaving AppImage users unsure whether to install WebKitGTK themselves; state explicitly what the AppImage bundles versus what it needs from the host (glibc floor, see the release.yml finding).
- apps/desktop/web-rs/src/components/update_splash.rs:40-43: the raw plugin error string (`e.message`, e.g. 'invalid updater binary format', 'temp directory is not on the same mount point as the AppImage') is shown verbatim in the warn Callout with no recovery hint; a small `updater_hint(code/message)` map like sign_in.rs::recovery_hint would help.

### gap-critic/gap-observability-support-log (5)

- A panic inside a #[tauri::command] future IS logged by the hook (std panic hooks run before tokio's catch_unwind), but tauri 2.11.6 `respond_async_serialized_inner` (ipc/mod.rs:370-388) calls `return_result` only after `task.await` returns, so the invoke promise never settles: `use_command::run_with` never clears `busy` (use_command.rs:64-74) and the UI spins forever with no toast: the `backend panic` log line is the only signal. Consider a frontend watchdog or a `tokio::spawn(...).await` wrapper mapping JoinError → UiError("internal_panic") in the few commands with `.expect()`s (throttle.rs:69/101).
- transport.rs:678 (`CAE claims challenge could not be satisfied silently`) is the only tracing call in the entire 784-line Graph transport; success paths log nothing at any level, so `RUST_LOG=azapptoolkit_graph=trace` (README advice) adds essentially no request-level output.
- `app.restart()` (updater.rs:71) and `restart_app` (config.rs:64) exit via std::process::exit, so the `WorkerGuard` managed in Tauri state is never dropped: lines still in the non_blocking channel at that instant are lost; a `tracing::info!("restarting for update")` immediately followed by exit may not reach the file. Flush/drop the guard (take it out of state) before restarting.
- Non-blocking appender is lossy by default (DEFAULT_BUFFERED_LINES_LIMIT 128_000); harmless at today's volume but worth `.lossy(false)` once per-request logging exists.
- PII inventory for the log at default filter: app display names in one warn (audit.rs:1497 `app = %app.display_name`), tenant ids (auth service/mod.rs:534,545), object/SP ids (backup.rs, sharepoint.rs:810). No request URLs or `$filter` values are logged at any level, so user-typed search prefixes and UPNs never reach the file; raw Graph error bodies do (F290).

### gap-critic/gap-desktop-inline-test-oracles (7)

- audit.rs:1976 `assert!(html.contains("<li><b>1</b> Critical</li>"))` and :1960 `assert!(!html.contains("class=\"caveat\""))` pin HTML markup and a CSS class; parse the HTML fragment or assert on `severity_summary` + a `data-` attribute instead.
- sso/mod.rs:2248 `assert!(csv.contains(",yes,no\n"))` pins column adjacency/order of the last two columns; use `csv_columns` + a header lookup like the sharepoint/tester CSV tests do.
- credentials.rs:562 `an_invalid_secret_window_never_reaches_graph` asserts `server.received_requests().await.unwrap_or_default().is_empty()`: `unwrap_or_default()` turns a wiremock recording failure into a passing empty Vec; use `.expect("request recording is on")`.
- backup.rs:1097 comment 'keeps the test free of a Tauri AppHandle / mock runtime' and bulk.rs:40-45 both restate the dropped `tauri/test` rationale; once ProgressSink is lifted, point both at progress.rs so the story lives in one place.
- cache.rs:189-197 `sp_index_store` and :284-292 `app_name_index_store` are `#[cfg(test)]` wrappers with identical bodies and identical 9-line doc comments; a single generic `#[cfg(test)] fn store_index<T>(cache, key, value)` would keep the 'cfg(test) is the enforcement' property with one copy.
- readiness.rs tests (:311, :330, :349) assert `detail.contains("Global Administrator")` etc. next to a typed `Verdict`; acceptable as secondary checks, but `azure_rbac_unknown_when_not_enumerable` asserts only `detail.contains("Azure")`, which any Azure-mentioning sentence satisfies.
- gallery.rs:319-326 test helper `rank()` re-implements the command's tokenisation (`trim().to_lowercase()`, `split_whitespace`) instead of calling the production tokeniser, so the two can drift while the comment claims 'the same entry point a keystroke does'.
## Appendix C: coverage and method notes

### Per-slice coverage

Condensed from each slice's own coverage statement. "Read fully" means every file in the slice was read end to end; supporting files outside a slice were read only in the excerpts needed to verify a finding. No slice ran cargo or just against the tree except the toolchain runner; line numbers come from the checked-out working tree.

- **backend-crates/core-audit**: all six audit files read fully including the 2123-line scoring tests; `scoping.rs` read to line 520 and the command-layer call sites only around the scorer; the legacy PowerShell module the citations refer to is not in the repo, so rule-vs-legacy parity was checked for internal consistency only.
- **backend-crates/core-infra-a**: cache, retry, error, settings, private_file, token, net, defaults and constants read fully; dead-code conclusions (`UserSettings::load`, `auto_update`) rest on repo-wide grep, not compiler diagnostics.
- **backend-crates/core-infra-b**: all eleven files read fully plus `tauri.conf.json` for the CSP cross-check; Microsoft Learn consulted for FIC subject nullability, redirect-URI rules, the RBAC-for-Applications role table and identifier-URI forms.
- **backend-crates/auth**: the whole auth crate, `token_adapter.rs` and the auth, session and consent commands read fully; `commands/consent.rs` turned out to be the tenant-wide grant audit and yielded nothing auth-specific; keyring and oauth2 crate sources read from the registry for zeroize and NoEntry semantics.
- **backend-crates/graph**: every client module and test file read fully; three Graph facts verified on Learn (CA `$top`, sign-in activity still beta-only, `$count` without ConsistencyLevel ignored); mixed-consistency paging was not observed live.
- **backend-crates/exchange**: every crate file and `exchange-scoping.md` read fully; the rustdoc broken-link claim is by inspection; whether `Get-ManagementRoleAssignment` exposes `CustomResourceScope` could not be confirmed on Learn and was not reported.
- **backend-crates/small-crates**: keyvault, arm and permissions read fully; ARM `atScope()`, Log Analytics `PartialError` and the Key Vault `managed` attribute verified on Learn; Graph and Exchange transports only grepped.
- **backend-crates/toolchain-runner**: ran the shared-crate tests, pedantic clippy, `cargo tree -d` with every duplicate traced, cargo-machete at root and in web-rs, the web-rs host tests and the wasm check; did not build the desktop crate (WebKitGTK absent), run the browser GUI tests (no Chrome) or cargo audit/deny.
- **backend-app/cmd-apps**: all 15 files read fully; Graph's handling of a caller-supplied `endDateTime` on `keyCredentials` PATCH was not verified against live docs.
- **backend-app/cmd-audit**: all seven files read fully (audit.rs 2011 lines, bulk.rs 1235) plus `cancel.rs` and `fanout.rs`; the throttle bug and the veto path were verified by reading control flow, and the GUI tests confirmed SP-only rows are pinned non-selectable.
- **backend-app/cmd-scoping**: every exchange command file, `sharepoint.rs` (1338 lines), `permission_tester.rs` (1535) and the three scoping docs read fully; the `ScopeKind` section of `core/scoping.rs` was not read.
- **backend-app/cmd-sso-ent**: every file read fully including `sso/mod.rs` (2349 lines); claims-mapping schema, role-assignment inheritance and `acceptMappedClaims` verified on Learn; the `acceptMappedClaims` concern was found not to be a defect because the editor is offered only for SAML apps.
- **backend-app/cmd-platform**: all slice files read fully including `tauri.conf.json`, capabilities and the vendored rcgen and updater plugin; Tauri's `core:default` permission TOML could not be located locally, so that item rests on the docs alone.
- **backend-app/invariants-dto-ipc**: all invariant tests and every DTO module read fully; IPC parity checked mechanically (186 commands declared, registered and bound, no arg or return drift); most bindings files covered by the parity scan rather than a read.
- **frontend/fe-core**: every file read fully including `styles.css` (4438 lines) in five chunks; the dead-CSS list is grep-based with a dynamic-modifier heuristic and should be re-checked with `just web-itest` after deletion.
- **frontend/fe-apps**: every list, pane, tab, dialog and picker file read fully; the remount claim relies on the code's own comments and the `Suspend` construction rather than a running app.
- **frontend/fe-enterprise**: every enterprise pane, MI, SSO and gallery file read fully; `sso/claims.rs` only grepped; Learn confirmed the claims editor's TransformationMethod list matches the reference.
- **frontend/fe-security**: every audit_view, security, consent, bulk and scoping component read fully, including `bulk_action_bar.rs` and `scope_wizard.rs`; the GUI tests were grepped, not read.
- **frontend/fe-tools**: Home, DR, settings, Key Vault, tester, readiness, Resource Access, global search (1159 lines) and the tool bindings read fully; the backend was read only in targeted sections.
- **frontend/fe-tests**: every GUI shard and module, the mock IPC bridge, fixtures, demo, test_support, build scripts and Trunk config read fully; shard wasm sizes were not measured, so shard-balance observations are test counts only.
- **frontend/fe-a11y-ux**: all primitives, dialogs, hooks and `frontend-workspace.md` read fully; views were read in targeted ranges; `styles.css` covered by token extraction, contrast computation and rule greps rather than line by line; GUI tests grepped for ARIA coverage.
- **cross-cutting/tooling**: justfile, all four workflows, CodeQL config, dependabot, deny and audit configs, both setup scripts, all hooks, skills and rules read fully; the parity hook's grep pipeline was re-run (zero false positives); branch protection could not be read, so the "8 required checks" list is unverified.
- **cross-cutting/docs-drift**: README, DEVELOPMENT, AGENTS, CLAUDE, CONTRIBUTING, SECURITY, templates, operator-rbac and all ten architecture docs read fully; CHANGELOG inspected for structure only; the WiX manual-install claim could not be verified because egress to the Tauri site is blocked.
- **cross-cutting/security**: the auth crate, net, private_file, settings, transports, token adapter, config, export, updater and the Tauri surface read fully or in the security-relevant ranges; large command bodies (sso, audit, backup, restore, bulk) and most views were grep-level only; Learn confirmed `Directory.Read.All` as the least-privileged grant read and the national-cloud host differences.
- **cross-cutting/deps-hygiene**: every manifest, deny.toml, audit.toml, dependabot and the dependency policy test read fully; both lockfiles interrogated via `cargo tree`, `cargo metadata` and `cargo update --dry-run` (lockfiles untouched); the upstream tauri-sys fix diff was not retrievable, so that finding relies on the pinned source plus the upstream issue text.
- **cross-cutting/graph-api-currency**: every Graph, Exchange, ARM and Key Vault client module read fully against Microsoft Learn; a list of endpoints verified current with no finding filed is recorded in the slice note (sign-in activity beta-only, ARM 2022-04-01, Log Analytics v1, Sites.Selected bodies, `$batch` limit).
- **cross-cutting/product-gaps**: README, lib.rs, capabilities, session state, scoring, CA, readiness, credentials, usage, config and auth commands and GitHub issues #109 and #110 read fully; the enterprise-pane tab enum was not located by grep, so the missing CA tab claim rests on import analysis.
- **gap-critic/gap-cancel-flag-sharing**: `state.rs`, `cancel.rs`, `throttle.rs`, `dispatch.rs` and the progress hooks read fully; every claim and cancel site read with context; the frontend Cancel wiring read in the relevant ranges of eleven views and components.
- **gap-critic/gap-error-code-to-screen**: the core error, reauth and retry modules, the DTO error type, the Exchange error module, the frontend error sink, `use_command`, the error primitives and the sign-in hints read fully; the roughly 110 `e.message` sink sites were counted by grep; reqwest's Display impl read from the registry.
- **gap-critic/gap-launch-sequence-perf**: Root, shell, Home, the list views' resource creation, the index and cache commands and the Graph paging constants read; Trunk's `minify` default verified from upstream source; Graph round-trip counts derived from `DEFAULT_APP_PAGE_SIZE` and the call graph, not measured.
- **gap-critic/gap-updater-install-format-platforms**: updater command, Tauri config, release workflow, build recipes, README and DEVELOPMENT sections, the vendored updater plugin and keyring stores read; the glibc floor was measured on a workspace binary built on the glibc-2.39 host, not on a release AppImage; no macOS or Windows host, so the keychain-prompt finding is reasoned from the ACL model.
- **gap-critic/gap-observability-support-log**: the Graph, ARM and retry transports, dispatch, throttle, progress, diagnostics and the frontend sink read fully; vendored Tauri IPC and tracing sources read for the panic and rejection behaviour; Learn consulted once for the `client-request-id` guidance.
- **gap-critic/gap-desktop-inline-test-oracles**: every `#[cfg(test)]` module in the named desktop files read fully with the handler code each bug cites; static reading only, nothing compiled; one line number (bulk.rs invalidate site at 288) differs from the index's 283.

### Recheck agents that never ran

The batch manifest reserved six second-verification agents (`backend-crates/recheck:exchange`, `backend-crates/recheck:small-crates`, `backend-app/recheck:cmd-apps`, `cross-cutting/recheck:security`, `cross-cutting/recheck:deps-hygiene`, `cross-cutting/recheck:graph-api-currency`). They were never needed: first-pass verification downgraded every high-severity bug or security item in those batches below the re-verification threshold, so there was nothing left for them to re-check. They are not coverage gaps.

### Toolchain baseline (lead session, from the runner's logs)

- `cargo test --locked` on the eight shared crates: all pass; one ignored doctest by design (`crates/azapptoolkit-core/src/http_error.rs:35`).
- `cargo test --locked` for web-rs on the host target: all pass (197 + 3); one ignored doctest (`src/hooks/use_command.rs:6`).
- `cargo check --target wasm32 --all-targets --features test-support` for web-rs: clean in 1m20s, with the warning that `proc-macro-error2 v2.0.1` (transitive via `leptos_macro`) will be rejected by a future Rust; a future rustc bump could break the WASM build with no change in this repo.
- All 10 packages share rust-version 1.98 and edition 2024 via `workspace = true`; every member carries `[lints] workspace = true`.
- Pedantic and nursery clippy over the shared crates, actionable subset: `future_not_send` x8 (public async fns returning non-Send futures in keyvault and graph), `significant_drop_tightening` x4 (`core/src/cache.rs:841`, `914`, `1059`), `unused_async` x2 (`auth/src/service/mod.rs:561` and `:679`), plus `redundant_closure` x12, `derive_partial_eq_without_eq` x7, `ref_option` x4, `needless_continue` x3; candidate `[workspace.lints.clippy]` additions the tree nearly passes already are `unused_async`, `redundant_clone`, `derive_partial_eq_without_eq`, `ref_option`, `needless_continue` and, after fixing the eight, `future_not_send`.
- Unused dependency declarations confirmed by cargo-machete plus grep: `tracing` in `crates/azapptoolkit-arm/Cargo.toml:19`, `crates/azapptoolkit-keyvault/Cargo.toml:20` and `apps/desktop/web-rs/Cargo.toml:63`; `url` in `crates/azapptoolkit-exchange/Cargo.toml:18`; `anyhow` and `thiserror` in `apps/desktop/src-tauri/Cargo.toml:42-43`. The `thiserror` declarations in arm, graph and keyvault are false positives required by `core::http_error_enum!`'s `::thiserror::Error` derive.
- The desktop crate cannot compile in the container (webkit2gtk-4.1 missing); its ~300 inline tests and the `repo_invariants` suite were reviewed statically.
- Lead-session spot-checks agreed with the verified finding for 12 of the 14 high items (F036/F139, F105, F151/F251, F178, F295, F394, F424, F488, F440 to F442, F039, F002, F371); F054, F055 to F057 and F070 were left to the agents' verification.

### Completeness critic's assessment

File coverage was close to complete: every source file under `crates/`, `apps/desktop/src-tauri`, `apps/desktop/web-rs/src`, `docs/` and `.github/` fell inside one of the 26 slices, and the only partially read regions were test tails, CHANGELOG entry bodies, both lockfiles and about 20 bindings files that were parity-scanned rather than read. The blind spots were lenses, not files, and the repo showed concrete evidence for each: concurrency across run kinds (a docstring asserting audit and bulk never overlap while `audit_cancel` is claimed in six command files), launch-time duplication (three full `/applications` paginations at sign-in), error UX end to end (the frontend branching on about 6 of about 30 UiError codes and only Graph setting a connect timeout), an install-format-blind updater, observability (one `error!` and 65 `warn!` backend-wide, no request-id capture outside Exchange, no frontend log persistence), and the unexecuted desktop inline tests whose oracle strength nobody had assessed. The critic also noted that perf was under-represented and that several backend findings implied frontend work nobody had scoped (F027/F058, F059/F178, F035, F073, F094, F127/F402) while F376/F377 need backend DTO changes; those pairings appear under "Changes that must ship together". The six gap slices that followed produced 52 further verified findings, including the two high items on the Linux glibc floor (F488) and the missing install-format gate (F487).
