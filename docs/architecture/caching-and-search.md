# Caching & search

Deep-dive companion to the **Tenant-scoped caches** gotcha in [AGENTS.md](../../AGENTS.md). Read this
before editing list commands, `global_search`, cache keys, or anything in
`azapptoolkit-core`'s cache module.

## Tenant-scoped keys — cross-tenant leakage is the #1 footgun

List cache keys are prefixed with the tenant id via helpers like
`apps_pairing_key(tenant_id)` → `"{tenant_id}|apps_pairing"`. **Never use an unscoped key.**
The convention is universal: every kind — Lists, Audit (`{tenant}|audit_run`,
`{tenant}|site_sweep`), ServicePrincipal, and Permissions — uses `{tenant_id}|…`, and `sign_out`
prefix-sweeps **all four kinds**, so a different operator signing into the *same* tenant never
reads the previous session's audit/sweep/SP data. The audit-run entry is stored typed
(`put_typed`, unpinned) and must be read with `get_typed::<CachedAuditRun>` — an untyped `get` on
it misses. The site and Key Vault sweeps are typed the same way (`put_typed_if_current`, read with
`get_typed::<SiteSweepResult>` / `get_typed::<KeyVaultSweepResult>`). `sign_out` calls `AppState::forget_tenant`, the one sign-out sweep: every per-tenant
client map (graph/exchange/kv/arm/la), the tenant's idle single-flight gates, and
`invalidate_tenant`. A new `Mutex<HashMap<…>>` field on `AppState` must be named there (pinned by
`repo_invariants/cache.rs::sign_out_forgets_every_per_tenant_map_on_app_state`). The `sign_in`
command calls it too — the account picker can return a different operator on the same tenant
without a sign-out in between — while `reauthenticate` (same account, oid-checked) never does
(`sign_in_forgets_the_tenant_but_reauthenticate_keeps_its_caches`).

### Proving the session, and what may be pinned

Two rules ride alongside the key prefix:

- **A command that can answer from cache must prove the session** with
  `session::prove_tenant_session(&state, &tenant_id)?` (or `state.auth.tenant_context(tenant_id)?`,
  or a `let Some(…) = ….tenant_context(…) else` guard) as its first statement, ahead of any cache
  read. Only a shape that returns on a missing session counts: a comment, `let _ = …` or
  `.is_some();` mention discards the answer and is not a proof. Every other read proves it implicitly by needing
  a token; a command answering from cache has no such gate, so without this an operator whose
  session died (or a window that never signed in) could still read a populated tenant's data. **A
  client factory call is not a proof**: `graph_for` / `exchange_for` / `arm_for` / `keyvault_for`
  only build token adapters, and no token is fetched until a request is sent. Reads through the
  index accessors (`sp_index_cached` / `app_name_index_cached` / `indexes_cached` / `*_hit` /
  `search_corpus` / `load_gallery_corpus`) count as cache reads. Pinned by
  `repo_invariants::cache::a_command_answering_from_cache_alone_checks_the_session` (and
  `every_index_accessor_counts_as_a_cache_read`).
- **Never pin a per-object key.** Pinning is for the handful of entries that cost a full directory
  scan to rebuild (the two indexes, the search corpus, the App Registrations / Enterprise Apps /
  Managed Identities lists and the credential-expiry roll-up). A pinned per-app entry can never be
  evicted, so a large tenant's thousands of `app_detail|…` writes would grow the bucket without
  bound. Pinned by `repo_invariants::cache::pinned_cache_writes_stay_on_the_tenant_wide_indexes`
  against its `PINNABLE_KEYS` list; a guarded `put_*index_if_current(watch, …)` names no key, so
  the rule reads the key off that watch's `generation_for` capture — or, for a store helper that
  takes the watch as a parameter (`sp_index_store_if_current`), off every caller's capture, which
  must all be on one pinnable key.
- **Bound bulk seeding by `capacity_for`.** Seeding a whole scan into a bucket must respect its
  capacity, or the seed evicts everything else the bucket holds — including entries the same run is
  about to read back.

## Two tenant-wide indexes, and every surface joins against them

There are exactly **two** cached tenant-wide directory enumerations, and no surface may run its own:

| Index | Key | Fetched by | Projection |
|---|---|---|---|
| Service principals | `sp_index_key` → `"{tenant}\|sp_index"` | `list_service_principals_index` | `id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,createdDateTime,alternativeNames` |
| App registrations | `app_name_index_key` → `"{tenant}\|app_name_index"` | `list_application_index_named`, or seeded (stripped to `id,appId,displayName`) by the App Registrations scan | `id,appId,displayName` |

Readers: both entity lists, global search, the security audit, the consent audit, the DR backup, the
managed-identity list, and the mailbox probe. A tab switch, a search keystroke, or a backup run right
after browsing reuses one directory scan rather than re-enumerating.

Both go through their accessor pairs in `commands/applications/cache.rs` — `sp_index_hit` /
`sp_index_store` / `sp_index_cached` and `app_name_index_hit` / `app_name_index_store` /
`app_name_index_cached` — never `cache.get`. Both are stored via `put_typed_index`, so they are
**typed** (a hit is a refcount clone, not a walk of a 10 000-entry JSON tree) and **pinned** (the
thousands of per-app `app_detail|…` / `mail_scopes|…` writes sharing their bucket can't evict an
entry that costs a full directory scan to rebuild). **Footgun:** a typed entry read untyped reads as
a *miss*, silently costing a tenant-wide rescan — pinned by a test per index.

`indexes_cached(state, client, tenant)` returns both, fetching only the cold ones and, when both are
cold, fetching them **concurrently**. Use it wherever a surface joins the two (the Enterprise Apps
pairing join, the DR backup estate). `global_search` deliberately does *not*: it runs the two
accessors under a non-short-circuiting `join` so one unreadable index degrades only its own half of
the corpus instead of blanking the results.

Both are bounded at `APPS_MAX` / `SP_INDEX_MAX` (both 10 000). Those caps must not drift — a surface
enumerating deeper than another silently knows about principals the other does not. `APPS_MAX` is
defined once, in `azapptoolkit_dto::applications`, so the App Registrations list's cap notice in the
frontend reads the same constant as the backend's enumerations; the SP-index lists learn
`SP_INDEX_MAX` at runtime from `get_directory_index_status` (`DirectoryIndexStatus`, also in the
dto crate).

### One `/applications` list scan

`scan_app_list` (in `commands/applications/mod.rs`) pages `/applications` once with the list-row
`$select`, a strict superset of the other two projections, and feeds three caches from it:
`apps_pairing` (the App Registrations rows), `credential_expirations` (the credential-expiry
roll-up) and `app_name_index` (stripped to `id,appId,displayName`, so no credential array is pinned
into an index six surfaces hold an `Arc` to). Readers go through `apps_pairing_cached` /
`credential_expirations_cached` / `app_name_index_cached`, all behind one single-flight gate,
`app_scan_gate`, keyed on `apps_pairing_key`. Each store has its own per-key watch captured before
the scan, so a credential write landing mid-scan refuses the two credential-bearing stores and
leaves the name index. The SP side of the pairing join goes through `sp_index_cached`, never the
client directly.

- **Lock order is scan gate → SP gate.** `scan_app_list` must never call `app_name_index_cached` or
  `indexes_cached`: both take the scan gate, and tokio's `Mutex` is not re-entrant.
- The audit (`$expand=owners`) and the bulk expired-credential sweep are the only other
  `list_applications_all` callers, pinned by `repo_invariants::the_full_application_list_scan_has_one_home`.
- A cold Home launch used to run three concurrent scans (the App Registrations, Enterprise Apps and
  Credential health cards): 3 × ceil(N/999) serial round trips, 18 → 6 at 5,000 apps. If the
  Enterprise card wins the gate it runs its lean scan and the list scan follows serially.
- Tradeoff: a cold standalone Credential Expiry visit now also reads the SP index (gated,
  concurrent with the app scan, and shared with every other reader).

### Every pinned entry is typed

All eight pinned keys (the two indexes, the search and gallery corpora, the App Registrations /
Enterprise Apps / Managed Identities lists and the credential-expiry roll-up) are stored with
`put_typed_index_if_current` (the gallery: `put_typed_index`). `Cache` has no untyped pinned store left. A warm list visit is then a refcount
clone of the cached `Arc<Vec<Row>>`, not a walk of the JSON tree back into thousands of rows; the
list commands return that `Arc` (`Result<Arc<Vec<Row>>, UiError>`), which serde writes exactly as
the `Vec` the binding decodes (`repo_invariants/ipc.rs` treats `Arc<T>` as `T` on the backend side).
The list rows and roll-up are read through `apps_pairing_hit` / `credential_expirations_hit` (under
`apps_pairing_cached` / `credential_expirations_cached`); the Enterprise Apps and Managed Identities
commands read their key with `get_typed` directly.

**Footgun:** an untyped `cache.get` on a typed entry *misses* (its JSON body is `Null`), silently
costing the full rescan the pin exists to avoid. Pinned by
`repo_invariants::cache::pinned_keys_are_read_only_through_get_typed`: no untyped pinned write
remains, no untyped `get` names a pinnable key builder (inline or through a `let key = …`), and every
pinnable key has a typed reader.

### Cached scan reads are `async` commands

`get_cached_audit`, `get_cached_audit_summary`, `get_cached_site_sweep`, `get_app_site_access` and
`get_cached_key_vault_access` answer from the `CacheKind::Audit` bucket alone. They used to be sync
`fn`s, which Tauri runs on the main thread: hydrating the Security tab copied and serialized up to
10 000 scored items with the window frozen, and every per-app site panel decoded the whole tenant
sweep from JSON there. They are now `async fn … -> Result<Option<_>, UiError>`, keeping the session
proof as `let Some(_) = state.auth.tenant_context(&tenant_id) else { return Ok(None) }` (no session
still reads as "nothing cached"). The two sweep readers return the cached `Arc`; `get_cached_audit`
still copies the items once, because `AuditRunResult` is a wire DTO that owns them. The frontend
binds them with `invoke_result` and folds an `Err` into `None`. Pinned by
`repo_invariants::cache::cached_scan_reads_are_async_commands`.

### TTL sweeps have slack

`Bucket::evict_if_needed` sweeps expired entries only once the oldest is past `ttl + ttl/8`
(`Bucket::sweep_after`). Without the slack, writes streaming across an expiry front swept on every
`put` (the next-oldest entry expired a moment after each sweep): O(n) per write under the bucket
mutex. A sweep now leaves nothing older than the TTL, so sweeps are at most one per `ttl/8`.
Correctness rides on `Cache::lookup`, which enforces the exact TTL on every read, so an entry the
sweep has not reached yet is never served. The slack applies only below the cap: a `put` that
takes a bucket over its cap sweeps at the **exact** TTL before LRU picks a victim, so an entry that
is expired but inside the slack never pushes out a live one. That at-cap sweep is rate-limited to
one per `Bucket::at_cap_sweep_interval` (`ttl/64`, at least 5 ms), otherwise a full bucket on an
expiry front swept on every `put` again; inside the gap the put falls through to plain LRU. The LRU index is pruned in place
(`prune_lru`) rather than rebuilt by cloning every key.

## Filtering happens in the frontend, on lean rows

The per-list filter boxes never reach the backend at all: each list loads once, then
search/date/facet filtering runs in memory through layered frontend memos (the `Loaded*` components
in `web-rs/src/views/`).

App Registration rows cross IPC as **lean pre-classified scalars** (`ApplicationListRowDto` carries
credential status/counts/soonest-expiry computed by `list_applications_with_pairing`, never the
credential arrays) — don't re-fatten the list row; the detail pane re-fetches the full
`Application`.

## `global_search` semantics

`global_search` does **substring** matching ("contains anywhere" on display name / appId / object
id) by filtering the tenant's search corpus in memory — Graph OData has no `contains()` for directory
objects, only `startswith` / token-based `$search`. A full-GUID query still takes the exact-lookup
fast path.

The corpus is a **pre-lowercased, typed-cached** index under
`search_corpus_key(tenant_id)` → `"{tenant_id}|search_corpus"`, built once from the two shared
indexes above (app registrations without a paired SP appear only in `app_name_index`) and stored via
`Cache::put_typed`. A debounced keystroke reads it
back with `Cache::get_typed` — a refcount clone of `Arc<Vec<SearchRow>>`, **no per-query deserialize
of the full SP/Application models and no per-query re-lowercasing** (`SearchRow` carries the
lowercased forms). `put_typed`/`get_typed` keep the original `Arc<T>` alongside a `Null` JSON value,
so the entry is read **only** via `get_typed` (an untyped `get::<T>` on it misses) but is still TTL-
bound and swept by tenant invalidation like any other. The corpus is derived from those two indexes,
so `invalidate_app_lists` busts it too; a credential-only mutation keeps all three (it changes none
of them).

The corpus build carries the same two guards its source indexes do, for the same reasons:

- **Single-flight** on `search_corpus_key`. A cold corpus is reached from the *keystroke* path —
  the debounce fires per burst, a re-run of the front-end resource does not cancel the command
  already in flight, and the focus prewarm below races the first query — so without a gate each
  one rebuilt the corpus and raced to overwrite the same pinned key.
- **`put_typed_index_if_current`**, with the generation captured *before* the index fetch. Both
  indexes already refuse to store a snapshot older than a mutation that landed mid-flight; the
  corpus is derived from them, so an unconditional store re-pinned a pre-mutation corpus for the
  full `Lists` TTL — a deleted app stayed searchable for an hour while the indexes were correct.

**`prefetch_search_corpus`** warms it off the keystroke path. The corpus is `Lists`-TTL'd (60 min)
and dropped by every `invalidate_app_lists`, so the first query after an idle hour or any app
mutation paid for two full directory scans *while the operator waited* — the top bar appeared to
hang. `GlobalSearch` fires this on focus (click or Cmd/Ctrl-K), so the rebuild overlaps typing.
Best-effort and idempotent, mirroring `prefetch_application_gallery`: warm returns immediately,
cold builds exactly once behind the gate, and a failed index degrades to a partial corpus rather
than an error.

## Gallery search — fetch the corpus once, match every keystroke locally

`search_application_templates` (the New-application → "Browse the gallery" picker) matches over a
**cached whole-gallery corpus**, like `global_search` — not a per-query server filter. The gallery
is a **static, tenant-independent catalog** (tens of thousands of rows) that no mutation in this app
can change, so one fetch backs every keystroke.

The earlier design sent the match server-side (`$filter=(contains(tolower(displayName),'t') or
contains(tolower(publisher),'t'))` AND-joined per token, plus `$count=true`). It was correct but
**slow**: `contains(tolower(…))` is non-indexable, so every uncached query was a full-catalog scan,
and each debounced keystroke (`"sa"`→`"sal"`→`"sale"`…) was a distinct cache key → its own
multi-second round trip. `GraphClient::search_application_templates` implemented that older design;
it has been **deleted** (it had no callers left — the command of the same name ranks against the
cached corpus instead).

The fast path, in two pieces:

- **`GraphClient::list_all_application_templates`** pulls the entire catalog **unfiltered** in a
  handful of round trips. Unfiltered, the endpoint honours `Prefer: odata.maxpagesize=2800` (its
  documented ceiling; a *filtered* read is capped at **200/page**, which is exactly why the old
  per-query path couldn't page cheaply), so ~tens-of-thousands of rows arrive in ≈`ceil(total/2800)`
  pages that `collect_all_pages` walks to the end. `$select` trims each row to the picker's fields.
  The `Prefer` header rides a new `prefer` arg on the transport's `send_core_url_with`; the page
  size carries into `@odata.nextLink`, so only the first request sets it.
- **`load_gallery_corpus`** caches the pre-lowercased `Arc<Vec<GalleryRow>>` under
  `gallery_corpus_key(tenant_id)` → `"{tenant_id}|gallery_corpus"` (`CacheKind::Lists`, 60-min TTL,
  stored via the `dyn Any` typed cache — no `Serialize` needed). Lowercasing happens once per corpus
  load, not per search. Tenant-scoped by the universal `{tenant_id}|` convention (so the sign-out
  prefix sweep collects it) even though the catalog is global; nothing else invalidates it, and the
  LRU bounds it to one entry per tenant.

`prefetch_application_gallery` warms that cache; the picker fires it on dialog-open (fire-and-forget)
so the one-time fetch overlaps the operator typing and their first real query is warm.

Each query then runs `rank_gallery` over the corpus **in memory** (exact → name prefix →
word-boundary → substring → publisher-only; *whether* a row matches is per-token **AND** across
name/publisher, so "office 365" doesn't drag in every "365" app while "teams microsoft" still finds
Microsoft Teams) and caps display at `GALLERY_TOP`. Because the corpus is the whole catalog,
`total_matches`/`truncated` are **exact** — "showing the closest 50 of N" is honest without a
`$count` round trip, and there is no partial-catalog state (a short fetch is an `Err`, not a partial
`Ok`).

One asymmetry worth keeping: **a failed corpus fetch propagates as an error**, unlike `search_corpus`,
which degrades to an empty corpus. An empty result set here is a *claim that no such app exists* — a
lie the operator can't distinguish from a broken fetch, which is the bug class this whole path exists
to avoid. (The demo's mock keeps its args-aware `gallery_search_for` match over the sample catalog.)

## Invalidation — only on `Ok`

After a successful mutation, bust the relevant list cache (`invalidate_app_lists(...)`); never on
the error path, so a failed write doesn't clear fresh data.

`invalidate_app_lists` drops every tenant key derived from the app/SP set: `apps_pairing_key`,
`enterprise_key`, `sp_index_key`, `app_name_index_key`, `search_corpus_key`, `mi_key` (the
managed-identity list, now a filtered projection of the SP index), `credential_expirations_key` (a
create/delete changes the app set it scans) and `invalidate_app_role_resources` (the Grant-access
picker's "Tenant app registrations" directory — a create/delete adds or removes an SP that may
expose roles), plus — transitively — the per-app detail cache (`invalidate_app_details`) and the
cached audit run (`invalidate_audit_cache`). The transitive two matter: a scope grant or credential
change re-scores the app, so the audit/posture tile must refetch too. Two reviews independently
mis-read this as a missing invalidation because earlier versions of this doc listed only the four
list keys, and the list drifted twice more after that; it is now pinned both ways
(`repo_invariants::the_list_tier_doc_names_every_key_invalidate_app_lists_drops` checks this
paragraph names every key the function drops, and
`invalidate_app_lists_drops_every_app_set_key_and_nothing_else` checks the runtime behaviour). Any
mutation that can add/remove/rename a service principal or app registration
(`grant_exchange_mailbox_access`, `bulk_restore_deleted`) must call it, or a stale pairing/search
index survives until the TTL. A create, delete or rename that holds the changed object takes the
patch tier instead (below).

**The recycle bin is the deliberate non-cache.** `list_recently_deleted` reads
`/directory/deletedItems/microsoft.graph.application` live on every dialog open and keeps nothing:
entries expire on their own (~30 days), a restore or purge changes what the *next* read must show,
and a cached stale bin would invite restoring the wrong thing. `bulk_restore_deleted` is a
set-changing mutation — restored apps rejoin the live set, so it calls `invalidate_app_lists` once
after any successful restore (pairing joins and the app list must re-read); a purge removes only
recycle-bin entries, touches no cached key, and busts nothing.

**Credential-only mutations are tiered.** `add_password`, `remove_password`, the certificate
add/remove pair, `generate_self_signed_certificate`, `remove_expired_passwords`,
`remediate_remove_expired_credentials` and the bulk `bulk_remove_expired_credentials` sweep (once
per mutated app) change a single app's secrets/certs — which surfaces in the App Registrations list row (its credential-status
badge), that app's detail payload, and the audit (expiring-credential findings), but **cannot** add,
remove, or rename a service principal or app registration. They call
`invalidate_app_credentials(cache, tenant, object_id)` instead of `invalidate_app_lists`: it drops
apps-pairing, the *one* app's detail, the credential-expiry list and the audit run, and deliberately **keeps** `sp_index`,
`app_name_index`, the enterprise list, and the mailbox-scope verdicts. Keeping the two tenant-wide
indexes is the point — dropping them would force the next list visit to re-enumerate every app and
every service principal (tens of seconds on a large tenant) for a change that touched neither.

**Set changes with the object in hand take the patch tier.** A create, delete or rename used to
call `invalidate_app_lists`, so the list reload that followed re-paged every `/applications` and
`/servicePrincipals` page: tens of seconds on a large tenant, for one row. Each of these writes
already knows what changed. The create POST (and `instantiate`) returns the new `Application` and
`ServicePrincipal`, a delete knows its object ids, and a rename knows its fields. So
`record_created_apps`, `record_deleted_apps` and `record_renamed_app` (`applications/cache.rs`)
rewrite the four scanned entries (`apps_pairing`, `app_name_index`, `credential_expirations`,
`sp_index`) in place through `Cache::patch_typed_index`. Everything else the list tier drops goes
through `invalidate_app_list_projections`; those entries rebuild from the patched indexes without a
Graph scan. `patch_tier_tests::the_projections_are_what_the_list_tier_drops_besides_the_scanned_entries`
pins the two sets together. The callers are the single and bulk create, the SAML/OIDC wizards, the
gallery create, the single and bulk delete, and `update_application` when the name or audience
changed (description or notes alone take `invalidate_app_details`). The rules:

- Only a clean `Ok` takes the patch tier. A step that failed after the first write (a partial
  create, a failed or lost bulk DELETE, a failed SSO configure step) may still have landed, and
  nothing in hand describes it, so it calls `invalidate_app_lists`.
- A patch that can't apply drops its key, so the worst case is the old cost. That covers a cold or
  expired key, a list at `APPS_MAX` / `SP_INDEX_MAX` (a truncated scan, where only a rescan knows
  which rows belong), and a delete whose `appId` no cached app entry can resolve (only `sp_index`
  drops). The credential roll-up has one row per credential and cannot see the app cap itself, so
  it follows the app list's verdict: whenever `apps_pairing` is not patched (at the cap, or cold or
  expired), the roll-up drops too, and the same rescan rebuilds both
  (`a_list_at_the_cap_is_dropped_not_patched`).
- The "invalidate only on `Ok`" rule covers these call sites by construction:
  `repo_invariants/cache.rs::invalidators` derives the set of invalidating helpers from the source
  (every non-command fn under `commands/` that calls a cache mutator, or another such helper, to a
  fixpoint), with the six tiered names as a floor it may never lose. A hand-kept list had left the
  patch tier and six `invalidate_*` helpers unscanned.
- A delete also removes the app's SP from `sp_index`, because Graph deletes an app's service
  principal in its home tenant along with it. A rename leaves `sp_index` alone: Graph syncs an SP's
  `displayName` from its app only eventually, so the Enterprise Apps row keeps what Graph returns
  until the TTL or a Refresh.
- A created SP is projected through `azapptoolkit_graph::client::sp_index_row` and a created app
  through `app_name_index_row`, so a patched row matches a scanned one. An added secret's
  `secret_text` is cleared before it reaches any row.
- Patches are idempotent (upsert, remove or set by id). The cache re-applies a patch that lost a
  race, and a scan that started after the write already contains it.

**Detail-affecting mutations that cannot change the set take `invalidate_app_detail_state`**
(= `invalidate_app_details` + `invalidate_audit_cache`): grant/revoke/scope a permission
(`permissions.rs`, the Exchange and SharePoint scoping cores), owners (`owners.rs`), authentication
settings (`authentication.rs`) and remediations (`remediation.rs`, `bulk.rs`). They change
detail-visible and audit-relevant state but add, remove or rename nothing, so the list tier stays
valid. Calling the one function instead of its two halves means a call site can't drop one of them.

**In-place PATCHes of one app take the detail tier.** SSO URLs (`set_saml_urls`), OIDC redirect
URIs (`set_oidc_redirect_uris`), the claims mapping (`set_claims_mapping`), and the exposed
roles/scopes (`app_roles.rs`, `expose_api.rs`) change one app or SP in place — they add, remove or
rename nothing, so nothing in the list tier changes — and call `invalidate_app_details` (the
can't-miss cheap sweep of the per-app payloads). `repo_invariants::an_in_place_write_never_busts_the_list_tier`
pins both tiers lexically: a command body with an in-place mutation call and no set-changing call
must not name `invalidate_app_lists`.

**The app-role resource directory has two busts.** `list_app_role_resources` (the Grant-access
picker's "Tenant app registrations" group) caches which tenant SPs expose ≥1 enabled Application
role. `invalidate_app_lists` drops it (a create/delete changes the set), and the App roles tab's
writers call `invalidate_app_role_resources` directly — the first Application role added, or the
last one disabled or removed, moves an SP in or out of the directory (pinned by
`an_exposed_app_role_write_refreshes_the_role_resource_directory`).

### The other half: a scan that raced an invalidation must not be stored

Invalidating on `Ok` only works if the reader on the other side of the race respects it. A
tenant-wide scan takes seconds under no lock, so a mutation routinely lands *during* one: the
mutation drops the key, and the scan then stores the snapshot it fetched **before** the change. For
a pinned entry that is not a stale read that ages out in seconds — LRU cannot evict it, so the list
shows a deleted app (or misses a new one) until the 60-minute TTL.

So every pinned index built from a live scan captures `cache.generation_for(kind, key)` **before**
the fetch and stores through `put_typed_index_if_current` (the only pinned guarded store; the
untyped `put_index` / `put_index_if_current` were removed once every pinned entry was typed), which drop a
snapshot whose key was invalidated in between. The counters are per **key**, so a credential-only
mutation — which drops `apps_pairing` and a per-app detail precisely in order to PRESERVE the
tenant-wide indexes — cannot make a valid index store refuse.

`generation_for` returns an owned `IndexWatch` guard rather than a bare counter, and the guard
releases its watch on `Drop`. That is what covers the paths that never reach a store: a failed
fetch, a cancelled task, a sibling future losing a `try_join`. Releasing only on a successful store
leaked one entry per failed scan, and because the watch table is capped and leaked entries were
never reclaimed, enough failures made `generation_for` unable to register at all — at which point
**every** pinned-index store refuses for the life of the process, degrading every tenant-wide read
to a full rescan with no error, no log at the point of failure, and no recovery short of a restart.
`repo_invariants::generation_for_hands_out_an_owned_guard_not_a_bare_counter` pins the shape, and
`a_watch_is_captured_before_the_fetch_it_guards_not_after` pins the ordering — a capture placed
after the fetch is textually identical to a correct one and silently empties the window being
checked, which is how two production sites drifted. The caller still returns its rows; only the *caching* is skipped, costing one
re-fetch. `repo_invariants::pinned_index_writes_are_guarded_except_the_static_gallery_corpus` pins
this — the sole exemption is the application gallery corpus, a static tenant-independent catalog no
mutation here can invalidate.

**A patch is a write the guard must see too.** `Cache::patch_typed_index` bumps the key's watches
before it reads, as `invalidate` does, so a scan that captured its watch before the write refuses
its pre-write snapshot. It computes the patch outside the bucket lock and swaps only if the entry is
still the allocation it read (pointer identity), re-applying the patch up to three times when
another writer got there first. The swap keeps the entry's `inserted`, so a patch never extends the
TTL of the scan it patched. It also keeps the `stamp`, so a rollback aimed at the store the patch
built on still removes it.

Two shapes of this bug are worth naming, because both hid behind a guard that looked present:

- `sp_index_store` / `app_name_index_store` pass a generation captured *after* the fetch, which
  makes the guard a no-op. They are `#[cfg(test)]` for exactly that reason — production callers
  cannot reach them, so the "capture it before the fetch" rule cannot be forgotten, only obeyed.
- The three list caches (App Registrations pairing, Enterprise Apps, Managed Identities) stored
  unconditionally, as did the search corpus — while the two indexes they are built from were
  already guarded. The indexes correctly refused their stale snapshots and the derived caches then
  re-pinned them anyway. The credential-expiry roll-up was the last one: stored with a plain
  `put`, it was both unguarded and unpinned, although the `put_index` doc named it as pinned. It is
  now a guarded, pinned store in the shared App Registrations scan.

**Long scans store through the guard too — unpinned.** The same race applies to every result a
scan takes seconds to minutes to produce, pinned or not: the audit run (`audit_cache_key`), the
site sweep (`sweep_cache_key`), the Key Vault sweep (`kv_sweep_cache_key`), the SSO certificate
board (`sso_certificate_expirations_key`), the Grant-access picker's app-role resource directory
(`app_role_resources_key`), the per-app detail fan-out (`app_detail_key`) and the per-app
mailbox-scope verdicts (`mail_scopes_key`, all three discriminators). Each used to store with a plain `put`/`put_typed` after its last
await, so a remediation, grant, scope change or sign-out's `invalidate_tenant` that landed
mid-scan was undone, and the pre-mutation result (a stale all-clear, a stale org-wide verdict)
served for the TTL. LRU is no safety net for an unpinned entry: nothing promises an eviction
before the TTL does.

So each captures `generation_for(kind, &key)` before the function's **first** await (right after
its `claim()` where it has a `CancelToken`, otherwise right after the cache miss) and stores through
`put_if_current` / `put_typed_if_current`, the unpinned twins of the index forms; they share
`store_if_current`, so they refuse on the same exact-key, prefix and tenant invalidations. A
per-object key (`mail_scopes|…`) is watched per key and **never** pinned. The watch table stays
small: the per-app probes are bounded by the audit's fan-out cap (8) plus the open Permissions
tabs, and a full table only makes the store refuse, which costs one re-probe. A guarded store
returns `true` only when something was actually written: a store the cache declined (caching
disabled, a serialization failure) returns `false`.

The watch cannot cover an input read *before* it. The audit reads the org-wide Entra mail grants
once at run start (`orgwide_mail_by_sp`), and each app's mailbox verdict is reconciled against
that snapshot. A strip landing after the run start but before that app's probe drops the key
before the probe's watch exists, so the watch stays clean. The audit verdict's key therefore
carries the snapshot it was reconciled against (`audit_mail_scopes_key`:
`audit|{app}|{perms}|orgwide:{held}`, where `held` is `perms` ∩ the org-wide set). A verdict built
from a stale snapshot lands under a key that a run reading the live set never looks up.

`repo_invariants::long_scan_results_store_through_the_guard` pins this: a function that builds
one of these keys may write only through the unpinned guarded forms (no plain, no pinned write),
and a function with an unpinned guarded store captures its watch before its first `.await`.
Fixture modules mounted by `#[cfg(test)] mod …;` are skipped, because they seed these keys directly.
The key set is a short list plus every key a command already watches for an unpinned guarded
store, and each listed key must still have such a store. `the_audit_run_is_cached_only_behind_run_is_cacheable`
follows the audit write through its watch binding.

Sign-out also **stops** the read sweeps. `AppState::forget_tenant` calls `cancel()` on the audit,
site-sweep, Key Vault sweep, mailbox-probe and backup flags. Their guarded stores would refuse
anyway once `invalidate_tenant` bumps their watches, but left running they keep issuing
requests against a purged session for minutes. It lives in `forget_tenant` rather than
`sign_out`, so `sign_in` (a different operator on the same tenant) stops the previous account's
scans too. That cancel is harmless when nothing is running, and `reauthenticate` never reaches
it. The write runs (`bulk_cancel`, `migration_cancel`, `restore_cancel`) are not cancelled: once
the tokens are purged, each stops at its dead-session latch. Pinned by
`repo_invariants::sign_out_stops_every_read_sweep`, which derives the flags from `AppState`.

The general rule for multi-step mutations: **a partial success is a real write — invalidate,
gated on "something actually changed."** Audit remediations, `remove_exchange_mailbox_access`,
`downgrade_application_permission`, `create_application`, `grant_single_permission`,
`grant_admin_consent` (and their bulk and DR-restore callers), the `bulk_*` commands, and the SSO
create flows all follow it
(see [audit-findings-and-remediation.md](./audit-findings-and-remediation.md#audit-remediations-one-click-fix) for the remediation case).
A core that can fail after its first write returns the landed-write flags plus an
`Option<UiError>` (`downgrade_application_permission_core`, `create_application_core`, the grant
cores' `GrantRun`); the command busts on those flags and only then returns the error. A failure
before the first write stays a plain `Err` — nothing landed, so nothing is invalidated. One
deliberate carve-out: the AAP migration busts on *any* real run that reached `migrate_one`
(`migration_should_invalidate`), even when that app's `Err` came before its first write. Its
writes span Exchange and Entra across many steps, threading landed-write flags through each would
cost more than the one extra re-read an over-invalidation costs, and under-invalidating shows a
stale scope verdict for the cache TTL.

## `CacheKind::ServicePrincipal` self-invalidates in the graph client

The per-app SP cache is keyed by **`appId`**, but the SP mutators take an SP **object** id — a
targeted single-key bust isn't possible without an extra lookup. So this kind invalidates in the
graph client, **not** via the command-side aggregators: `delete_service_principal`,
`patch_service_principal`, and `set_service_principal_tags` call a private tenant-prefix sweep
(`invalidate_sp_cache`) on `Ok` — the can't-miss option. `set_service_principal_app_roles` rides
this via `patch_service_principal`. `delete_application` and `restore_deleted_item` sweep too
(`invalidate_principal_caches`: the SP objects, the resource-SP definitions and the grant matrices):
Graph deletes an app's home-tenant SP with it, and `restore_deleted_item` also restores service
principals (the bulk restore brings the paired SP back with a second call); without the sweep the
Security tab kept a deleted SP's application permissions live for the TTL. `graph_client_sp_mutators_sweep_the_sp_cache` pins every
DELETE/PATCH of a service-principal object, every app DELETE and every restore to one of the two
sweeps. **`invalidate_app_lists` does not touch this kind** — don't rely on it for SP-field
freshness.

The read-throughs are watched. `invalidate_prefix` bumps only the watches it finds, so a lookup
that was in flight when a sweep landed used to store the pre-sweep object for the TTL — the two
per-appId SP lookups, `resolve_resource_sp`, both grant matrices, the sign-in activity reads and
the app-management policies. Each now captures `generation_for(kind, &key)` before its fetch and
stores through `put_if_current`; `graph_client_read_throughs_store_through_a_watch` pins that no
Graph client function `cache.put`s after an await, with the batch prewarm (`prewarm_sps`, which
`prewarm_resource_sps` delegates to) as the named exception: a watch per id would overflow
`MAX_WATCHES`, and it is a best-effort warm-up a later sweep or the TTL corrects. (The audit's bulk
lean-SP path is `seed_lean_sps_from_index`, a synchronous put from the already-fetched index.)

Related: `ensure_service_principal` returns `(ServicePrincipal, bool)` where the bool is
**created**. First-grant paths (`grant_single_permission`, `grant_admin_consent[_core]`, the bulk
grant) call `invalidate_app_lists` only when an SP was newly created; otherwise the cheaper
detail + audit bust suffices. `GrantRun.sp_created` survives a later failure in the same run, so
an SP created just before a refused grant still busts the list tier. `grant_exchange_mailbox_access`
does the same when `apply_exchange_mailbox_scope` refuses after its SP was created (the core busts
the list tier itself on success).

## Batched Graph fan-out + the adaptive throttle

Large per-object fan-outs (the security audit, DR backup) ride two shared pieces — reuse them for
any new heavy fan-out; don't hand-roll a second tracker or a raw per-item loop:

- **Graph JSON batching** — `client.batch_get_json[_with_headers]`
  (`graph/src/client/batch.rs`): 20 GETs per POST, results returned in input order, inner-429
  and 5xx sub-requests re-batched on the shared `RetryBudget` (the same policy the GET would get
  sent alone; only a 429 notifies the throttle observer). Advanced queries inside a batch (e.g. `memberOf` `$count`) need the
  **per-sub-request** header form — the outer POST's headers don't reach sub-requests.
  Whole-batch failures must degrade to per-object reads through `dispatch::batch_or_serial`,
  never fail the run.
- **`ConcurrencyThrottle`** (`commands/throttle.rs`) — wired as the client's `ThrottleObserver`
  and fed to `dispatch_capped` as `|| meter.limit()`, so the in-flight cap halves on
  429 and recovers when quiet. Wire it through `FanOutMeter::attach(client, cap)` (the audit, the
  bulk fan-outs, the site sweep and the DR backup), which owns the tracker, a completion counter
  (`meter.ticker().tick()` → `(done, cap)`) and the `ThrottleGuard` RAII; nothing outside
  `throttle.rs` calls `ThrottleGuard::attach` (pinned by
  `repo_invariants::fanout::the_throttle_observer_is_attached_only_through_fan_out_meter`). The
  guard detaches on drop, so an early `?` can't leave a stale observer
  halving the shared per-tenant client's cap, and a finishing fan-out detaches only its own tracker
  (the slot is single: a concurrent attach displaces the earlier run, which then runs at a fixed
  cap — logged). The halve window is anchored on the last *halving*, not the last 429, so a
  sustained storm keeps degrading toward the floor instead of holding at half.

### `$count`/`$orderby` belong to `$search` alone

Entra's advanced query capabilities (`ConsistencyLevel: eventual` + `$count=true`) are what make
`$search` and some `$filter` forms work — but they do **not** compose with `$expand`. An advanced
query carrying `$expand` fails *silently*: Graph returns 200 with the expanded property missing
rather than an error, so the caller reads an empty collection and concludes the object has no
related entities. Keep `$count`/`$orderby` on the `$search` paths that need them, and never add them
to a request that expands.

Every paging helper (`collect_all_pages`, `collect_all_pages_capped`, `finish_paged_batch`) takes
the consistency flag page 1 was issued with — there is no default. Graph does not carry
`ConsistencyLevel` into the `nextLink` request, so an advanced query (the SP index, the `memberOf`
casts) restates it on every continuation, and a plain read never adds it: page 2 of an `$expand`
scan would lose the expansion, and page 2 of any other plain read would come from the
eventually-consistent index while page 1 came from the directory. The scoped helpers
(`collect_pages_from`, `collect_pages_from_capped`) take a fetch closure instead of a consistency flag,
origin-check each nextLink before the scoped bearer is attached, and share the one `client::MAX_PAGES`
page cap with the rest.

## Page size is a wall-clock divisor, not a tuning knob

Paging is strictly **serial** — each request needs the prior response's `@odata.nextLink` — so the
`$top` on a paged read divides its round-trip count directly. Graph's default is **100**, so an
omitted `$top` is a 10× round-trip multiplier on any collection that pages.

Every paged read in `azapptoolkit-graph` therefore sends `client::MAX_PAGE_SIZE` (999), the
documented maximum for these directory collections; `/applications` enumerations use the equivalent
public `DEFAULT_APP_PAGE_SIZE`. Asking above an endpoint's real cap is harmless (Graph clamps
silently), and per-endpoint caps are **not reliably documented** — `list_service_principals_index`
logs its effective first-page size for exactly that reason. Batched sub-requests carry it too, so a
`$batch` sub-response rarely overflows into `finish_paged_batch`'s serial continuation.

The rule is pinned by `repo_invariants/fanout.rs::every_paged_graph_read_sends_a_page_size`: every
function in `graph/src/client/` that calls a paging helper must send `$top` (as a query pair or
inline, `MAX_PAGE_SIZE` / `DEFAULT_APP_PAGE_SIZE`) or, where an endpoint's `$top` ceiling is too
low, `Prefer: odata.maxpagesize` (the application gallery, 2800 a page). Two exemptions are
justified in its table: `list_applications_all` (page 1 is `list_applications`, which sends
`DEFAULT_APP_PAGE_SIZE`) and `list_federated_credentials` (Graph caps them at 20 per app). A stale
exemption fails the rule.

The read that dominates is `appRoleAssignedTo` **on the Microsoft Graph service principal**: it holds
every application-permission grant in the tenant, and both the security audit
(`prefetch_graph_app_roles`) and the consent view walk it end-to-end *before* they can score
anything. Those two — and only those two — read it through the Permissions-kind read-through
`list_app_role_assigned_to_cached` (`{tenant}|grants:assigned_to:{sp}`), swept by every grant
mutator in the client (`invalidate_grant_cache`). A grant changed outside the app (the portal) can
lag there by up to the Permissions TTL, the same contract as `grants:oauth2_all`; the Cache dialog's
Permissions clear resets it. Every other `appRoleAssignedTo` reader — the Enterprise Access tab, the
permission tester, the audit's EWS full-access check, the DR backup's per-SP fallback — calls the
live `list_app_role_assigned_to`, so its reload or re-run always sees portal-side changes.
`appRoleAssignments` (what one SP holds) is deliberately **uncached**: it is per-SP and small, and
the pre-write `existing` checks read it, so it must be live.

The write fan-outs (bulk delete / grant / remove-expired, DR backup writes) **can't `$batch`** —
Graph batches GETs — so their win is bounded concurrency + adaptive 429 backoff, not round-trip
collapse. They emit the live cap in `BulkProgress.in_flight_cap` (additive `Option`; the DR view
shows it plus a back-off notice).

## The site-sweep cache invalidates on site-permission mutations

The Resource Access reverse-lookup caches a **complete** site sweep under `{tenant}|site_sweep`
(`CacheKind::Audit`, audit TTL). That key is *not* part of `invalidate_app_lists` /
`invalidate_audit_cache` (it is a different Audit-kind key), so the per-site permission mutations
bust it directly: `grant_site_access`, `remove_site_permission`, and
`convert_site_access_to_selected` all call `invalidate_site_sweep` on success. Without that, the
sweep — a security-posture surface — could show a revoked grant as still present (or miss a new
one) for up to the audit TTL.

The **Key Vault RBAC** reverse-lookup caches its completed sweep under `{tenant}|keyvault_sweep`
(same `CacheKind::Audit` + TTL). The sweep itself is a **read-only** view of ARM role assignments,
but the app's own `assign_managed_identity_azure_role` (the Managed Identities pane) can change the
answer, so it calls `invalidate_kv_sweep` on `Ok` — **unconditionally**, not only for a
`/providers/Microsoft.KeyVault/vaults/` scope, because a resource-group or subscription-level grant
reaches every vault beneath it and the sweep keeps the assignment's own scope (pinned by
`an_azure_role_assignment_busts_the_key_vault_sweep`). The 60-minute TTL and the sign-out tenant
sweep remain the other clears. Like the site sweep, a cancelled or partially-failed run is never
cached, so coverage is never overstated.

## Mailbox-scope verdicts are cached per principal

`get_mail_permission_scopes` / `get_mail_scopes_for_principal` resolve the Permissions-tab "Scope"
column through several Exchange admin-API cmdlets (each a proxied PowerShell invocation, seconds
apiece), so successful verdicts are cached under `mail_scopes_key(tenant_id, …)`:
`"{tenant_id}|mail_scopes|declared|{object_id}"` for app registrations (manifest permissions) and
`"{tenant_id}|mail_scopes|held|{app_id}|{perms}"` for bare principals (managed identities /
enterprise apps) — keyed on the caller-supplied grant set so the two commands never collide on one
app id. Errors are never cached, so a transient Exchange failure doesn't pin "Unknown" for the TTL.

`invalidate_app_details` sweeps the whole `{tenant_id}|mail_scopes|` prefix, so every mutation path
that busts the detail payload (grants, revokes, scoping actions) also drops the verdicts.
`remove_exchange_mailbox_access` invalidates even on **partial** success — assignments were really
removed (the same rule as audit remediations above).

## Cancellation and dead sessions in long-running writes

A command that reads a tenant-wide collection and then writes per result must stop for two distinct
reasons: the operator pressed Cancel, and the session died underneath it. Both are handled at the
same place, and the shape is load-bearing enough that `repo_invariants/{cancel,fanout}.rs` derives
its expectations from the source tree per **call site** — not from an allowlist, and `KNOWN_GAPS`
stays empty.

- **Claim the `CancelToken` once, before the first suspension point.** `claim()` stamps a
  generation, and `is_cancelled()` compares `cancelled >= generation`. A token claimed *after* an
  await therefore carries a higher generation than a cancel issued *during* that await, and silently
  discards it — the run carries on after the operator asked it to stop. The tenant-wide read at the
  top of these commands can walk 10 000 objects, so that window is not theoretical.
  (The invariant test scans source text, so a comment containing a literal `.await` above the claim
  line reads as a suspension point and trips it. Word around it rather than suppressing the test.)
- **Latch `dispatch::SessionDead` and break on both.** A dead refresh token cannot be re-minted
  silently, so every remaining item would fail identically — turning one recoverable
  "re-authenticate" into a wall of N indistinguishable failures.
- **Flag the result incomplete.** A cancelled or session-dead run is never cached and never renders
  as an all-clear; failures are fed in through `note` / `note_code` / `note_fatal`.
- **Fan-outs gate `dispatch_capped`'s `spawn` on `is_dead()`.** A **read** fan-out (the site / Key
  Vault sweeps, a backup; the audit with its own captured fatal error) then returns the dead-session
  error rather than a partial result, because a partial read presented as complete is a wrong answer. A **mutating** fan-out (the bulk
  delete, consent grant and expired-secret sweep) returns what landed instead: the ids it deleted,
  the outcomes it has, and the failure that latched the dead session carrying its wire code
  (`BulkError.code`, `BulkDeleteFailure.code`), with `cancelled` reserved for the operator's Cancel.
  The bar reads that code (`session_dead_error`) to prompt re-authentication, prunes the deleted ids
  from the selection and offers Undo — an error there used to throw the landed deletes away, leaving
  them selected with no Undo. Sequential flows that have already mutated (restore, AAP migration)
  likewise break each pass and flag the report — stopping is not enough once writes have landed.

**One flag per run kind, each with exactly one Cancel command.** `audit_cancel` (`run_audit`,
`cancel_audit`), `bulk_cancel` (every `bulk_*`, `cancel_bulk`), `migration_cancel` (the AAP
migration, `cancel_aap_migration`), `scope_move_cancel` (the "Move to managed group" member copy,
`cancel_scope_move`), `site_sweep_cancel` (`sweep_site_permissions`, from the Sites
tab and the per-app site panel, `cancel_site_sweep`), `key_vault_sweep_cancel`
(`cancel_key_vault_sweep`), `mailbox_probe_cancel` (`find_mailbox_reachers`,
`cancel_mailbox_probe`), `backup_cancel` (`cancel_backup`) and `restore_cancel` (`cancel_restore`).
Why per kind: `CancelFlag::cancel` stamps the flag's current generation, so it stops *every* run on
the flag, and the views that start these runs stay mounted (keep-alive views, display-toggled
panels), so runs of different kinds overlap — a shared flag let cancelling a read-only audit halt a
bulk delete, or a mailbox probe's Cancel throw away a site sweep. The one remaining same-kind
overlap: a bulk run and a Recently-deleted restore share `bulk_cancel`, so one Cancel stops both
(separating them needs a per-run id). The bars themselves no longer overlap — the frontend admits
one bar run at a time (`TenantScopedUi::bulk_running`, frontend-workspace.md). Pinned by `repo_invariants/cancel.rs`
(`every_cancel_flag_belongs_to_one_run_kind_and_one_cancel_command`).
