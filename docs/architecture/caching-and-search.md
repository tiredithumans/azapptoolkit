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
reads the previous session's audit/sweep/SP data.

## One SP enumeration feeds two lists

The App Registrations and Enterprise Apps lists share **one** cached service-principal enumeration
under `sp_index_key(tenant_id)` → `"{tenant_id}|sp_index"` (fetched by
`list_service_principals_index`), so a tab switch (or a global-search keystroke) reuses one
directory scan instead of re-enumerating every SP.

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
`search_corpus_key(tenant_id)` → `"{tenant_id}|search_corpus"`, built once (from `sp_index` plus the
app-registration name index `app_name_index_key(tenant_id)` → `"{tenant_id}|app_name_index"`, fetched
by `list_application_index_named`) and stored via `Cache::put_typed`. A debounced keystroke reads it
back with `Cache::get_typed` — a refcount clone of `Arc<Vec<SearchRow>>`, **no per-query deserialize
of the full SP/Application models and no per-query re-lowercasing** (`SearchRow` carries the
lowercased forms). `put_typed`/`get_typed` keep the original `Arc<T>` alongside a `Null` JSON value,
so the entry is read **only** via `get_typed` (an untyped `get::<T>` on it misses) but is still TTL-
bound and swept by tenant invalidation like any other. The corpus is derived from those two indexes,
so `invalidate_app_lists` busts it too; a credential-only mutation keeps all three (it changes none
of them).

## Gallery search matches in memory too — don't put the filter back on the server

`search_application_templates` (the New-application → "Browse the gallery" picker) has the same
shape as `global_search`, for the same reason: `GET /applicationTemplates` supports **no `$search`**
and **no documented `contains()`** — only `startswith`. A server-side
`$filter=startswith(displayName,'…')` therefore can't find "Salesforce" from "force" or
"Office 365" from "365", which is exactly how it failed: real gallery apps were simply absent from
results, and the picker then rendered "Type an app name to search the gallery." over the empty list,
so a miss looked like the search had never run.

So `GraphClient::list_application_templates` pulls the gallery **whole** (unfiltered, `$select`ed to
the picker's fields, `$top=999` as a page-size hint, `@odata.nextLink` followed to completion via
`collect_all_pages_capped`) and matching happens in memory. **Don't reintroduce a `$filter` here** —
the graph-client test asserts `query_param_is_missing("$filter")` precisely to stop that
"optimization" from silently restoring prefix-only search.

The corpus is typed-cached under `gallery_corpus_key(tenant_id)` → `"{tenant_id}|gallery_templates"`
(`CacheKind::Lists`, 60-min TTL) via `put_typed`/`get_typed`, so a debounced keystroke is a refcount
clone rather than a re-deserialize of ~3k templates plus a re-lowercasing — and the per-keystroke
Graph round trip is gone entirely. It is tenant-scoped by the universal `{tenant_id}|` convention
even though the gallery is Microsoft's **global** catalog and not tenant data, purely so the
sign-out prefix sweep collects it like everything else. Nothing invalidates it: no mutation in this
app can change the gallery, so `invalidate_app_lists` deliberately does **not** name it.

Two asymmetries worth keeping:

- **Ranking tiers differ from `global_search`.** Gallery rows rank exact → name prefix →
  word-boundary → substring → publisher-only, and *whether* a row matches is decided separately:
  every whitespace token must hit the name or publisher (**AND**, not OR — ORing would make
  "office 365" drag in every app containing "365", while ANDing still finds "Microsoft Teams" from
  "teams microsoft").
- **A failed gallery fetch propagates as an error**, unlike `search_corpus`, which degrades to an
  empty corpus. An empty result set here is a *claim that no such app exists* — a lie the operator
  can't distinguish from a broken fetch, which is the bug class this whole path exists to avoid.
  `GallerySearchResultsDto` carries `total_matches`/`truncated`/`partial_catalog` so the picker can
  say "showing the closest 50 of 200" or admit a partial catalog rather than imply a confident zero.

## Invalidation — only on `Ok`

After a successful mutation, bust the relevant list cache (`invalidate_app_lists(...)`); never on
the error path, so a failed write doesn't clear fresh data.

`invalidate_app_lists` drops **seven** things together: the apps-pairing, enterprise, `sp_index`,
`app_name_index`, and `search_corpus` keys, plus — transitively — the per-app detail cache
(`invalidate_app_details`) and the cached audit run (`invalidate_audit_cache`). The transitive two
matter: a scope grant or credential change re-scores the app, so the audit/posture tile must
refetch too (two reviews independently mis-read this as a missing invalidation because earlier
versions of this doc listed only the four list keys) — so any mutation that can add/remove/rename a service principal or app registration
(`create_application`, `grant_exchange_mailbox_access`) must call it, or a stale pairing/search
index survives until the TTL.

**Credential-only mutations are tiered.** `add_password`, `remove_password`, the certificate
add/remove pair, `generate_self_signed_certificate`, and `remove_expired_passwords` change a single
app's secrets/certs — which surfaces in the App Registrations list row (its credential-status
badge), that app's detail payload, and the audit (expiring-credential findings), but **cannot** add,
remove, or rename a service principal or app registration. They call
`invalidate_app_credentials(cache, tenant, object_id)` instead of `invalidate_app_lists`: it drops
apps-pairing, the *one* app's detail, and the audit run, and deliberately **keeps** `sp_index`,
`app_name_index`, the enterprise list, and the mailbox-scope verdicts. Keeping the two tenant-wide
indexes is the point — dropping them would force the next list visit to re-enumerate every app and
every service principal (tens of seconds on a large tenant) for a change that touched neither.

The general rule for multi-step mutations: **a partial success is a real write — invalidate,
gated on "something actually changed."** Audit remediations, `remove_exchange_mailbox_access`,
`downgrade_application_permission`, the `bulk_*` commands, and the SSO create flows all follow it
(see [scoping-and-audit.md](./scoping-and-audit.md) for the remediation case).

## `CacheKind::ServicePrincipal` self-invalidates in the graph client

The per-app SP cache is keyed by **`appId`**, but the SP mutators take an SP **object** id — a
targeted single-key bust isn't possible without an extra lookup. So this kind invalidates in the
graph client, **not** via the command-side aggregators: `delete_service_principal`,
`patch_service_principal`, and `set_service_principal_tags` call a private tenant-prefix sweep
(`invalidate_sp_cache`) on `Ok` — the can't-miss option. `set_service_principal_app_roles` rides
this via `patch_service_principal`. **`invalidate_app_lists` does not touch this kind** — don't
rely on it for SP-field freshness.

Related: `ensure_service_principal` returns `(ServicePrincipal, bool)` where the bool is
**created**. First-grant paths (`grant_single_permission`, `grant_admin_consent[_core]`, the bulk
grant) call `invalidate_app_lists` only when an SP was newly created; otherwise the cheaper
detail + audit bust suffices.

## Batched Graph fan-out + the adaptive throttle

Large per-object fan-outs (the security audit, DR backup) ride two shared pieces — reuse them for
any new heavy fan-out; don't hand-roll a second tracker or a raw per-item loop:

- **Graph JSON batching** — `client.batch_get_json[_with_headers]`
  (`graph/src/client/batch.rs`): 20 GETs per POST, results returned in input order, inner-429
  sub-requests re-batched. Advanced queries inside a batch (e.g. `memberOf` `$count`) need the
  **per-sub-request** header form — the outer POST's headers don't reach sub-requests.
  Whole-batch failures must degrade to per-object reads, never fail the run.
- **`ConcurrencyThrottle`** (`commands/throttle.rs`) — wired as the client's `ThrottleObserver`
  and fed to `dispatch_capped` as `|| throttle.current_limit()`, so the in-flight cap halves on
  429 and recovers when quiet. Attach/detach with the `ThrottleGuard::attach(client, tracker)`
  RAII (used by the audit and the bulk fan-outs) so an early `?` can't leave a stale observer
  halving the shared per-tenant client's cap.

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
(same `CacheKind::Audit` + TTL). It's a **read-only** view of ARM role assignments — the app grants
no Key Vault roles — so there's no in-app mutation to invalidate it; the 60-minute TTL and the
sign-out tenant sweep are the only clears (matching the managed-identity Azure-roles read caches).
Like the site sweep, a cancelled or partially-failed run is never cached, so coverage is never
overstated.

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
