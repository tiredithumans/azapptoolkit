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

## The site-sweep cache invalidates on site-permission mutations

The Resource Access reverse-lookup caches a **complete** site sweep under `{tenant}|site_sweep`
(`CacheKind::Audit`, audit TTL). That key is *not* part of `invalidate_app_lists` /
`invalidate_audit_cache` (it is a different Audit-kind key), so the per-site permission mutations
bust it directly: `grant_site_access`, `remove_site_permission`, and
`convert_site_access_to_selected` all call `invalidate_site_sweep` on success. Without that, the
sweep — a security-posture surface — could show a revoked grant as still present (or miss a new
one) for up to the audit TTL.

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
