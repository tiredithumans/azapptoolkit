---
paths:
  - "crates/azapptoolkit-exchange/**"
  - "crates/azapptoolkit-core/src/audit/**"
  - "crates/azapptoolkit-core/src/scoping.rs"
  - "apps/desktop/src-tauri/src/commands/exchange/**"
  - "apps/desktop/src-tauri/src/commands/{sharepoint,audit,remediation,bulk,permissions,permission_tester,graph_roles}.rs"
  - "apps/desktop/web-rs/src/views/audit_view/**"
  - "apps/desktop/web-rs/src/views/{security_view,bulk_actions_view}.rs"
  - "apps/desktop/web-rs/src/views/resource_access/**"
  - "apps/desktop/web-rs/src/components/{scope_wizard,scope_badge,bulk_action_bar,exchange_scoping_section,sharepoint_sites_section,app_site_access_panel,aap_migration_report,managed_scope_group_panel,orgwide_scope_callout,legacy_exchange_grants_callout}.rs"
---

# Scoping & audit — the detail behind the AGENTS.md one-liners

Deep-dives: `docs/architecture/exchange-scoping.md`, `sharepoint-selected.md`, `audit-findings-and-remediation.md`, `resource-access-and-permission-tester.md`.

- **Scope-aware audit risk.** `score_application` reads `AppPermissions.mail_scopes` (empty map = org-wide, so an unresolved probe never under-reports). A **legacy AAP** verdict is its OWN finding + migrate Fix — same reduced weight, but never the `SCOPED_VIA_RBAC` healthy one. Badges: `web-rs/components/scope_badge.rs`.
- **Mailbox AND SharePoint permissions live on TWO resources each — carry the resource, never the bare value.** Only Graph's are confinable, so a value-keyed shortcut silently widens access. Permissions travel as `audit::ResourcePermission`; every gate uses the POSITIVE `is_scopable_{exchange,sharepoint}_resource_permission` / `scope_kind_for`. The value-only forms are **deleted** and `repo_invariants.rs` fails if one returns.
- **`Sites.Selected` reach is knowable only from the site side.** No reverse `appId → sites` lookup exists, so the Resource Access sweep and the per-app "Sites this app can reach" panel share ONE tenant index; `AppSiteAccessDto::from_sweep` is the single projection (cached ⇒ backend-side, fresh ⇒ frontend), and an empty list means "no grants" only when `is_complete()`.
- **Sub-site Selected scopes are a SECOND mechanism, and their reach is not enumerable at all.** `Lists.`/`ListItems.`/`Files.SelectedOperations.Selected` → `ScopeKind::SharePointItem` (Graph-only, like the site gate); the body is **`grantedToV2`**, never the site endpoint's `grantedToIdentities`. A URL is resolved *before* granting and checked with `selected_scope_accepts` — fail closed, never one level up. Both apply paths **declare** the appRole (`declare_graph_role`) before assigning it: the Permissions tab renders declarations, so an undeclared assignment shows nowhere. Sub-site 403s key to their OWN capability (`sharepoint_selected_items`). No sweep exists: grants are verified per URL, and empty means "this resource has no grants", never "this app has none".
- **AAP migration is guarded, not mechanical.** `RestrictAccess` only (a `DenyAccess` blocklist inverts), one batch per **app**, policies deleted only once every grant they confined is re-scoped **and** both mailbox resources resolved; an unverifiable set fails closed. Planner: `azapptoolkit-exchange::aap` (pure, tested).
- **Scoped grants reuse shared cores.** Exchange + SharePoint grant scoped access *before* stripping org-wide, so a failure never strands the principal. The Exchange scope and its backing mail-group use two distinct per-tenant patterns (`scope_name_for`/`group_name_for`) covering **every** scoping path, resolved via `load_tenant_defaults`. Membership changes **don't** invalidate caches.
- **Repointing a management scope is an explicit action, and fail-closed.** `ensure_management_scope` is create-only; `set_management_scope_filter` is the sole filter mutator, and Exchange applies it to **every** role assignment on that scope. A filter is rewritten only once proven a pure `MemberOfGroup` OR-chain — the planners refuse rather than fall back.
- **Unified "Grant access" wizard.** One button per principal (`ScopeWizard`): permissions → access → grant. `mechanism` is `Some(kind)` only when every cart item is an Application permission of the **same** `ScopeKind`; anything else is org-wide. Adding a mechanism touches exactly three places and nothing else branches on it.
- **Audit remediation (one-click "Fix")** — only for findings with a safe, existing mutation (additive/reversible qualifies); the handler **re-resolves live state**. Which are scorer-attached, which reuse an existing core, and the `DisableSignIn` post-pass are in the audit deep-dive.
- **The audit also scores SP-only principals (no local app registration) — and those rows are NOT bulk targets.** `AuditItem.principal_kind` drives routing; SP rows' Fixes call the SP-only cores, **never** `remediate_scope_*` (which `get_application` first → 404), render no checkbox, and are excluded from select-all.
- **Security tab = findings-first workbench: one controller, read-only posture strip.** Filtering has exactly two homes (Findings accordion + All-apps `audit_severity`); `BulkActionBar` is the single home of bulk command-calling; **no Grant consent on audit surfaces**. The `scoped_mailbox` matcher asymmetry is load-bearing (see `frontend-workspace.md`).
- **Audit scoring rule** — implement in `azapptoolkit-core::audit` with a table-driven test citing the legacy PowerShell `file:line`. A rule that shifts ranking needs a CHANGELOG note — operators watch these scores.
