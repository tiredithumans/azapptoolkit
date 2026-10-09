# SharePoint `Sites.Selected` & sub-site Selected scopes

Deep-dive companion to the SharePoint scoping gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `commands::sharepoint`, `GraphClient`'s SharePoint client, `scoping::selected_scope_accepts`,
or the site/item selection panels in the frontend. The Exchange sibling is
[exchange-scoping.md](./exchange-scoping.md); the tenant-wide site sweep is in
[resource-access-and-permission-tester.md](./resource-access-and-permission-tester.md).

## SharePoint scoping is encoded by the permission name

**SharePoint is the simpler sibling.** Its scoping is encoded by the permission *name*
(`Sites.Selected` = scoped to individually-granted sites; every other `Sites.*` = org-wide), so the
verdict needs no live call and no `mail_scopes`-style map — Rule 12 derives it directly, and the
Permissions-tab "Scope" column / audit facets reuse the same name check. Graph has **no reverse
`appId → sites` lookup**, so the named sites are found from the site side: the tenant site sweep
behind "Sites this app can reach" in the SharePoint site access section on the Permissions tab (see
[resource-access-and-permission-tester.md](./resource-access-and-permission-tester.md)). `Sites.ReadWrite.All` is scored high-risk (a deliberate net-new deviation from the PowerShell
source, alongside `Sites.FullControl.All`).

## The Selected family is four levels, not one

`Sites.Selected` is the site-collection member of a family Microsoft applies at four levels of the
same hierarchy, all with identical three-step semantics — consent the scope, POST a per-resource
permission, present a token carrying the scope; miss any step and there is **no** access:

| Scope | Level | Grant endpoint | `ScopeKind` |
|---|---|---|---|
| `Sites.Selected` | site collection | `POST /sites/{siteId}/permissions` | `SharePoint` |
| `Lists.SelectedOperations.Selected` | list / document library | `POST /sites/{siteId}/lists/{listId}/permissions` | `SharePointItem` |
| `ListItems.SelectedOperations.Selected` | list item (incl. folders) | `.../lists/{listId}/items/{itemId}/permissions` | `SharePointItem` |
| `Files.SelectedOperations.Selected` | file or **library** folder | same listItem endpoint | `SharePointItem` |

Four things about the sub-site three that the site path does not have to deal with:

- **The request body differs.** `POST /sites/{id}/permissions` takes `grantedToIdentities` (an
  array); the list / listItem / driveItem endpoints take **`grantedToV2`** (a single identity set)
  and Graph's driveItem reference rejects the array forms outright. Two builders,
  deliberately — `granted_to_v2_body` is separate from the site body so writing the wrong shape
  cannot be a one-character mistake, and a unit test pins the split.
- **The level must be checked, and the check is not equality.** All files are list items, but not
  all list items are files: `ListItems.*` can grant against an item in a document library, while
  `Files.*` cannot reach an item in a plain list. `scoping::selected_scope_accepts` is that
  relation. A URL is resolved *before* anything is granted
  (`GraphClient::resolve_sharepoint_resource`: site → drives → path-addressed driveItem, at most
  three reads) and a mismatch is **skipped with a warning, never granted one level up**.
- **Nothing is stripped.** These scopes have no org-wide predecessor — an operator reaching for
  `Files.SelectedOperations.Selected` is granting least privilege from the start, so
  `remove_orgwide` has nothing to remove. Converting `Files.Read.All` would be a different,
  audit-driven flow — today the audit only *advises* it: `ORG_WIDE_FILES` names
  `Files.SelectedOperations.Selected` as the least-privilege model (Rule 12, no remediation, no
  bulk Fix) and `least_privilege_alternative_for` gives the picker the same pointer, but no
  handler converts a held `Files.*.All`.
- **Reach is not enumerable — worse than the site blind spot.** `sweep_site_permissions` can walk
  every site in the tenant; *nothing* walks every folder, and there is no reverse `appId → items`
  lookup either. So there is no sweep, no cached index, and
  `list_selected_item_permissions` is a **verify-by-URL** read. An empty result means "this resource
  has no app grants", never "this app has no item-level access". Any future panel must say so —
  the Permission tester's grants table (F094) says so on the section and in its empty-message, and
  its GUI tests pin the wording.

## The per-app record of item grants

Since Graph can't answer "which libraries, folders and files can this app reach", the app keeps
its own answer: **one `tags` entry per grant on the app registration**
(`commands::sharepoint_item_scopes`). On the app object rather than on one machine, so every
operator sees the same list.

- **Format:** `azapptoolkit:spItem:v1|{level}|{site_id}|{list_id}[|{item_id}]`, where `level` is
  `list`, `list_item` or `file` (folders are `file`, as the resolver reports them). Ids, not URLs:
  they survive renames and moves, and a URL can exceed Entra's 256-character tag limit. A tag that
  would exceed it is not recorded, and the grant result says so.
- **Tags are untrusted input.** Anyone who can edit the app can edit them, and their ids go into
  Graph paths, so `decode_tag` accepts only `host,guid,guid` / a GUID / a numeric item id, and
  counts anything else (an unknown version included) as `malformed` without acting on it.
- **Writes are full-collection and serialized.** Graph replaces the whole `tags` array, so
  `remember`/`forget` re-read the live tags, change only their own entries, and write everything
  back (the DR `restoredFrom` marker and any other tag survive), under a per-app
  `single_flight("{tenant}|app_tags|{object_id}")`.
- **Who records.** `grant_selected_item_access` records every landed grant when it has an
  `object_id`: the Grant-access wizard and the section alike. A record failure is a warning, never
  a rollback of the grant (`recorded_on_app` says whether everything was recorded). A
  service-principal-only principal (managed identity, foreign enterprise app) has no registration,
  so nothing is recorded and no section is offered.
- **Reading back.** `list_app_item_scopes` reads each recorded resource's permission entries and
  name in two scoped `$batch`es and reports `Granted { permission_id, roles }`, `NotGranted` (read,
  and none is this app's), `Missing` (404) or `Unreadable`. A failed read is never `NotGranted`.
- **Removing.** `remove_app_item_scope` re-reads the resource and deletes the entry only if it is
  **this app's** application grant (`not_this_apps_grant` otherwise), then forgets the record.
  Without a permission id it only forgets the record, touching no SharePoint endpoint.
- **Grants made elsewhere** (before this version, in the Permission Tester, by script) are not in
  the record until tracked by URL (`track_app_item_scope`). The section's copy and empty state say
  so; the list is "what azapptoolkit recorded", never "everything this app can reach".
- **No role change in place.** Graph v1.0 has no role update for list or list-item permissions
  (beta only), and remove-then-add would cut access in between, so a role change is Remove, then
  Add with the other role, and the section says so.

The UI is `components::sharepoint_item_scopes_section` ("SharePoint item access"), mounted on the
app-registration Permissions tab when an Application row is a sub-site Selected scope, and on the
enterprise pane only when the SP has a paired app registration.

A grant at any sub-site level also **breaks SharePoint permission inheritance** on its target and
consumes one of the library's unique permission scopes (guidance: stay under 5 000 per library).
`ItemSelectionPanel` warns before granting and nudges toward a dedicated library — or a dedicated
site, where `Sites.Selected` applies and inheritance is untouched, because a site collection is the
root of inheritance.

## Declare, then assign

Both SharePoint apply paths reach `declare_graph_role` through `declare_and_grant_graph_role`, which
also owns the idempotent assign; the `Sites.Selected` conversion's org-wide strip is
`graph_roles::strip_app_role_grants`, shared with the Exchange core. `declare_graph_role` runs
before the appRole is granted: it patches the app
registration's `requiredResourceAccess`, exactly as `permissions::grant_single_permission_core`
does. This is not cosmetic. The Permissions tab renders **declarations** and joins runtime
assignments *onto* those rows (`applications::permissions_resolve` iterates `declared`), so an
assignment with no declaration is invisible on the app registration — and the wizard's picker is the
full live catalog rather than the declared set, so "granted but never declared" is the *normal* case
here, not an edge one. The PATCH invalidates the detail cache itself, because the steps after it can
still fail. `object_id` is `None` for a service-principal-only principal (enterprise app / managed
identity): there is no registration to declare on, and `declared_permission` comes back false.

Both paths also check the **pairing** before any write: the webview sends `sp_object_id`,
`object_id` and `app_id` as three arguments, so `declare_and_grant_graph_role` resolves the service
principal by object id and `declare_graph_role` reads the registration, and each must carry the
`appId` the per-resource grant is made to (`principal_mismatch` otherwise — nothing declared,
assigned or granted). A separate gate covers the role on all three grant commands
(`grant_site_access` included): `core::scoping::is_grantable_selected_role` admits only `read` and
`write` at every level, so a webview call cannot grant `owner` or `fullcontrol` the wizard never
offers.

## Input boundary: URLs and ids in Graph paths

The site lookup, the item resolver's URL parser and every permission DELETE splice operator- or
webview-supplied text into a path sent on the `Sites.FullControl.All` bearer, so the graph client
validates at that boundary rather than trusting its callers (pinned by `repo_invariants/trust.rs`);
the other ids a call takes come from Graph's own responses.

- **Site URLs** go through `site_lookup_path`, which parses the text as a URL (`url::Url` resolves
  `..` / `%2e%2e` and turns `\` into `/` the way a browser does), rebuilds the path from the parsed
  segments so nothing can climb out of `/sites/{host}:/`, and refuses a segment holding `:` (Graph's
  path-addressing pivot — `/sites/Fin:/drive/root:/x` answers with a driveItem), an encoded `/`,
  `\`, `:` or `.`, a host with an empty label (`.` and `..` parse as hosts), credentials, a port or
  a non-http(s) scheme. The id Graph answers with must itself be a single path segment. The item
  resolver's `url_host_and_segments` applies the same segment rule, because its output is spliced
  into `root:/{path}:` drive addressing. Refusals never echo the input.
- **Permission, site, list and item ids** in every DELETE go through
  `validate::require_path_segment` (the `azapptoolkit-arm` / `azapptoolkit-keyvault` pattern):
  non-empty, not a dot segment, none of `/ \ ? # % :`, no whitespace or control character. A
  `permission_id` of `../../../drives/{d}/items/{i}` could delete a file.

## Who may grant: the site collection is not the sub-site

The scope requirement is the same (`Sites.FullControl.All`), but the **user** requirement is not, and
this is the difference operators actually hit. A delegated call is the intersection of the token's
scopes and the caller's own SharePoint permissions ([Selected permissions overview][sel]: "in all
delegated cases the current user also needs sufficient permissions to manage access by calling the
API"). `POST /sites/{id}/permissions` is administrative at the root of the site collection and the
tenant SharePoint Administrator role covers it; a sub-site grant writes a role assignment onto a
securable *inside* the site's content, which that role does not reach — the operator also needs Full
Control on the site (site collection administrator, or its Owners group). So site-level grants can
succeed while list/file grants 403 for the same operator with the same token.

The two levels therefore key to **different** capabilities — `sharepoint_sites_selected` and
`sharepoint_selected_items` (`ScopeKind::capability_key`) — so the 403 message, the readiness row and
the proactive "Requires:" tooltip name the right requirement. `commands::sharepoint::map_sharepoint_err`
logs Graph's real 403 body at `warn` before replacing the message, since the substitution is
otherwise the only record and it names a role, not the actual denial.

[sel]: https://learn.microsoft.com/graph/permissions-selected-overview

## Testing reach: `test_site_access`

The permission tester takes any level, not just a site collection. It resolves the URL, then answers
in the order SharePoint itself does: an org-wide `Sites.*` grant wins outright; otherwise it walks
the securable chain **upward** (item → list → site collection), because Microsoft's access
calculation finds the application record "on the resource *or a securable hierarchical parent*" — so
a file with no entry of its own still reports the access it inherits. A found entry is then checked
against the scopes the principal actually holds, reusing `selected_scope_accepts` so the tester and
the granter agree on which scope reaches what. **An entry with no matching scope reports
`no_access`**, naming the missing half: the three-step model means a permission entry alone grants
nothing. A failure to read the assignments reports `unknown`, never "no access".

