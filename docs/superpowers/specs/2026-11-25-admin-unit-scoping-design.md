# Design — Project C1: limit directory writes to an administrative unit

## Context and intent

Project A made the toolkit flag highly privileged Microsoft Graph application permissions that
Microsoft offers no way to narrow, and Project B added safeguards around them (usage, a network
lock, expiry dates). Project C adds limits **Microsoft itself enforces**. It was split three ways,
and the user chose to build C1 first:

- **C1 (this doc): admin-unit-limited roles.** Instead of the tenant-wide `User.ReadWrite.All`,
  `Group.ReadWrite.All` or `Device.ReadWrite.All`, the app's service principal gets the matching
  Microsoft Entra admin role **assigned at administrative-unit scope**, so its writes reach only the
  unit's members. Microsoft supports this for service principals.
- C2 (Teams resource-specific consent) and C3 (Teams meeting access policy, PowerShell only) are
  decided after C1.

The apps are both in-house and vendor ("Both"); admin-unit roles work for any service principal in
the tenant, including a multi-tenant vendor app's (unlike the Conditional Access lock).

## Decisions made with the user

| Decision | Choice |
|---|---|
| Order within C | C1 admin-unit roles first, as its own reviewed PR |
| Where the admin unit comes from | Pick an existing one, or create one with a dynamic membership rule |
| How it is built | A new mechanism in the Grant access wizard, with Permissions-tab and audit integration |

## Microsoft facts this rests on (verified 2026-11-25 on Microsoft Learn)

- Roles that can be assigned at admin-unit scope include User Administrator, Groups Administrator
  and Cloud Device Administrator (plus Helpdesk, Password, Authentication, License administrators and
  custom roles). Service principals can hold them. Assign with `POST
  /roleManagement/directory/roleAssignments` and `directoryScopeId:
  "/administrativeUnits/{id}"`.
- **A service principal can't use an AU-scoped role unless it can also read the objects
  tenant-wide** (Directory Readers or another read permission at tenant scope). Directory reads
  can't be limited to an admin unit.
- Adding a **group** to an admin unit covers the group object, **not its members**. Users must be
  members directly or by a dynamic rule. Dynamic rules cover **users and devices only**, never
  groups, and need Entra ID P1 for each member. Admin units can't be nested.
- Licence: P1 for each admin-unit administrator. Microsoft doesn't say how that counts for a
  service principal; the toolkit can't check licences.

## Goals

1. Offer "Limit writes to an admin unit" in the Grant access wizard for the three permissions, on
   app registrations and service-principal-only principals (vendor apps, managed identities).
2. Assign the mapped role at admin-unit scope, make sure the app keeps tenant-wide read, and only
   then remove the tenant-wide write permission.
3. Let the operator pick an existing admin unit or create one with a dynamic membership rule.
4. Show it: a scope badge and **Scope…** on the permission's row; a "Directory roles" list on the
   app's Permissions tab (and the held-permissions panels) with Remove for admin-unit-scoped roles.
5. Audit: holders of the tenant-wide permission get an actionable finding with a Scope fix;
   principals whose writes are limited show as healthy.

## Non-goals

- Teams consent and the meeting policy (C2, C3).
- Managing an admin unit's members by hand, restricted-management admin units, or editing an
  existing unit's rule. Those stay in the Entra portal.
- Custom least-privilege roles (a closer match than the built-in roles; a possible follow-up).
- Scoring or flagging tenant-wide directory roles held by apps (a real gap today, noted as a
  follow-up; C1 only lists them).
- `Directory.ReadWrite.All` and other permissions with no single matching role.

## Anti-goals (a failure even if it technically works)

- **Removing the tenant-wide permission before the limited role and tenant-wide read have
  landed.** That strands the app. Grant first, strip last, fail closed: the order the Exchange and
  SharePoint scoping already follow.
- **Presenting the role as equivalent to the permission.** Each role allows things the permission
  doesn't (see the mapping). The wizard must say what else it allows, every time.
- **Ever assigning a role at tenant scope** (`directoryScopeId: "/"`). C1 assigns at admin-unit
  scope only and refuses anything else.
- **Breaking an app with an empty unit.** A just-created dynamic unit starts empty while Microsoft
  calculates membership; stripping the tenant-wide write then would cut the app off from everyone.

## Approaches considered

1. **A new wizard mechanism with Permissions-tab and audit integration (chosen).** Consistent with
   Exchange and SharePoint scoping; the only option where the audit reflects the limit.
2. A standalone per-app "Admin roles" panel. Quicker, but the operator removes the tenant-wide
   permission by hand and the audit keeps flagging the app.
3. Guidance only in the Rule 24 checklist. Cheap; nothing enforced.

## Design

### 1. The mapping (core, curated, one table)

| Permission (Microsoft Graph) | Role at admin-unit scope | Tenant-wide read it needs | What else the role allows | What the app can no longer do |
|---|---|---|---|---|
| `User.ReadWrite.All` | User Administrator | `User.Read.All` | Reset passwords of non-admin users in the unit; manage groups in the unit | Change users outside the unit (and anything Microsoft doesn't allow at unit scope, e.g. creating users, if so) |
| `Group.ReadWrite.All` | Groups Administrator | `Group.Read.All` | Manage group settings for groups in the unit | Change groups outside the unit; create groups, if Microsoft doesn't allow it at unit scope |
| `Device.ReadWrite.All` | Cloud Device Administrator | `Device.Read.All` | Enable, disable and delete devices in the unit; read their BitLocker recovery keys | Change devices outside the unit |

Both right-hand columns are shown in the wizard's review, every time: an app that creates objects
or touches non-members breaks once the tenant-wide permission goes, and the operator must see that
before confirming. The columns are a starting point. **The builder verifies each line, and the role
template ids, against Microsoft's built-in roles reference** and records the source; a line
Microsoft doesn't support is removed, one it adds is added. The table carries the resource: Graph
only (a value on another resource never matches).

- `ScopeKind::AdministrativeUnit` (the enum already reserves it), with its `capability_key`
  (`admin_unit_roles`, Privileged Role Administrator) and `admin_applicable` arms, and its predicate
  in `scope_kind_for` reading the table.
- Rule 24's classifier then sees these three as `NativeScoping::Managed`, so they leave "No
  built-in scoping"; their `MICROSOFT_UNMANAGED` entries and the `AdministrativeUnitRole` variant
  go.

### 2. Admin units: pick or create

- **One permission per run.** The mechanism applies only when the cart is exactly one of the three
  permissions: each needs a different role and a different kind of unit, so one unit can't serve
  two (a mixed cart falls back to org-wide, as other mixed carts do).
- **Pick:** list the tenant's admin units (name, membership type, rule, restricted flag). A unit
  that can't hold the permission's object type is shown but disabled with the reason: a group
  permission needs a unit with **assigned** membership (dynamic rules can't add groups). A
  restricted-management unit is listed; whether the operator can use it is Graph's answer.
- **Create by rule:** a name, and a rule.
  - Users (for `User.ReadWrite.All`): a small builder, "users whose [attribute] equals [value]"
    (department, company name, office location, country, job title, employee type), producing
    e.g. `(user.department -eq "Finance")`, plus an "Advanced rule" text field.
  - Devices (for `Device.ReadWrite.All`): the advanced rule field, with examples.
  - Groups: no create (dynamic rules can't add groups); the panel says so and links to the portal.
  - Graph validates the rule; its error is shown on the field. The copy says membership takes a
    while to calculate and needs Entra ID P1 per member.

### 3. Applying it (one core for both principal kinds)

`scope_directory_write` (app registration or service principal, the permission, the unit) runs, in
order, stopping at the first failure:

1. Re-read live: the principal's service principal, its app-role grants, its **direct, active**
   directory role assignments, and the unit.
2. Assign the mapped role at `/administrativeUnits/{id}` (idempotent: an existing identical
   assignment counts as landed).
3. Make sure the app can read tenant-wide: the mapped read permission, or `Directory.Read.All` /
   `Directory.ReadWrite.All`, held on Microsoft Graph (checked by resource and value). If none is
   held, grant the mapped read through the existing grant core (an app-role assignment; on an app
   registration also declared).
4. Remove the tenant-wide write permission (the grant; on an app registration also its
   declaration) — **only if** steps 2 and 3 landed, the unit wasn't created in this same run, and
   it **has members of the permission's object type** (users, groups or devices; a dynamic unit
   also needs its rule processing `On`). Otherwise the result says the tenant-wide permission was
   kept and why — for a group permission whose unit holds no groups: "add groups to the unit in the
   Entra portal, then Scope… again" — and the audit keeps offering the Scope fix to finish later.

**A covering tenant-scope role voids the limit.** If the principal also holds the same role, or
Global Administrator, at tenant scope (a direct, active assignment), its writes still reach
everyone: the result warns, the badge reads "Not limited: also holds User Administrator
tenant-wide", and no healthy finding is shown. The strip still runs (it removes a real grant).
C1 reads direct, active assignments only; roles inherited through a role-assignable group and
PIM-eligible assignments are a documented limitation.

The result reports each step (`role_assigned`, `read_granted`, `orgwide_removed`, `kept_reason`,
`warnings`), like the SharePoint conversion's.

### 4. Surfaces

- **Wizard:** a `ScopeMode` for the mechanism and its `mode_options` row, its target panel (pick or
  create), review lines that name the role, the unit, the read permission, the "what else it
  allows" lines and whether the tenant-wide write will be removed, and the apply plan. The
  mechanism-specific gates the compiler doesn't see (`row_scope_kind`, `is_held_scopable`, the
  step copy) are listed in `docs/architecture/audit-findings-and-remediation.md` ("To teach the app
  a new mechanism").
- **Permissions tab and held panels:** the three rows get a scope badge ("Writes limited to Finance"
  when the principal holds the mapped role at a unit scope, "Org-wide" otherwise) and **Scope…**.
- **Directory roles list** (new, on the app registration's Permissions tab and the enterprise-app
  and managed-identity panels): every **direct, active** role assignment the principal holds, with
  its scope (tenant or admin-unit name). Admin-unit-scoped ones have **Remove** (click-confirm
  naming the role and unit; re-read live; refuses a tenant-scope assignment), whoever made them;
  when the principal no longer holds the tenant-wide permission, the confirm says its writes to the
  unit stop. Tenant-scope ones are listed only.

### 5. Audit

- A run prefetch reads the direct, active role assignments once: one tenant query if Graph's
  filters allow it, else one read per admin unit (units are few). It isn't cached beyond the run.
  Unreadable → unknown, over-reporting: the org-wide finding still shows, no healthy finding.
- **New actionable finding** for a principal holding one of the three permissions tenant-wide:
  advisory (the weight is already Rules 1/2's), with a `RemediationKind` that opens the wizard
  pre-seeded, like the mailbox and SharePoint Scope fixes. SP-only rows route to the SP-only core.
- **New healthy finding** for a principal holding the mapped role at a unit scope, not the
  tenant-wide permission, and no covering tenant-scope role.
- **Scoring — both, like a scoped mailbox permission:** the limited role shows in the healthy group
  **and** scores at the reduced scoped weight of its permission's tier (all three are High, so the
  scoped High weight, today 3 points), so limiting an app never reads as all-clear. The scoring
  input (`AppPermissions`) gains the principal's admin-unit-scoped roles. This shifts ranking for
  apps that already hold such a role: CHANGELOG note.

### 6. Access the operator needs

- A new on-demand consent feature for the writes, following the existing incremental consent
  pattern exactly (like `conditional_access_write`; no new sign-in flow, nothing pre-registered):
  role assignment and admin-unit creation (expected `RoleManagement.ReadWrite.Directory` +
  `AdministrativeUnit.ReadWrite.All`; the builder confirms the least set). Reads (listing units, role assignments) use the read scopes the builder confirms;
  a missing read degrades to unknown, never to "no roles".
- The capability catalog entry `admin_unit_roles` names Privileged Role Administrator, spliced into
  403s like the others.

### 7. Docs

CHANGELOG `[Unreleased]` (the feature, and the ranking note); the mechanism's section in
`audit-findings-and-remediation.md`; a line in `.claude/rules/scoping-and-audit.md`.

## Calls I made (check these while reading)

1. **A just-created dynamic unit never triggers the strip** in the same run (section 3, step 4).
2. **Group permissions can't use "create by rule"**, because dynamic rules can't add groups.
3. **Scoring gives the limited role the reduced "scoped" weight**, with a CHANGELOG ranking note.
4. **The Directory roles list shows tenant-scope roles too, read-only.** Free once the assignments
   are read, and a privileged tenant-wide role on an app is worth seeing.
5. **Device writes are included even though Cloud Device Administrator can read BitLocker keys**;
   the wizard must say so before the operator confirms.
6. **One permission per run** (section 2): the three need different roles and kinds of unit.
7. **The strip also needs members of the right type** (users, groups or devices; a dynamic unit's
   rule processing `On`); otherwise the tenant-wide permission is kept with the reason.
8. **A covering tenant-scope role (same role or Global Administrator) voids the limit**: warned,
   never shown healthy. Only direct, active assignments are read; group-inherited and PIM-eligible
   roles are a documented limitation.
9. **The review also says what the app can no longer do**, so an app that creates objects or
   touches non-members isn't broken by surprise.
10. **Remove works on any admin-unit-scoped role**, whoever assigned it, behind a click-confirm.
11. **Tenant-wide read is satisfied by the mapped read or `Directory.Read(Write).All`**; a missing
    one is granted through the existing grant core.

## Left to the builder

- The exact Graph filters and expands for reading role assignments by principal and at admin-unit
  scope (v1.0 vs beta), and a fallback if a filter isn't supported.
- The least consent scopes for each read and write, and the error mapping (licence, missing role,
  invalid rule, restricted unit).
- Verifying the mapping table against Microsoft's built-in roles reference.
- The rule builder's attribute list and quoting; the layout of the panels.
- Cache keys and tiers for the new reads (tenant-scoped, invalidated only on `Ok`).

## Verification

- **Core:** the mapping (resource carried; non-Graph never matches), `scope_kind_for`, the Rule 24
  classifier change, scoring of a limited role.
- **Backend (mock Graph):** grant-before-strip ordering; a failed role assignment or read grant
  strips nothing; a just-created unit keeps the tenant-wide permission; an existing identical
  assignment is idempotent; tenant-scope removal is refused; app registration vs SP-only routing.
- **Browser GUI:** the wizard's pick and create paths, the "what else it allows" review lines, the
  kept-tenant-wide result, the Directory roles list with Remove, the badge, and the two audit
  findings with the Scope fix.
- `just verify`, `just verify-full`.
- **Manual (test tenant):** limit a test app's `User.ReadWrite.All` to a small unit and confirm it
  can update a member but not a non-member; repeat for a multi-tenant vendor app's service
  principal.
