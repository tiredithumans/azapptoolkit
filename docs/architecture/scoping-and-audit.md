# Exchange/SharePoint scoping & the security audit

This deep-dive was split into four focused documents so an edit reads only the subsystem it
touches. Links to this file remain valid; pick the part you need:

- [exchange-scoping.md](./exchange-scoping.md) — mailbox permissions on two resources, the Exchange
  grant core, the toolkit-managed scope group, legacy-AAP migration, repointing a management scope.
- [sharepoint-selected.md](./sharepoint-selected.md) — `Sites.Selected` and the sub-site Selected
  family: levels, `grantedToV2`, declare-then-assign, who may grant, testing reach.
- [audit-findings-and-remediation.md](./audit-findings-and-remediation.md) — scope-aware scoring,
  the scope registry + wizard, one-click remediations, Rule 18 / downgrades, finding groups, bulk
  remediations, SP-only principals.
- [resource-access-and-permission-tester.md](./resource-access-and-permission-tester.md) — the
  resource → identities reverse lookups (site sweep, mailbox reachers) and the permission tester.
