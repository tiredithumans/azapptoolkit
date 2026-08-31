//! Permission-*scoping* predicates shared by the backend and the WASM frontend.
//!
//! Both surfaces need to answer the same two questions about an application
//! permission value, and they must answer them identically:
//! - **Exchange** (mail/calendar/contacts, plus the EWS `full_access_as_app`
//!   scope on the legacy Office 365 Exchange Online resource): can this
//!   permission be resource-scoped via RBAC for Applications? The answer is
//!   authoritative only if it matches the exact set Exchange recognises, so it is
//!   derived from the role *map*, never a loose prefix check
//!   (`Mail.ReadWrite.Shared` looks mail-ish but has no Exchange application
//!   role, so it is **not** scopable).
//! - **SharePoint** (`Sites.*` and the sub-site Selected scopes): scoping is
//!   encoded by the permission name — `Sites.Selected` confines to whole site
//!   collections, `Lists.`/`ListItems.`/`Files.SelectedOperations.Selected`
//!   confine to one list, folder or file, and every other `Sites.*` is org-wide.
//!   The two site-vs-sub-site families are separate [`ScopeKind`]s because they
//!   grant against different securables through different endpoints.
//!
//! This lives in `azapptoolkit-core` (which compiles to `wasm32`) so the badge
//! rendering in `web-rs` and the grant/scope logic in the Tauri backend call one
//! definition instead of drifting copies. `azapptoolkit-exchange` re-exports the
//! Exchange helpers for its existing callers.

/// Microsoft Graph's first-party app id — the resource that exposes the
/// mail/calendar/contacts **application** permissions.
pub const MICROSOFT_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// The legacy **Office 365 Exchange Online** resource. It carries the EWS
/// [`EWS_FULL_ACCESS_AS_APP`] scope, which is the one non-Graph permission the
/// old Application Access Policies could confine — so every Exchange scoping
/// path has to understand it, not just the Graph resource.
pub const OFFICE365_EXCHANGE_ONLINE_APP_ID: &str = "00000002-0000-0ff1-ce00-000000000000";

/// **Office 365 SharePoint Online** — the second resource exposing `Sites.*`
/// application permissions, for apps calling the SharePoint REST APIs rather
/// than Microsoft Graph. `Sites.Selected` exists on both, so a `Sites.*` value
/// alone never identifies which API surface a grant opens.
pub const OFFICE365_SHAREPOINT_ONLINE_APP_ID: &str = "00000003-0000-0ff1-ce00-000000000000";

/// Exchange Web Services full-mailbox-access scope, exposed as an appRole on
/// [`OFFICE365_EXCHANGE_ONLINE_APP_ID`] (never on Microsoft Graph). Documented
/// as an Application-Access-Policy-supported scope, and scopable under RBAC for
/// Applications via `Application EWS.AccessAsApp`.
pub const EWS_FULL_ACCESS_AS_APP: &str = "full_access_as_app";

/// RBAC-for-Applications role backing [`EWS_FULL_ACCESS_AS_APP`].
const EWS_ACCESS_AS_APP_ROLE: &str = "Application EWS.AccessAsApp";

/// A human-readable name for one of the three resources whose appRoles collide
/// by value, falling back to the raw app id for anything else.
///
/// Exists so operator-facing text can say *which* `Mail.Read` or `Sites.Read.All`
/// it means. The same permission name on Microsoft Graph and on the legacy
/// Office 365 resources authorizes against different APIs, and only Graph's is
/// confinable — so a finding or a Fix that names the value alone is ambiguous
/// exactly where the consequences differ.
pub fn resource_label(resource_app_id: &str) -> &str {
    match resource_app_id {
        MICROSOFT_GRAPH_APP_ID => "Microsoft Graph",
        OFFICE365_EXCHANGE_ONLINE_APP_ID => "Office 365 Exchange Online",
        OFFICE365_SHAREPOINT_ONLINE_APP_ID => "Office 365 SharePoint Online",
        other => other,
    }
}

/// The Exchange application role for a **Microsoft Graph** mail/calendar/contacts
/// application permission. This set is exactly the Graph permission list
/// Application Access Policies supported, so an AAP migration can always map
/// what a policy was confining.
///
/// Source: <https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac>
/// ("Supported Application Roles") ∩
/// <https://learn.microsoft.com/en-us/exchange/permissions-exo/application-access-policies>
/// ("Supported permissions"). The full RBAC role list is larger (mailbox
/// folders/items, SMTP, MailTips, and the composite full-access roles); those
/// were never AAP-scopable, so they are deliberately absent here.
fn graph_mail_role(value: &str) -> Option<&'static str> {
    let role = match value {
        "Mail.Read" => "Application Mail.Read",
        "Mail.ReadBasic" | "Mail.ReadBasic.All" => "Application Mail.ReadBasic",
        "Mail.ReadWrite" => "Application Mail.ReadWrite",
        "Mail.Send" => "Application Mail.Send",
        "MailboxSettings.Read" => "Application MailboxSettings.Read",
        "MailboxSettings.ReadWrite" => "Application MailboxSettings.ReadWrite",
        "Calendars.Read" => "Application Calendars.Read",
        "Calendars.ReadWrite" => "Application Calendars.ReadWrite",
        "Contacts.Read" => "Application Contacts.Read",
        "Contacts.ReadWrite" => "Application Contacts.ReadWrite",
        _ => return None,
    };
    Some(role)
}

/// The Exchange application role that grants the same capability as the
/// permission `value` on `resource_app_id` — the **authoritative** form, used by
/// every path that has to name a concrete Entra app-role grant (deriving scope
/// targets, stripping the org-wide grant). Returns `None` when the resource
/// doesn't expose a scopable mailbox permission of that name.
///
/// The resource matters: the legacy Office 365 Exchange Online resource exposes
/// `Mail.Read`-style appRoles of its own for the retired Outlook REST API, and
/// those have **no** RBAC-for-Applications counterpart (the supported protocols
/// are MS Graph and EWS only). Matching them to `Application Mail.Read` would
/// claim a scope the toolkit can't actually enforce, so only the EWS scope maps
/// on that resource.
pub fn exchange_role_for_resource_permission(
    resource_app_id: &str,
    value: &str,
) -> Option<&'static str> {
    match resource_app_id {
        MICROSOFT_GRAPH_APP_ID => graph_mail_role(value),
        OFFICE365_EXCHANGE_ONLINE_APP_ID => {
            (value == EWS_FULL_ACCESS_AS_APP).then_some(EWS_ACCESS_AS_APP_ROLE)
        }
        _ => None,
    }
}

/// True when `value` on `resource_app_id` is an Exchange mailbox permission
/// RBAC for Applications can confine — the only form there is, because it is
/// the only one that can be right. Office 365 Exchange
/// Online's own `Mail.Read`-family appRoles (retired Outlook REST) have no RBAC
/// role, so only the resource-aware answer can tell them apart from Microsoft
/// Graph's identically named ones. A `None` resource means "a resource this build
/// doesn't resolve", which is never scopable.
pub fn is_scopable_exchange_resource_permission(
    resource_app_id: Option<&str>,
    value: &str,
) -> bool {
    resource_app_id.is_some_and(|id| exchange_role_for_resource_permission(id, value).is_some())
}

/// True for an application permission on the legacy **Office 365 Exchange
/// Online** resource that names a mailbox capability RBAC for Applications
/// cannot confine: that resource's own `Mail.*` / `Calendars.*` / `Contacts.*` /
/// `MailboxSettings.*` appRoles, which authorized the Outlook REST API
/// (deprecated, endpoints decommissioned March 2024).
///
/// These sit in the awkward middle of the two-resource split. They are **not**
/// scopable — RBAC for Applications supports Microsoft Graph and EWS only, so
/// [`exchange_role_for_resource_permission`] returns `None` for them — yet they
/// still *name* a mailbox permission, so a surviving grant unions with (and
/// therefore defeats) the RBAC scope of the identically named Microsoft Graph
/// permission. Removing the grant is the only remedy, which is why the UI calls
/// them out instead of offering a "Scope…" action that can't be honoured.
///
/// Deliberately **excludes** the rest of the resource's appRoles:
/// [`EWS_FULL_ACCESS_AS_APP`] IS scopable (via `Application EWS.AccessAsApp`),
/// and `EWS.AccessAsApp` / `Exchange.ManageAsApp` / `IMAP.AccessAsApp` /
/// `POP.AccessAsApp` / `SMTP.SendAsApp` back protocols that are very much alive.
/// Widening this to "everything on resource `00000002-…`" would tell an operator
/// to break EWS, Exchange Online PowerShell, or IMAP/POP/SMTP.
pub fn is_unscopable_legacy_exchange_permission(resource_app_id: &str, value: &str) -> bool {
    resource_app_id == OFFICE365_EXCHANGE_ONLINE_APP_ID && graph_mail_role(value).is_some()
}

/// True for a grant that reaches **every** mailbox with full access regardless
/// of which individual mail permission is being examined — today only the EWS
/// [`EWS_FULL_ACCESS_AS_APP`] scope.
///
/// Such a surviving org-wide grant defeats *every* per-permission RBAC scope on
/// the same principal (RBAC and Entra grants union), so the effective-scope
/// reconciliation treats it as a blanket veto rather than matching it against
/// one permission value.
pub fn is_blanket_mailbox_grant(value: &str) -> bool {
    value == EWS_FULL_ACCESS_AS_APP
}

/// True when an application permission on `resource_app_id` reaches Exchange
/// mailboxes **at all** — the superset the audit's mailbox advisory classifies
/// before splitting it into scoped / org-wide-scopable / unscopable-legacy.
///
/// Resource-aware on purpose. A name-shaped `Mail.*` / `MailboxSettings.*` test
/// alone misses the EWS [`EWS_FULL_ACCESS_AS_APP`] scope — full access to every
/// mailbox in the tenant, and the single most dangerous mailbox grant there is —
/// because it is named nothing like a mail permission. It also cannot tell the
/// legacy resource's unscopable Outlook REST roles apart from Graph's confinable
/// namesakes.
///
/// A `None` resource falls back to the name-shaped check, so a build that cannot
/// resolve the resource still reports reach rather than silently dropping it.
pub fn is_mailbox_reaching_permission(resource_app_id: Option<&str>, value: &str) -> bool {
    /// Name-shaped mailbox reach, for the arms with no authoritative resource
    /// mapping to consult.
    ///
    /// Covers all four families [`graph_mail_role`] maps — `Mail.*`,
    /// `MailboxSettings.*`, `Calendars.*`, `Contacts.*`. A narrower `Mail.` /
    /// `MailboxSettings.`-only test used to drop Graph `Calendars.*` and
    /// `Contacts.*` grants out of the mailbox advisory entirely: this function
    /// decides advisory membership, and the org-wide / scopable / unscopable
    /// split happens only among its hits, so an org-wide calendar or contacts
    /// grant that RBAC for Applications *can* confine produced neither a
    /// finding nor a `ScopeMailboxAccess` fix.
    fn mailbox_named(value: &str) -> bool {
        ["Mail.", "MailboxSettings.", "Calendars.", "Contacts."]
            .iter()
            .any(|prefix| value.starts_with(prefix))
    }
    match resource_app_id {
        // Authoritative on Graph — every value with an RBAC role reaches
        // mailboxes — plus the name-shaped test, so a Graph permission this
        // build's `graph_mail_role` table doesn't know yet still reports reach
        // rather than vanishing from the advisory.
        Some(MICROSOFT_GRAPH_APP_ID) => graph_mail_role(value).is_some() || mailbox_named(value),
        Some(OFFICE365_EXCHANGE_ONLINE_APP_ID) => {
            is_blanket_mailbox_grant(value)
                || is_unscopable_legacy_exchange_permission(OFFICE365_EXCHANGE_ONLINE_APP_ID, value)
        }
        // A resource this build doesn't map (or didn't resolve): only the
        // name-shaped signal is available, and over-reporting is the safe side.
        _ => mailbox_named(value),
    }
}

/// `Lists.SelectedOperations.Selected` — Microsoft Graph's Selected scope for a
/// single **list**. A document library is a list, so this is the level that
/// confines an app to one library.
pub const SP_LISTS_SELECTED: &str = "Lists.SelectedOperations.Selected";

/// `ListItems.SelectedOperations.Selected` — the Selected scope for a single
/// **list item**, which in SharePoint includes folders and files.
pub const SP_LIST_ITEMS_SELECTED: &str = "ListItems.SelectedOperations.Selected";

/// `Files.SelectedOperations.Selected` — the Selected scope for a single **file
/// or library folder**.
///
/// Narrower than [`SP_LIST_ITEMS_SELECTED`] and not a rename of it: all files
/// are list items, but not all list items are files, so this scope reaches only
/// items inside document libraries (or other lists marked as holding
/// documents). The *destination* decides, not the Graph path used to reach it.
pub const SP_FILES_SELECTED: &str = "Files.SelectedOperations.Selected";

/// Which SharePoint securable a Selected scope confines an application to.
///
/// Microsoft's Selected family is one model applied at four levels of the same
/// hierarchy, and each level has its own grant endpoint. The level decides which
/// URL an operator may point a grant at, so it travels with the permission
/// instead of being re-derived at each call site — pointing a
/// `Files.SelectedOperations.Selected` grant at a site URL has to fail closed,
/// not silently grant one level up.
///
/// Source: <https://learn.microsoft.com/graph/permissions-selected-overview>
///
/// Serializes as its [`SelectedScopeLevel::key`] — one spelling on the wire, in
/// the backend, and in the frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedScopeLevel {
    /// `Sites.Selected` → `POST /sites/{siteId}/permissions`.
    Site,
    /// `Lists.SelectedOperations.Selected` →
    /// `POST /sites/{siteId}/lists/{listId}/permissions`.
    List,
    /// `ListItems.SelectedOperations.Selected` → an item in **any** list,
    /// via `POST /sites/{siteId}/lists/{listId}/items/{itemId}/permissions`.
    ListItem,
    /// `Files.SelectedOperations.Selected` → an item in a **document library**:
    /// a file, or a library folder.
    ///
    /// Granted through the same listItem endpoint (a file *is* a list item,
    /// and the listItem form is what Microsoft documents for a folder), so the
    /// distinction from [`SelectedScopeLevel::ListItem`] is about *reach*, not
    /// about the call: `Files.*` cannot touch an item in a plain list.
    File,
}

impl SelectedScopeLevel {
    /// Stable wire key — one spelling shared by the backend, the DTOs and the
    /// frontend, in the spirit of [`ScopeKind::capability_key`].
    pub fn key(self) -> &'static str {
        match self {
            SelectedScopeLevel::Site => "site",
            SelectedScopeLevel::List => "list",
            SelectedScopeLevel::ListItem => "list_item",
            SelectedScopeLevel::File => "file",
        }
    }

    /// Operator-facing noun for the securable this level grants against. Used
    /// wherever a level mismatch has to be explained in words.
    pub fn label(self) -> &'static str {
        match self {
            SelectedScopeLevel::Site => "site",
            SelectedScopeLevel::List => "list or library",
            SelectedScopeLevel::ListItem => "list item",
            SelectedScopeLevel::File => "file or library folder",
        }
    }

    /// True when this level's permission is granted below the site collection —
    /// i.e. the levels [`ScopeKind::SharePointItem`] dispatches on.
    ///
    /// Assigning a permission at any of these breaks SharePoint's permission
    /// inheritance on the target and consumes a unique permission scope; the
    /// site level does not, because it is the root of inheritance.
    pub fn breaks_inheritance(self) -> bool {
        !matches!(self, SelectedScopeLevel::Site)
    }
}

/// The Selected-scope level `value` confines `resource_app_id` to, or `None`
/// when it isn't a Selected scope this toolkit can act on.
///
/// **Microsoft Graph only**, for the handler reason documented at length on
/// [`is_scopable_sharepoint_resource_permission`]: the grant path resolves the
/// appRole on the *Microsoft Graph* service principal and reads and writes
/// Graph's per-resource permissions. Office 365 SharePoint Online exposes
/// look-alike values whose reach this toolkit can neither verify nor manage, so
/// the gate stays closed there — and for an unresolved (`None`) resource.
pub fn selected_scope_level_for(
    resource_app_id: Option<&str>,
    value: &str,
) -> Option<SelectedScopeLevel> {
    if resource_app_id != Some(MICROSOFT_GRAPH_APP_ID) {
        return None;
    }
    match value {
        "Sites.Selected" => Some(SelectedScopeLevel::Site),
        SP_LISTS_SELECTED => Some(SelectedScopeLevel::List),
        SP_LIST_ITEMS_SELECTED => Some(SelectedScopeLevel::ListItem),
        SP_FILES_SELECTED => Some(SelectedScopeLevel::File),
        _ => None,
    }
}

/// True when `value` is one of the **sub-site** Selected scopes — the positive
/// gate for [`ScopeKind::SharePointItem`], one level below the site gate in
/// [`is_scoped_sharepoint_resource_permission`].
///
/// Positive and resource-aware by construction, like every other scoping gate
/// here. A value-only form would read `Files.SelectedOperations.Selected` on
/// Office 365 SharePoint Online as scopable and offer a grant flow that writes
/// nothing the toolkit can verify — the same silent-widening bug the mailbox and
/// SharePoint value-only helpers were deleted for, which `repo_invariants.rs`
/// fails the build over if one returns.
pub fn is_scoped_sharepoint_item_resource_permission(
    resource_app_id: Option<&str>,
    value: &str,
) -> bool {
    selected_scope_level_for(resource_app_id, value)
        .is_some_and(SelectedScopeLevel::breaks_inheritance)
}

/// True when a Selected scope at `scope` level can grant against a resource the
/// resolver classified as `resolved` — the **fail-closed** check that stops a
/// grant landing one level away from where the operator aimed it.
///
/// Almost equality, with one deliberate asymmetry taken straight from
/// Microsoft's model: *all files are list items, but not all list items are
/// files*. So `ListItems.SelectedOperations.Selected` can grant against an item
/// in a document library, while `Files.SelectedOperations.Selected` cannot
/// reach an item in a plain list. Collapsing the two would silently widen a
/// `Files.*` grant, and rejecting the compatible direction would refuse a
/// perfectly valid `ListItems.*` grant on a folder.
pub fn selected_scope_accepts(scope: SelectedScopeLevel, resolved: SelectedScopeLevel) -> bool {
    match (scope, resolved) {
        (SelectedScopeLevel::ListItem, SelectedScopeLevel::File) => true,
        (a, b) => a == b,
    }
}

/// True for an org-wide SharePoint permission *by name* — every `Sites.*`
/// except `Sites.Selected` (the scoped model).
///
/// Name-shaped only. `Sites.*` lives on **two** resources, exactly like the
/// mailbox family: Microsoft Graph and Office 365 SharePoint Online. A caller
/// that knows the resource must use [`is_sharepoint_orgwide_permission`] to
/// classify and [`is_scopable_sharepoint_resource_permission`] to decide
/// whether a fix may be offered.
pub fn is_sharepoint_orgwide(value: &str) -> bool {
    value.starts_with("Sites.") && value != "Sites.Selected"
}

/// True when a grant reaches SharePoint site content org-wide, on either
/// resource. A `None` resource falls back to the name-shaped check, so a build
/// that cannot resolve the resource reports reach rather than dropping it.
pub fn is_sharepoint_orgwide_permission(resource_app_id: Option<&str>, value: &str) -> bool {
    match resource_app_id {
        Some(MICROSOFT_GRAPH_APP_ID) | Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID) | None => {
            is_sharepoint_orgwide(value)
        }
        // Some other resource that happens to expose a `Sites.`-prefixed role
        // is not SharePoint site access.
        Some(_) => false,
    }
}

/// True when an org-wide `Sites.*` grant is one the toolkit's `Sites.Selected`
/// conversion can actually confine — **the positive gate** for offering the
/// [`crate::audit::RemediationKind::ScopeSharePointAccess`] fix.
///
/// Only Microsoft Graph qualifies, and the reason is in the handler rather than
/// in the permission model: `convert_site_access_to_selected` resolves the
/// `Sites.Selected` appRole on the *Microsoft Graph* service principal and
/// strips org-wide grants whose `resource_id` is Graph's. Run against a grant on
/// Office 365 SharePoint Online it would add Graph's `Sites.Selected`, grant the
/// per-site permissions, strip **nothing**, and leave the app just as org-wide
/// as before — while the audit re-scored it as confined.
///
/// Both resources *can* be confined by the `Sites.Selected` model in principle
/// (per-site grants apply to Graph and the SharePoint REST APIs alike), so this
/// is a limit of the current handler, not of Microsoft's model: teach
/// `convert_site_access_to_selected` to grant and strip on the SharePoint
/// resource too and this gate can widen. Until then it must stay closed — an
/// unresolved (`None`) resource included.
pub fn is_scopable_sharepoint_resource_permission(
    resource_app_id: Option<&str>,
    value: &str,
) -> bool {
    resource_app_id == Some(MICROSOFT_GRAPH_APP_ID) && is_sharepoint_orgwide(value)
}

/// True when a `Sites.Selected` grant is the confined end state **this toolkit
/// can verify** — the positive gate for the healthy `SCOPED_SHAREPOINT` audit
/// note, and the counterpart to [`is_scopable_sharepoint_resource_permission`].
///
/// Deliberately NOT expressible through that function: it is the *org-wide*
/// gate, and `is_sharepoint_orgwide` excludes `Sites.Selected` by construction
/// (`value != "Sites.Selected"`), so reusing it here would always answer false.
///
/// Only Microsoft Graph qualifies, mirroring the handler limit documented
/// above. Office 365 SharePoint Online also exposes `Sites.Selected`, and a
/// grant of it there *is* genuinely confined in SharePoint's own model — but
/// the per-site grants this toolkit reads and writes are Graph's, so it can
/// neither verify which sites that grant reaches nor manage it. Claiming the
/// healthy verdict on a grant it cannot inspect is the same false-confidence
/// bug as the mailbox side's, so the legacy resource gets no note in either
/// direction: not org-wide (it isn't), and not confirmed-scoped (unverifiable).
pub fn is_scoped_sharepoint_resource_permission(
    resource_app_id: Option<&str>,
    value: &str,
) -> bool {
    resource_app_id == Some(MICROSOFT_GRAPH_APP_ID) && value == "Sites.Selected"
}

/// Which scoping *authority* can confine a Graph application permission. Each
/// mechanism has its own target type and apply strategy, but the scope UX shell
/// (pick permission → choose targets → review) is uniform across them — this enum
/// is the dispatch key. Add a variant (plus a target panel + apply arm) to teach
/// the app a new mechanism; nothing else branches on the concrete mechanism.
///
/// Distinct from [`crate::audit::ScopeMechanism`], which is the Exchange-*internal*
/// detail (RBAC vs legacy Application Access Policy) of how mail is confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// Mail/calendar/contacts → confine to mailbox group(s) via Exchange RBAC.
    Exchange,
    /// `Sites.*` → confine to specific sites via `Sites.Selected`.
    SharePoint,
    /// The sub-site Selected scopes (`Lists.`/`ListItems.`/`Files.`
    /// `SelectedOperations.Selected`) → confine to specific lists, folders or
    /// files.
    ///
    /// A separate mechanism from [`ScopeKind::SharePoint`] rather than a mode of
    /// it: the target is a different securable, resolved from a different URL
    /// shape and granted through a different endpoint, so a cart mixing the two
    /// has no single target panel to show and must fall back to org-wide.
    SharePointItem,
    // Future: AdministrativeUnit (directory perms), AzureRbac (ARM/MI),
    // ResourceSpecificConsent (Teams/Chat — owner-consented, see `admin_applicable`).
}

impl ScopeKind {
    /// Capabilities-catalog key for the role hint a scope action surfaces.
    pub fn capability_key(self) -> &'static str {
        match self {
            ScopeKind::Exchange => "exchange_rbac",
            ScopeKind::SharePoint => "sharepoint_sites_selected",
            // NOT the same key as `SharePoint`, despite the identical scope:
            // the two mechanisms differ on the *user* half. A delegated call is
            // the intersection of the token's scopes and the caller's own
            // SharePoint permissions, and a sub-site grant writes onto a
            // securable inside the site's content — which the tenant
            // SharePoint Administrator role does not reach. Sharing one key
            // made the proactive hint promise a role that isn't sufficient.
            ScopeKind::SharePointItem => "sharepoint_selected_items",
        }
    }

    /// Whether an admin can apply this scoping centrally. Future owner-consented
    /// mechanisms (Teams/Chat resource-specific consent) return `false`, so the UI
    /// renders guidance instead of an apply button rather than offering a control
    /// that can't work.
    pub fn admin_applicable(self) -> bool {
        match self {
            ScopeKind::Exchange | ScopeKind::SharePoint | ScopeKind::SharePointItem => true,
        }
    }
}

/// The mechanism (if any) that can resource-scope `value` on `resource_app_id`.
/// Single source of truth: mail/calendar/contacts and the EWS
/// `full_access_as_app` scope → Exchange RBAC; `Sites.Selected` or a broad
/// `Sites.*` → SharePoint `Sites.Selected`; a sub-site Selected scope
/// (`Lists.`/`ListItems.`/`Files.SelectedOperations.Selected`) → per-item
/// SharePoint grants; everything else (e.g. `Directory.Read.All`) is org-wide
/// only and returns `None`.
///
/// The resource decides whether the mechanism can be applied at all. Office 365
/// Exchange Online's retired Outlook REST `Mail.*` appRoles and Office 365
/// SharePoint Online's `Sites.*` share their names with Graph's, and neither is
/// something this toolkit can confine. Inferring a mechanism from the name
/// alone offers the operator a "Scope…" action that resolves to a no-op against
/// that resource, while the grant stays org-wide.
pub fn scope_kind_for(resource_app_id: Option<&str>, value: &str) -> Option<ScopeKind> {
    if is_scopable_exchange_resource_permission(resource_app_id, value) {
        Some(ScopeKind::Exchange)
    } else if is_scoped_sharepoint_resource_permission(resource_app_id, value)
        || is_scopable_sharepoint_resource_permission(resource_app_id, value)
    {
        Some(ScopeKind::SharePoint)
    } else if is_scoped_sharepoint_item_resource_permission(resource_app_id, value) {
        Some(ScopeKind::SharePointItem)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_common_mail_permissions() {
        assert_eq!(
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Mail.Read"),
            Some("Application Mail.Read")
        );
        assert_eq!(
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Calendars.ReadWrite"),
            Some("Application Calendars.ReadWrite")
        );
        assert_eq!(
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Mail.ReadBasic.All"),
            Some("Application Mail.ReadBasic")
        );
    }

    #[test]
    fn unmapped_permission_returns_none() {
        assert_eq!(
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "User.Read.All"),
            None
        );
        assert!(!is_scopable_exchange_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Directory.Read.All"
        ));
        assert!(is_scopable_exchange_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Mail.Send"
        ));
    }

    #[test]
    fn ews_full_access_as_app_maps_on_the_exchange_online_resource() {
        // The one non-Graph permission Application Access Policies could
        // confine. It must map, or an AAP migration silently leaves the app with
        // org-wide EWS access to every mailbox.
        assert_eq!(
            exchange_role_for_resource_permission(
                OFFICE365_EXCHANGE_ONLINE_APP_ID,
                EWS_FULL_ACCESS_AS_APP
            ),
            Some("Application EWS.AccessAsApp")
        );
        assert!(is_scopable_exchange_resource_permission(
            Some(OFFICE365_EXCHANGE_ONLINE_APP_ID),
            EWS_FULL_ACCESS_AS_APP
        ));
        assert_eq!(
            scope_kind_for(
                Some(OFFICE365_EXCHANGE_ONLINE_APP_ID),
                EWS_FULL_ACCESS_AS_APP
            ),
            Some(ScopeKind::Exchange)
        );
        // ...and only on that resource — Graph never exposes it.
        assert_eq!(
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, EWS_FULL_ACCESS_AS_APP),
            None
        );
    }

    #[test]
    fn exchange_online_mail_lookalikes_have_no_rbac_role() {
        // Office 365 Exchange Online exposes its own `Mail.Read`-style appRoles
        // for the retired Outlook REST API. RBAC for Applications covers only MS
        // Graph and EWS, so those must NOT map — claiming otherwise would report
        // a scope the toolkit can't enforce and would strip a grant with no
        // scoped replacement.
        for value in ["Mail.Read", "Mail.Send", "Calendars.ReadWrite"] {
            assert_eq!(
                exchange_role_for_resource_permission(OFFICE365_EXCHANGE_ONLINE_APP_ID, value),
                None,
                "{value} on Office 365 Exchange Online must not map to an RBAC role"
            );
            // The same value on Graph does map.
            assert!(exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, value).is_some());
        }
    }

    #[test]
    fn unscopable_legacy_exchange_permissions_are_the_outlook_rest_family_only() {
        // The set the UI calls out: named like a Graph mail permission, but on the
        // legacy resource, so no RBAC role can confine it.
        for value in [
            "Mail.Read",
            "Mail.ReadWrite",
            "Mail.Send",
            "Calendars.ReadWrite",
            "Contacts.ReadWrite",
            "MailboxSettings.Read",
        ] {
            assert!(
                is_unscopable_legacy_exchange_permission(OFFICE365_EXCHANGE_ONLINE_APP_ID, value),
                "{value} on Office 365 Exchange Online is unscopable and must be called out"
            );
            // The identically named Graph permission is scopable, never called out.
            assert!(!is_unscopable_legacy_exchange_permission(
                MICROSOFT_GRAPH_APP_ID,
                value
            ));
        }
    }

    #[test]
    fn unscopable_legacy_exchange_spares_the_live_protocol_roles() {
        // Load-bearing exclusions: `full_access_as_app` IS scopable, and the rest
        // back EWS / Exchange Online PowerShell / IMAP / POP / SMTP. Calling any of
        // them "remove this" would break a working integration.
        for value in [
            EWS_FULL_ACCESS_AS_APP,
            "EWS.AccessAsApp",
            "Exchange.ManageAsApp",
            "IMAP.AccessAsApp",
            "POP.AccessAsApp",
            "SMTP.SendAsApp",
        ] {
            assert!(
                !is_unscopable_legacy_exchange_permission(OFFICE365_EXCHANGE_ONLINE_APP_ID, value),
                "{value} backs a live protocol (or is scopable) — must never be called out"
            );
        }
    }

    #[test]
    fn unknown_resource_maps_nothing() {
        assert_eq!(
            exchange_role_for_resource_permission(
                "11111111-2222-3333-4444-555555555555",
                "Mail.Read"
            ),
            None
        );
    }

    #[test]
    fn only_ews_full_access_is_a_blanket_grant() {
        // A blanket grant vetoes every per-permission scope verdict, so the set
        // must stay exactly the permission that really reaches all mailboxes.
        assert!(is_blanket_mailbox_grant(EWS_FULL_ACCESS_AS_APP));
        assert!(!is_blanket_mailbox_grant("Mail.ReadWrite"));
        assert!(!is_blanket_mailbox_grant("Mail.Read"));
    }

    #[test]
    fn loose_mail_lookalikes_are_not_scopable() {
        // The map is authoritative: these look mail-ish but have no Exchange
        // application role, so a prefix check would wrongly call them scopable.
        assert!(!is_scopable_exchange_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Mail.ReadWrite.Shared"
        ));
        assert!(!is_scopable_exchange_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "MailboxSettings.ReadBasic"
        ));
    }

    #[test]
    fn mailbox_reach_is_resource_aware_and_includes_the_ews_blanket_scope() {
        // The whole point of the resource-aware form: a bare `Mail.*` name test
        // cannot see `full_access_as_app` (full access to every mailbox in the
        // tenant), and cannot tell the legacy resource's unscopable Outlook REST
        // roles from Graph's confinable namesakes.
        let graph = Some(MICROSOFT_GRAPH_APP_ID);
        let exo = Some(OFFICE365_EXCHANGE_ONLINE_APP_ID);

        assert!(is_mailbox_reaching_permission(graph, "Mail.Read"));
        assert!(is_mailbox_reaching_permission(
            graph,
            "MailboxSettings.ReadWrite"
        ));
        // Named nothing like a mail permission, but reaches every mailbox.
        assert!(is_mailbox_reaching_permission(exo, EWS_FULL_ACCESS_AS_APP));
        // Graph never exposes it, so it is not mail-reaching *there*.
        assert!(!is_mailbox_reaching_permission(
            graph,
            EWS_FULL_ACCESS_AS_APP
        ));
        // The legacy Outlook REST family still reaches mailboxes (and defeats the
        // Graph namesake's scope), so it must be classified in.
        assert!(is_mailbox_reaching_permission(exo, "Mail.Read"));
        // ...but the live-protocol roles on that resource are not mailbox reach.
        for value in ["Exchange.ManageAsApp", "IMAP.AccessAsApp", "SMTP.SendAsApp"] {
            assert!(
                !is_mailbox_reaching_permission(exo, value),
                "{value} backs a live protocol, not org-wide mailbox reach"
            );
        }
        // Non-mail permissions are never mailbox reach.
        assert!(!is_mailbox_reaching_permission(graph, "Directory.Read.All"));
        // Unknown resource falls back to the name shape — over-report, never under.
        assert!(is_mailbox_reaching_permission(None, "Mail.Read"));
        assert!(!is_mailbox_reaching_permission(None, "Directory.Read.All"));
    }

    #[test]
    fn every_confinable_graph_mail_permission_reaches_mailboxes() {
        // The advisory's membership test must be a SUPERSET of what can be
        // scoped, or a grant is confinable but never offered the fix. This used
        // to test `Mail.` / `MailboxSettings.` prefixes only, so Graph's
        // `Calendars.*` and `Contacts.*` — which `graph_mail_role` maps to real
        // RBAC-for-Applications roles — produced no mailbox finding and no
        // `ScopeMailboxAccess` fix, while the identically named grant on the
        // LEGACY resource was classified in. Org-wide calendar and contacts
        // access across every mailbox simply did not appear in the audit.
        let graph = Some(MICROSOFT_GRAPH_APP_ID);
        for value in [
            "Mail.Read",
            "Mail.ReadBasic",
            "Mail.ReadBasic.All",
            "Mail.ReadWrite",
            "Mail.Send",
            "MailboxSettings.Read",
            "MailboxSettings.ReadWrite",
            "Calendars.Read",
            "Calendars.ReadWrite",
            "Contacts.Read",
            "Contacts.ReadWrite",
        ] {
            assert!(
                graph_mail_role(value).is_some(),
                "{value} should map to an Exchange RBAC role"
            );
            assert!(
                is_mailbox_reaching_permission(graph, value),
                "{value} is confinable on Graph, so it must enter the mailbox advisory"
            );
            assert!(
                is_scopable_exchange_resource_permission(graph, value),
                "{value} must remain offerable for scoping"
            );
        }
        // The legacy namesakes stay classified in (they defeat the Graph
        // scope) but are still NOT scopable — the asymmetry that must hold.
        let exo = Some(OFFICE365_EXCHANGE_ONLINE_APP_ID);
        for value in ["Calendars.Read", "Contacts.ReadWrite"] {
            assert!(is_mailbox_reaching_permission(exo, value));
            assert!(!is_scopable_exchange_resource_permission(exo, value));
        }
        // Non-mailbox Graph permissions sharing no prefix are still excluded.
        for value in ["Directory.Read.All", "Files.ReadWrite.All", "User.Read.All"] {
            assert!(!is_mailbox_reaching_permission(graph, value));
        }
    }

    #[test]
    fn the_sharepoint_fix_gate_is_positive_and_graph_only() {
        // Mirrors `is_scopable_exchange_resource_permission`: a POSITIVE test,
        // so an unmapped or unresolved resource fails closed instead of
        // inheriting a fix that cannot apply to it.
        assert!(is_scopable_sharepoint_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Sites.Read.All"
        ));
        assert!(!is_scopable_sharepoint_resource_permission(
            Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID),
            "Sites.Read.All"
        ));
        assert!(
            !is_scopable_sharepoint_resource_permission(None, "Sites.Read.All"),
            "an unresolved resource must not earn a fix"
        );
        // Already the scoped model — nothing to convert.
        assert!(!is_scopable_sharepoint_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Sites.Selected"
        ));
    }

    #[test]
    fn the_scoped_sharepoint_gate_is_positive_and_cannot_be_derived_from_the_orgwide_one() {
        // The healthy note needs its OWN gate: `is_sharepoint_orgwide` excludes
        // Sites.Selected by construction, so routing this question through
        // `is_scopable_sharepoint_resource_permission` always answers false —
        // which is why the note was value-keyed in the first place.
        assert!(!is_scopable_sharepoint_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Sites.Selected"
        ));
        assert!(is_scoped_sharepoint_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Sites.Selected"
        ));
        // The legacy resource's Sites.Selected is genuinely confined in
        // SharePoint's own model, but the per-site grants this toolkit reads are
        // Graph's — unverifiable here, so no healthy claim.
        assert!(!is_scoped_sharepoint_resource_permission(
            Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID),
            "Sites.Selected"
        ));
        assert!(
            !is_scoped_sharepoint_resource_permission(None, "Sites.Selected"),
            "an unresolved resource must not earn a healthy verdict"
        );
        // Only the scoped model qualifies — a broad grant is not "scoped".
        assert!(!is_scoped_sharepoint_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Sites.Read.All"
        ));
    }

    /// The whole Selected family, at every resource, in one table — the gate a
    /// `Files.SelectedOperations.Selected` grant has to pass before the wizard
    /// will offer it a target panel.
    #[test]
    fn the_selected_family_maps_to_its_level_on_graph_only() {
        let levels = [
            ("Sites.Selected", SelectedScopeLevel::Site),
            (SP_LISTS_SELECTED, SelectedScopeLevel::List),
            (SP_LIST_ITEMS_SELECTED, SelectedScopeLevel::ListItem),
            (SP_FILES_SELECTED, SelectedScopeLevel::File),
        ];
        for (value, level) in levels {
            assert_eq!(
                selected_scope_level_for(Some(MICROSOFT_GRAPH_APP_ID), value),
                Some(level),
                "{value} is Graph's Selected scope for the {} level",
                level.label()
            );
            // Office 365 SharePoint Online exposes look-alikes this toolkit can
            // neither verify nor manage, and an unresolved resource is never a
            // reason to widen — both stay closed.
            for resource in [Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID), None] {
                assert_eq!(
                    selected_scope_level_for(resource, value),
                    None,
                    "{value} must not resolve a level off Microsoft Graph"
                );
            }
        }
        // The org-wide siblings are not Selected scopes: they need converting,
        // which is Rule 12's job, not this gate's.
        for value in ["Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All"] {
            assert_eq!(
                selected_scope_level_for(Some(MICROSOFT_GRAPH_APP_ID), value),
                None,
                "{value} is org-wide, not a Selected scope"
            );
        }
    }

    #[test]
    fn the_item_gate_is_the_sub_site_levels_and_they_break_inheritance() {
        // Positive, resource-aware, and strictly below the site level: the site
        // scope has its own ScopeKind and its own target panel.
        assert!(!is_scoped_sharepoint_item_resource_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "Sites.Selected"
        ));
        for value in [SP_LISTS_SELECTED, SP_LIST_ITEMS_SELECTED, SP_FILES_SELECTED] {
            assert!(is_scoped_sharepoint_item_resource_permission(
                Some(MICROSOFT_GRAPH_APP_ID),
                value
            ));
            assert!(!is_scoped_sharepoint_item_resource_permission(
                Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID),
                value
            ));
            assert!(
                !is_scoped_sharepoint_item_resource_permission(None, value),
                "{value} on an unresolved resource must not offer a grant flow"
            );
        }
        // Only the site level is the root of inheritance; everything below
        // breaks it, which is what the operator has to be warned about.
        assert!(!SelectedScopeLevel::Site.breaks_inheritance());
        for level in [
            SelectedScopeLevel::List,
            SelectedScopeLevel::ListItem,
            SelectedScopeLevel::File,
        ] {
            assert!(level.breaks_inheritance());
        }
    }

    #[test]
    fn selected_scopes_dispatch_to_the_item_mechanism_not_the_site_one() {
        // The reported bug: these returned `None`, so the wizard offered no
        // scoping at all and fell through to an org-wide grant.
        for value in [SP_LISTS_SELECTED, SP_LIST_ITEMS_SELECTED, SP_FILES_SELECTED] {
            assert_eq!(
                scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), value),
                Some(ScopeKind::SharePointItem),
                "{value} must reach the per-item mechanism"
            );
            assert_eq!(
                scope_kind_for(Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID), value),
                None
            );
        }
        // The site family is untouched by the new arm.
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Sites.Selected"),
            Some(ScopeKind::SharePoint)
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Sites.Read.All"),
            Some(ScopeKind::SharePoint)
        );
        // The two SharePoint mechanisms answer to DIFFERENT operator
        // capabilities. Same scope, different user-side requirement: a sub-site
        // grant also needs Full Control on the target site, which the tenant
        // SharePoint Administrator role doesn't confer. Sharing one key made
        // the hint name a role that isn't sufficient.
        assert_ne!(
            ScopeKind::SharePointItem.capability_key(),
            ScopeKind::SharePoint.capability_key()
        );
        assert!(ScopeKind::SharePointItem.admin_applicable());
    }

    /// The one place a grant can land somewhere the operator didn't aim it, so
    /// the table is spelled out in full rather than derived.
    #[test]
    fn a_scope_accepts_only_the_levels_it_can_actually_reach() {
        use SelectedScopeLevel::{File, List, ListItem, Site};

        // Every level accepts its own target.
        for level in [Site, List, ListItem, File] {
            assert!(selected_scope_accepts(level, level));
        }
        // All files are list items: a ListItems.* scope reaches a document
        // library item, which is the common case for a folder grant.
        assert!(selected_scope_accepts(ListItem, File));
        // But not all list items are files: Files.* must NOT reach an item in a
        // plain list, or the grant silently widens past what was consented.
        assert!(!selected_scope_accepts(File, ListItem));
        // No level ever reaches up the hierarchy. Pointing a Files.* grant at a
        // site URL is the mistake this check exists to refuse.
        for (scope, resolved) in [
            (File, Site),
            (File, List),
            (ListItem, Site),
            (ListItem, List),
            (List, Site),
            (List, File),
            (Site, List),
            (Site, File),
        ] {
            assert!(
                !selected_scope_accepts(scope, resolved),
                "a {} scope must not grant against a {}",
                scope.label(),
                resolved.label()
            );
        }
    }

    /// A Selected scope is the least-privilege end state, so it must never be
    /// mistaken for org-wide reach the way a broad `Sites.*` is.
    #[test]
    fn selected_scopes_are_never_reported_as_orgwide() {
        for value in [SP_LISTS_SELECTED, SP_LIST_ITEMS_SELECTED, SP_FILES_SELECTED] {
            assert!(!is_sharepoint_orgwide(value));
            for resource in [
                Some(MICROSOFT_GRAPH_APP_ID),
                Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID),
                None,
            ] {
                assert!(!is_sharepoint_orgwide_permission(resource, value));
            }
            // Nor as something the Sites.Selected conversion should be offered for.
            assert!(!is_scopable_sharepoint_resource_permission(
                Some(MICROSOFT_GRAPH_APP_ID),
                value
            ));
        }
    }

    #[test]
    fn sharepoint_reach_is_reported_on_both_resources() {
        for resource in [
            Some(MICROSOFT_GRAPH_APP_ID),
            Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID),
            None,
        ] {
            assert!(
                is_sharepoint_orgwide_permission(resource, "Sites.FullControl.All"),
                "{resource:?} reaches site content org-wide"
            );
            assert!(!is_sharepoint_orgwide_permission(
                resource,
                "Sites.Selected"
            ));
        }
        // A `Sites.`-prefixed role on some unrelated resource isn't SharePoint.
        assert!(!is_sharepoint_orgwide_permission(
            Some(OFFICE365_EXCHANGE_ONLINE_APP_ID),
            "Sites.Read.All"
        ));
    }

    #[test]
    fn sharepoint_org_wide_is_every_sites_except_selected() {
        assert!(is_sharepoint_orgwide("Sites.Read.All"));
        assert!(is_sharepoint_orgwide("Sites.ReadWrite.All"));
        assert!(is_sharepoint_orgwide("Sites.FullControl.All"));
        assert!(!is_sharepoint_orgwide("Sites.Selected"));
        assert!(!is_sharepoint_orgwide("Mail.Read"));
        assert!(!is_sharepoint_orgwide("Directory.Read.All"));
    }

    #[test]
    fn scope_kind_classifies_by_mechanism() {
        // Mail/calendar/contacts → Exchange RBAC.
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Mail.Read"),
            Some(ScopeKind::Exchange)
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Calendars.ReadWrite"),
            Some(ScopeKind::Exchange)
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Contacts.Read"),
            Some(ScopeKind::Exchange)
        );
        // Both the scoped model and a broad Sites.* → SharePoint.
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Sites.Selected"),
            Some(ScopeKind::SharePoint)
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Sites.Read.All"),
            Some(ScopeKind::SharePoint)
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Sites.FullControl.All"),
            Some(ScopeKind::SharePoint)
        );
        // Org-wide-only permissions are not scopable.
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Directory.Read.All"),
            None
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "User.Read.All"),
            None
        );
        // A mail look-alike with no Exchange role is not scopable.
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Mail.ReadWrite.Shared"),
            None
        );
    }

    #[test]
    fn scope_kind_metadata_is_per_mechanism() {
        assert_eq!(ScopeKind::Exchange.capability_key(), "exchange_rbac");
        assert_eq!(
            ScopeKind::SharePoint.capability_key(),
            "sharepoint_sites_selected"
        );
        // The sub-site mechanism carries its OWN key: same scope, different
        // user-side requirement (Full Control on the target site).
        assert_eq!(
            ScopeKind::SharePointItem.capability_key(),
            "sharepoint_selected_items"
        );
        assert!(ScopeKind::Exchange.admin_applicable());
        assert!(ScopeKind::SharePoint.admin_applicable());
    }
}

#[cfg(test)]
mod resource_aware_gate_tests {
    use super::*;

    /// The defect this pair of functions exists to separate.
    ///
    /// Both mailbox resources expose appRoles named `Mail.Read`, `Contacts.Read`
    /// and friends, and only Microsoft Graph's can be confined by RBAC for
    /// Applications — Office 365 Exchange Online's are the retired Outlook REST
    /// family, which nothing here can scope. A value-only gate could not see the
    /// difference, so it reported the legacy grant as scopable: the audit
    /// counted mailbox reach it could not confine, the effective-scope probe
    /// offered it as a candidate, and a legacy AAP verdict scored it at the
    /// reduced "scoped" weight — hiding org-wide mailbox access behind a
    /// healthy-looking badge. There is no value-only gate left to make that
    /// mistake; this pins the distinction the surviving one has to draw.
    #[test]
    fn the_legacy_namesake_is_not_scopable_even_though_it_shares_the_name() {
        for value in ["Mail.Read", "Mail.Send", "Contacts.Read", "Calendars.Read"] {
            assert!(
                is_scopable_exchange_resource_permission(Some(MICROSOFT_GRAPH_APP_ID), value),
                "Graph's {value} IS confinable by RBAC for Applications"
            );
            assert!(
                !is_scopable_exchange_resource_permission(
                    Some(OFFICE365_EXCHANGE_ONLINE_APP_ID),
                    value
                ),
                "Office 365 Exchange Online's {value} is retired Outlook REST — unscopable"
            );
        }
    }

    #[test]
    fn an_unresolved_resource_is_never_scopable() {
        // Conservative by construction: an unresolvable resource can only
        // over-report risk, never under-report it.
        for value in ["Mail.Read", EWS_FULL_ACCESS_AS_APP, "Sites.Read.All"] {
            assert!(!is_scopable_exchange_resource_permission(None, value));
            assert_eq!(scope_kind_for(None, value), None);
        }
    }

    #[test]
    fn the_ews_scope_is_scopable_only_on_the_resource_that_defines_it() {
        assert_eq!(
            scope_kind_for(
                Some(OFFICE365_EXCHANGE_ONLINE_APP_ID),
                EWS_FULL_ACCESS_AS_APP
            ),
            Some(ScopeKind::Exchange),
            "full_access_as_app lives only on Office 365 Exchange Online"
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), EWS_FULL_ACCESS_AS_APP),
            None,
            "Graph does not define it, so no mechanism applies there"
        );
        // The display-only form stays optimistic so a bare-value badge still
        // recognises the most dangerous mailbox grant there is.
        assert_eq!(
            scope_kind_for(
                Some(OFFICE365_EXCHANGE_ONLINE_APP_ID),
                EWS_FULL_ACCESS_AS_APP
            ),
            Some(ScopeKind::Exchange)
        );
    }

    #[test]
    fn a_mechanism_is_inferred_only_where_it_can_actually_be_applied() {
        // The ScopeWizard turns this into an apply step. On the legacy
        // resources the apply is a no-op that leaves the grant org-wide, so no
        // mechanism must be offered at all.
        assert_eq!(
            scope_kind_for(Some(OFFICE365_EXCHANGE_ONLINE_APP_ID), "Mail.Read"),
            None
        );
        assert_eq!(
            scope_kind_for(Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID), "Sites.Read.All"),
            None
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Sites.Read.All"),
            Some(ScopeKind::SharePoint)
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Sites.Selected"),
            Some(ScopeKind::SharePoint),
            "already-scoped still reports its mechanism, so the wizard can re-target it"
        );
        assert_eq!(
            scope_kind_for(Some(MICROSOFT_GRAPH_APP_ID), "Directory.Read.All"),
            None
        );
    }

    #[test]
    fn least_privilege_advice_is_not_offered_where_it_cannot_be_followed() {
        assert_eq!(
            crate::audit::least_privilege_alternative_for(
                Some(MICROSOFT_GRAPH_APP_ID),
                "Mail.Read"
            ),
            Some("Scope to specific mailboxes (Exchange RBAC)")
        );
        assert_eq!(
            crate::audit::least_privilege_alternative_for(
                Some(OFFICE365_EXCHANGE_ONLINE_APP_ID),
                "Mail.Read"
            ),
            None,
            "telling an operator to scope an unscopable grant sends them after a fix that \
             cannot be applied, and implies the grant is containable when removal is the \
             only remedy"
        );
    }
}
