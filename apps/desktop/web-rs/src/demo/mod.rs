//! Standalone browser demo wiring for the GitHub Pages build. Installs the
//! shared mock IPC bridge ([`crate::ipc_mock`]) pre-loaded with curated sample
//! data and signs into a demo tenant, so the **full UI runs in a plain browser
//! with no Tauri backend**.
//!
//! Read commands are answered from fixtures; everything else — mutations (grant,
//! delete, scope, create secret), exports, sign-out — is left unregistered and
//! degrades to a friendly "not available in the live demo" error toast via
//! [`Unmocked::DemoFriendly`]. The handful of infallible `invoke()` commands
//! (which would *panic* on a rejected promise) are registered explicitly.
//! `tests/demo_fixture_coverage.rs` holds all three sides of that: every
//! infallible invoke is registered, every fallible read is registered or
//! explained, and every registration names a command a binding still invokes.
//!
//! Detail commands are registered **args-aware** ([`mock_each`]) so each selected
//! app/SP returns its own payload (otherwise the detail pane wouldn't switch).
//! All ids are deterministic synthetic GUIDs ([`fixtures::guid`]) so they look
//! like real Entra ids while staying stable across reloads.
//!
//! **One catalog, many surfaces.** The audit run, the credential-expiry board,
//! the SSO certificate board, the site sweep and the mailbox lookup are all
//! built from — or re-keyed onto — the same catalog ([`catalog`],
//! [`ENTERPRISE_APPS`]) through the pure builders below. That is what makes
//! "Open" from any of those rows land on the app it names instead of a
//! placeholder, and it is pinned by this module's tests, which `just web-test`
//! runs natively with the `demo` feature on.
//!
//! Compiled only under the `demo` feature, so none of this — nor the mock bridge
//! or fixtures it pulls in — ever enters the shipped desktop Trunk bundle.

use std::collections::{HashMap, HashSet};

use azapptoolkit_core::audit::{MailPermissionScope, RiskLevel, ScopeMechanism};
use azapptoolkit_core::identity::TenantContext;
use azapptoolkit_core::models::{Application, KeyCredential, PasswordCredential};
use azapptoolkit_core::scoping::{
    OFFICE365_SHAREPOINT_ONLINE_APP_ID, exchange_role_for_resource_permission,
};
use azapptoolkit_dto::applications::{
    ApplicationDetail, ApplicationListRowDto, DirectoryIndexStatus,
};
use azapptoolkit_dto::audit::{AuditRunResult, CachedAuditSummary};
use azapptoolkit_dto::credentials::CredentialRowDto;
use azapptoolkit_dto::enterprise_application::{
    EnterpriseApplicationDetail, EnterpriseApplicationDto,
};
use azapptoolkit_dto::exchange::{ExchangeRoleAssignmentDto, MailScopeEntry};
use azapptoolkit_dto::managed_identity::MiSubtype;
use azapptoolkit_dto::permission_tester::MailboxReachersResult;
use azapptoolkit_dto::permissions::{PermissionKind, ResolvedPermission};
use azapptoolkit_dto::search::GlobalSearchResults;
use azapptoolkit_dto::sharepoint::{AppSiteAccessDto, SitePermissionDto, SiteSweepResult};
use azapptoolkit_dto::sso::SsoCertificateRowDto;
use chrono::{DateTime, Utc};

use crate::ipc_mock::{self, Unmocked, fixtures as f, mock_each, mock_ok};

/// Microsoft Graph — the resource most demo held-permissions are exposed by.
const GRAPH: &str = f::MICROSOFT_GRAPH_APP_ID;

/// The demo tenant's id (mirrors [`demo_tenant`]).
const DEMO_TENANT_ID: &str = "demo-tenant";

fn obj_id(name: &str) -> String {
    f::guid(&format!("{name}:obj"))
}
fn app_id(name: &str) -> String {
    f::guid(&format!("{name}:app"))
}

/// Deterministically pick one of `n` fixture variants from an id, so per-id
/// reads (held grants, Azure roles) differ across principals but stay stable
/// across reloads for a given principal.
fn variant_index(id: &str, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    id.bytes().map(usize::from).sum::<usize>() % n
}

/// A string argument of a mocked call (camelCase key), or `""`.
fn arg<'a>(args: &'a serde_json::Value, key: &str) -> &'a str {
    args.get(key).and_then(|v| v.as_str()).unwrap_or_default()
}

/// The signed-in tenant the demo presents (presentable copy; mirrors
/// `test_support::test_tenant`). `App` seeds this as the active tenant so the
/// config + sign-in gates fall through straight to the authenticated shell.
pub fn demo_tenant() -> TenantContext {
    TenantContext {
        tenant_id: DEMO_TENANT_ID.to_string(),
        account_oid: f::guid("demo:admin"),
        username: Some("admin@contoso.onmicrosoft.com".to_string()),
        display_name: Some("Contoso Ltd (demo)".to_string()),
    }
}

/// Install the mock bridge, switch unmocked commands to the friendly demo
/// fallback, and register sample data for every read surface. Called once from
/// [`crate::run`] before the app mounts.
pub fn install() {
    ipc_mock::reset();
    ipc_mock::set_unmocked_mode(Unmocked::DemoFriendly);
    register_fixtures();
}

/// One curated app registration: its display name, credentials, held permissions,
/// and (optional) Exchange mailbox scoping. Ids are derived from the name. The
/// list badge is NOT stored here: [`list_row`] classifies the credentials with
/// the backend's own policy, so it can't disagree with the Credentials tab.
struct DemoApp {
    name: &'static str,
    secrets: Vec<PasswordCredential>,
    certs: Vec<KeyCredential>,
    perms: Vec<ResolvedPermission>,
    mail_scopes: Vec<MailScopeEntry>,
}

/// An Application-kind held permission on Microsoft Graph.
fn app_perm(value: &str, display: &str) -> ResolvedPermission {
    f::resolved_permission(
        GRAPH,
        "Microsoft Graph",
        value,
        display,
        PermissionKind::Application,
    )
}
/// A Delegated-kind held permission on Microsoft Graph.
fn deleg_perm(value: &str, display: &str) -> ResolvedPermission {
    f::resolved_permission(
        GRAPH,
        "Microsoft Graph",
        value,
        display,
        PermissionKind::Delegated,
    )
}

/// A lean app: permissions only (and optionally one secret), no mail scoping.
fn lean_app(
    name: &'static str,
    secret_days: Option<i64>,
    perms: Vec<ResolvedPermission>,
) -> DemoApp {
    DemoApp {
        name,
        secrets: secret_days
            .map(|d| {
                vec![f::password_credential(
                    "app-secret",
                    "x2Q",
                    f::days_from_now(d),
                )]
            })
            .unwrap_or_default(),
        certs: vec![],
        perms,
        mail_scopes: vec![],
    }
}

/// The curated app-registration catalog. The first few are "showcase" apps with
/// credentials + scoped/org-wide permissions; then the apps the sample audit
/// run names, each holding the permission its finding cites; the rest are lean
/// but realistic.
///
/// Every expiry is an offset from today ([`f::days_from_now`]), kept clear of
/// the 0 / 7 / 30-day bucket edges, so the credential story (one expired, one
/// due within a week, two within a month, the rest healthy) holds whenever
/// the page is loaded.
fn catalog() -> Vec<DemoApp> {
    let mut apps = vec![
        // Mailbox permission scoped to a group via Exchange RBAC + a SharePoint
        // site-scoped permission + an org-wide one, plus secrets and a cert.
        DemoApp {
            name: "Contoso CRM",
            secrets: vec![
                f::password_credential("crm-prod-secret", "Hq9", f::days_from_now(12)),
                f::password_credential("crm-legacy-secret", "a1Z", f::days_from_now(-240)),
            ],
            certs: vec![f::key_credential("crm-signing-cert", f::days_from_now(410))],
            perms: vec![
                app_perm("Mail.Read", "Read mail in all mailboxes"),
                app_perm("Sites.Selected", "Access selected SharePoint sites"),
                app_perm("User.Read.All", "Read all users' full profiles"),
                app_perm(
                    "Application.ReadWrite.All",
                    "Read and write all applications",
                ),
            ],
            mail_scopes: vec![f::mail_scope_scoped("Mail.Read", "Finance Mailboxes", 2)],
        },
        // Org-wide mailbox access (contrast: no scope entry → "Org-wide" badge).
        DemoApp {
            name: "Fabrikam Mail Sync",
            secrets: vec![f::password_credential(
                "mailsync-secret",
                "7Kp",
                f::days_from_now(3),
            )],
            certs: vec![],
            perms: vec![
                app_perm("Mail.ReadWrite", "Read and write mail in all mailboxes"),
                app_perm("Mail.Send", "Send mail as any user"),
            ],
            mail_scopes: vec![],
        },
        // SharePoint: site-scoped (Sites.Selected) vs org-wide (Sites.FullControl.All).
        DemoApp {
            name: "Northwind SharePoint Bot",
            secrets: vec![],
            certs: vec![f::key_credential("spbot-cert", f::days_from_now(236))],
            perms: vec![
                app_perm("Sites.Selected", "Access selected SharePoint sites"),
                app_perm(
                    "Sites.FullControl.All",
                    "Full control of all SharePoint sites",
                ),
            ],
            mail_scopes: vec![],
        },
        DemoApp {
            name: "Adventure Works API",
            secrets: vec![f::password_credential(
                "aw-api-secret",
                "Mn3",
                f::days_from_now(95),
            )],
            certs: vec![],
            perms: vec![
                deleg_perm("User.Read", "Sign in and read user profile"),
                app_perm("Directory.Read.All", "Read directory data"),
            ],
            mail_scopes: vec![],
        },
        DemoApp {
            name: "Tailspin Reporting",
            secrets: vec![],
            certs: vec![f::key_credential(
                "tailspin-cert-2024",
                f::days_from_now(21),
            )],
            perms: vec![app_perm("Reports.Read.All", "Read all usage reports")],
            mail_scopes: vec![],
        },
        // ---- The rest of the sample audit run's apps, holding what it cites ----
        lean_app(
            "Trey Research Sync",
            Some(180),
            vec![
                app_perm("Mail.ReadWrite", "Read and write mail in all mailboxes"),
                app_perm("Mail.Read", "Read mail in all mailboxes"),
            ],
        ),
        lean_app(
            "Woodgrove Portal",
            None,
            vec![
                deleg_perm("User.Read", "Sign in and read user profile"),
                deleg_perm(
                    "Directory.AccessAsUser.All",
                    "Access directory as the signed-in user",
                ),
            ],
        ),
        DemoApp {
            mail_scopes: vec![f::mail_scope_legacy_policy(
                "Mail.Read",
                "Coho Mail Recipients",
                1,
            )],
            ..lean_app(
                "Coho Winery Mailer",
                Some(120),
                vec![app_perm("Mail.Read", "Read mail in all mailboxes")],
            )
        },
        // The legacy Office 365 resources: identically named permissions the
        // toolkit can't confine, which is exactly what their findings say.
        lean_app(
            "Lamna Mail Reader",
            Some(200),
            vec![f::resolved_permission(
                f::OFFICE365_EXCHANGE_ONLINE_APP_ID,
                "Office 365 Exchange Online",
                "Mail.Read",
                "Read mail in all mailboxes",
                PermissionKind::Application,
            )],
        ),
        DemoApp {
            certs: vec![f::key_credential(
                "records-archive-cert",
                f::days_from_now(300),
            )],
            ..lean_app(
                "Relecloud Records Archive",
                None,
                vec![f::resolved_permission(
                    OFFICE365_SHAREPOINT_ONLINE_APP_ID,
                    "Office 365 SharePoint Online",
                    "Sites.Read.All",
                    "Read items in all site collections",
                    PermissionKind::Application,
                )],
            )
        },
        lean_app(
            "Wingtip Toys Connector",
            Some(150),
            vec![
                app_perm("User.Read.All", "Read all users' full profiles"),
                app_perm("Directory.ReadWrite.All", "Read and write directory data"),
            ],
        ),
        // The audit's healthy counterparts: confined, so they score Low.
        DemoApp {
            mail_scopes: vec![f::mail_scope_scoped("Mail.Read", "Travel Desk", 1)],
            ..lean_app(
                "Margie's Travel Portal",
                Some(175),
                vec![app_perm("Mail.Read", "Read mail in all mailboxes")],
            )
        },
        lean_app(
            "Alpine Ski House Booking",
            Some(200),
            vec![app_perm(
                "Sites.Selected",
                "Access selected SharePoint sites",
            )],
        ),
    ];
    // Lean-but-realistic filler apps so the list looks populated.
    apps.extend(
        [
            "Proseware Sync",
            "Litware Analytics",
            "Blue Yonder Airlines API",
            "Coho Vineyard Storefront",
        ]
        .into_iter()
        .zip(0i64..)
        .map(|(name, i)| {
            lean_app(
                name,
                Some(225 + 25 * i),
                vec![app_perm("User.Read.All", "Read all users' full profiles")],
            )
        }),
    );
    apps
}

/// The Enterprise Applications catalog: `(name, account_enabled,
/// is_foreign_tenant)`. Includes every service principal another demo surface
/// opens — the audit's SP-only foreign app and the SSO board's SAML apps.
const ENTERPRISE_APPS: &[(&str, bool, bool)] = &[
    ("Salesforce", true, false),
    ("ServiceNow", false, false),
    ("Datadog", true, true),
    ("GitHub Enterprise", true, false),
    ("Zoom", true, false),
    ("Slack", true, false),
    ("Workday", true, false),
    ("Atlassian Cloud", true, false),
    ("Fourth Coffee Connector", true, true),
    ("Contoso Payroll", true, false),
    ("Contoso SSO Portal", true, false),
    ("Contoso Expenses", true, false),
];

fn enterprise_apps() -> Vec<EnterpriseApplicationDto> {
    ENTERPRISE_APPS
        .iter()
        .map(|&(name, enabled, foreign)| {
            let mut e = f::enterprise_app(&obj_id(name), name);
            e.app_id = app_id(name);
            e.account_enabled = Some(enabled);
            e.is_foreign_tenant = foreign;
            if foreign {
                e.app_owner_organization_id = Some(f::guid(&format!("{name}:org")));
            }
            e
        })
        .collect()
}

fn app_detail(a: &DemoApp) -> ApplicationDetail {
    ApplicationDetail {
        application: Application {
            id: obj_id(a.name),
            app_id: app_id(a.name),
            display_name: a.name.to_string(),
            sign_in_audience: Some("AzureADMyOrg".to_string()),
            description: Some(format!("{} — sample app shown in the live demo.", a.name)),
            created_date_time: f::date(2023, 3, 14),
            password_credentials: a.secrets.clone(),
            key_credentials: a.certs.clone(),
            notes: Some(format!(
                "Owned by the Identity Platform team — rotate {} credentials quarterly.",
                a.name
            )),
            ..Default::default()
        },
        service_principal: None,
        owners: Vec::new(),
        app_role_assignments: Vec::new(),
        oauth2_permission_grants: Vec::new(),
        resolved_permissions: a.perms.clone(),
        resolution_degraded: false,
    }
}

fn app_details(apps: &[DemoApp]) -> HashMap<String, ApplicationDetail> {
    apps.iter()
        .map(|a| (obj_id(a.name), app_detail(a)))
        .collect()
}

/// The list row, through the backend's own projection — so the credential
/// badge is `ListCredentialStatus::classify` over the same credentials the
/// Credentials tab reads, and the soonest expiry is filled in too.
fn list_row(a: &DemoApp, now: DateTime<Utc>) -> ApplicationListRowDto {
    ApplicationListRowDto::from_application(app_detail(a).application, None, now)
}

/// The sample audit run, re-keyed onto the catalog's ids (the fixture's
/// `obj-<name>` ids exist nowhere in the demo, so "Open" on a finding would
/// land on a placeholder) and completed with a clean Low row for every catalog
/// app it doesn't mention, so "All apps" matches the App Registrations list.
fn audit_run(apps: &[DemoApp]) -> AuditRunResult {
    let mut run = f::audit_run_result();
    let named: HashSet<String> = run
        .items
        .iter()
        .map(|i| i.application_name.clone())
        .collect();
    run.items.extend(
        apps.iter()
            .filter(|a| !named.contains(a.name))
            .map(|a| f::audit_item(a.name, RiskLevel::Low, &[])),
    );
    // Application rows carry the app object id, SP-only rows the SP object
    // id — both derived from the name, the same way the catalogs derive theirs.
    for item in &mut run.items {
        item.object_id = obj_id(&item.application_name);
        item.app_id = app_id(&item.application_name);
    }
    run.total_apps = run.items.len();
    run
}

/// The credential-expiry board, derived from the catalog exactly as the
/// backend's `commands::credentials::credential_rows` derives it from the
/// tenant: `summarize_credentials` per app, sorted soonest-first with no-expiry
/// rows last. Ids, names, days and status therefore all agree with the
/// Credentials tab of the app a row opens.
fn credential_rows(apps: &[DemoApp], now: DateTime<Utc>) -> Vec<CredentialRowDto> {
    let mut rows: Vec<CredentialRowDto> = Vec::new();
    for a in apps {
        let application = app_detail(a).application;
        let (secrets, certs) = azapptoolkit_core::audit::summarize_credentials(&application, now);
        for c in secrets.into_iter().chain(certs) {
            rows.push(CredentialRowDto {
                app_object_id: application.id.clone(),
                app_id: application.app_id.clone(),
                app_display_name: application.display_name.clone(),
                credential_name: c.name,
                kind: c.kind,
                start_date_time: c.start_date_time,
                end_date_time: c.end_date_time,
                days_to_expiry: c.days_to_expiry,
                status: c.status,
            });
        }
    }
    rows.sort_by_key(|r| match r.days_to_expiry {
        Some(d) => (0u8, d),
        None => (1, 0),
    });
    rows
}

/// The SSO certificate board, re-keyed onto [`ENTERPRISE_APPS`] ids.
fn sso_rows() -> Vec<SsoCertificateRowDto> {
    let mut rows = f::sso_certificate_rows();
    for r in &mut rows {
        r.service_principal_id = obj_id(&r.display_name);
        r.app_id = app_id(&r.display_name);
    }
    rows
}

/// Holds Microsoft Graph's `Sites.Selected` as an Application permission — the
/// resource-aware test (Office 365 SharePoint Online has no `Sites.Selected`).
fn holds_graph_sites_selected(a: &DemoApp) -> bool {
    a.perms.iter().any(|p| {
        p.resource_app_id == GRAPH
            && p.permission_kind == PermissionKind::Application
            && p.permission_value.as_deref() == Some("Sites.Selected")
    })
}

/// The tenant site sweep: two per-site grants for every `Sites.Selected` app.
/// An org-wide `Sites.*` holder reaches every site *without* a per-site grant,
/// which is exactly the distinction the per-app panel draws.
fn site_sweep(apps: &[DemoApp]) -> SiteSweepResult {
    let rows = apps
        .iter()
        .filter(|a| holds_graph_sites_selected(a))
        .flat_map(|a| {
            let id = app_id(a.name);
            [
                f::site_grant_row(&id, a.name, "Marketing", &["read"]),
                f::site_grant_row(&id, a.name, "Projects", &["write"]),
            ]
        })
        .collect();
    f::site_sweep(DEMO_TENANT_ID, 42, rows)
}

/// `list_site_permissions` for one site URL, answered from the sweep.
fn site_permissions(sweep: &SiteSweepResult, site_url: &str) -> Vec<SitePermissionDto> {
    let wanted = site_url.trim().trim_end_matches('/');
    sweep
        .rows
        .iter()
        .filter(|r| {
            r.site_url
                .as_deref()
                .is_some_and(|u| u.eq_ignore_ascii_case(wanted))
        })
        .map(|r| SitePermissionDto {
            id: r.permission_id.clone(),
            roles: r.roles.clone(),
            app_id: r.app_id.clone(),
            app_display_name: r.app_display_name.clone(),
        })
        .collect()
}

/// The app's Graph mail permissions that RBAC for Applications can confine —
/// the backend's resource-aware gate, never a value-only `Mail.*` match.
fn scopable_mail_perms(a: &DemoApp) -> Vec<&str> {
    a.perms
        .iter()
        .filter(|p| p.permission_kind == PermissionKind::Application)
        .filter_map(|p| {
            let value = p.permission_value.as_deref()?;
            exchange_role_for_resource_permission(&p.resource_app_id, value).map(|_| value)
        })
        .collect()
}

/// The Exchange role assignments an app's RBAC-scoped mail entries imply (a
/// legacy Application Access Policy is not an RBAC assignment).
fn exchange_role_assignments(a: &DemoApp) -> Vec<ExchangeRoleAssignmentDto> {
    a.mail_scopes
        .iter()
        .filter_map(|m| match &m.scope {
            MailPermissionScope::Scoped {
                scope_name: Some(scope),
                mechanism: ScopeMechanism::Rbac,
                ..
            } => Some(f::exchange_role_assignment(&m.exchange_role, scope)),
            _ => None,
        })
        .collect()
}

/// The mailbox reverse lookup against `mailbox`: every catalog app holding a
/// confinable mail permission, `scoped` when a scope entry confines it.
fn mailbox_reachers(apps: &[DemoApp], mailbox: &str) -> MailboxReachersResult {
    let rows: Vec<_> = apps
        .iter()
        .filter_map(|a| {
            let held = scopable_mail_perms(a);
            if held.is_empty() {
                return None;
            }
            let scoped = a
                .mail_scopes
                .iter()
                .any(|m| matches!(m.scope, MailPermissionScope::Scoped { .. }));
            // Exchange names a role only for an RBAC assignment; a legacy
            // policy confines without one.
            let roles: Vec<Option<String>> = exchange_role_assignments(a)
                .into_iter()
                .map(|r| r.role)
                .collect();
            let roles: Vec<&str> = roles.iter().flatten().map(String::as_str).collect();
            Some(f::mailbox_reacher_row(
                &app_id(a.name),
                &obj_id(a.name),
                a.name,
                &held,
                if scoped { "scoped" } else { "org_wide" },
                &roles,
            ))
        })
        .collect();
    MailboxReachersResult {
        tenant_id: DEMO_TENANT_ID.to_string(),
        mailbox: mailbox.to_string(),
        total_candidates: rows.len(),
        rows,
        exchange_available: true,
        exchange_sp_store_read: true,
        cancelled: false,
    }
}

/// The top-bar search's sample hits, re-keyed onto the catalog's ids.
fn global_search(names: &[&str]) -> GlobalSearchResults {
    let mut results = f::global_search_apps(names);
    for hit in &mut results.app_registrations {
        hit.id = obj_id(&hit.display_name);
        hit.app_id = Some(app_id(&hit.display_name));
    }
    results
}

/// The managed identities' Key Vault reach: one high-privilege assignment and
/// one inherited from the resource group, across the vaults the picker lists.
fn key_vault_rows() -> Vec<azapptoolkit_dto::keyvault::KeyVaultAccessRow> {
    let mi = |name: &str| obj_id(name);
    vec![
        f::key_vault_access_row(
            "kv-contoso-prod",
            "Key Vault Secrets User",
            "aks-prod-identity",
            &mi("aks-prod-identity"),
            false,
            false,
        ),
        f::key_vault_access_row(
            "kv-contoso-prod",
            "Key Vault Administrator",
            "func-orders-mi",
            &mi("func-orders-mi"),
            true,
            false,
        ),
        f::key_vault_access_row(
            "kv-contoso-secrets",
            "Key Vault Secrets User",
            "logic-app-connector",
            &mi("logic-app-connector"),
            false,
            false,
        ),
        f::key_vault_access_row(
            "kv-contoso-dev",
            "Key Vault Reader",
            "data-factory-mi",
            &mi("data-factory-mi"),
            false,
            true,
        ),
    ]
}

fn register_fixtures() {
    let now = Utc::now();

    // ---- Startup / shell ----
    mock_ok("get_auth_config", &f::configured());
    mock_ok("get_organization", &f::organization("Contoso Ltd"));
    // Sign-out clears the tenant (→ sign-in screen); mocking sign_in lets the
    // demo round-trip back into the shell instead of dead-ending.
    mock_ok("sign_in", &f::sign_in_outcome(demo_tenant()));
    // `sign_out` must be mocked as a SUCCESS, not left to the friendly-unmocked
    // path. The shell now only clears the tenant when the backend confirms the
    // credentials were cleared — reporting "signed out" without that is a claim
    // the app has not verified. An unmocked `sign_out` therefore reads as a
    // failure and leaves the demo stuck in the shell. There is no keyring
    // behind the demo, so signing out really does succeed.
    mock_ok("sign_out", &());
    mock_ok("reauthenticate", &f::sign_in_outcome(demo_tenant()));

    // ---- App Registrations: list + per-id detail + per-id mailbox scopes ----
    let apps = catalog();
    let rows: Vec<ApplicationListRowDto> = apps.iter().map(|a| list_row(a, now)).collect();
    mock_ok("list_applications_with_pairing", &rows);

    let detail_by_id = app_details(&apps);
    // objectId → appId, for the tabs keyed on the object but reporting the app.
    let app_id_by_obj: HashMap<String, String> = detail_by_id
        .iter()
        .map(|(oid, d)| (oid.clone(), d.application.app_id.clone()))
        .collect();
    mock_each("get_application_detail", move |args| {
        let oid = arg(args, "objectId");
        detail_by_id
            .get(oid)
            .cloned()
            .unwrap_or_else(|| f::application_detail(oid, oid, "Demo App"))
    });

    // The tenant site sweep, and "Sites this app can reach" projected from it
    // with the backend's single projection (`AppSiteAccessDto::from_sweep`), so
    // the Resource Access Sites pane and every per-app panel tell one story.
    let sweep = site_sweep(&apps);
    mock_ok("get_cached_site_sweep", &Some(sweep.clone()));
    let sweep_for_app = sweep.clone();
    mock_each("get_app_site_access", move |args| {
        Some(AppSiteAccessDto::from_sweep(
            &sweep_for_app,
            arg(args, "appId"),
        ))
    });
    mock_each("list_site_permissions", move |args| {
        site_permissions(&sweep, arg(args, "siteUrl"))
    });

    // The sub-site Selected scopes. Both commands are fallible, so the demo
    // survives without them — but the "Grant access" wizard resolves every
    // pasted URL as you type, and an unmocked resolve turns the panel into a
    // wall of errors that reads like a broken build rather than a demo.
    mock_each("resolve_sharepoint_resource", |args| {
        Some(f::sharepoint_resource_ref(arg(args, "url")))
    });
    mock_each("list_selected_item_permissions", |_args| {
        Some(Vec::<azapptoolkit_dto::sharepoint::SelectedItemPermissionDto>::new())
    });

    let scopes_by_id: HashMap<String, Vec<MailScopeEntry>> = apps
        .iter()
        .map(|a| (obj_id(a.name), a.mail_scopes.clone()))
        .collect();
    mock_each("get_mail_permission_scopes", move |args| {
        scopes_by_id
            .get(arg(args, "objectId"))
            .cloned()
            .unwrap_or_default()
    });

    // Exchange RBAC panels (keyed on appId): the role assignments behind each
    // RBAC-scoped entry, and the toolkit-managed scope group — named by the
    // tenant's own pattern, the single definition the backend uses too.
    let assignments_by_app: HashMap<String, Vec<ExchangeRoleAssignmentDto>> = apps
        .iter()
        .map(|a| (app_id(a.name), exchange_role_assignments(a)))
        .collect();
    mock_each("list_exchange_role_assignments", move |args| {
        assignments_by_app
            .get(arg(args, "appId"))
            .cloned()
            .unwrap_or_default()
    });
    let defaults = f::tenant_defaults();
    let rbac_scoped_apps: HashSet<String> = apps
        .iter()
        .filter(|a| !exchange_role_assignments(a).is_empty())
        .map(|a| app_id(a.name))
        .collect();
    mock_each("list_exchange_scope_group", move |args| {
        let app = arg(args, "appId");
        let group = defaults.group_name_for(app);
        if rbac_scoped_apps.contains(app) {
            f::exchange_scope_group(&group, true, &["Finance Team", "Accounts Payable"])
        } else {
            f::exchange_scope_group(&group, false, &[])
        }
    });
    // Mail scoping for a principal with no manifest (enterprise apps, managed
    // identities): the backend's resource-aware gate over what it holds —
    // an Office 365 Exchange Online `Mail.Read` is correctly not scopable.
    mock_each("get_mail_scopes_for_principal", |args| {
        args.get("permissions")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|p| {
                let value = arg(p, "value");
                exchange_role_for_resource_permission(arg(p, "resourceAppId"), value).map(|role| {
                    MailScopeEntry {
                        graph_permission: value.to_string(),
                        exchange_role: role.to_string(),
                        scope: MailPermissionScope::OrgWide,
                    }
                })
            })
            .collect::<Vec<_>>()
    });
    let reacher_apps = catalog();
    mock_each("find_mailbox_reachers", move |args| {
        mailbox_reachers(&reacher_apps, arg(args, "mailbox"))
    });

    // Authentication tab. Both its commands are fallible, so an unmocked read
    // can't panic — but without this a visitor clicking Authentication got the
    // DemoFriendly rejection where the form should be. Seeded with enough reply
    // URLs to show the per-row editor doing its job.
    mock_ok(
        "get_application_authentication",
        &f::application_authentication(
            &[
                "https://crm.contoso.com/signin-oidc",
                "https://crm.contoso.com/auth/callback",
                "https://staging.crm.contoso.com/signin-oidc",
                "http://localhost:5173/signin-oidc",
            ],
            &["https://crm.contoso.com/"],
            &["myapp://auth"],
        ),
    );

    // The remaining app-registration tabs. Each is a fallible read, so a
    // missing fixture rendered the demo rejection where the tab should be.
    // Adventure Works API is the "API" app: it is the one that exposes a scope
    // and trusts GitHub Actions, and the audit calls it unused — so its
    // sign-in report has no entry.
    let api_app = obj_id("Adventure Works API");
    let api_app_id = app_id("Adventure Works API");
    let federated_for = api_app.clone();
    mock_each("list_federated_credentials", move |args| {
        if arg(args, "objectId") == federated_for {
            vec![
                f::federated_credential(
                    "github-main",
                    Some("repo:contoso/adventure-works-api:ref:refs/heads/main"),
                ),
                f::federated_credential(
                    "github-pull-requests",
                    Some("repo:contoso/adventure-works-api:pull_request"),
                ),
            ]
        } else {
            Vec::new()
        }
    });
    mock_each("get_expose_api", move |args| {
        let oid = arg(args, "objectId");
        let app = app_id_by_obj.get(oid).map_or(oid, String::as_str);
        let scopes: &[&str] = if oid == api_app {
            &["access_as_user"]
        } else {
            &[]
        };
        f::expose_api(app, scopes)
    });
    mock_ok(
        "list_conditional_access_for_app",
        &f::conditional_access_policies(),
    );
    mock_ok("list_directory_audits_for_app", &f::directory_audits());
    mock_each("get_app_sign_in_activity", move |args| {
        f::sign_in_activity(
            (arg(args, "appId") != api_app_id).then(|| Utc::now() - chrono::Duration::days(2)),
        )
    });
    mock_each("get_app_graph_usage", |args| {
        let days = args
            .get("days")
            .and_then(|v| v.as_u64())
            .and_then(|d| u32::try_from(d).ok())
            .unwrap_or(90);
        f::graph_usage(arg(args, "appId"), days)
    });

    // ---- Enterprise Applications: list + per-id detail ----
    let enterprise = enterprise_apps();
    mock_ok("list_enterprise_applications", &enterprise);
    // The demo tenant is far below the SP-index cap, so the truncation notice
    // stays hidden. Registered rather than left to the rejected-promise
    // fallback so the demo console stays clean.
    mock_ok(
        "get_directory_index_status",
        &DirectoryIndexStatus {
            sp_index_truncated: false,
            sp_index_cap: 10_000,
        },
    );

    let owners = vec![
        f::directory_object(
            "owner:alex",
            "Alex Johnson",
            "alex.johnson@contoso.onmicrosoft.com",
        ),
        f::directory_object(
            "owner:sam",
            "Sam Patel",
            "sam.patel@contoso.onmicrosoft.com",
        ),
    ];
    let sp_app_ids: HashMap<String, String> = enterprise
        .iter()
        .map(|e| (e.id.clone(), e.app_id.clone()))
        .collect();
    let ent_detail_by_id: HashMap<String, EnterpriseApplicationDetail> = enterprise
        .iter()
        .map(|e| {
            (
                e.id.clone(),
                EnterpriseApplicationDetail {
                    service_principal: e.clone(),
                    owners: owners.clone(),
                },
            )
        })
        .collect();
    mock_each("get_enterprise_application_detail", move |args| {
        let id = arg(args, "servicePrincipalId");
        ent_detail_by_id
            .get(id)
            .cloned()
            .unwrap_or_else(|| f::enterprise_application_detail(id, "Demo Enterprise App"))
    });

    // Enterprise detail sub-tabs — representative sample data shown for every SP.
    mock_ok(
        "list_enterprise_app_assignments",
        &vec![
            f::app_assignment("Sales Team", "Group"),
            f::app_assignment("Ava Martinez", "User"),
            f::app_assignment("Liam Chen", "User"),
        ],
    );
    mock_ok(
        "list_enterprise_app_roles",
        &f::app_roles_view(vec![
            f::exposed_app_role("User", "User", "Standard application user."),
            f::exposed_app_role("Admin", "Administrator", "Full administrative access."),
            f::exposed_app_role(
                "msiam_access",
                "msiam_access",
                "Default single sign-on access.",
            ),
        ]),
    );
    mock_ok(
        "list_sp_group_memberships",
        &vec![
            f::group_membership("All Company", true, true),
            f::group_membership("SaaS Applications", true, false),
        ],
    );
    // The SSO tab is fallible, so an unmocked read can't panic — but without
    // this a visitor clicking SSO got the DemoFriendly rejection where the
    // whole tab should be, on the surface this app is most known for. The
    // fixture also carries "Details for the application owner" — the values
    // the whole SSO flow exists to produce, and the home of the "Copy all
    // details" action — and the rollover panel's initial (staged) state.
    // Args-aware so the payload names the SP that was opened.
    let sso_app_ids = sp_app_ids.clone();
    mock_each("get_sso_config", move |args| {
        let id = arg(args, "servicePrincipalId");
        f::sso_config(id, sso_app_ids.get(id).map_or(id, String::as_str))
    });
    // The rollover panel re-reads after its own buttons (stage, activate, …),
    // so it needs the same treatment — and the staged phase is the one worth
    // showing a visitor.
    mock_each("get_signing_cert_rollover", move |args| {
        let id = arg(args, "servicePrincipalId");
        f::signing_cert_rollover(id, sp_app_ids.get(id).map_or(id, String::as_str))
    });
    // The metadata probe is an explicit button, but mocking it lets a visitor
    // actually press it and see what "Entra publishes 2 signing keys" looks
    // like — the whole point of the staged flow.
    mock_ok("probe_federation_metadata", &f::metadata_probe());
    // The Security tab's SSO certificate board — the whole point of the demo is
    // showing an operator what "expiring, nothing staged, nobody notified"
    // looks like before it happens to them.
    mock_ok("list_sso_certificate_expirations", &sso_rows());
    mock_ok(
        "get_enterprise_app_provisioning",
        &vec![f::provisioning_job(
            "Active",
            "Succeeded",
            "2026-06-25T02:14:00Z",
        )],
    );

    // Held app-role grants — the Permissions/"granted" tab on BOTH enterprise apps
    // and managed identities (shared command). Varied per id so different
    // principals show different grants. One variant holds the legacy EWS
    // `full_access_as_app` scope on Office 365 Exchange Online: it's the broadest
    // mailbox grant there is, it's Exchange-RBAC-scopable, and a surviving one
    // defeats every other mailbox scope — so the demo shows the org-wide callout
    // naming it, which is the flow an operator migrating off Application Access
    // Policies actually walks.
    let held_variants: Vec<Vec<_>> = vec![
        vec![
            f::held_grant("User.Read.All"),
            f::held_grant("Group.Read.All"),
        ],
        vec![f::held_grant("Mail.Send"), f::held_grant("Files.Read.All")],
        vec![
            f::held_grant("Directory.Read.All"),
            f::held_exchange_grant("full_access_as_app"),
        ],
    ];
    mock_each("list_held_app_role_grants", move |args| {
        let id = arg(args, "servicePrincipalId");
        held_variants[variant_index(id, held_variants.len())].clone()
    });

    // ---- Managed Identities ----
    let mut managed = f::managed_identities(&[
        "aks-prod-identity",
        "func-orders-mi",
        "vm-backup-agent",
        "logic-app-connector",
        "data-factory-mi",
    ]);
    for mi in managed.iter_mut() {
        mi.id = obj_id(&mi.display_name);
        mi.app_id = app_id(&mi.display_name);
    }
    managed[0].mi_subtype = MiSubtype::SystemAssigned;
    managed[2].mi_subtype = MiSubtype::SystemAssigned;
    mock_ok("list_managed_identities", &managed);

    // Azure RBAC roles held by each managed identity (Azure roles tab), varied
    // per id. (Held Graph grants are covered by `list_held_app_role_grants` above.)
    let azure_variants: Vec<_> = vec![
        f::azure_roles(vec![
            f::azure_role("Reader", "Subscription", "Production", false),
            f::azure_role(
                "Storage Blob Data Reader",
                "Resource group",
                "Production",
                false,
            ),
        ]),
        f::azure_roles(vec![f::azure_role(
            "Contributor",
            "Resource group",
            "Production",
            true,
        )]),
        f::azure_roles(vec![f::azure_role(
            "Key Vault Secrets User",
            "Resource",
            "Production",
            false,
        )]),
    ];
    mock_each("list_managed_identity_azure_roles", move |args| {
        let id = arg(args, "principalId");
        azure_variants[variant_index(id, azure_variants.len())].clone()
    });

    // ---- Security / health ----
    mock_ok("list_credential_expirations", &credential_rows(&apps, now));
    let audit_run = audit_run(&apps);
    // Home's posture card reads the counts-only summary; derived from the same
    // run so the demo's Home card and Security strip agree.
    mock_ok(
        "get_cached_audit_summary",
        &Some(CachedAuditSummary::from_items(
            &audit_run.items,
            audit_run.completed_at.clone(),
        )),
    );
    mock_ok("get_cached_audit", &Some(audit_run));
    // The two grant lenses of the Security workbench. Both are fallible reads,
    // so an unmocked route degrades to the lens's error state rather than
    // panicking — but that would show the demo's visitors a failure where the
    // feature should be.
    mock_ok("list_oauth2_grants_audit", &f::oauth2_grants());
    mock_ok("list_app_permission_grants", &f::app_permission_grants());

    // ---- Key Vault ----
    mock_ok(
        "kv_list_secrets",
        &f::kv_secrets(&[
            "graph-api-client-secret",
            "smtp-relay-password",
            "storage-account-key",
            "webhook-signing-token",
        ]),
    );
    mock_ok(
        "kv_get_secret",
        &f::kv_secret_value("graph-api-client-secret", "demo-value—not-a-real-secret"),
    );
    // Vault discovery for the rotation/browser picker (fallible; unmocked would
    // just yield no chips — mocked here so the demo shows the picker populated).
    let vaults = vec![
        "kv-contoso-prod".to_string(),
        "kv-contoso-dev".to_string(),
        "kv-contoso-secrets".to_string(),
    ];
    mock_ok(
        "get_cached_key_vault_access",
        &Some(f::key_vault_access(
            DEMO_TENANT_ID,
            vaults.len(),
            key_vault_rows(),
        )),
    );
    mock_ok("list_available_key_vaults", &vaults);

    // ---- Readiness ----
    mock_ok("check_readiness", &f::readiness_report());

    // ---- Settings (per-tenant defaults) + owner search ----
    // get_tenant_defaults is an infallible `invoke`, so it MUST be mocked or the
    // demo panics on the rejected-promise fallback. search_users powers the owner
    // pickers (Settings + the Owners tabs); search_groups powers the Access tab's
    // Groups scope and the Exchange scope typeahead.
    mock_ok("get_tenant_defaults", &f::tenant_defaults());
    mock_ok("set_tenant_defaults", &());
    mock_ok("search_users", &f::directory_user_search());
    mock_ok("search_groups", &f::directory_group_search());
    mock_ok("search_distribution_lists", &f::distribution_list_search());
    // "New application" → Browse the gallery: template search + instantiate.
    // Args-aware so the demo runs the real substring match over the sample
    // catalog ("force" → Salesforce) instead of echoing the whole list back for
    // every keystroke — the very thing the picker is supposed to demonstrate.
    // Corpus prewarm fired on dialog-open; a no-op in the demo (the search mock
    // below already answers from the sample catalog without a corpus fetch).
    mock_ok("prefetch_application_gallery", &());
    mock_each("search_application_templates", |args| {
        f::gallery_search_for(arg(args, "query"))
    });
    mock_ok("create_gallery_application", &f::gallery_app_summary());

    // ---- Global search (top bar) ----
    // The corpus prewarm fires on focus; unregistered it would reject and the
    // bar would render a search failure the moment the box is clicked.
    mock_ok("prefetch_search_corpus", &());
    mock_ok(
        "global_search",
        &global_search(&[
            "Contoso CRM",
            "Fabrikam Mail Sync",
            "Northwind SharePoint Bot",
        ]),
    );

    // ---- Permissions catalog (Grant-access wizard picker) ----
    let resources = vec![f::graph_resource_summary()];
    mock_ok("list_catalog_resources", &resources);
    mock_ok("list_resource_permission_counts", &resources);
    // The tenant's own app registrations that expose Application app roles — the
    // picker's second resource group (the managed-identity / app-reg grant flow).
    let tenant_res = f::tenant_app_role_resource();
    let tenant_app_id = tenant_res.app_id.clone();
    mock_ok("list_app_role_resources", &vec![tenant_res]);
    // Per-resource roles, args-aware so the demo is coherent: the tenant app
    // shows its own Orders.* roles; every other resource (the bundled Graph)
    // shows the Graph sample set.
    let graph_perms =
        f::graph_resource_permissions(&["User.Read.All", "Mail.Read", "Sites.Selected"]);
    let tenant_perms = f::tenant_app_role_permissions();
    mock_each("list_resource_permissions", move |args| {
        if arg(args, "resourceAppId") == tenant_app_id {
            tenant_perms.clone()
        } else {
            graph_perms.clone()
        }
    });

    // ---- Infallible `invoke()` commands: must resolve or they panic on the
    // rejected-promise fallback (Result-returning reads can safely fall through).
    mock_ok("cache_stats", &f::cache_stats());
    // `()`-returning commands reachable without a prior mutation — chiefly the
    // per-list Refresh button (`invalidate_list_cache`) and the Cache dialog.
    for cmd in [
        "invalidate_list_cache",
        "clear_cache",
        "set_cache_enabled",
        "cancel_audit",
        "cancel_bulk",
        "restart_app",
    ] {
        mock_ok(cmd, &());
    }
    // Fire-and-forget Cancel commands: Result-returning, but a demo Cancel
    // should resolve rather than reject.
    for cmd in [
        "cancel_site_sweep",
        "cancel_key_vault_sweep",
        "cancel_mailbox_probe",
        "cancel_backup",
        "cancel_restore",
        "cancel_aap_migration",
    ] {
        mock_ok(cmd, &());
    }
}

/// Native tests (`just web-test` runs them with `--features demo`). They call
/// only the pure builders above — never `mock_*`, which needs a browser.
#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::{
        AuditPrincipalKind, CredentialStatus, EXPIRY_WARNING_DAYS, ListCredentialStatus,
    };

    fn enterprise_ids() -> HashSet<String> {
        enterprise_apps().into_iter().map(|e| e.id).collect()
    }

    /// Every row another surface offers to "Open" names an object the detail
    /// commands actually hold — the finding → open journey, the credential
    /// board, the SSO board, the mailbox lookup and the top-bar search.
    #[test]
    fn every_open_target_resolves() {
        let apps = catalog();
        let details = app_details(&apps);
        let sps = enterprise_ids();

        for item in audit_run(&apps).items {
            let known = match item.principal_kind {
                AuditPrincipalKind::Application => details
                    .get(&item.object_id)
                    .is_some_and(|d| d.application.app_id == item.app_id),
                AuditPrincipalKind::ServicePrincipal => sps.contains(&item.object_id),
                AuditPrincipalKind::ManagedIdentity => false,
            };
            assert!(known, "audit row `{}` opens nothing", item.application_name);
        }

        for row in credential_rows(&apps, Utc::now()) {
            let detail = details.get(&row.app_object_id).unwrap_or_else(|| {
                panic!(
                    "credential row for `{}` opens nothing",
                    row.app_display_name
                )
            });
            let app = &detail.application;
            let names: Vec<_> = app
                .password_credentials
                .iter()
                .filter_map(|c| c.display_name.as_deref())
                .chain(
                    app.key_credentials
                        .iter()
                        .filter_map(|c| c.display_name.as_deref()),
                )
                .collect();
            assert!(
                names.contains(&row.credential_name.as_str()),
                "`{}` lists `{}`, which its Credentials tab doesn't hold",
                row.app_display_name,
                row.credential_name
            );
        }

        for row in sso_rows() {
            assert!(
                sps.contains(&row.service_principal_id),
                "SSO row `{}` opens nothing",
                row.display_name
            );
        }

        let reachers = mailbox_reachers(&apps, "finance@contoso.com");
        assert!(!reachers.rows.is_empty(), "the lookup should find someone");
        for row in reachers.rows {
            assert_eq!(row.principal_kind, AuditPrincipalKind::Application);
            assert!(
                details.contains_key(&row.object_id),
                "mailbox reacher `{:?}` opens nothing",
                row.display_name
            );
        }

        for hit in global_search(&["Contoso CRM", "Fabrikam Mail Sync"]).app_registrations {
            assert!(
                details.contains_key(&hit.id),
                "search hit `{}` opens nothing",
                hit.display_name
            );
        }
    }

    /// The fixture module's synthetic `obj-<name>` / `sp-<name>` ids exist in no
    /// demo catalog; one surviving means a builder stopped re-keying.
    #[test]
    fn no_row_opens_the_placeholder() {
        let apps = catalog();
        let ids = audit_run(&apps)
            .items
            .into_iter()
            .map(|i| i.object_id)
            .chain(
                credential_rows(&apps, Utc::now())
                    .into_iter()
                    .map(|r| r.app_object_id),
            )
            .chain(sso_rows().into_iter().map(|r| r.service_principal_id))
            .chain(
                global_search(&["Contoso CRM"])
                    .app_registrations
                    .into_iter()
                    .map(|h| h.id),
            );
        for id in ids {
            assert!(
                !id.starts_with("obj-") && !id.starts_with("sp-"),
                "`{id}` is a fixture placeholder id"
            );
        }
    }

    /// The audit covers the whole catalog, so "All apps" and the list agree.
    #[test]
    fn the_audit_run_covers_every_catalog_app() {
        let apps = catalog();
        let run = audit_run(&apps);
        assert_eq!(run.total_apps, run.items.len());
        for a in &apps {
            assert!(
                run.items.iter().any(|i| i.application_name == a.name),
                "`{}` is missing from the audit run",
                a.name
            );
        }
    }

    #[test]
    fn list_badges_match_the_credentials_tab() {
        let now = Utc::now();
        for a in catalog() {
            assert_eq!(
                list_row(&a, now).credential_status,
                ListCredentialStatus::classify(&a.secrets, &a.certs, now),
                "`{}`'s list badge disagrees with its credentials",
                a.name
            );
        }
    }

    /// The Credential Health story — one expired, one due this week, one due
    /// this month, the rest healthy — must hold on whatever day the page loads.
    #[test]
    fn the_credential_story_spans_every_bucket_whenever_loaded() {
        let rows = credential_rows(&catalog(), Utc::now());
        let days =
            |pred: &dyn Fn(i64) -> bool| rows.iter().any(|r| r.days_to_expiry.is_some_and(pred));
        assert!(rows.iter().any(|r| r.status == CredentialStatus::Expired));
        assert!(days(&|d| (0..=7).contains(&d)), "nothing due within a week");
        assert!(
            days(&|d| (8..=EXPIRY_WARNING_DAYS).contains(&d)),
            "nothing due within the month"
        );
        assert!(rows.iter().any(|r| r.status == CredentialStatus::Active));
        assert!(
            rows.windows(2).all(
                |w| w[0].days_to_expiry <= w[1].days_to_expiry || w[1].days_to_expiry.is_none()
            ),
            "the board is sorted soonest-first"
        );
    }

    #[test]
    fn sso_rows_dates_agree_with_days_left() {
        for row in sso_rows() {
            let end = row
                .end_date_time
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .expect("every board row has a parseable expiry")
                .with_timezone(&Utc);
            let left = row.days_to_expiry.expect("every board row has days left");
            assert!(end > Utc::now(), "`{}` expired already", row.display_name);
            assert!(
                ((end - Utc::now()).num_days() - left).abs() <= 1,
                "`{}`: {end} vs {left} days",
                row.display_name
            );
        }
    }

    /// Only Microsoft Graph's `Sites.Selected` holders get per-site grants, and
    /// each app's slice comes from the one projection the backend uses.
    #[test]
    fn the_site_sweep_is_the_catalogs_sites_selected_apps() {
        let apps = catalog();
        let sweep = site_sweep(&apps);
        for a in &apps {
            let slice = AppSiteAccessDto::from_sweep(&sweep, &app_id(a.name));
            assert_eq!(
                !slice.sites.is_empty(),
                holds_graph_sites_selected(a),
                "{}",
                a.name
            );
            assert!(slice.is_complete());
        }
        let marketing = site_permissions(&sweep, "https://contoso.sharepoint.com/sites/Marketing/");
        assert_eq!(marketing.len(), sweep.rows.len() / 2);
        assert!(site_permissions(&sweep, "https://contoso.sharepoint.com/sites/Nope").is_empty());
    }

    /// The mailbox answers go through the resource-aware gate: the Office 365
    /// Exchange Online `Mail.Read` holder is not a reacher, the scoped apps are
    /// `scoped`, and only RBAC (not the legacy policy) implies role assignments.
    #[test]
    fn mailbox_answers_carry_the_resource() {
        let apps = catalog();
        let reachers = mailbox_reachers(&apps, "x@contoso.com");
        let verdict = |name: &str| {
            reachers
                .rows
                .iter()
                .find(|r| r.display_name.as_deref() == Some(name))
                .map(|r| r.verdict.clone())
        };
        assert_eq!(verdict("Lamna Mail Reader"), None);
        assert_eq!(verdict("Contoso CRM").as_deref(), Some("scoped"));
        assert_eq!(verdict("Coho Winery Mailer").as_deref(), Some("scoped"));
        assert_eq!(verdict("Fabrikam Mail Sync").as_deref(), Some("org_wide"));

        let by_name = |name: &str| apps.iter().find(|a| a.name == name).expect(name);
        assert_eq!(exchange_role_assignments(by_name("Contoso CRM")).len(), 1);
        assert!(exchange_role_assignments(by_name("Coho Winery Mailer")).is_empty());
    }
}
