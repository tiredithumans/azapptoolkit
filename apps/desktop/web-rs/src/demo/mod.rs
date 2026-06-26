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
//!
//! Detail commands are registered **args-aware** ([`mock_each`]) so each selected
//! app/SP returns its own payload (otherwise the detail pane wouldn't switch).
//! All ids are deterministic synthetic GUIDs ([`fixtures::guid`]) so they look
//! like real Entra ids while staying stable across reloads.
//!
//! Compiled only under the `demo` feature, so none of this — nor the mock bridge
//! or fixtures it pulls in — ever enters the shipped desktop Trunk bundle.

use std::collections::HashMap;

use azapptoolkit_core::audit::ListCredentialStatus;
use azapptoolkit_core::identity::TenantContext;
use azapptoolkit_core::models::{Application, KeyCredential, PasswordCredential};
use azapptoolkit_dto::applications::{ApplicationDetail, ApplicationListRowDto};
use azapptoolkit_dto::enterprise_application::EnterpriseApplicationDetail;
use azapptoolkit_dto::exchange::MailScopeEntry;
use azapptoolkit_dto::managed_identity::MiSubtype;
use azapptoolkit_dto::permissions::{PermissionKind, ResolvedPermission};

use crate::ipc_mock::{self, Unmocked, fixtures as f, mock_each, mock_ok};

/// Microsoft Graph — the resource every demo held-permission is exposed by.
const GRAPH: &str = f::MICROSOFT_GRAPH_APP_ID;

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

/// The signed-in tenant the demo presents (presentable copy; mirrors
/// `test_support::test_tenant`). `App` seeds this as the active tenant so the
/// config + sign-in gates fall through straight to the authenticated shell.
pub fn demo_tenant() -> TenantContext {
    TenantContext {
        tenant_id: "demo-tenant".to_string(),
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
/// and (optional) Exchange mailbox scoping. Ids are derived from the name.
struct DemoApp {
    name: &'static str,
    secrets: Vec<PasswordCredential>,
    certs: Vec<KeyCredential>,
    perms: Vec<ResolvedPermission>,
    mail_scopes: Vec<MailScopeEntry>,
    cred_status: ListCredentialStatus,
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

/// The curated app-registration catalog. The first few are "showcase" apps with
/// credentials + scoped/org-wide permissions; the rest are lean but realistic.
fn catalog() -> Vec<DemoApp> {
    use ListCredentialStatus as S;
    vec![
        // Mailbox permission scoped to a group via Exchange RBAC + a SharePoint
        // site-scoped permission + an org-wide one, plus secrets and a cert.
        DemoApp {
            name: "Contoso CRM",
            secrets: vec![
                f::password_credential("crm-prod-secret", "Hq9", f::date(2025, 8, 30)),
                f::password_credential("crm-legacy-secret", "a1Z", f::date(2024, 2, 1)),
            ],
            certs: vec![f::key_credential("crm-signing-cert", f::date(2026, 11, 15))],
            perms: vec![
                app_perm("Mail.Read", "Read mail in all mailboxes"),
                app_perm("Sites.Selected", "Access selected SharePoint sites"),
                app_perm("User.Read.All", "Read all users' full profiles"),
            ],
            mail_scopes: vec![f::mail_scope_scoped("Mail.Read", "Finance Mailboxes", 2)],
            cred_status: S::Expiring,
        },
        // Org-wide mailbox access (contrast: no scope entry → "Org-wide" badge).
        DemoApp {
            name: "Fabrikam Mail Sync",
            secrets: vec![f::password_credential(
                "mailsync-secret",
                "7Kp",
                f::date(2025, 7, 9),
            )],
            certs: vec![],
            perms: vec![
                app_perm("Mail.ReadWrite", "Read and write mail in all mailboxes"),
                app_perm("Mail.Send", "Send mail as any user"),
            ],
            mail_scopes: vec![],
            cred_status: S::Expiring,
        },
        // SharePoint: site-scoped (Sites.Selected) vs org-wide (Sites.FullControl.All).
        DemoApp {
            name: "Northwind SharePoint Bot",
            secrets: vec![],
            certs: vec![f::key_credential("spbot-cert", f::date(2026, 5, 20))],
            perms: vec![
                app_perm("Sites.Selected", "Access selected SharePoint sites"),
                app_perm(
                    "Sites.FullControl.All",
                    "Full control of all SharePoint sites",
                ),
            ],
            mail_scopes: vec![],
            cred_status: S::Active,
        },
        DemoApp {
            name: "Adventure Works API",
            secrets: vec![f::password_credential(
                "aw-api-secret",
                "Mn3",
                f::date(2025, 9, 28),
            )],
            certs: vec![],
            perms: vec![
                deleg_perm("User.Read", "Sign in and read user profile"),
                app_perm("Directory.Read.All", "Read directory data"),
            ],
            mail_scopes: vec![],
            cred_status: S::Active,
        },
        DemoApp {
            name: "Tailspin Reporting",
            secrets: vec![],
            certs: vec![f::key_credential(
                "tailspin-cert-2024",
                f::date(2026, 6, 30),
            )],
            perms: vec![app_perm("Reports.Read.All", "Read all usage reports")],
            mail_scopes: vec![],
            cred_status: S::Active,
        },
    ]
    .into_iter()
    // Lean-but-realistic filler apps so the list looks populated.
    .chain(
        [
            "Wingtip Toys Connector",
            "Proseware Sync",
            "Litware Analytics",
            "Margie's Travel Portal",
            "Alpine Ski House Booking",
            "Blue Yonder Airlines API",
            "Coho Vineyard Storefront",
        ]
        .into_iter()
        .map(|name| DemoApp {
            name,
            secrets: vec![f::password_credential(
                "app-secret",
                "x2Q",
                f::date(2026, 1, 31),
            )],
            certs: vec![],
            perms: vec![app_perm("User.Read.All", "Read all users' full profiles")],
            mail_scopes: vec![],
            cred_status: ListCredentialStatus::Active,
        }),
    )
    .collect()
}

fn list_row(a: &DemoApp) -> ApplicationListRowDto {
    let oid = obj_id(a.name);
    let mut row = f::app_row(&oid, a.name);
    row.app_id = app_id(a.name);
    row.password_credential_count = a.secrets.len();
    row.key_credential_count = a.certs.len();
    row.credential_status = a.cred_status;
    row
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
            ..Default::default()
        },
        service_principal: None,
        owners: Vec::new(),
        app_role_assignments: Vec::new(),
        oauth2_permission_grants: Vec::new(),
        resolved_permissions: a.perms.clone(),
    }
}

fn register_fixtures() {
    // ---- Startup / shell ----
    mock_ok("get_auth_config", &f::configured());
    mock_ok("get_organization", &f::organization("Contoso Ltd"));
    // Sign-out clears the tenant (→ sign-in screen); mocking sign_in lets the
    // demo round-trip back into the shell instead of dead-ending.
    mock_ok("sign_in", &f::sign_in_outcome(demo_tenant()));
    mock_ok("reauthenticate", &f::sign_in_outcome(demo_tenant()));
    mock_ok("current_tenants", &vec![demo_tenant()]);

    // ---- App Registrations: list + per-id detail + per-id mailbox scopes ----
    let apps = catalog();
    let rows: Vec<ApplicationListRowDto> = apps.iter().map(list_row).collect();
    mock_ok("list_applications_with_pairing", &rows);

    let detail_by_id: HashMap<String, ApplicationDetail> = apps
        .iter()
        .map(|a| (obj_id(a.name), app_detail(a)))
        .collect();
    mock_each("get_application_detail", move |args| {
        let oid = args
            .get("objectId")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        detail_by_id
            .get(oid)
            .cloned()
            .unwrap_or_else(|| f::application_detail(oid, oid, "Demo App"))
    });

    let scopes_by_id: HashMap<String, Vec<MailScopeEntry>> = apps
        .iter()
        .map(|a| (obj_id(a.name), a.mail_scopes.clone()))
        .collect();
    mock_each("get_mail_permission_scopes", move |args| {
        let oid = args
            .get("objectId")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        scopes_by_id.get(oid).cloned().unwrap_or_default()
    });

    // ---- Enterprise Applications: list + per-id detail ----
    let ent_specs: &[(&str, bool, bool)] = &[
        // (name, account_enabled, is_foreign_tenant)
        ("Salesforce", true, false),
        ("ServiceNow", false, false),
        ("Datadog", true, true),
        ("GitHub Enterprise", true, false),
        ("Zoom", true, false),
        ("Slack", true, false),
        ("Workday", true, false),
        ("Atlassian Cloud", true, false),
    ];
    let enterprise: Vec<_> = ent_specs
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
        .collect();
    mock_ok("list_enterprise_applications", &enterprise);

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
        let id = args
            .get("servicePrincipalId")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
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
    mock_ok(
        "get_enterprise_app_provisioning",
        &vec![f::provisioning_job(
            "Active",
            "Succeeded",
            "2026-06-25T02:14:00Z",
        )],
    );

    // Held Microsoft Graph app-role grants — the Permissions/"granted" tab on
    // BOTH enterprise apps and managed identities (shared command). Varied per id
    // so different principals show different grants.
    let held_variants: Vec<Vec<_>> = vec![
        vec![
            f::held_grant("User.Read.All"),
            f::held_grant("Group.Read.All"),
        ],
        vec![f::held_grant("Mail.Send"), f::held_grant("Files.Read.All")],
        vec![f::held_grant("Directory.Read.All")],
    ];
    mock_each("list_held_app_role_grants", move |args| {
        let id = args
            .get("servicePrincipalId")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
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
        let id = args
            .get("principalId")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        azure_variants[variant_index(id, azure_variants.len())].clone()
    });

    // ---- Security / health ----
    mock_ok("list_credential_expirations", &f::credential_expirations());
    mock_ok("get_cached_audit", &Some(f::audit_run_result()));

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

    // ---- Readiness ----
    mock_ok("check_readiness", &f::readiness_report());

    // ---- Global search (top bar) ----
    mock_ok(
        "global_search",
        &f::global_search_apps(&[
            "Contoso CRM",
            "Fabrikam Mail Sync",
            "Northwind SharePoint Bot",
        ]),
    );

    // ---- Permissions catalog (Grant-access wizard picker) ----
    let resources = vec![f::graph_resource_summary()];
    mock_ok("list_catalog_resources", &resources);
    mock_ok("list_resource_permission_counts", &resources);
    mock_ok(
        "list_resource_permissions",
        &f::graph_resource_permissions(&["User.Read.All", "Mail.Read", "Sites.Selected"]),
    );

    // ---- Infallible `invoke()` commands: must resolve or they panic on the
    // rejected-promise fallback (Result-returning reads can safely fall through).
    mock_ok("cache_stats", &f::cache_stats());
    mock_ok(
        "export_audit_csv",
        &"Application,Risk,Finding\nContoso CRM,Critical,Over-privileged\n".to_string(),
    );
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
}
