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
//! Compiled only under the `demo` feature, so none of this — nor the mock bridge
//! or fixtures it pulls in — ever enters the shipped desktop Trunk bundle.

use azapptoolkit_core::audit::ListCredentialStatus;
use azapptoolkit_core::identity::TenantContext;
use azapptoolkit_dto::managed_identity::MiSubtype;

use crate::ipc_mock::{self, Unmocked, fixtures as f, mock_ok};

/// The signed-in tenant the demo presents (presentable copy; mirrors
/// `test_support::test_tenant`). `App` seeds this as the active tenant so the
/// config + sign-in gates fall through straight to the authenticated shell.
pub fn demo_tenant() -> TenantContext {
    TenantContext {
        tenant_id: "demo-tenant".to_string(),
        account_oid: "00000000-0000-0000-0000-0000000000de".to_string(),
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

fn register_fixtures() {
    // ---- Startup / shell ----
    mock_ok("get_auth_config", &f::configured());
    mock_ok("get_organization", &f::organization("Contoso Ltd"));
    // Sign-out clears the tenant (→ sign-in screen); mocking sign_in lets the
    // demo round-trip back into the shell instead of dead-ending.
    mock_ok("sign_in", &f::sign_in_outcome(demo_tenant()));
    mock_ok("reauthenticate", &f::sign_in_outcome(demo_tenant()));
    mock_ok("current_tenants", &vec![demo_tenant()]);

    // ---- App Registrations ----
    let mut apps = f::apps(&[
        "Contoso CRM",
        "Fabrikam Mail Sync",
        "Northwind SharePoint Bot",
        "Adventure Works API",
        "Tailspin Reporting",
        "Wingtip Toys Connector",
        "Proseware Sync",
        "Litware Analytics",
        "Margie's Travel Portal",
        "Alpine Ski House Booking",
        "Blue Yonder Airlines API",
        "Coho Vineyard Storefront",
    ]);
    // Enrich a few rows so the Home "With secrets / With certs" metrics are
    // non-zero and the credential-status column shows variety.
    apps[0].password_credential_count = 2;
    apps[0].credential_status = ListCredentialStatus::Expired;
    apps[1].password_credential_count = 1;
    apps[1].credential_status = ListCredentialStatus::Expiring;
    apps[2].key_credential_count = 1;
    apps[4].key_credential_count = 1;
    apps[5].password_credential_count = 1;
    mock_ok("list_applications_with_pairing", &apps);
    mock_ok(
        "get_application_detail",
        &f::application_detail("obj-0", "obj-0-appid", "Contoso CRM"),
    );

    // ---- Enterprise Applications ----
    let mut enterprise = f::enterprise_apps(&[
        "Salesforce",
        "ServiceNow",
        "Datadog (foreign tenant)",
        "GitHub Enterprise",
        "Zoom",
        "Slack",
        "Workday",
        "Atlassian Cloud",
    ]);
    enterprise[1].account_enabled = Some(false);
    enterprise[2].is_foreign_tenant = true;
    enterprise[2].app_owner_organization_id =
        Some("ffffffff-ffff-ffff-ffff-ffffffffffff".to_string());
    mock_ok("list_enterprise_applications", &enterprise);
    mock_ok(
        "get_enterprise_application_detail",
        &f::enterprise_application_detail("sp-0", "Salesforce"),
    );

    // ---- Managed Identities ----
    let mut managed = f::managed_identities(&[
        "aks-prod-identity",
        "func-orders-mi",
        "vm-backup-agent",
        "logic-app-connector",
        "data-factory-mi",
    ]);
    managed[0].mi_subtype = MiSubtype::SystemAssigned;
    managed[2].mi_subtype = MiSubtype::SystemAssigned;
    mock_ok("list_managed_identities", &managed);

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
    let catalog = vec![f::graph_resource_summary()];
    mock_ok("list_catalog_resources", &catalog);
    mock_ok("list_resource_permission_counts", &catalog);
    mock_ok(
        "list_resource_permissions",
        &f::graph_resource_permissions(&["User.Read.All", "Mail.Read", "Directory.Read.All"]),
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
