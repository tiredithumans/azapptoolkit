//! GUI test for the Managed Identity inline scoping path: picking a scopable
//! Microsoft Graph mail permission (e.g. `Mail.Read`) in the permission picker
//! must open the inline Exchange scope panel — letting you confine the grant to
//! mailbox group(s) at add-time — instead of granting org-wide immediately, and
//! submitting it must route to the *scoped* grant. Proves the picker→scope-panel
//! wiring (`do_grant` → `scope_kind_for` → `pending_scope` → `ScopePanel`) the
//! App Registrations flow handles per-row and the MI flow handles at grant time.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::exchange::MailScopeEntry;
use azapptoolkit_dto::managed_identity::{AppRoleGrantDto, AzureRolesResult};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::managed_identities::ManagedIdentitiesView;

wasm_bindgen_test_configure!(run_in_browser);

/// Mocks every command the MI list + detail pane + picker fire, mounts the view,
/// selects the one managed identity (on its Permissions tab), and reveals the
/// permission picker — leaving a single `Mail.Read` application-permission row
/// with its Grant button rendered. Returns the mount handle (keep it alive).
async fn mount_and_open_picker() -> ts::Mounted {
    ts::reset();
    // List + detail-pane resources (held permissions empty: no mail held yet, so
    // the app-wide section's mail-scope lookup is never invoked — but mock it
    // empty for safety against a re-run).
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-prod-api"]),
    );
    ts::mock_ok("list_held_app_role_grants", &Vec::<AppRoleGrantDto>::new());
    ts::mock_ok(
        "get_mail_scopes_for_principal",
        &Vec::<MailScopeEntry>::new(),
    );
    ts::mock_ok(
        "list_managed_identity_azure_roles",
        &AzureRolesResult::default(),
    );
    // Permission picker resources: Microsoft Graph exposing a single Mail.Read
    // application permission.
    ts::mock_ok(
        "list_catalog_resources",
        &vec![fixtures::graph_resource_summary()],
    );
    ts::mock_ok(
        "list_resource_permission_counts",
        &vec![fixtures::graph_resource_summary()],
    );
    ts::mock_ok(
        "list_resource_permissions",
        &fixtures::graph_resource_permissions(&["Mail.Read"]),
    );

    let m = ts::mount_view(|| view! { <ManagedIdentitiesView /> });

    // List loaded.
    ts::wait_for(|| ts::query_all(".app-list__row").len() == 1).await;

    // Open the detail pane on the Permissions tab for the one identity. The pane
    // initialises its active tab from `last_mi_tab`, so set it before selecting.
    m.session.last_mi_tab.set("permissions".to_string());
    m.session
        .selected_managed_identity_id
        .set(Some("mi-0".to_string()));

    // Detail pane mounted (its grant section header renders).
    ts::wait_for(|| ts::body_contains("Grant application permissions")).await;

    // Reveal the picker ("Add permission"), then wait for the Mail.Read row.
    ts::click(".mi-grant header button");
    ts::wait_for(|| {
        ts::body_contains("Mail.Read") && !ts::query_all(".permission-picker__row").is_empty()
    })
    .await;

    m
}

#[wasm_bindgen_test]
async fn picking_mail_permission_opens_inline_exchange_scope_panel() {
    let _m = mount_and_open_picker().await;

    // Grant the (only) row — Mail.Read.
    ts::click(".permission-picker__row button");

    // The inline Exchange scope panel opens instead of an org-wide grant.
    ts::wait_for(|| ts::query(".mi-scope-panel").is_some()).await;

    // It is the Exchange (scope-to-mailboxes) variant, exposing a free-text
    // group/mailbox field — the "scope to existing groups" affordance.
    assert!(ts::body_contains("to specific mailboxes"));
    assert!(ts::body_contains("Mail.Read"));
    assert!(ts::body_contains("Scope to mailboxes"));
    assert!(
        ts::query(".mi-scope-panel textarea").is_some(),
        "scope panel should expose the free-text group/mailbox field"
    );

    // The crux: picking a scopable permission INTERCEPTS — it must open the
    // scope panel, not fire the org-wide grant.
    assert_eq!(
        ts::call_count("grant_managed_identity_permission"),
        0,
        "a scopable permission must open the scope panel, not grant org-wide"
    );
}

#[wasm_bindgen_test]
async fn scoping_inline_calls_scoped_exchange_grant_not_orgwide() {
    let _m = mount_and_open_picker().await;
    // The scoped-grant the panel submits to (added after `mount_and_open_picker`,
    // whose `reset()` would otherwise clear it).
    ts::mock_ok(
        "grant_managed_identity_scoped_exchange_access",
        &fixtures::exchange_access_result(),
    );

    ts::click(".permission-picker__row button");
    ts::wait_for(|| ts::query(".mi-scope-panel textarea").is_some()).await;

    // Scope it to an existing mailbox group, then confine.
    ts::set_textarea_value(".mi-scope-panel textarea", "hr-team@contoso.com");
    ts::click(".mi-scope-panel .actions-row button"); // first button: "Scope to mailboxes"

    ts::wait_for(|| ts::call_count("grant_managed_identity_scoped_exchange_access") == 1).await;

    let call = ts::last_call("grant_managed_identity_scoped_exchange_access").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    // Scoped to the typed group, for the Mail.Read permission, stripping org-wide.
    assert_eq!(
        call.args
            .get("groups")
            .and_then(|g| g.as_array())
            .map(|a| a.len()),
        Some(1)
    );
    assert!(
        call.args
            .get("mailPermissions")
            .and_then(|p| p.as_array())
            .map(|a| a.iter().any(|v| v.as_str() == Some("Mail.Read")))
            .unwrap_or(false),
        "scoped grant should carry the Mail.Read permission"
    );
    assert_eq!(
        call.args
            .get("removeUnscopedEntraGrants")
            .and_then(|v| v.as_bool()),
        Some(true)
    );

    // Never granted org-wide.
    assert_eq!(ts::call_count("grant_managed_identity_permission"), 0);
}
