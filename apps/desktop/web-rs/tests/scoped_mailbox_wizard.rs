//! GUI test for the "Grant mailbox access" wizard (`ScopedMailboxWizard`). Proves
//! the streamlined flow's command orchestration for an app registration:
//!
//! - **Scoped (default):** picking mail permissions + the managed-group mailboxes
//!   and applying must DECLARE each permission (no org-wide grant) and then assign
//!   the scoped Exchange RBAC roles with `removeUnscopedEntraGrants = true` — and
//!   must NOT fire the org-wide `grant_single_permission`.
//! - **Org-wide (rare):** choosing the org-wide option must instead grant via
//!   `grant_single_permission` and NOT touch Exchange RBAC.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::exchange::{ExchangeGroupMemberDto, ExchangeScopeGroupDto};
use azapptoolkit_web_rs::components::exchange_scoping_section::ExchangeScopeTarget;
use azapptoolkit_web_rs::components::scoped_mailbox_wizard::ScopedMailboxWizard;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

wasm_bindgen_test_configure!(run_in_browser);

/// A managed scope group that already exists with one member — so the wizard's
/// managed-mailboxes mode can resolve a group SMTP to scope to.
fn populated_scope_group() -> ExchangeScopeGroupDto {
    ExchangeScopeGroupDto {
        group_name: "azapptoolkit_app-0".to_string(),
        exists: true,
        primary_smtp_address: Some("azapptoolkit_app-0@contoso.com".to_string()),
        distinguished_name: Some("CN=azapptoolkit_app-0,OU=contoso".to_string()),
        members: vec![ExchangeGroupMemberDto {
            display_name: Some("Alice".to_string()),
            primary_smtp_address: Some("alice@contoso.com".to_string()),
            recipient_type: Some("UserMailbox".to_string()),
        }],
    }
}

/// Click the first button whose trimmed text equals `label` (the harness clicks
/// by selector only; the wizard footer's buttons are distinguished by text).
fn click_button(label: &str) {
    for el in ts::query_all("button") {
        if el.text_content().unwrap_or_default().trim() == label {
            let el: web_sys::HtmlElement = el.unchecked_into();
            el.click();
            return;
        }
    }
    panic!("no button labelled `{label}`");
}

/// Toggle every permission checkbox currently shown in the primary checklist.
fn check_all_primary_perms() {
    for el in ts::query_all(".checkbox-list input") {
        let el: web_sys::HtmlElement = el.unchecked_into();
        el.click();
    }
}

/// True once the footer "Next" button is enabled — the gate flips reactively a
/// tick after a permission is checked, so callers `wait_for` it before clicking.
fn next_enabled() -> bool {
    ts::query_all("button").iter().any(|el| {
        el.text_content().unwrap_or_default().trim() == "Next"
            && el
                .dyn_ref::<web_sys::HtmlButtonElement>()
                .map(|b| !b.disabled())
                .unwrap_or(false)
    })
}

/// Mount the wizard (open) for an app-registration target and the Graph catalog
/// the apply step resolves permission ids from.
fn mount_wizard() -> ts::Mounted {
    ts::reset();
    ts::mock_ok(
        "list_resource_permissions",
        &fixtures::graph_resource_permissions(&["Mail.Read", "Mail.ReadWrite", "Mail.Send"]),
    );
    ts::mount_view(|| {
        let open = RwSignal::new(true);
        let target = Signal::derive(|| ExchangeScopeTarget::Application {
            object_id: "obj-app".to_string(),
        });
        let app_id = Signal::derive(|| "app-0".to_string());
        view! {
            <ScopedMailboxWizard
                open=open
                target=target
                app_id=app_id
                on_close=Callback::new(|()| {})
                on_changed=Callback::new(|()| {})
            />
        }
    })
}

#[wasm_bindgen_test]
async fn scoped_path_declares_then_scopes_without_orgwide() {
    let _m = mount_wizard();
    ts::mock_ok("list_exchange_scope_group", &populated_scope_group());
    ts::mock_ok("declare_app_permission", &());
    ts::mock_ok(
        "grant_exchange_mailbox_access",
        &fixtures::exchange_access_result(),
    );

    // Step 1 — pick all three mail permissions, then advance once Next enables.
    ts::wait_for(|| ts::body_contains("Mail.Send")).await;
    check_all_primary_perms();
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // Step 2 — managed-mailboxes is the default; wait for its group to resolve.
    ts::wait_for(|| ts::body_contains("alice@contoso.com")).await;
    click_button("Next");

    // Step 3 — review, then grant.
    ts::wait_for(|| ts::body_contains("not have org-wide mailbox access")).await;
    click_button("Grant access");

    ts::wait_for(|| ts::call_count("grant_exchange_mailbox_access") == 1).await;

    // Each permission was DECLARED (no org-wide grant created)…
    assert_eq!(
        ts::call_count("declare_app_permission"),
        3,
        "all three permissions should be declared (manifest only)"
    );
    // …and never granted org-wide.
    assert_eq!(
        ts::call_count("grant_single_permission"),
        0,
        "scoped path must not create an org-wide grant"
    );

    // The scoped grant carried all three permissions, one group, and the strip flag.
    let call = ts::last_call("grant_exchange_mailbox_access").unwrap();
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
    assert_eq!(call.arg_str("objectId").as_deref(), Some("obj-app"));
    assert_eq!(
        call.args
            .get("permissions")
            .and_then(|p| p.as_array())
            .map(|a| a.len()),
        Some(3),
        "scoped grant should carry all three selected permissions"
    );
    assert_eq!(
        call.args
            .get("groups")
            .and_then(|g| g.as_array())
            .map(|a| a.len()),
        Some(1),
        "scoped to the one managed group"
    );
    assert_eq!(
        call.args
            .get("removeUnscopedEntraGrants")
            .and_then(|v| v.as_bool()),
        Some(true),
        "scoping must strip any org-wide grant to bite"
    );
}

#[wasm_bindgen_test]
async fn orgwide_option_grants_without_scoping() {
    let _m = mount_wizard();
    ts::mock_ok("grant_single_permission", &fixtures::grant_result());
    // The managed panel mounts briefly (Managed is the default mode) before we
    // switch to org-wide, so mock its load to keep it from rejecting unmocked.
    ts::mock_ok("list_exchange_scope_group", &populated_scope_group());

    // Step 1 — pick the permissions, then advance once Next enables.
    ts::wait_for(|| ts::body_contains("Mail.Read")).await;
    check_all_primary_perms();
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // Step 2 — choose the rare org-wide option (the third radio).
    ts::wait_for(|| ts::body_contains("Org-wide")).await;
    let radios = ts::query_all(".radio-row input");
    assert_eq!(radios.len(), 3, "managed / existing / org-wide");
    let orgwide: web_sys::HtmlElement = radios[2].clone().unchecked_into();
    orgwide.click();
    ts::tick().await;
    click_button("Next");

    // Step 3 — review warns about tenant-wide reach, then grant.
    ts::wait_for(|| ts::body_contains("EVERY mailbox")).await;
    click_button("Grant access");

    ts::wait_for(|| ts::call_count("grant_single_permission") == 3).await;

    // Org-wide grants, never the scoped Exchange path.
    assert_eq!(ts::call_count("grant_exchange_mailbox_access"), 0);
    assert_eq!(ts::call_count("declare_app_permission"), 0);
    let call = ts::last_call("grant_single_permission").unwrap();
    assert_eq!(
        call.arg_str("resourceAppId").as_deref(),
        Some(fixtures::MICROSOFT_GRAPH_APP_ID)
    );
}
