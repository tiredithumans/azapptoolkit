//! GUI test for the mechanism-dispatched "Grant scoped access" wizard
//! (`ScopeWizard`). Proves the apply orchestration per mechanism for an app
//! registration:
//!
//! - **Exchange (default):** picking mail permissions + the managed-group
//!   mailboxes DECLAREs each permission (no org-wide grant) and assigns the
//!   scoped Exchange RBAC roles with `removeUnscopedEntraGrants = true`.
//! - **Org-wide (rare):** the org-wide option grants via `grant_single_permission`.
//! - **SharePoint:** picking `Sites.Read.All` + a site URL routes to
//!   `convert_site_access_to_selected` with `removeOrgwide = true` and never
//!   touches Exchange RBAC.
//! - **Pre-seed:** opening with a permission pre-selected jumps to the target step.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::exchange::{ExchangeGroupMemberDto, ExchangeScopeGroupDto};
use azapptoolkit_dto::sharepoint::SiteScopeResult;
use azapptoolkit_web_rs::components::scope_wizard::{ScopeTarget, ScopeWizard};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

wasm_bindgen_test_configure!(run_in_browser);

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

fn site_scope_result() -> SiteScopeResult {
    SiteScopeResult {
        granted_role_added: true,
        sites_granted: Vec::new(),
        removed_orgwide_grants: vec!["Sites.Read.All".to_string()],
        warnings: Vec::new(),
    }
}

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

fn next_enabled() -> bool {
    ts::query_all("button").iter().any(|el| {
        el.text_content().unwrap_or_default().trim() == "Next"
            && el
                .dyn_ref::<web_sys::HtmlButtonElement>()
                .map(|b| !b.disabled())
                .unwrap_or(false)
    })
}

/// Click the nth (0-based) checkbox across the visible checklists (mail primary
/// first, then SharePoint).
fn click_checkbox(n: usize) {
    let boxes = ts::query_all(".checkbox-list input");
    let el: web_sys::HtmlElement = boxes[n].clone().unchecked_into();
    el.click();
}

/// Mount the wizard (open) for an app-registration target, with `preseed`.
fn mount_wizard(preseed: Option<&'static str>) -> ts::Mounted {
    ts::reset();
    ts::mock_ok(
        "list_resource_permissions",
        &fixtures::graph_resource_permissions(&["Mail.Read", "Mail.ReadWrite", "Mail.Send"]),
    );
    ts::mount_view(move || {
        let open = RwSignal::new(true);
        let target = Signal::derive(|| ScopeTarget {
            object_id: Some("obj-app".to_string()),
            sp_object_id: "sp-app".to_string(),
            app_id: "app-0".to_string(),
            display_name: "App".to_string(),
            is_managed_identity: false,
        });
        let preseed = Signal::derive(move || preseed.map(str::to_string));
        view! {
            <ScopeWizard
                open=open
                target=target
                preseed=preseed
                on_close=Callback::new(|()| {})
                on_changed=Callback::new(|()| {})
            />
        }
    })
}

#[wasm_bindgen_test]
async fn exchange_scoped_path_declares_then_scopes_without_orgwide() {
    let _m = mount_wizard(None);
    ts::mock_ok("list_exchange_scope_group", &populated_scope_group());
    ts::mock_ok("declare_app_permission", &());
    ts::mock_ok(
        "grant_exchange_mailbox_access",
        &fixtures::exchange_access_result(),
    );

    // Step 1 — pick the three mail permissions (first three checkboxes).
    ts::wait_for(|| ts::body_contains("Mail.Send")).await;
    click_checkbox(0);
    click_checkbox(1);
    click_checkbox(2);
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // Step 2 — managed mailboxes (default); wait for the group to resolve.
    ts::wait_for(|| ts::body_contains("alice@contoso.com")).await;
    click_button("Next");

    // Step 3 — review, then grant.
    ts::wait_for(|| ts::body_contains("not have org-wide mailbox access")).await;
    click_button("Grant access");
    ts::wait_for(|| ts::call_count("grant_exchange_mailbox_access") == 1).await;

    assert_eq!(ts::call_count("declare_app_permission"), 3);
    assert_eq!(ts::call_count("grant_single_permission"), 0);
    let call = ts::last_call("grant_exchange_mailbox_access").unwrap();
    assert_eq!(
        call.args
            .get("permissions")
            .and_then(|p| p.as_array())
            .map(|a| a.len()),
        Some(3)
    );
    assert_eq!(
        call.args
            .get("removeUnscopedEntraGrants")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[wasm_bindgen_test]
async fn orgwide_option_grants_without_scoping() {
    let _m = mount_wizard(None);
    ts::mock_ok("grant_single_permission", &fixtures::grant_result());
    ts::mock_ok("list_exchange_scope_group", &populated_scope_group());

    ts::wait_for(|| ts::body_contains("Mail.Read")).await;
    click_checkbox(0);
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // Step 2 — the org-wide radio is the last mode option.
    ts::wait_for(|| ts::body_contains("Org-wide")).await;
    let radios = ts::query_all(".radio-row input");
    let orgwide: web_sys::HtmlElement = radios[radios.len() - 1].clone().unchecked_into();
    orgwide.click();
    ts::tick().await;
    click_button("Next");

    ts::wait_for(|| ts::body_contains("EVERY resource")).await;
    click_button("Grant access");
    ts::wait_for(|| ts::call_count("grant_single_permission") == 1).await;

    assert_eq!(ts::call_count("grant_exchange_mailbox_access"), 0);
    assert_eq!(ts::call_count("declare_app_permission"), 0);
}

#[wasm_bindgen_test]
async fn sharepoint_path_converts_to_sites_selected() {
    let _m = mount_wizard(None);
    ts::mock_ok("convert_site_access_to_selected", &site_scope_result());

    // Step 1 — pick Sites.Read.All (the first SharePoint checkbox, index 3 after
    // the three mail permissions).
    ts::wait_for(|| ts::body_contains("Sites.Read.All")).await;
    click_checkbox(3);
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // Step 2 — SharePoint site selection.
    ts::wait_for(|| ts::query(".modal textarea").is_some()).await;
    ts::set_textarea_value(
        ".modal textarea",
        "https://contoso.sharepoint.com/sites/Marketing",
    );
    click_button("Next");

    // Step 3 — review, then grant.
    ts::wait_for(|| ts::body_contains("not have org-wide site access")).await;
    click_button("Grant access");
    ts::wait_for(|| ts::call_count("convert_site_access_to_selected") == 1).await;

    // SharePoint scoping only — never the Exchange RBAC path.
    assert_eq!(ts::call_count("grant_exchange_mailbox_access"), 0);
    assert_eq!(ts::call_count("declare_app_permission"), 0);
    let call = ts::last_call("convert_site_access_to_selected").unwrap();
    assert_eq!(
        call.args
            .get("siteUrls")
            .and_then(|u| u.as_array())
            .map(|a| a.len()),
        Some(1)
    );
    assert_eq!(
        call.args.get("removeOrgwide").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[wasm_bindgen_test]
async fn preseed_jumps_to_the_target_step() {
    // Opening with a permission pre-selected (the per-row "Scope…" entry) skips
    // the pick step and lands on that permission's target step.
    let _m = mount_wizard(Some("Sites.Read.All"));
    ts::wait_for(|| ts::body_contains("Site URLs")).await;
    assert!(
        ts::body_contains("Step 2 of 3"),
        "preseed should jump straight to the target step"
    );
}
