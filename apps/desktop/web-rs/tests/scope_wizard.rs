//! GUI test for the unified, mechanism-dispatched "Grant access" wizard
//! (`ScopeWizard`). Step 1 is now the full live permission catalog
//! (`PermissionPicker`) as a multi-select cart; the wizard infers the scoping
//! mechanism from the whole cart and dispatches the apply per mechanism for an
//! app registration:
//!
//! - **Exchange (default):** picking mail permissions + the managed-group
//!   mailboxes DECLAREs each permission (no org-wide grant) and assigns the
//!   scoped Exchange RBAC roles with `removeUnscopedEntraGrants = true`.
//! - **Org-wide (rare):** the org-wide option grants via `grant_single_permission`.
//! - **SharePoint:** picking `Sites.Read.All` + a site URL routes to
//!   `convert_site_access_to_selected` with `removeOrgwide = true` and never
//!   touches Exchange RBAC.
//! - **Mixed (not homogeneously scopable):** selecting permissions from two
//!   mechanisms hides scoping entirely and grants org-wide.
//! - **Pre-seed:** opening with a permission pre-selected jumps to the
//!   choose-access step.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::exchange::{ExchangeGroupMemberDto, ExchangeScopeGroupDto};
use azapptoolkit_dto::permissions::PermissionKind;
use azapptoolkit_dto::sharepoint::SiteScopeResult;
use azapptoolkit_web_rs::components::permission_picker::PickerSelection;
use azapptoolkit_web_rs::components::scope_wizard::{ScopeTarget, ScopeWizard};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

wasm_bindgen_test_configure!(run_in_browser);

/// The catalog the mounted picker exposes — covers both scopable mechanisms
/// (Exchange mail, SharePoint sites) plus a non-scopable permission, so a single
/// fixture drives every path including the mixed/org-wide case.
const CATALOG: &[&str] = &[
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Sites.Read.All",
    "User.Read.All",
];

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

/// A pre-seed selection for a Microsoft Graph application permission (the per-row
/// "Scope…" entry hands the wizard a full selection).
fn graph_app_selection(value: &str) -> PickerSelection {
    PickerSelection {
        resource_app_id: fixtures::MICROSOFT_GRAPH_APP_ID.to_string(),
        kind: PermissionKind::Application,
        permission_id: format!("{value}-role-id"),
        permission_value: value.to_string(),
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

/// Toggle the catalog row whose permission value matches `value` exactly (the
/// `<strong>` head), clicking its cart checkbox.
fn select_permission(value: &str) {
    for row in ts::query_all(".permission-picker__row") {
        let head = row
            .query_selector(".permission-picker__row-head strong")
            .ok()
            .flatten();
        let is_match = head
            .map(|h| h.text_content().unwrap_or_default().trim() == value)
            .unwrap_or(false);
        if is_match {
            let cb = row
                .query_selector(".permission-picker__check")
                .ok()
                .flatten()
                .expect("permission row has a checkbox");
            let el: web_sys::HtmlElement = cb.unchecked_into();
            el.click();
            return;
        }
    }
    panic!("no permission row for `{value}`");
}

/// Mount the wizard (open) for an app-registration target, with `preseed`.
fn mount_wizard(preseed: Option<PickerSelection>) -> ts::Mounted {
    ts::reset();
    ts::mock_ok(
        "list_resource_permissions",
        &fixtures::graph_resource_permissions(CATALOG),
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
        let preseed = Signal::derive(move || preseed.clone());
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

    // Step 1 — pick the three mail permissions from the catalog.
    ts::wait_for(|| ts::body_contains("Mail.Send")).await;
    select_permission("Mail.Read");
    select_permission("Mail.ReadWrite");
    select_permission("Mail.Send");
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
    select_permission("Mail.Read");
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // Step 2 — the org-wide radio is the last of the three Exchange mode options.
    ts::wait_for(|| ts::query_all(".radio-row input").len() == 3).await;
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

    // Step 1 — pick Sites.Read.All from the catalog.
    ts::wait_for(|| ts::body_contains("Sites.Read.All")).await;
    select_permission("Sites.Read.All");
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
async fn mixed_selection_grants_org_wide_only() {
    // A cart spanning two mechanisms (mail + SharePoint) can't be scoped in one
    // run, so the wizard hides scoping and grants org-wide.
    let _m = mount_wizard(None);
    ts::mock_ok("grant_single_permission", &fixtures::grant_result());

    ts::wait_for(|| ts::body_contains("Sites.Read.All")).await;
    select_permission("Mail.Read");
    select_permission("Sites.Read.All");
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // Step 2 — no scoped targets; the note explains why, and org-wide is forced.
    ts::wait_for(|| ts::body_contains("can't be scoped together")).await;
    click_button("Next");

    ts::wait_for(|| ts::body_contains("EVERY resource")).await;
    click_button("Grant access");
    ts::wait_for(|| ts::call_count("grant_single_permission") == 2).await;

    assert_eq!(ts::call_count("grant_exchange_mailbox_access"), 0);
    assert_eq!(ts::call_count("declare_app_permission"), 0);
}

#[wasm_bindgen_test]
async fn preseed_jumps_to_the_choose_access_step() {
    // Opening with a permission pre-selected (the per-row "Scope…" entry) skips
    // the select step and lands on that permission's choose-access step.
    let _m = mount_wizard(Some(graph_app_selection("Sites.Read.All")));
    ts::wait_for(|| ts::body_contains("Site URLs")).await;
    assert!(
        ts::body_contains("Step 2 of 3"),
        "preseed should jump straight to the choose-access step"
    );
}
