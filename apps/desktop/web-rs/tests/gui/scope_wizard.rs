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
//! - **SharePoint item:** picking `Files.SelectedOperations.Selected` + a folder
//!   URL routes to `grant_selected_item_access`, resolving each URL first so the
//!   operator sees what it is about to touch.
//! - **Mixed (not homogeneously scopable):** selecting permissions from two
//!   mechanisms — or two *levels* of the Selected family — hides scoping
//!   entirely and grants org-wide.
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

/// The catalog the mounted picker exposes — covers both scopable mechanisms
/// (Exchange mail, SharePoint sites) plus a non-scopable permission, so a single
/// fixture drives every path including the mixed/org-wide case.
const CATALOG: &[&str] = &[
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Sites.Read.All",
    "Files.SelectedOperations.Selected",
    "Lists.SelectedOperations.Selected",
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

/// A scope group that does NOT exist yet — the panel must announce it will be
/// created rather than implying it already exists.
fn missing_scope_group() -> ExchangeScopeGroupDto {
    ExchangeScopeGroupDto {
        group_name: "app_scope_group_app-0".to_string(),
        exists: false,
        primary_smtp_address: None,
        distinguished_name: None,
        members: Vec::new(),
    }
}

fn site_scope_result() -> SiteScopeResult {
    SiteScopeResult {
        granted_role_added: true,
        declared_permission: true,
        sites_granted: Vec::new(),
        removed_orgwide_grants: vec!["Sites.Read.All".to_string()],
        warnings: Vec::new(),
    }
}

fn selected_item_scope_result() -> azapptoolkit_dto::sharepoint::SelectedItemScopeResult {
    azapptoolkit_dto::sharepoint::SelectedItemScopeResult {
        granted_role_added: true,
        declared_permission: true,
        granted: Vec::new(),
        warnings: Vec::new(),
    }
}

/// A resolved target at `level`, as `resolve_sharepoint_resource` would return.
fn resource_ref(
    level: azapptoolkit_core::scoping::SelectedScopeLevel,
    display_path: &str,
) -> azapptoolkit_dto::sharepoint::SharePointResourceRef {
    use azapptoolkit_core::scoping::SelectedScopeLevel;
    azapptoolkit_dto::sharepoint::SharePointResourceRef {
        level,
        site_id: "contoso.sharepoint.com,site-1".to_string(),
        site_url: Some("https://contoso.sharepoint.com/sites/Finance".to_string()),
        site_name: Some("Finance".to_string()),
        list_id: (level != SelectedScopeLevel::Site).then(|| "list-1".to_string()),
        list_name: Some("Documents".to_string()),
        item_id: (level == SelectedScopeLevel::File).then(|| "item-1".to_string()),
        drive_id: Some("drive-1".to_string()),
        is_folder: level == SelectedScopeLevel::File,
        display_path: display_path.to_string(),
        input_url: "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices"
            .to_string(),
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
async fn step1_hint_explains_disabled_next_until_a_permission_is_picked() {
    let _m = mount_wizard(None);
    ts::wait_for(|| ts::body_contains("Mail.Read")).await;
    // Empty cart: Next is disabled and a hint says why (the apply-time validation
    // message is unreachable from step 1, so without this the button is mute).
    assert!(!next_enabled());
    assert!(ts::body_contains(
        "Select at least one permission to continue."
    ));
    // Picking one clears the hint and enables Next.
    select_permission("Mail.Read");
    ts::wait_for(next_enabled).await;
    assert!(!ts::body_contains(
        "Select at least one permission to continue."
    ));
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
async fn managed_group_panel_flags_a_not_yet_created_group() {
    // Step 2's managed-mailbox panel must clearly distinguish a group that will be
    // created on first add from one that already exists.
    let _m = mount_wizard(None);
    ts::mock_ok("list_exchange_scope_group", &missing_scope_group());

    ts::wait_for(|| ts::body_contains("Mail.Read")).await;
    select_permission("Mail.Read");
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // The panel resolves the (missing) group and announces it will be created.
    ts::wait_for(|| ts::body_contains("Will be created")).await;
    assert!(ts::body_contains("doesn't exist yet"));
}

#[wasm_bindgen_test]
async fn managed_group_panel_marks_an_existing_group_and_lists_members() {
    // An existing group is badged "Exists" and its members are listed so it's
    // clear which mailboxes the scoping applies to.
    let _m = mount_wizard(None);
    ts::mock_ok("list_exchange_scope_group", &populated_scope_group());

    ts::wait_for(|| ts::body_contains("Mail.Read")).await;
    select_permission("Mail.Read");
    ts::wait_for(next_enabled).await;
    click_button("Next");

    ts::wait_for(|| ts::body_contains("alice@contoso.com")).await;
    assert!(ts::body_contains("Exists"));
    assert!(ts::body_contains("1 mailbox in scope"));
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
    // Same contract on the site path: declare Sites.Selected, don't just assign it.
    assert_eq!(
        call.args.get("objectId").and_then(|v| v.as_str()),
        Some("obj-app")
    );
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

#[wasm_bindgen_test]
async fn selected_item_path_grants_against_the_resolved_folder() {
    // The reported gap: `Files.SelectedOperations.Selected` produced no scoping
    // affordance at all and fell through to an org-wide grant.
    use azapptoolkit_core::scoping::SelectedScopeLevel;
    let _m = mount_wizard(None);
    ts::mock_ok(
        "resolve_sharepoint_resource",
        &resource_ref(SelectedScopeLevel::File, "Finance / Documents / Invoices"),
    );
    ts::mock_ok("grant_selected_item_access", &selected_item_scope_result());

    ts::wait_for(|| ts::body_contains("Files.SelectedOperations.Selected")).await;
    select_permission("Files.SelectedOperations.Selected");
    ts::wait_for(next_enabled).await;
    click_button("Next");

    // Step 2 offers the item panel, NOT the "can't be scoped" fallback.
    ts::wait_for(|| ts::body_contains("Library, folder or file URLs")).await;
    assert!(
        !ts::body_contains("can't be scoped together"),
        "a homogeneous Selected cart is scopable and must not fall through to org-wide"
    );
    ts::set_textarea_value(
        ".modal textarea",
        "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices",
    );

    // The panel resolves the URL and shows what it found, before any grant runs
    // — which also requires the row to re-render as its probe completes.
    ts::wait_for(|| ts::body_contains("Finance / Documents / Invoices")).await;
    assert!(
        ts::body_contains("Folder"),
        "a folder reads as a folder, not a file"
    );

    click_button("Next");
    ts::wait_for(|| ts::body_contains("permission inheritance is broken")).await;
    click_button("Grant access");
    ts::wait_for(|| ts::call_count("grant_selected_item_access") == 1).await;

    // The item path only — never the site conversion or the org-wide grant.
    assert_eq!(ts::call_count("convert_site_access_to_selected"), 0);
    assert_eq!(ts::call_count("grant_single_permission"), 0);
    let call = ts::last_call("grant_selected_item_access").unwrap();
    assert_eq!(
        call.args.get("permissionValue").and_then(|v| v.as_str()),
        Some("Files.SelectedOperations.Selected")
    );
    // The app-registration object id rides along so the backend can DECLARE the
    // permission, not just assign it. Without it the grant was real but
    // invisible: the Permissions tab renders `requiredResourceAccess` and joins
    // runtime assignments onto declared rows, so an undeclared assignment shows
    // nowhere — and this picker is the full catalog, so undeclared is the norm.
    assert_eq!(
        call.args.get("objectId").and_then(|v| v.as_str()),
        Some("obj-app")
    );
    assert_eq!(
        call.args
            .get("targetUrls")
            .and_then(|u| u.as_array())
            .map(|a| a.len()),
        Some(1)
    );
}

#[wasm_bindgen_test]
async fn a_target_the_permission_cannot_reach_is_flagged_before_granting() {
    // Pointing a file-level scope at a site URL is the mistake the resolve step
    // exists to catch. The backend fails closed on it either way; the panel has
    // to say so while it is still a correctable typo.
    use azapptoolkit_core::scoping::SelectedScopeLevel;
    let _m = mount_wizard(None);
    ts::mock_ok(
        "resolve_sharepoint_resource",
        &resource_ref(SelectedScopeLevel::Site, "Finance"),
    );

    ts::wait_for(|| ts::body_contains("Files.SelectedOperations.Selected")).await;
    select_permission("Files.SelectedOperations.Selected");
    ts::wait_for(next_enabled).await;
    click_button("Next");

    ts::wait_for(|| ts::body_contains("Library, folder or file URLs")).await;
    ts::set_textarea_value(
        ".modal textarea",
        "https://contoso.sharepoint.com/sites/Finance",
    );

    ts::wait_for(|| ts::body_contains("level this permission can't grant against")).await;
    // The row itself must say what the URL actually resolved to, and why that
    // level is out of reach — the Callout alone doesn't tell you which line to
    // correct. This also pins the row re-rendering as its probe resolves: keyed
    // rendering left them stuck on the spinner while the Callout updated.
    assert!(
        ts::body_contains("Site"),
        "the row names the resolved level"
    );
    assert!(ts::body_contains("cannot reach it"));
}

#[wasm_bindgen_test]
async fn two_selected_levels_in_one_cart_fall_back_to_org_wide() {
    // `Lists.*` grants against a library and `Files.*` against an item inside
    // one — two securables, two endpoints. There is no single target panel that
    // honours both, so the cart is not scopable even though both items share a
    // mechanism.
    let _m = mount_wizard(None);
    ts::mock_ok("grant_single_permission", &fixtures::grant_result());

    ts::wait_for(|| ts::body_contains("Lists.SelectedOperations.Selected")).await;
    select_permission("Files.SelectedOperations.Selected");
    select_permission("Lists.SelectedOperations.Selected");
    ts::wait_for(next_enabled).await;
    click_button("Next");

    ts::wait_for(|| ts::body_contains("can't be scoped together")).await;
    assert!(
        !ts::body_contains("Library, folder or file URLs"),
        "a mixed-level cart must not offer a target panel it cannot apply"
    );
    assert_eq!(ts::call_count("grant_selected_item_access"), 0);
}
