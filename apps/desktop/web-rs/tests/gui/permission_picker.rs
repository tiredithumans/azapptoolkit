//! GUI test for the permission picker's "Tenant app registrations" resource
//! group — the tenant's own app registrations that expose Application app roles,
//! surfaced so a managed identity (or app registration) can be granted a custom
//! API's app role. The backend grant path is already resource-agnostic; this
//! proves the picker lists the tenant resource and that an org-wide managed-
//! identity grant carries the tenant app's appId as the resource.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::managed_identity::GrantManagedIdentityResult;
use azapptoolkit_dto::permissions::{CatalogResourceSummary, ResourcePermissions, RoleEntry};
use azapptoolkit_web_rs::components::scope_wizard::{ScopeTarget, ScopeWizard};
use azapptoolkit_web_rs::test_support::{self as ts};

const TENANT_APP_ID: &str = "app-orders";

fn tenant_resource() -> CatalogResourceSummary {
    CatalogResourceSummary {
        app_id: TENANT_APP_ID.to_string(),
        display_name: "Contoso Orders API".to_string(),
        role_count: 2,
        scope_count: 0,
    }
}

/// The tenant app's roles — all Application so the managed-identity picker
/// (`ApplicationOnly`) keeps them. `app_id` matches the dropdown value, so the
/// emitted `PickerSelection.resource_app_id` (taken from the resolved
/// `ResourcePermissions`) is the tenant appId.
fn tenant_permissions() -> ResourcePermissions {
    ResourcePermissions {
        app_id: TENANT_APP_ID.to_string(),
        display_name: "Contoso Orders API".to_string(),
        app_roles: ["Orders.Read.All", "Orders.ReadWrite.All"]
            .iter()
            .map(|v| RoleEntry {
                id: format!("{v}-role-id"),
                value: (*v).to_string(),
                display_name: format!("{v} (application)"),
                description: None,
                allowed_member_types: vec!["Application".to_string()],
            })
            .collect(),
        oauth2_permission_scopes: Vec::new(),
        source: "test".to_string(),
    }
}

fn grant_mi_result() -> GrantManagedIdentityResult {
    GrantManagedIdentityResult {
        managed_identity_id: "mi-sp".to_string(),
        granted: vec!["Orders.Read.All".to_string()],
        skipped: Vec::new(),
        failures: Vec::new(),
    }
}

/// Mount the wizard (open) for a managed-identity target (`object_id: None` →
/// `ApplicationOnly` picker), with the tenant-app resource + its roles mocked.
fn mount_mi_wizard() -> ts::Mounted {
    ts::reset();
    ts::mock_ok("list_app_role_resources", &vec![tenant_resource()]);
    // One payload serves both the default-resource load and the tenant-app
    // selection; we only assert behavior tied to the tenant resource.
    ts::mock_ok("list_resource_permissions", &tenant_permissions());
    ts::mount_view(move || {
        let open = RwSignal::new(true);
        let target = Signal::derive(|| ScopeTarget {
            object_id: None,
            sp_object_id: "mi-sp".to_string(),
            app_id: "mi-app".to_string(),
            display_name: "vm-identity".to_string(),
            is_managed_identity: true,
        });
        let preseed = Signal::derive(|| None);
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

fn select_resource(app_id: &str) {
    let select: web_sys::HtmlSelectElement = ts::query(".permission-picker__select")
        .expect("resource select present")
        .unchecked_into();
    select.set_value(app_id);
    let ev = web_sys::Event::new("change").unwrap();
    select.dispatch_event(&ev).unwrap();
}

/// Toggle the catalog row whose permission value matches `value` exactly.
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

#[wasm_bindgen_test]
async fn picker_lists_tenant_app_registrations_group() {
    let _m = mount_mi_wizard();
    ts::wait_for(|| ts::body_contains("Contoso Orders API")).await;
    assert!(
        ts::query("optgroup[label='Tenant app registrations']").is_some(),
        "tenant app registrations optgroup is present"
    );
    // The label carries the grantable-role count.
    assert!(ts::body_contains("Contoso Orders API (2 app roles)"));
}

#[wasm_bindgen_test]
async fn granting_tenant_app_role_to_managed_identity_passes_tenant_resource() {
    let _m = mount_mi_wizard();
    ts::mock_ok("grant_managed_identity_permission", &grant_mi_result());

    ts::wait_for(|| ts::body_contains("Contoso Orders API")).await;
    // Select the tenant app as the resource; its Application roles load.
    select_resource(TENANT_APP_ID);
    ts::wait_for(|| ts::body_contains("Orders.Read.All")).await;
    select_permission("Orders.Read.All");
    ts::wait_for(next_enabled).await;

    // A managed identity + a custom-API role isn't Exchange/SharePoint-scopable,
    // so the wizard grants org-wide. Step through choose-access → review → grant.
    click_button("Next");
    ts::wait_for(|| ts::body_contains("granted org-wide")).await;
    click_button("Next");
    ts::wait_for(|| ts::body_contains("EVERY resource")).await;
    click_button("Grant access");
    ts::wait_for(|| ts::call_count("grant_managed_identity_permission") == 1).await;

    let call = ts::last_call("grant_managed_identity_permission").unwrap();
    assert_eq!(
        call.args.get("resourceAppId").and_then(|v| v.as_str()),
        Some(TENANT_APP_ID),
        "the grant targets the tenant app registration as the resource"
    );
    assert_eq!(
        call.args
            .get("roles")
            .and_then(|r| r.as_array())
            .map(|a| a.len()),
        Some(1)
    );
}
