//! GUI tests for "SharePoint item access" (`SharePointItemScopesSection`): the
//! libraries, folders and files an app was granted under a sub-site Selected
//! permission, read from the app's own record because Graph can't list them.
//!
//! Pins what makes the list trustworthy and safe: it costs nothing while
//! collapsed, each status reads as what SharePoint said (an unreadable row is
//! never "not granted"), only a live grant offers a revoke (and only through a
//! confirm, by ids), a stale row is forgotten without touching SharePoint, and
//! the empty state says grants made elsewhere aren't listed.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_core::scoping::SelectedScopeLevel;
use azapptoolkit_dto::sharepoint::{
    AppItemScopeDto, AppItemScopesDto, ItemScopeRef, ItemScopeStatus, SelectedItemScopeResult,
};
use azapptoolkit_web_rs::components::sharepoint_item_scopes_section::SharePointItemScopesSection;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

const APP_ID: &str = "11111111-2222-3333-4444-555555555555";
const OBJ: &str = "obj-app";
const SITE: &str = "contoso.sharepoint.com,2c712604-1370-44e7-a1f5-426573fda80a,2d2244c3-251a-49ea-93a8-39e1c3a060fe";
const LIST: &str = "8b1e5c2a-0d3f-4a1b-9c2e-1f2a3b4c5d6e";
const URL_INPUT: &str = "input[placeholder^='https://contoso.sharepoint.com/sites/Finance']";

fn entry(item: &str, name: &str, is_folder: bool, status: ItemScopeStatus) -> AppItemScopeDto {
    AppItemScopeDto {
        scope: ItemScopeRef {
            level: SelectedScopeLevel::File,
            site_id: SITE.into(),
            list_id: LIST.into(),
            item_id: Some(item.into()),
        },
        name: Some(name.into()),
        web_url: Some(format!(
            "https://contoso.sharepoint.com/sites/Finance/{name}"
        )),
        is_folder,
        status,
    }
}

fn four_statuses() -> AppItemScopesDto {
    AppItemScopesDto {
        entries: vec![
            entry(
                "17",
                "Q1 Invoices.xlsx",
                false,
                ItemScopeStatus::Granted {
                    permission_id: "perm-17".into(),
                    roles: vec!["read".into()],
                },
            ),
            entry("18", "2026", true, ItemScopeStatus::NotGranted),
            entry("19", "Old.docx", false, ItemScopeStatus::Missing),
            entry(
                "20",
                "Locked.pdf",
                false,
                ItemScopeStatus::Unreadable {
                    message: "access denied".into(),
                },
            ),
        ],
        malformed: 0,
    }
}

/// Mounts the section collapsed, proves it cost no IPC, then expands it.
async fn mount_with(scopes: AppItemScopesDto) -> ts::Mounted {
    ts::reset();
    ts::mock_ok("list_app_item_scopes", &scopes);
    let m = ts::mount_view(|| {
        view! {
            <SharePointItemScopesSection
                object_id=Signal::derive(|| OBJ.to_string())
                sp_object_id=Signal::derive(|| "sp-app".to_string())
                app_id=Signal::derive(|| APP_ID.to_string())
                app_display_name=Signal::derive(|| "Payroll API".to_string())
                permission_values=Signal::derive(|| {
                    vec!["Files.SelectedOperations.Selected".to_string()]
                })
                on_changed=Callback::new(|()| {})
            />
        }
    });
    ts::wait_for(|| ts::body_contains("SharePoint item access")).await;
    assert_eq!(
        ts::call_count("list_app_item_scopes"),
        0,
        "a collapsed section must cost no IPC"
    );
    ts::click_button_labelled("Show");
    m
}

fn buttons(label: &str) -> usize {
    ts::query_all("button")
        .into_iter()
        .filter(|b| b.text_content().unwrap_or_default().trim() == label)
        .count()
}

#[wasm_bindgen_test]
async fn each_recorded_grant_reads_as_what_sharepoint_said() {
    let _m = mount_with(four_statuses()).await;
    ts::wait_for(|| ts::body_contains("Q1 Invoices.xlsx")).await;

    let call = ts::last_call("list_app_item_scopes").unwrap();
    assert_eq!(call.arg_str("objectId").as_deref(), Some(OBJ));
    assert_eq!(call.arg_str("appId").as_deref(), Some(APP_ID));

    assert!(ts::body_contains("Folder"));
    assert!(ts::body_contains(
        "Not granted (removed outside azapptoolkit)"
    ));
    assert!(ts::body_contains(
        "Not found (deleted, or moved to another library)"
    ));
    assert!(
        ts::body_contains("Couldn't check: access denied"),
        "an unreadable row says so, never 'not granted'"
    );
    assert_eq!(buttons("Remove"), 1, "only the live grant can be revoked");
    assert_eq!(buttons("Forget"), 3);
}

/// Revoking goes through a confirm and sends the record's ids and the entry
/// id, which the backend re-checks belongs to this app before deleting.
#[wasm_bindgen_test]
async fn remove_confirms_then_revokes_by_ids() {
    let _m = mount_with(four_statuses()).await;
    ts::mock_ok("remove_app_item_scope", &serde_json::json!(null));
    ts::wait_for(|| ts::body_contains("Q1 Invoices.xlsx")).await;

    ts::click("button[aria-label='Remove access to Q1 Invoices.xlsx']");
    ts::wait_for(|| ts::query(".modal").is_some()).await;
    assert_eq!(
        ts::call_count("remove_app_item_scope"),
        0,
        "nothing before the confirm"
    );
    ts::click_button_labelled_in(".modal", "Remove");

    ts::wait_for(|| ts::call_count("remove_app_item_scope") == 1).await;
    let call = ts::last_call("remove_app_item_scope").unwrap();
    assert_eq!(call.arg_str("permissionId").as_deref(), Some("perm-17"));
    assert_eq!(call.args["scope"]["item_id"], "17");
    assert_eq!(call.args["scope"]["list_id"], LIST);
    ts::wait_for(|| ts::call_count("list_app_item_scopes") == 2).await;
}

/// A stale row is forgotten without a confirm and without a permission id:
/// it only drops the record, never touches SharePoint.
#[wasm_bindgen_test]
async fn forget_drops_only_the_record() {
    let _m = mount_with(four_statuses()).await;
    ts::mock_ok("remove_app_item_scope", &serde_json::json!(null));
    ts::wait_for(|| ts::body_contains("Old.docx")).await;

    ts::click("button[aria-label='Forget Old.docx']");

    ts::wait_for(|| ts::call_count("remove_app_item_scope") == 1).await;
    let call = ts::last_call("remove_app_item_scope").unwrap();
    assert!(call.args["permissionId"].is_null());
    assert_eq!(call.args["scope"]["item_id"], "19");
}

#[wasm_bindgen_test]
async fn the_empty_state_says_grants_made_elsewhere_are_not_listed() {
    let _m = mount_with(AppItemScopesDto {
        entries: Vec::new(),
        malformed: 0,
    })
    .await;
    ts::wait_for(|| ts::body_contains("No libraries, folders or files recorded")).await;
    assert!(ts::body_contains(
        "aren't listed until you track them below"
    ));
}

/// Add resolves the URL, grants on it with the chosen role, shows the
/// backend's warnings, and reloads the list.
#[wasm_bindgen_test]
async fn add_grants_the_url_with_the_chosen_role() {
    const URL: &str = "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Q2.xlsx";
    let _m = mount_with(four_statuses()).await;
    ts::mock_ok(
        "resolve_sharepoint_resource",
        &fixtures::sharepoint_resource_ref(URL),
    );
    ts::mock_ok(
        "grant_selected_item_access",
        &SelectedItemScopeResult {
            granted_role_added: false,
            declared_permission: false,
            granted: Vec::new(),
            warnings: vec!["could not resolve 'x': gone".into()],
            recorded_on_app: true,
        },
    );
    ts::wait_for(|| ts::query(URL_INPUT).is_some()).await;

    ts::set_input_value(URL_INPUT, URL);
    ts::click_button_labelled("Grant read");

    ts::wait_for(|| ts::call_count("grant_selected_item_access") == 1).await;
    let call = ts::last_call("grant_selected_item_access").unwrap();
    assert_eq!(call.arg_str("role").as_deref(), Some("read"));
    assert_eq!(call.arg_str("objectId").as_deref(), Some(OBJ));
    assert_eq!(call.arg_str("spObjectId").as_deref(), Some("sp-app"));
    assert_eq!(
        call.arg_str("permissionValue").as_deref(),
        Some("Files.SelectedOperations.Selected")
    );
    assert_eq!(call.args["targetUrls"][0], URL);
    ts::wait_for(|| ts::body_contains("could not resolve 'x': gone")).await;
    ts::wait_for(|| ts::call_count("list_app_item_scopes") == 2).await;
}

/// A grant made outside azapptoolkit is tracked by URL, then the list reloads.
#[wasm_bindgen_test]
async fn track_records_an_existing_grant_by_url() {
    const URL: &str = "https://contoso.sharepoint.com/sites/Finance/Shared Documents";
    let _m = mount_with(four_statuses()).await;
    ts::mock_ok(
        "track_app_item_scope",
        &ItemScopeRef {
            level: SelectedScopeLevel::List,
            site_id: SITE.into(),
            list_id: LIST.into(),
            item_id: None,
        },
    );
    ts::wait_for(|| ts::query(URL_INPUT).is_some()).await;

    ts::set_input_value(URL_INPUT, URL);
    ts::click_button_labelled("Track existing grant");

    ts::wait_for(|| ts::call_count("track_app_item_scope") == 1).await;
    let call = ts::last_call("track_app_item_scope").unwrap();
    assert_eq!(call.arg_str("url").as_deref(), Some(URL));
    assert_eq!(call.arg_str("objectId").as_deref(), Some(OBJ));
    ts::wait_for(|| ts::call_count("list_app_item_scopes") == 2).await;
}
