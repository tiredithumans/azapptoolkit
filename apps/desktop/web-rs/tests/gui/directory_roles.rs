//! The Directory roles section (C1): lists a principal's direct, active
//! roles, removes only admin-unit-scoped ones behind a named confirm, and says
//! whether a unit-limited write is real or voided by a tenant-wide role.

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::admin_units::{DirectoryRoleDto, DirectoryRoleScopeDto};
use azapptoolkit_web_rs::components::directory_roles_section::DirectoryRolesSection;
use azapptoolkit_web_rs::test_support as ts;

const SP: &str = "5f8b2c1a-0d3e-4b6f-9a7c-1e2d3f4a5b6c";
const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
const REPORTS_READER: &str = "4a5d8f65-41da-4de4-8968-e035b65339cf";

fn unit_role() -> DirectoryRoleDto {
    DirectoryRoleDto {
        assignment_id: "ra-unit".into(),
        role_template_id: USER_ADMIN.into(),
        role_name: "User Administrator".into(),
        scope: DirectoryRoleScopeDto::AdminUnit {
            id: "au-1".into(),
            name: "Finance".into(),
        },
    }
}

fn tenant_role(id: &str, template: &str, name: &str) -> DirectoryRoleDto {
    DirectoryRoleDto {
        assignment_id: id.into(),
        role_template_id: template.into(),
        role_name: name.into(),
        scope: DirectoryRoleScopeDto::Tenant,
    }
}

fn mount() -> ts::Mounted {
    ts::mount_view(|| {
        view! { <DirectoryRolesSection sp_object_id=Signal::derive(|| SP.to_string()) /> }
    })
}

fn remove_buttons() -> Vec<web_sys::HtmlElement> {
    ts::query_all(".directory-roles button[aria-label^='Remove ']")
        .into_iter()
        .map(|el| el.unchecked_into())
        .collect()
}

#[wasm_bindgen_test]
async fn the_directory_roles_section_lists_and_removes_a_unit_role() {
    ts::reset();
    ts::mock_ok(
        "list_directory_roles",
        &vec![
            unit_role(),
            tenant_role("ra-tenant", REPORTS_READER, "Reports Reader"),
        ],
    );
    ts::mock_ok("remove_admin_unit_role", &());
    let _m = mount();
    ts::wait_for(|| ts::body_contains("Reports Reader")).await;
    assert!(ts::body_contains("Tenant"));
    assert!(ts::body_contains("Writes limited to Finance"));
    let buttons = remove_buttons();
    assert_eq!(
        buttons.len(),
        1,
        "only the unit-scoped role can be removed here"
    );
    buttons[0].click();
    ts::wait_for(|| ts::body_contains("Remove this role?")).await;
    assert_eq!(
        ts::query(".confirm-dialog__subject")
            .and_then(|el| el.text_content())
            .as_deref(),
        Some("User Administrator — Finance")
    );
    ts::click_button_labelled("Remove role");
    ts::wait_for(|| ts::call_count("remove_admin_unit_role") == 1).await;
    let args = ts::last_call("remove_admin_unit_role").unwrap().args;
    assert_eq!(args["spObjectId"], SP);
    assert_eq!(args["assignmentId"], "ra-unit");
}

#[wasm_bindgen_test]
async fn a_covering_tenant_role_says_not_limited() {
    ts::reset();
    ts::mock_ok(
        "list_directory_roles",
        &vec![
            unit_role(),
            tenant_role("ra-ga", GLOBAL_ADMIN, "Global Administrator"),
        ],
    );
    let _m = mount();
    ts::wait_for(|| ts::body_contains("Not limited")).await;
    assert!(
        ts::body_contains("Not limited: also holds Global Administrator tenant-wide"),
        "a tenant-wide Global Administrator voids the unit limit"
    );
    assert!(!ts::body_contains("Writes limited to Finance"));
}
