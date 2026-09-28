//! GUI tests for the Federated credentials tab.
//!
//! Mounts `FederatedTab` directly (the tab owns its own load), like the
//! Authentication tab tests.
#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::tabs::federated_tab::FederatedTab;

const ROWS: &str = ".data-table tbody tr";

fn mount() -> ts::Mounted {
    ts::mock_ok(
        "list_federated_credentials",
        &vec![
            fixtures::federated_credential("gh-main", Some("repo:contoso/app:ref:refs/heads/main")),
            fixtures::federated_credential("gh-flex", None),
        ],
    );
    let detail = Arc::new(fixtures::application_detail(
        "obj-1",
        "app-1",
        "Contoso CRM",
    ));
    ts::mount_view(move || {
        let d = detail.clone();
        view! { <FederatedTab detail=Signal::derive(move || d.clone()) /> }
    })
}

/// Buttons inside the credentials table whose visible text is exactly `label`.
fn table_buttons(label: &str) -> usize {
    ts::query_all(".data-table tbody button")
        .into_iter()
        .filter(|el| el.text_content().unwrap_or_default().trim() == label)
        .count()
}

/// A flexible credential (`subject: null`, matched by a claims expression)
/// used to fail the whole list. It now lists with a placeholder in the Subject
/// column and can be removed but not edited — the edit form needs a subject.
#[wasm_bindgen_test]
async fn a_flexible_credential_lists_without_a_subject_or_edit() {
    ts::reset();
    let _m = mount();
    ts::wait_for(|| ts::query_all(ROWS).len() == 2).await;

    assert!(ts::body_contains("Expression-matched (flexible)"));
    assert!(ts::body_contains("repo:contoso/app:ref:refs/heads/main"));
    assert_eq!(
        table_buttons("Edit"),
        1,
        "only the subject-bearing row is editable"
    );
    assert_eq!(table_buttons("Remove"), 2, "every row stays removable");
    // Each Remove names its credential, and DataTable names the action column.
    for name in ["gh-main", "gh-flex"] {
        let selector = format!("button[aria-label=\"Remove federated credential {name}\"]");
        assert!(ts::query(&selector).is_some(), "no row button `{selector}`");
    }
    assert_eq!(
        ts::text(".data-table thead th:last-child .visually-hidden"),
        "Actions"
    );
}
