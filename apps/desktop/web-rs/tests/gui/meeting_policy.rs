//! The Teams meeting access policy dialog (C3): builds the PowerShell from
//! picked users or one group, warns about one-policy-per-user, never writes a
//! -Global grant; and the Permissions tab offers it on meeting permissions.

use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::permissions::PermissionKind;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::dialogs::meeting_policy_dialog::MeetingPolicyDialog;
use azapptoolkit_web_rs::views::tabs::permissions_tab::PermissionsTab;

const APP: &str = "11111111-2222-4333-8444-555555555555";

/// Mounted closed and then opened, as every pane does.
async fn mount_dialog() -> ts::Mounted {
    mount_dialog_with(Callback::new(|()| {})).await
}

async fn mount_dialog_with(on_close: Callback<()>) -> ts::Mounted {
    let open = RwSignal::new(false);
    let m = ts::mount_view(move || {
        view! {
            <MeetingPolicyDialog
                open=open
                app_id=Signal::derive(|| APP.to_string())
                app_name=Signal::derive(|| "Contoso Recorder".to_string())
                on_close=on_close
            />
        }
    });
    ts::tick().await;
    open.set(true);
    m
}

fn script_text() -> String {
    ts::query(".meeting-policy__script")
        .and_then(|el| el.text_content())
        .unwrap_or_default()
}

/// Searches `query`, waits for the result naming `name`, and adds it.
async fn pick(query: &str, name: &str) {
    ts::set_input_value(".meeting-policy__search input", query);
    ts::wait_until("the search result to add", || {
        ts::query(".meeting-policy__search")
            .and_then(|el| el.text_content())
            .is_some_and(|t| t.contains(name))
    })
    .await;
    ts::click_button_labelled_in(".meeting-policy__search", "Add");
    ts::tick().await;
}

#[wasm_bindgen_test]
async fn the_dialog_builds_a_users_script_and_never_global() {
    ts::reset();
    let pat = fixtures::directory_object("search:pat", "Pat Rivera", "pat@contoso.com");
    let jordan = fixtures::directory_object("search:jordan", "Jordan Lee", "jordan@contoso.com");
    let _m = mount_dialog().await;
    ts::wait_for(|| ts::query(".meeting-policy__search input").is_some()).await;
    ts::mock_ok("search_users", &vec![pat.clone()]);
    pick("pat", "Pat Rivera").await;
    ts::wait_until("Pat in the list", || ts::body_contains("Pat Rivera")).await;
    ts::mock_ok("search_users", &vec![jordan.clone()]);
    pick("jordan", "Jordan Lee").await;
    ts::wait_for(|| script_text().contains(&jordan.id)).await;
    // Each Remove names its user (C3c).
    assert!(ts::query("[aria-label='Remove Pat Rivera']").is_some());
    assert!(ts::query("[aria-label='Remove Jordan Lee']").is_some());
    let s = script_text();
    for id in [&pat.id, &jordan.id] {
        assert!(
            s.contains(&format!(
                "Grant-CsApplicationAccessPolicy -PolicyName 'azapptoolkit-Contoso-Recorder-11111111' -Identity '{id}'"
            )),
            "{s}"
        );
    }
    assert!(s.contains("New-CsApplicationAccessPolicy"), "{s}");
    assert!(!s.contains("-Global"), "never a -Global grant: {s}");
    assert!(ts::body_contains(
        "A user holds one application access policy"
    ));
    assert!(ts::body_contains("-Global isn't offered"));
    assert!(
        ts::body_contains("Search users"),
        "the search says what it searches"
    );
    // Adding the app to an existing policy still replaces each picked user's
    // current policy, so the warning stays (I4).
    let modes = ts::query_all("input[name='meeting-policy-mode']");
    let add: web_sys::HtmlElement = wasm_bindgen::JsCast::unchecked_into(modes[1].clone());
    add.click();
    ts::wait_until("the Set- line", || {
        script_text().contains("Set-CsApplicationAccessPolicy")
    })
    .await;
    assert!(ts::body_contains(
        "A user holds one application access policy"
    ));
    // The prefilled name is ours, not theirs (C3h).
    assert!(ts::body_contains("Type the existing policy's name"));
    let new: web_sys::HtmlElement = wasm_bindgen::JsCast::unchecked_into(modes[0].clone());
    new.click();
    ts::wait_until("the hint to go", || {
        !ts::body_contains("Type the existing policy's name")
    })
    .await;
}

/// Opening the dialog isn't an error: with no one picked yet it says what to
/// do, quietly (C3e), and each radio group is named (C3b).
#[wasm_bindgen_test]
async fn the_dialog_opens_without_an_error() {
    ts::reset();
    let _m = mount_dialog().await;
    ts::wait_until("the hint", || {
        ts::body_contains("Pick at least one user or a group to build the script.")
    })
    .await;
    assert!(ts::query(".form-error").is_none(), "no alert on open");
    for group in ["Policy", "Grant to"] {
        assert_eq!(
            ts::query_all(&format!(
                "[role='radiogroup'][aria-label='{group}'] input[type='radio']"
            ))
            .len(),
            2,
            "{group}"
        );
    }
}

#[wasm_bindgen_test]
async fn the_dialog_closes_from_its_close_button() {
    ts::reset();
    let closed = RwSignal::new(false);
    let _m = mount_dialog_with(Callback::new(move |()| closed.set(true))).await;
    ts::wait_until("the Close button", || ts::has_button_labelled("Close")).await;
    ts::click_button_labelled("Close");
    ts::wait_until("on_close", || closed.get_untracked()).await;
}

#[wasm_bindgen_test]
async fn the_group_mode_builds_one_grant_with_rank() {
    ts::reset();
    let group = fixtures::directory_object("search:sales", "Sales", "sales@contoso.com");
    let _m = mount_dialog().await;
    ts::wait_until("the target radios", || {
        ts::query("input[name='meeting-policy-targets']").is_some()
    })
    .await;
    let radios = ts::query_all("input[name='meeting-policy-targets']");
    let group_radio: web_sys::HtmlElement = wasm_bindgen::JsCast::unchecked_into(radios[1].clone());
    group_radio.click();
    ts::tick().await;
    ts::mock_ok("search_groups", &vec![group.clone()]);
    pick("sal", "Sales").await;
    ts::wait_until("the rank field", || {
        ts::query(".meeting-policy__rank input").is_some()
    })
    .await;
    ts::set_input_value(".meeting-policy__rank input", "2");
    ts::wait_until("the -Rank 2 line", || script_text().contains("-Rank 2")).await;
    let s = script_text();
    assert!(
        s.contains(&format!(
            "Grant-CsApplicationAccessPolicy -PolicyName 'azapptoolkit-Contoso-Recorder-11111111' -Group '{}' -Rank 2",
            group.id
        )),
        "{s}"
    );
    assert_eq!(s.matches("Grant-CsApplicationAccessPolicy").count(), 1);
    // A typo isn't silently "last" (C3d).
    ts::set_input_value(".meeting-policy__rank input", "1st");
    ts::wait_until("the rank error", || {
        ts::query(".form-error")
            .and_then(|el| el.text_content())
            .is_some_and(|t| t.contains("Rank is a whole number"))
    })
    .await;
    assert!(
        script_text().is_empty(),
        "no script while the rank is wrong"
    );
    ts::set_input_value(".meeting-policy__rank input", "2");
    ts::wait_until("the script again", || script_text().contains("-Rank 2")).await;
    // A group grant follows group-assignment rules, not "replaces theirs" (I4).
    assert!(ts::body_contains("direct members only"));
    assert!(!ts::body_contains(
        "A user holds one application access policy"
    ));
    assert!(ts::body_contains("Search groups"));
}

#[wasm_bindgen_test]
async fn the_permissions_tab_offers_meeting_policy_on_online_meetings_rows() {
    ts::reset();
    let mut detail = fixtures::application_detail("obj-1", "app-1", "Contoso Recorder");
    detail.resolved_permissions = vec![
        fixtures::resolved_permission(
            fixtures::MICROSOFT_GRAPH_APP_ID,
            "Microsoft Graph",
            "OnlineMeetings.Read.All",
            "Read online meeting details",
            PermissionKind::Application,
        ),
        fixtures::resolved_permission(
            fixtures::MICROSOFT_GRAPH_APP_ID,
            "Microsoft Graph",
            "User.Read.All",
            "Read all users' full profiles",
            PermissionKind::Application,
        ),
        // A policy gates app-only access, so a Delegated row has no button.
        fixtures::resolved_permission(
            fixtures::MICROSOFT_GRAPH_APP_ID,
            "Microsoft Graph",
            "OnlineMeetings.Read.All",
            "Read online meeting details",
            PermissionKind::Delegated,
        ),
    ];
    let detail = Arc::new(detail);
    let _m = ts::mount_view(move || {
        let d = detail.clone();
        view! {
            <PermissionsTab detail=Signal::derive(move || d.clone()) on_changed=Callback::new(|()| {}) />
        }
    });
    ts::wait_for(|| ts::body_contains("OnlineMeetings.Read.All")).await;
    // The Delegated row rendered too (its value shows twice), yet only the
    // Application row has the button.
    assert!(
        ts::body_text().matches("OnlineMeetings.Read.All").count() >= 2,
        "{}",
        ts::body_text()
    );
    assert_eq!(
        ts::query_all("[aria-label='Meeting policy for OnlineMeetings.Read.All']").len(),
        1,
        "the Application row only"
    );
    assert!(ts::query("[aria-label='Meeting policy for User.Read.All']").is_none());
    ts::click("[aria-label='Meeting policy for OnlineMeetings.Read.All']");
    ts::wait_for(|| ts::body_contains("Meeting access policy")).await;
}
