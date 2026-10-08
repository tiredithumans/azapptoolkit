//! The per-app record of sub-site Selected grants (libraries, folders and
//! files) and the commands behind the "SharePoint item access" section.
//!
//! Graph can say who holds access to one list or item, but never which items
//! one app can reach: there is no reverse lookup, and walking every folder in a
//! tenant is out of the question. So the app keeps its own record, one `tags`
//! entry per grant on the app registration (`azapptoolkit:spItem:v1|…`). It is
//! written whenever a grant lands through `grant_selected_item_access` (the
//! wizard and the section alike) and read back here, each entry with the live
//! status of its resource. Grants made outside the tool are not in it until
//! they are tracked by URL, and the UI says so.
//!
//! Tags are shared, editable data on the app object, so every tag is parsed as
//! untrusted input: the ids end up in Graph URL paths, and anything that is not
//! exactly `host,guid,guid` / a GUID / a numeric item id is ignored.

use tauri::State;

use azapptoolkit_core::guid::is_guid;
use azapptoolkit_core::models::SelectedPermission;
use azapptoolkit_core::scoping::SelectedScopeLevel;
use azapptoolkit_graph::client::SelectedTarget;
use azapptoolkit_graph::{GraphClient, GraphError};

use crate::commands::sharepoint::{sharepoint_client_checked, sharepoint_item_err};
use crate::dto::UiError;
use crate::dto::sharepoint::{
    AppItemScopeDto, AppItemScopesDto, ItemScopeRef, ItemScopeStatus, SelectedItemGrantDto,
    SharePointResourceRef,
};
use crate::state::AppState;

/// Every record tag starts with this; the version follows.
const TAG_FAMILY: &str = "azapptoolkit:spItem:";
/// The current record format.
const TAG_V1: &str = "v1|";
/// Entra's limit on one application tag.
const MAX_TAG_LEN: usize = 256;

// ---------------- Tag codec ----------------

fn level_code(level: SelectedScopeLevel) -> Option<&'static str> {
    match level {
        SelectedScopeLevel::List => Some("list"),
        SelectedScopeLevel::ListItem => Some("list_item"),
        SelectedScopeLevel::File => Some("file"),
        SelectedScopeLevel::Site => None,
    }
}

fn parse_level(code: &str) -> Option<SelectedScopeLevel> {
    match code {
        "list" => Some(SelectedScopeLevel::List),
        "list_item" => Some(SelectedScopeLevel::ListItem),
        "file" => Some(SelectedScopeLevel::File),
        _ => None,
    }
}

/// A Graph site id: `{hostname},{site collection GUID},{web GUID}`.
fn is_site_id(site_id: &str) -> bool {
    let mut parts = site_id.split(',');
    let (Some(host), Some(collection), Some(web), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && is_guid(collection)
        && is_guid(web)
}

/// Whether `scope` is safe to put in a Graph path and consistent with its
/// level: a list has no item id, an item always has a numeric one.
pub(crate) fn is_valid_scope(scope: &ItemScopeRef) -> bool {
    let item_ok = match (scope.level, scope.item_id.as_deref()) {
        (SelectedScopeLevel::List, None) => true,
        (SelectedScopeLevel::ListItem | SelectedScopeLevel::File, Some(item)) => {
            !item.is_empty() && item.chars().all(|c| c.is_ascii_digit())
        }
        _ => false,
    };
    item_ok && is_site_id(&scope.site_id) && is_guid(&scope.list_id)
}

/// The record tag for `scope`, or `None` when the scope is invalid or its tag
/// would exceed Entra's 256-character limit.
pub(crate) fn encode_tag(scope: &ItemScopeRef) -> Option<String> {
    if !is_valid_scope(scope) {
        return None;
    }
    let mut tag = format!(
        "{TAG_FAMILY}{TAG_V1}{}|{}|{}",
        level_code(scope.level)?,
        scope.site_id,
        scope.list_id
    );
    if let Some(item) = &scope.item_id {
        tag.push('|');
        tag.push_str(item);
    }
    (tag.len() <= MAX_TAG_LEN).then_some(tag)
}

/// `None` when `tag` is not a record tag at all; `Some(None)` when it is one
/// that can't be used (an unknown version, a malformed or unsafe id).
pub(crate) fn decode_tag(tag: &str) -> Option<Option<ItemScopeRef>> {
    let rest = tag.strip_prefix(TAG_FAMILY)?;
    Some(decode_v1(rest))
}

fn decode_v1(rest: &str) -> Option<ItemScopeRef> {
    let body = rest.strip_prefix(TAG_V1)?;
    let parts: Vec<&str> = body.split('|').collect();
    let (level, site_id, list_id, item_id) = match parts.as_slice() {
        [level, site, list] => (*level, *site, *list, None),
        [level, site, list, item] => (*level, *site, *list, Some(*item)),
        _ => return None,
    };
    let scope = ItemScopeRef {
        level: parse_level(level)?,
        site_id: site_id.to_string(),
        list_id: list_id.to_string(),
        item_id: item_id.map(str::to_string),
    };
    is_valid_scope(&scope).then_some(scope)
}

/// The record of a granted or resolved resource, or `None` for a site (which
/// `Sites.Selected` and its own section own).
pub(crate) fn scope_of(resource: &SharePointResourceRef) -> Option<ItemScopeRef> {
    level_code(resource.level)?;
    Some(ItemScopeRef {
        level: resource.level,
        site_id: resource.site_id.clone(),
        list_id: resource.list_id.clone()?,
        item_id: resource.item_id.clone(),
    })
}

fn target_of(scope: &ItemScopeRef) -> SelectedTarget<'_> {
    SelectedTarget {
        site_id: &scope.site_id,
        list_id: &scope.list_id,
        item_id: scope.item_id.as_deref(),
    }
}

// ---------------- Record writes ----------------

/// One app's record is read, changed and written back as a whole (Graph
/// replaces the full `tags` collection), so two writers must not interleave.
fn tags_gate(
    state: &AppState,
    tenant_id: &str,
    object_id: &str,
) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    state.single_flight(&format!("{tenant_id}|app_tags|{object_id}"))
}

/// Adds the record tags for `scopes` to the app, keeping every other tag.
/// Returns one message per scope that can't be recorded (its tag would be too
/// long). A Graph failure is the `Err`.
pub(crate) async fn remember(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
    object_id: &str,
    scopes: &[ItemScopeRef],
) -> Result<Vec<String>, UiError> {
    let mut skipped = Vec::new();
    let mut wanted = Vec::new();
    for scope in scopes {
        match encode_tag(scope) {
            Some(tag) => wanted.push(tag),
            None => skipped.push(format!(
                "a grant on list {} could not be recorded on the app: its ids are longer than an \
                 app tag allows",
                scope.list_id
            )),
        }
    }
    if wanted.is_empty() {
        return Ok(skipped);
    }
    let gate = tags_gate(state, tenant_id, object_id);
    let _held = gate.lock().await;
    let mut tags = client.get_application_tags(object_id).await?;
    let before = tags.len();
    for tag in wanted {
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    if tags.len() != before {
        client.set_application_tags(object_id, &tags).await?;
    }
    Ok(skipped)
}

/// Removes every record tag for `scope` from the app, keeping every other tag.
pub(crate) async fn forget(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
    object_id: &str,
    scope: &ItemScopeRef,
) -> Result<(), UiError> {
    let gate = tags_gate(state, tenant_id, object_id);
    let _held = gate.lock().await;
    let mut tags = client.get_application_tags(object_id).await?;
    let before = tags.len();
    tags.retain(|tag| decode_tag(tag).flatten().as_ref() != Some(scope));
    if tags.len() != before {
        client.set_application_tags(object_id, &tags).await?;
    }
    Ok(())
}

/// Records what a `grant_selected_item_access` run granted. Returns whether
/// every grant is now recorded: false for a service-principal-only principal
/// (`object_id: None`, no registration to record on) and when a record failed,
/// which also lands in `warnings`. The grants themselves stand either way.
pub(crate) async fn record_granted(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
    object_id: Option<&str>,
    granted: &[SelectedItemGrantDto],
    warnings: &mut Vec<String>,
) -> bool {
    let Some(object_id) = object_id else {
        return false;
    };
    let scopes: Vec<ItemScopeRef> = granted
        .iter()
        .filter_map(|g| scope_of(&g.resource))
        .collect();
    if scopes.is_empty() {
        return true;
    }
    match remember(state, client, tenant_id, object_id, &scopes).await {
        Ok(skipped) => {
            let all = skipped.is_empty();
            warnings.extend(skipped);
            all
        }
        Err(err) => {
            warnings.push(format!(
                "the access was granted, but it could not be recorded on the app, so the \
                 SharePoint item access list will not show it: {}",
                err.message
            ));
            false
        }
    }
}

// ---------------- Reads ----------------

/// What one resource's entries say about `app_id`.
fn status_of(read: Result<Vec<SelectedPermission>, GraphError>, app_id: &str) -> ItemScopeStatus {
    match read {
        Ok(perms) => perms
            .into_iter()
            .find(|p| p.app_id().is_some_and(|id| id.eq_ignore_ascii_case(app_id)))
            .map_or(ItemScopeStatus::NotGranted, |p| ItemScopeStatus::Granted {
                permission_id: p.id,
                roles: p.roles,
            }),
        Err(GraphError::NotFound(_)) => ItemScopeStatus::Missing,
        Err(err) => ItemScopeStatus::Unreadable {
            message: sharepoint_item_err(err).message,
        },
    }
}

/// The grants recorded on one app, each with its live status. Permission
/// entries and names are read for every recorded resource in two scoped
/// `$batch`es; a resource whose entries can't be read is `Unreadable`, never
/// `NotGranted`.
pub(crate) async fn list_app_item_scopes_with(
    client: &GraphClient,
    object_id: &str,
    app_id: &str,
) -> Result<AppItemScopesDto, UiError> {
    let tags = client.get_application_tags(object_id).await?;
    let mut malformed = 0;
    let mut scopes: Vec<ItemScopeRef> = Vec::new();
    for tag in &tags {
        match decode_tag(tag) {
            Some(None) => malformed += 1,
            Some(Some(scope)) if !scopes.contains(&scope) => scopes.push(scope),
            // Not a record tag, or a duplicate of one already read.
            _ => {}
        }
    }
    if scopes.is_empty() {
        return Ok(AppItemScopesDto {
            entries: Vec::new(),
            malformed,
        });
    }

    let targets: Vec<SelectedTarget<'_>> = scopes.iter().map(target_of).collect();
    let (perms, names) = futures::future::try_join(
        client.batch_list_selected_permissions(&targets),
        client.batch_get_selected_target_names(&targets),
    )
    .await
    .map_err(sharepoint_item_err)?;

    let entries = scopes
        .iter()
        .zip(perms)
        .zip(names)
        .map(|((scope, read), name)| {
            let named = name.ok();
            AppItemScopeDto {
                scope: scope.clone(),
                name: named
                    .as_ref()
                    .and_then(|n| n.display_name.clone().or_else(|| n.name.clone())),
                web_url: named.as_ref().and_then(|n| n.web_url.clone()),
                is_folder: named.as_ref().is_some_and(|n| n.folder.is_some()),
                status: status_of(read, app_id),
            }
        })
        .collect();
    Ok(AppItemScopesDto { entries, malformed })
}

/// Lists the libraries, folders and files recorded on an app registration,
/// each with what SharePoint says about it now.
#[tauri::command]
pub async fn list_app_item_scopes(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    app_id: String,
) -> Result<AppItemScopesDto, UiError> {
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    list_app_item_scopes_with(&client, &object_id, &app_id).await
}

// ---------------- Writes ----------------

/// Removes the app's grant on `scope` (when `permission_id` is set) and then
/// its record.
///
/// Fail-closed: the entry is re-read and must be **this app's** application
/// grant before it is deleted, so a stale or tampered id can never revoke a
/// person's or another app's access. An entry or resource already gone counts
/// as removed. Without a `permission_id` only the record goes: the row was
/// already showing "not granted" or "not found".
pub(crate) async fn remove_app_item_scope_with(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
    object_id: &str,
    app_id: &str,
    scope: &ItemScopeRef,
    permission_id: Option<&str>,
) -> Result<(), UiError> {
    if !is_valid_scope(scope) {
        return Err(UiError::validation(
            "invalid_scope",
            "That library, folder or file reference is not valid.",
        ));
    }
    if let Some(permission_id) = permission_id {
        let target = target_of(scope);
        let read = match target.item_id {
            Some(item) => {
                client
                    .list_list_item_permissions(target.site_id, target.list_id, item)
                    .await
            }
            None => {
                client
                    .list_list_permissions(target.site_id, target.list_id)
                    .await
            }
        };
        let perms = match read {
            Ok(perms) => perms,
            // The resource is gone, and its entries with it.
            Err(GraphError::NotFound(_)) => Vec::new(),
            Err(err) => return Err(sharepoint_item_err(err)),
        };
        if let Some(entry) = perms.iter().find(|p| p.id == permission_id) {
            if !entry
                .app_id()
                .is_some_and(|id| id.eq_ignore_ascii_case(app_id))
            {
                return Err(UiError::validation(
                    "not_this_apps_grant",
                    "That permission entry is not this app's grant, so it was left in place.",
                ));
            }
            let removed = match target.item_id {
                Some(item) => {
                    client
                        .remove_list_item_permission(
                            target.site_id,
                            target.list_id,
                            item,
                            permission_id,
                        )
                        .await
                }
                None => {
                    client
                        .remove_list_permission(target.site_id, target.list_id, permission_id)
                        .await
                }
            };
            match removed {
                Ok(()) | Err(GraphError::NotFound(_)) => {}
                Err(err) => return Err(sharepoint_item_err(err)),
            }
        }
    }
    forget(state, client, tenant_id, object_id, scope).await
}

/// Removes an app's grant on one recorded library, folder or file, or (with no
/// `permission_id`) just forgets the record.
#[tauri::command]
pub async fn remove_app_item_scope(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    app_id: String,
    scope: ItemScopeRef,
    permission_id: Option<String>,
) -> Result<(), UiError> {
    // Forgetting a record touches only the app object; revoking a grant needs
    // the SharePoint scope, so only that path asks for its consent.
    let client = if permission_id.is_some() {
        sharepoint_client_checked(&state, &tenant_id).await?
    } else {
        state.graph_for(&tenant_id)
    };
    remove_app_item_scope_with(
        &state,
        &client,
        &tenant_id,
        &object_id,
        &app_id,
        &scope,
        permission_id.as_deref(),
    )
    .await
}

/// Records an existing grant by URL (one made before this version, in the
/// Permission Tester, or outside the tool), so the list shows its status.
pub(crate) async fn track_app_item_scope_with(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
    object_id: &str,
    url: &str,
) -> Result<ItemScopeRef, UiError> {
    let resolved = client
        .resolve_sharepoint_resource(url)
        .await
        .map_err(sharepoint_item_err)?;
    let resource = crate::commands::sharepoint::to_resource_ref(resolved, url.to_string());
    let scope = scope_of(&resource).ok_or_else(|| {
        UiError::validation(
            "level_mismatch",
            "That URL is a whole site. Site access is listed under SharePoint site access.",
        )
    })?;
    let skipped = remember(
        state,
        client,
        tenant_id,
        object_id,
        std::slice::from_ref(&scope),
    )
    .await?;
    match skipped.into_iter().next() {
        Some(message) => Err(UiError::validation("tag_too_long", message)),
        None => Ok(scope),
    }
}

/// Adds a library, folder or file to an app's record by URL.
#[tauri::command]
pub async fn track_app_item_scope(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    url: String,
) -> Result<ItemScopeRef, UiError> {
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    track_app_item_scope_with(&state, &client, &tenant_id, &object_id, &url).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use crate::commands::test_support::mock_graph;

    const TENANT: &str = "t1";
    const OBJ: &str = "obj-1";
    const APP: &str = "11111111-1111-1111-1111-111111111111";
    const SITE: &str = "contoso.sharepoint.com,2c712604-1370-44e7-a1f5-426573fda80a,2d2244c3-251a-49ea-93a8-39e1c3a060fe";
    const LIST: &str = "8b1e5c2a-0d3f-4a1b-9c2e-1f2a3b4c5d6e";
    const OTHER: &str = "keep-me";

    fn list_scope() -> ItemScopeRef {
        ItemScopeRef {
            level: SelectedScopeLevel::List,
            site_id: SITE.into(),
            list_id: LIST.into(),
            item_id: None,
        }
    }

    fn file_scope(item: &str) -> ItemScopeRef {
        ItemScopeRef {
            level: SelectedScopeLevel::File,
            site_id: SITE.into(),
            list_id: LIST.into(),
            item_id: Some(item.into()),
        }
    }

    fn tag(scope: &ItemScopeRef) -> String {
        encode_tag(scope).expect("a valid scope encodes")
    }

    fn client(server: &MockServer) -> GraphClient {
        mock_graph(server).with_sharepoint_token(StaticTokenProvider::new("sp"))
    }

    async fn mount_tags(server: &MockServer, tags: Vec<String>) {
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/applications/{OBJ}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id": OBJ, "tags": tags })),
            )
            .mount(server)
            .await;
    }

    async fn expect_tags_written(server: &MockServer, tags: Vec<String>) {
        Mock::given(method("PATCH"))
            .and(path(format!("/v1.0/applications/{OBJ}")))
            .and(body_json(serde_json::json!({ "tags": tags })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn a_record_tag_round_trips() {
        for scope in [list_scope(), file_scope("17")] {
            assert_eq!(decode_tag(&tag(&scope)), Some(Some(scope)));
        }
        assert_eq!(
            tag(&file_scope("17")),
            format!("azapptoolkit:spItem:v1|file|{SITE}|{LIST}|17")
        );
    }

    /// Tags are editable by anyone who can edit the app, and their ids are
    /// pasted into Graph paths, so anything that isn't exactly the expected
    /// shape is unusable, not "probably fine".
    #[test]
    fn a_tag_that_is_not_exactly_the_record_shape_is_unusable() {
        assert_eq!(decode_tag("HideApp"), None, "not ours");
        assert_eq!(decode_tag("azapptoolkit:restoredFrom:x"), None, "not ours");
        let bad = [
            format!("azapptoolkit:spItem:v2|file|{SITE}|{LIST}|17"),
            format!("azapptoolkit:spItem:v1|site|{SITE}|{LIST}"),
            format!("azapptoolkit:spItem:v1|file|{SITE}|{LIST}"),
            format!("azapptoolkit:spItem:v1|list|{SITE}|{LIST}|17"),
            format!("azapptoolkit:spItem:v1|file|{SITE}|{LIST}|17/../../x"),
            format!("azapptoolkit:spItem:v1|file|../../users|{LIST}|17"),
            format!("azapptoolkit:spItem:v1|file|{SITE}|not-a-guid|17"),
            format!("azapptoolkit:spItem:v1|file|{SITE}|{LIST}|17|extra"),
            "azapptoolkit:spItem:".to_string(),
        ];
        for t in bad {
            assert_eq!(decode_tag(&t), Some(None), "{t}");
        }
    }

    /// Entra caps one tag at 256 characters. A scope whose ids would exceed it
    /// is not recorded (the caller reports it), rather than truncated.
    #[test]
    fn a_tag_past_the_entra_limit_is_not_encoded() {
        let host = format!("{}.sharepoint.com", "a".repeat(150));
        let long = ItemScopeRef {
            site_id: SITE.replacen("contoso.sharepoint.com", &host, 1),
            ..file_scope("17")
        };
        assert!(is_valid_scope(&long));
        assert_eq!(encode_tag(&long), None);
    }

    /// Recording adds only its own tag; Graph replaces the whole collection,
    /// so every other tag is written back unchanged.
    #[tokio::test]
    async fn remember_adds_its_tag_and_keeps_every_other_tag() {
        let server = MockServer::start().await;
        mount_tags(&server, vec![OTHER.into()]).await;
        expect_tags_written(&server, vec![OTHER.into(), tag(&file_scope("17"))]).await;
        let state = AppState::for_test(TENANT, &server.uri());

        let skipped = remember(&state, &client(&server), TENANT, OBJ, &[file_scope("17")])
            .await
            .unwrap();
        assert!(skipped.is_empty());
    }

    #[tokio::test]
    async fn remember_writes_nothing_when_the_record_is_already_there() {
        let server = MockServer::start().await;
        mount_tags(&server, vec![tag(&list_scope())]).await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        let state = AppState::for_test(TENANT, &server.uri());

        remember(&state, &client(&server), TENANT, OBJ, &[list_scope()])
            .await
            .unwrap();
    }

    /// A service-principal-only principal has no registration to record on:
    /// nothing is read or written, and the result says it wasn't recorded.
    #[tokio::test]
    async fn a_grant_to_a_principal_without_a_registration_records_nothing() {
        let server = MockServer::start().await;
        let state = AppState::for_test(TENANT, &server.uri());
        let mut warnings = Vec::new();

        let recorded =
            record_granted(&state, &client(&server), TENANT, None, &[], &mut warnings).await;

        assert!(!recorded);
        assert!(warnings.is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Answers the two `$batch`es of `list_app_item_scopes` by sub-request URL:
    /// item 17 holds this app's grant, item 18 only another app's, item 19 is
    /// gone, and item 20's entries can't be read.
    struct ScopesBatch;

    impl Respond for ScopesBatch {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body: serde_json::Value = request.body_json().unwrap();
            let responses: Vec<serde_json::Value> = body["requests"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    let id = r["id"].clone();
                    let url = r["url"].as_str().unwrap();
                    let item = url.split("/items/").nth(1).map(|s| &s[..2]);
                    let (status, body) = match (url.contains("/permissions"), item) {
                        (_, Some("19")) => (
                            404,
                            serde_json::json!({ "error": { "code": "itemNotFound" } }),
                        ),
                        (true, Some("20")) => (
                            403,
                            serde_json::json!({ "error": { "code": "accessDenied" } }),
                        ),
                        (true, Some("17")) => (
                            200,
                            serde_json::json!({ "value": [
                            { "id": "p-mine", "roles": ["write"],
                              "grantedToV2": { "application": { "id": APP } } } ] }),
                        ),
                        (true, _) => (
                            200,
                            serde_json::json!({ "value": [
                            { "id": "p-other", "roles": ["read"],
                              "grantedToV2": { "application": { "id": "other-app" } } } ] }),
                        ),
                        (false, Some(n)) => (
                            200,
                            serde_json::json!({
                            "name": format!("file-{n}"), "webUrl": format!("https://x/{n}") }),
                        ),
                        (false, None) => (200, serde_json::json!({ "displayName": "Documents" })),
                    };
                    serde_json::json!({ "id": id, "status": status, "body": body })
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "responses": responses }))
        }
    }

    #[tokio::test]
    async fn each_recorded_grant_reports_what_sharepoint_says_now() {
        let server = MockServer::start().await;
        mount_tags(
            &server,
            vec![
                OTHER.into(),
                tag(&file_scope("17")),
                tag(&file_scope("18")),
                tag(&file_scope("19")),
                tag(&file_scope("20")),
                "azapptoolkit:spItem:v1|file|../x|y|1".into(),
            ],
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/v1.0/$batch"))
            .respond_with(ScopesBatch)
            .mount(&server)
            .await;

        let out = list_app_item_scopes_with(&client(&server), OBJ, APP)
            .await
            .unwrap();

        assert_eq!(out.malformed, 1);
        let statuses: Vec<&ItemScopeStatus> = out.entries.iter().map(|e| &e.status).collect();
        assert_eq!(
            statuses[0],
            &ItemScopeStatus::Granted {
                permission_id: "p-mine".into(),
                roles: vec!["write".into()]
            }
        );
        assert_eq!(
            statuses[1],
            &ItemScopeStatus::NotGranted,
            "another app's entry is not ours"
        );
        assert_eq!(statuses[2], &ItemScopeStatus::Missing);
        assert!(
            matches!(statuses[3], ItemScopeStatus::Unreadable { .. }),
            "a failed read is never reported as not granted"
        );
        assert_eq!(out.entries[0].name.as_deref(), Some("file-17"));
    }

    async fn mount_item_permissions(server: &MockServer, grantee: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1.0/sites/{SITE}/lists/{LIST}/items/17/permissions"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "p1", "roles": ["read"], "grantedToV2": grantee }]
            })))
            .mount(server)
            .await;
    }

    /// The entry is re-read and must be this app's before anything is
    /// deleted: a stale or edited id must never revoke a person's access.
    #[tokio::test]
    async fn remove_refuses_an_entry_that_is_not_this_apps_grant() {
        let server = MockServer::start().await;
        mount_item_permissions(
            &server,
            serde_json::json!({ "user": { "id": "u-1", "displayName": "Jane" } }),
        )
        .await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        let state = AppState::for_test(TENANT, &server.uri());

        let err = remove_app_item_scope_with(
            &state,
            &client(&server),
            TENANT,
            OBJ,
            APP,
            &file_scope("17"),
            Some("p1"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, "not_this_apps_grant");
    }

    #[tokio::test]
    async fn remove_revokes_this_apps_grant_then_drops_its_record() {
        let server = MockServer::start().await;
        mount_item_permissions(&server, serde_json::json!({ "application": { "id": APP } })).await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/v1.0/sites/{SITE}/lists/{LIST}/items/17/permissions/p1"
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        mount_tags(&server, vec![OTHER.into(), tag(&file_scope("17"))]).await;
        expect_tags_written(&server, vec![OTHER.into()]).await;
        let state = AppState::for_test(TENANT, &server.uri());

        remove_app_item_scope_with(
            &state,
            &client(&server),
            TENANT,
            OBJ,
            APP,
            &file_scope("17"),
            Some("p1"),
        )
        .await
        .unwrap();
    }

    /// Forgetting a stale row touches only the app object, never SharePoint.
    #[tokio::test]
    async fn forgetting_a_stale_record_touches_only_the_app() {
        let server = MockServer::start().await;
        mount_tags(&server, vec![tag(&file_scope("19")), OTHER.into()]).await;
        expect_tags_written(&server, vec![OTHER.into()]).await;
        let state = AppState::for_test(TENANT, &server.uri());

        remove_app_item_scope_with(
            &state,
            &client(&server),
            TENANT,
            OBJ,
            APP,
            &file_scope("19"),
            None,
        )
        .await
        .unwrap();
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.url.path().starts_with("/v1.0/applications/")),
            "no SharePoint call"
        );
    }

    /// A grant made elsewhere is tracked by URL: resolved, then recorded.
    #[tokio::test]
    async fn tracking_a_library_url_records_its_list() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/sites/contoso.sharepoint.com:/sites/Finance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": SITE, "webUrl": "https://contoso.sharepoint.com/sites/Finance"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/sites/{SITE}/drives")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "drive-1", "name": "Documents",
                    "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/drives/drive-1/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": LIST, "displayName": "Documents"
            })))
            .mount(&server)
            .await;
        mount_tags(&server, vec![]).await;
        expect_tags_written(&server, vec![tag(&list_scope())]).await;
        let state = AppState::for_test(TENANT, &server.uri());

        let scope = track_app_item_scope_with(
            &state,
            &client(&server),
            TENANT,
            OBJ,
            "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents",
        )
        .await
        .unwrap();
        assert_eq!(scope, list_scope());
    }

    /// Only Entra ids are looked up: a SharePoint group's id is local to the
    /// site and means nothing to the directory. A found name fills the row.
    #[tokio::test]
    async fn only_entra_principals_without_a_name_are_looked_up() {
        use crate::dto::sharepoint::{PrincipalKind, SelectedItemPermissionDto};

        const USER: &str = "22222222-2222-2222-2222-222222222222";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/$batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "responses": [{ "id": "0", "status": 200, "body": {
                    "id": USER, "displayName": "Jane Doe", "mail": "jane@contoso.com" } }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let entry = |grantee: serde_json::Value| {
            crate::commands::sharepoint::to_item_dto(
                serde_json::from_value(serde_json::json!({ "id": "p", "grantedToV2": grantee }))
                    .unwrap(),
            )
        };
        let mut rows: Vec<SelectedItemPermissionDto> = vec![
            entry(serde_json::json!({ "user": { "id": USER } })),
            entry(serde_json::json!({ "siteGroup": { "id": "10" } })),
        ];

        crate::commands::sharepoint::fill_principal_names(&client(&server), &mut rows).await;

        let user = &rows[0].principals[0];
        assert_eq!(user.kind, PrincipalKind::User);
        assert_eq!(user.display_name.as_deref(), Some("Jane Doe"));
        assert_eq!(user.detail.as_deref(), Some("jane@contoso.com"));
        let body: serde_json::Value = server.received_requests().await.unwrap()[0]
            .body_json()
            .unwrap();
        assert_eq!(
            body["requests"].as_array().unwrap().len(),
            1,
            "the site group is not sent"
        );
    }
}
