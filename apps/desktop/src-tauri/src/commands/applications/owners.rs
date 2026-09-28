use std::collections::HashSet;

use tauri::State;

use azapptoolkit_core::models::DirectoryObject;

use crate::dto::UiError;
use crate::dto::applications::{OwnerChangeFailure, SetOwnersResult};
use crate::state::AppState;

use super::invalidate_app_detail_state;

#[tauri::command]
pub async fn add_application_owner(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.add_owner(&object_id, &principal_id).await?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

#[tauri::command]
pub async fn remove_application_owner(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.remove_owner(&object_id, &principal_id).await?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

/// Reconciles an application's owner set to exactly `principal_ids`, mirroring
/// `Set-AzAppOwner`. Owners present in the target but not currently assigned are
/// added first (so the app is never transiently ownerless), then owners no
/// longer in the target are removed. Per-principal failures are collected rather
/// than aborting the whole operation — except a re-auth-fatal one: a dead
/// session fails every remaining change identically, so the reconcile stops
/// there (a fatal add also skips every removal, keeping "never transiently
/// ownerless") and the fatal-coded failure tells the UI to offer
/// Re-authenticate.
#[tauri::command]
pub async fn set_application_owners(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_ids: Vec<String>,
) -> Result<SetOwnersResult, UiError> {
    set_application_owners_core(&state, &tenant_id, &object_id, principal_ids).await
}

/// The body of [`set_application_owners`], taking `&AppState` so the
/// invalidation rule — bust the detail state only when an owner was actually
/// added or removed, never on the error path, and never the tenant-wide
/// indexes — is reachable from a test (the `add_password_core` seam).
pub(crate) async fn set_application_owners_core(
    state: &AppState,
    tenant_id: &str,
    object_id: &str,
    principal_ids: Vec<String>,
) -> Result<SetOwnersResult, UiError> {
    let client = state.graph_for(tenant_id);
    let current = client.list_owners(object_id).await?;
    let current_ids: HashSet<String> = current.into_iter().map(|o| o.id).collect();
    let desired: HashSet<String> = principal_ids.into_iter().collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut failures = Vec::new();

    // Set when a change failed on a dead session: nothing after it can land.
    let mut stopped = false;
    for id in desired.iter().filter(|id| !current_ids.contains(*id)) {
        match client.add_owner(object_id, id).await {
            Ok(()) => added.push(id.clone()),
            Err(err) => {
                let failure = owner_failure(id, "add", err.into());
                stopped = failure.is_reauth_fatal();
                failures.push(failure);
                if stopped {
                    break;
                }
            }
        }
    }
    if !stopped {
        for id in current_ids.iter().filter(|id| !desired.contains(*id)) {
            match client.remove_owner(object_id, id).await {
                Ok(()) => removed.push(id.clone()),
                Err(err) => {
                    let failure = owner_failure(id, "remove", err.into());
                    let fatal = failure.is_reauth_fatal();
                    failures.push(failure);
                    if fatal {
                        break;
                    }
                }
            }
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        invalidate_app_detail_state(&state.cache, tenant_id);
    }

    Ok(SetOwnersResult {
        added,
        removed,
        failures,
    })
}

/// One failed owner change, carrying the error's `code` so the UI can tell a
/// dead session (re-auth-fatal) from a per-principal refusal.
fn owner_failure(principal_id: &str, action: &str, err: UiError) -> OwnerChangeFailure {
    OwnerChangeFailure {
        principal_id: principal_id.to_string(),
        action: action.to_string(),
        code: err.code,
        message: err.message,
    }
}

#[tauri::command]
pub async fn search_users(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<Vec<DirectoryObject>, UiError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let client = state.graph_for(&tenant_id);
    client.search_users(q).await.map_err(Into::into)
}

#[tauri::command]
pub async fn search_groups(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<Vec<DirectoryObject>, UiError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let client = state.graph_for(&tenant_id);
    client.search_groups(q).await.map_err(Into::into)
}

/// Searches mail-enabled groups / distribution lists (returns those with a mail
/// address) — used to seed the SSO notification-email default from a team DL.
#[tauri::command]
pub async fn search_distribution_lists(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<Vec<DirectoryObject>, UiError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let client = state.graph_for(&tenant_id);
    client
        .search_distribution_lists(q)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::commands::test_support::{
        dead_token, detail_cached, indexes_intact, mock_state, mock_state_with_write_token,
        seed_indexes_and_detail,
    };

    const TENANT: &str = "t1";
    const OBJECT: &str = "obj-1";

    async fn mount_owners(server: &MockServer, ids: &[&str]) {
        let value: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| serde_json::json!({ "id": id }))
            .collect();
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/applications/{OBJECT}/owners")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": value })),
            )
            .mount(server)
            .await;
    }

    async fn writes(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.method.as_str() != "GET")
            .count()
    }

    // `invalidate_app_detail_state` drops every `app_detail|` row, the
    // `mail_scopes|` verdicts and the audit run — never the two indexes, since
    // an owner change adds, removes or renames no app or SP.
    #[tokio::test]
    async fn reconciling_owners_adds_then_removes_and_busts_the_detail_state_only() {
        let (server, state) = mock_state(TENANT).await;
        mount_owners(&server, &["u1"]).await;
        Mock::given(method("POST"))
            .and(path(format!("/v1.0/applications/{OBJECT}/owners/$ref")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/v1.0/applications/{OBJECT}/owners/u1/$ref")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        seed_indexes_and_detail(&state, TENANT, OBJECT);

        let out = set_application_owners_core(&state, TENANT, OBJECT, vec!["u2".into()])
            .await
            .expect("both mocked writes succeed");
        assert_eq!(out.added, ["u2"]);
        assert_eq!(out.removed, ["u1"]);
        assert!(out.failures.is_empty());

        assert!(
            !detail_cached(&state, TENANT, OBJECT),
            "the owner list is detail-pane state"
        );
        assert!(
            indexes_intact(&state, TENANT),
            "an owner change must keep both tenant-wide indexes"
        );
    }

    #[tokio::test]
    async fn an_unchanged_owner_set_writes_nothing_and_busts_nothing() {
        let (server, state) = mock_state(TENANT).await;
        mount_owners(&server, &["u1"]).await;
        seed_indexes_and_detail(&state, TENANT, OBJECT);

        let out = set_application_owners_core(&state, TENANT, OBJECT, vec!["u1".into()])
            .await
            .expect("a no-op reconcile is a success");
        assert!(out.added.is_empty() && out.removed.is_empty() && out.failures.is_empty());
        assert_eq!(writes(&server).await, 0);
        assert!(detail_cached(&state, TENANT, OBJECT));
        assert!(indexes_intact(&state, TENANT));
    }

    #[tokio::test]
    async fn a_reconcile_where_every_write_fails_busts_nothing() {
        let (server, state) = mock_state(TENANT).await;
        mount_owners(&server, &[]).await;
        Mock::given(method("POST"))
            .and(path(format!("/v1.0/applications/{OBJECT}/owners/$ref")))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(&server)
            .await;
        seed_indexes_and_detail(&state, TENANT, OBJECT);

        let out = set_application_owners_core(&state, TENANT, OBJECT, vec!["u2".into()])
            .await
            .expect("a per-principal failure is data, not an error");
        assert!(out.added.is_empty() && out.removed.is_empty());
        assert_eq!(out.failures.len(), 1);
        assert_eq!(out.failures[0].principal_id, "u2");
        assert_eq!(out.failures[0].action, "add");
        assert_eq!(out.failures[0].code, "forbidden");
        assert!(!out.failures[0].is_reauth_fatal());
        assert!(
            detail_cached(&state, TENANT, OBJECT),
            "nothing changed, so nothing is busted"
        );
        assert!(indexes_intact(&state, TENANT));
    }

    /// A dead session on the first add stops the reconcile: no removal runs
    /// (the app must never be left ownerless by a half-applied replace), and
    /// the failure names the re-auth-fatal code the UI routes on.
    #[tokio::test]
    async fn a_dead_session_stops_the_reconcile_before_any_removal() {
        let (server, state) = mock_state_with_write_token(TENANT, dead_token()).await;
        mount_owners(&server, &["u1"]).await;
        seed_indexes_and_detail(&state, TENANT, OBJECT);

        let out = set_application_owners_core(&state, TENANT, OBJECT, vec!["u2".into()])
            .await
            .expect("a per-principal failure is data, not an error");
        assert!(out.added.is_empty() && out.removed.is_empty());
        assert_eq!(
            out.failures.len(),
            1,
            "the removal of u1 is never attempted"
        );
        assert_eq!(out.failures[0].principal_id, "u2");
        assert_eq!(out.failures[0].action, "add");
        assert_eq!(out.failures[0].code, "refresh_missing");
        assert!(out.failures[0].is_reauth_fatal());
        assert_eq!(writes(&server).await, 0);
        assert!(detail_cached(&state, TENANT, OBJECT));
        assert!(indexes_intact(&state, TENANT));
    }
}
