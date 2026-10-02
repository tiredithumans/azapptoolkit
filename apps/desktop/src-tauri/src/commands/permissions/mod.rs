//! Permission commands: the permission picker's resource-directory reads and
//! the `requiredResourceAccess` + runtime-grant writers built on them.
//!
//! Split by concern: `catalog` (picker reads), `manifest` (declaration edits,
//! including the pure manifest-array primitives shared with the scoping and
//! remediation flows), `consent` (admin consent), `grant` (single-permission
//! grant), `downgrade` (the least-privilege swap), `revoke` (single runtime
//! grants). The `GrantRun` machinery and the kind -> entry-type mapping are
//! shared by consent, grant and downgrade, so they live here.

mod catalog;
mod consent;
mod downgrade;
mod grant;
mod manifest;
mod revoke;

// Glob re-exports keep every item reachable at `crate::commands::permissions::*`
// (the pre-split path) — crucially including the hidden `__cmd__<name>` items
// that `#[tauri::command]` generates, which `generate_handler!` resolves at
// `commands::permissions::<fn>` alongside the function itself.
pub use catalog::*;
pub use consent::*;
pub use downgrade::*;
pub use grant::*;
pub use manifest::*;
pub use revoke::*;

use crate::dto::UiError;
use crate::dto::permissions::{GrantResult, PermissionKind};

// ---------------- Shared grant plumbing ----------------

/// Builds a grant-failure message from a Graph error, appending the admin-consent
/// role guidance when the failure is a 403. A forbidden on a *grant* operation
/// means the signed-in user lacks the directory role to consent (the
/// `admin_consent` capability — Application / Cloud Application Administrator
/// for most APIs, Privileged Role Administrator / Global Administrator for
/// Microsoft Graph and Azure AD Graph app roles), not that the permission itself
/// is wrong, so the hint points there.
pub(crate) fn grant_failure_message(err: &azapptoolkit_graph::GraphError) -> String {
    let base = err.to_string();
    if matches!(err, azapptoolkit_graph::GraphError::Forbidden(_))
        && let Some(cap) = azapptoolkit_core::capabilities::capability("admin_consent")
    {
        return format!("{base}\n\n{}", cap.remediation);
    }
    base
}

/// What a grant core did: its [`GrantResult`] plus the writes that landed, so
/// the caller can bust the right tier **even when a later step failed**.
///
/// The `downgrade_application_permission_core` shape: a failure before the
/// first write is a plain `Err` (nothing landed, nothing to invalidate); a
/// failure after one comes back here as `error: Some(..)` beside the landed
/// flags, with `result` empty — the run stops at the failed step, as the
/// earlier `?` did. Backend-only, never an IPC type.
#[derive(Debug)]
pub(crate) struct GrantRun {
    /// Meaningful only when `error` is `None`. On a stopped run it is a
    /// placeholder: its ids may be empty (an SP failure after the manifest
    /// PATCH leaves `client_service_principal_id` as `""`), so a caller reads
    /// the landed flags, never this, once `error` is `Some`.
    pub(crate) result: GrantResult,
    /// The app's `requiredResourceAccess` was PATCHed (single grant only).
    pub(crate) manifest_changed: bool,
    /// Ensuring the client SP created a brand-new one — a new Enterprise App
    /// row / search-index entry.
    pub(crate) sp_created: bool,
    /// The step that failed after a write had landed; `None` for a full run.
    pub(crate) error: Option<UiError>,
}

/// An empty [`GrantResult`] for a run that stopped after a landed write.
pub(crate) fn empty_grant(client_service_principal_id: String) -> GrantResult {
    GrantResult {
        client_service_principal_id,
        role_assignments_created: Vec::new(),
        role_assignments_skipped: Vec::new(),
        scope_grants_upserted: Vec::new(),
        failures: Vec::new(),
    }
}

/// The cache bust a grant run's landed writes need: a brand-new SP is a new
/// Enterprise App row / search-index entry, so the full list tier; any other
/// completed run, or a stopped one whose manifest PATCH landed, the cheaper
/// detail + audit tier. A stopped run that landed nothing busts nothing.
pub(crate) fn invalidate_after_grant(
    cache: &azapptoolkit_core::cache::Cache,
    tenant_id: &str,
    run: &GrantRun,
) {
    if run.sp_created {
        super::applications::invalidate_app_lists(cache, tenant_id);
    } else if run.error.is_none() || run.manifest_changed {
        super::applications::invalidate_app_detail_state(cache, tenant_id);
    }
}

/// The manifest entry type a permission kind declares, or a validation error for
/// `Unknown`.
///
/// Split out so the mapping is testable without a session: `Unknown` reaching
/// Graph would declare a `requiredResourceAccess` entry with a meaningless type.
pub(crate) fn entry_type_for(kind: PermissionKind) -> Result<&'static str, UiError> {
    match kind {
        PermissionKind::Application => Ok("Role"),
        PermissionKind::Delegated => Ok("Scope"),
        PermissionKind::Unknown => Err(UiError::validation(
            "invalid_permission_kind",
            "permission kind must be Application or Delegated",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_application_and_delegated_declare_a_manifest_entry() {
        // `Unknown` reaching Graph would PATCH `requiredResourceAccess` with a
        // meaningless entry type, which is not something the portal can show or
        // a later grant can match. It is rejected before any round trip.
        assert_eq!(entry_type_for(PermissionKind::Application).unwrap(), "Role");
        assert_eq!(entry_type_for(PermissionKind::Delegated).unwrap(), "Scope");
        let err = entry_type_for(PermissionKind::Unknown).expect_err("Unknown must be refused");
        assert_eq!(err.code, "invalid_permission_kind");
    }
}

/// Core-level partial-write tests: the grant cores take `&GraphClient`, so a
/// mock Graph drives them as-is. A failure after a landed write comes back as a
/// [`GrantRun`] carrying the landed flags; one before any write stays `Err`.
#[cfg(test)]
mod handler_tests {
    use super::*;

    use crate::state::AppState;

    use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::commands::test_support::{
        detail_cached, indexes_intact, mock_graph, sample_app_json, seed_indexes_and_detail,
    };

    /// `sample_app_json()` (obj-1 / app-1, nothing declared) and no SP for
    /// app-1 yet — the state in which both cores must create one.
    async fn mount_app_without_sp(server: &MockServer) {
        mount_app(server, sample_app_json()).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", "appId eq 'app-1'"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .mount(server)
            .await;
    }

    async fn mount_app(server: &MockServer, app: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/v1.0/applications/obj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(app))
            .mount(server)
            .await;
    }

    async fn refuse_sp_create(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/v1.0/servicePrincipals"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(server)
            .await;
    }

    /// The idempotency snapshot the admin-consent core reads right after the
    /// client SP: its app-role assignments are refused.
    async fn refuse_assignment_snapshot(server: &MockServer, sp_id: &str) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
            )))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/oauth2PermissionGrants"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .mount(server)
            .await;
    }

    async fn received(server: &MockServer, verb: &str, url_path: &str) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method.as_str() == verb && r.url.path() == url_path)
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect()
    }

    #[tokio::test]
    async fn grant_single_permission_core_reports_the_landed_manifest_patch_when_sp_creation_fails()
    {
        let server = MockServer::start().await;
        mount_app_without_sp(&server).await;
        Mock::given(method("PATCH"))
            .and(path("/v1.0/applications/obj-1"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        refuse_sp_create(&server).await;
        let client = mock_graph(&server);

        let run = grant_single_permission_core(
            &client,
            "obj-1",
            MICROSOFT_GRAPH_APP_ID,
            "role-1",
            PermissionKind::Application,
        )
        .await
        .expect("the manifest PATCH landed, so the run is Ok with an error beside it");
        assert!(run.manifest_changed, "the PATCH is reported");
        assert!(!run.sp_created);
        assert_eq!(
            run.error.expect("the SP failure is reported").code,
            "forbidden"
        );

        let patches = received(&server, "PATCH", "/v1.0/applications/obj-1").await;
        assert_eq!(patches.len(), 1, "exactly one manifest PATCH was sent");
        assert!(patches[0].contains("role-1"), "{}", patches[0]);
        assert!(
            patches[0].contains(MICROSOFT_GRAPH_APP_ID),
            "{}",
            patches[0]
        );
        assert_eq!(
            received(&server, "POST", "/v1.0/servicePrincipals")
                .await
                .len(),
            1
        );
    }

    /// Already declared → no PATCH, so an SP failure landed nothing: plain Err.
    #[tokio::test]
    async fn grant_single_permission_core_errs_when_nothing_landed_before_the_failure() {
        let server = MockServer::start().await;
        let mut app = sample_app_json();
        app["requiredResourceAccess"] = serde_json::json!([{
            "resourceAppId": MICROSOFT_GRAPH_APP_ID,
            "resourceAccess": [{ "id": "role-1", "type": "Role" }],
        }]);
        mount_app(&server, app).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", "appId eq 'app-1'"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .mount(&server)
            .await;
        refuse_sp_create(&server).await;
        let client = mock_graph(&server);

        let err = grant_single_permission_core(
            &client,
            "obj-1",
            MICROSOFT_GRAPH_APP_ID,
            "role-1",
            PermissionKind::Application,
        )
        .await
        .expect_err("nothing landed, so the failure is a plain Err");
        assert_eq!(err.code, "forbidden");
        assert!(
            received(&server, "PATCH", "/v1.0/applications/obj-1")
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn grant_admin_consent_core_reports_the_created_sp_when_the_grant_snapshot_fails() {
        let server = MockServer::start().await;
        mount_app_without_sp(&server).await;
        Mock::given(method("POST"))
            .and(path("/v1.0/servicePrincipals"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "sp-new",
                "appId": "app-1",
                "displayName": "Demo App",
            })))
            .mount(&server)
            .await;
        refuse_assignment_snapshot(&server, "sp-new").await;
        let client = mock_graph(&server);

        let run = grant_admin_consent_core(&client, "obj-1")
            .await
            .expect("the SP was created, so the run is Ok with an error beside it");
        assert!(run.sp_created, "the created SP survives the later failure");
        assert!(!run.manifest_changed);
        assert_eq!(run.result.client_service_principal_id, "sp-new");
        assert!(run.result.role_assignments_created.is_empty());
        assert_eq!(
            run.error.expect("the snapshot failure is reported").code,
            "forbidden"
        );
        assert_eq!(
            received(&server, "POST", "/v1.0/servicePrincipals")
                .await
                .len(),
            1,
            "the SP creation landed before the failure"
        );
        assert!(
            received(
                &server,
                "POST",
                "/v1.0/servicePrincipals/sp-new/appRoleAssignments"
            )
            .await
            .is_empty(),
            "the run stops: no grant is written with the granted set unknown"
        );
    }

    /// The SP already existed → nothing landed before the snapshot failure:
    /// plain Err.
    #[tokio::test]
    async fn grant_admin_consent_core_errs_when_the_sp_already_existed() {
        let server = MockServer::start().await;
        mount_app(&server, sample_app_json()).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", "appId eq 'app-1'"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "sp-1", "appId": "app-1", "displayName": "Demo App" }]
            })))
            .mount(&server)
            .await;
        refuse_assignment_snapshot(&server, "sp-1").await;
        let client = mock_graph(&server);

        let err = grant_admin_consent_core(&client, "obj-1")
            .await
            .expect_err("nothing landed, so the failure is a plain Err");
        assert_eq!(err.code, "forbidden");
        assert!(
            received(&server, "POST", "/v1.0/servicePrincipals")
                .await
                .is_empty()
        );
    }

    /// Each landed-write shape busts exactly the tier it needs — and a stopped
    /// run that landed nothing busts nothing.
    #[test]
    fn invalidate_after_grant_busts_the_tier_the_landed_writes_need() {
        const TENANT: &str = "t1";
        const OBJECT: &str = "obj-1";
        let forbidden = || Some(UiError::new("forbidden", "no", false));
        // (manifest_changed, sp_created, error, detail kept, indexes kept)
        let rows: [(bool, bool, Option<UiError>, bool, bool); 5] = [
            (false, true, None, false, false),
            (false, true, forbidden(), false, false),
            (false, false, None, false, true),
            (true, false, forbidden(), false, true),
            (false, false, forbidden(), true, true),
        ];
        for (i, (manifest_changed, sp_created, error, detail_kept, indexes_kept)) in
            rows.into_iter().enumerate()
        {
            let state = AppState::for_test(TENANT, "http://127.0.0.1:9");
            seed_indexes_and_detail(&state, TENANT, OBJECT);
            let run = GrantRun {
                result: empty_grant(String::new()),
                manifest_changed,
                sp_created,
                error,
            };
            invalidate_after_grant(&state.cache, TENANT, &run);
            assert_eq!(
                detail_cached(&state, TENANT, OBJECT),
                detail_kept,
                "row {i}"
            );
            assert_eq!(indexes_intact(&state, TENANT), indexes_kept, "row {i}");
        }
    }
}
