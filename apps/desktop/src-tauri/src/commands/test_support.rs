//! Shared fixtures for the command layer's handler tests.
//!
//! One home for what every wiremock-backed handler test re-solved on its own:
//!
//! - **One mock base-URL convention.** Every client built here is rooted at
//!   `{mock}/v1.0` — what production and [`AppState::for_test`] use — so a
//!   mock path copied from one handler test to another (`/v1.0/applications/…`)
//!   matches in both. Two conventions coexisted before, and a path copied
//!   across them silently 404'd.
//! - The fixed clock, the canned Graph payload, a dead-session token, the
//!   progress [`Recorder`] and the cache seed/assert helpers the tiering tests
//!   share.
//!
//! The graph crate's own `client/tests/common.rs` (`make_client`,
//! `sample_apps_json`) is `pub(crate)` there, so it is not reachable from this
//! crate; exposing it would take a `test-support` feature on the graph crate,
//! which is not worth one payload. The one payload is copied below instead.
//!
//! Mounted test-only at the very end of `commands/mod.rs` (the cfg sits on the
//! `mod` line there). The `repo_invariants` source walk reads this file as
//! production code — it carries no test-cfg marker of its own for
//! `strip_tests` to cut at, and it must not grow one — so it stays free of
//! anything those rules key on: no commands, no cache invalidations or pinned
//! index writes, no fan-out drivers.

use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{Application, ServicePrincipal};
use azapptoolkit_core::token::{BearerProvider, StaticTokenProvider, TokenError};
use azapptoolkit_graph::GraphClient;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use wiremock::MockServer;

use crate::commands::applications::{
    app_detail_key, app_name_index_hit, app_name_index_store, sp_index_hit, sp_index_store,
};
use crate::commands::progress::ProgressSink;
use crate::state::AppState;

/// The fixed "now" the date-window tests anchor to.
pub(crate) const FIXED_NOW: &str = "2026-01-01T00:00:00Z";

/// Parses an RFC 3339 timestamp; panics on a malformed fixture.
pub(crate) fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("fixture timestamps are RFC 3339")
        .with_timezone(&Utc)
}

/// [`FIXED_NOW`] as a `DateTime`.
pub(crate) fn fixed_now() -> DateTime<Utc> {
    at(FIXED_NOW)
}

/// A Graph client over `server`, rooted at `{mock}/v1.0`, with a static bearer
/// and a cache of its own.
pub(crate) fn mock_graph(server: &MockServer) -> GraphClient {
    mock_graph_with(server, StaticTokenProvider::new("tok"), Cache::new())
}

/// [`mock_graph`] with a caller-chosen token provider and cache — a
/// [`dead_token`] to drive the re-auth-fatal paths, or a cache the test reads
/// back afterwards.
pub(crate) fn mock_graph_with(
    server: &MockServer,
    token: Arc<dyn BearerProvider>,
    cache: Arc<Cache>,
) -> GraphClient {
    GraphClient::with_base_url(
        "tenant-test",
        token.clone(),
        token,
        cache,
        format!("{}/v1.0", server.uri()),
    )
}

/// A token provider whose refresh token is gone: every read fails with the
/// re-auth-fatal `refresh_missing` code before any request is sent.
pub(crate) struct DeadSession;

#[async_trait::async_trait]
impl BearerProvider for DeadSession {
    async fn bearer(&self) -> Result<String, TokenError> {
        Err(TokenError::new("refresh_missing", "gone"))
    }
}

/// [`DeadSession`] as the trait object a client takes.
pub(crate) fn dead_token() -> Arc<dyn BearerProvider> {
    Arc::new(DeadSession)
}

/// A token provider that serves `n` bearers and then dies with the
/// re-auth-fatal `refresh_missing` code — a session that expires partway
/// through a multi-write operation. Used as a client's **write** token (see
/// [`mock_graph_rw`] / [`mock_state_with_write_token`]) so the reads before
/// the loop still succeed.
pub(crate) struct DiesAfter(AtomicUsize);

#[async_trait::async_trait]
impl BearerProvider for DiesAfter {
    async fn bearer(&self) -> Result<String, TokenError> {
        let left = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        match left {
            Ok(_) => Ok("tok".to_string()),
            Err(_) => Err(TokenError::new("refresh_missing", "gone")),
        }
    }
}

/// [`DiesAfter`]`(n)` as the trait object a client takes.
pub(crate) fn dies_after(n: usize) -> Arc<dyn BearerProvider> {
    Arc::new(DiesAfter(AtomicUsize::new(n)))
}

/// [`mock_graph_with`] with separate read and write tokens. The client picks
/// one per request by HTTP verb (GET reads, everything else writes), so a
/// [`dies_after`] write token lets the reads succeed and fails the writes.
pub(crate) fn mock_graph_rw(
    server: &MockServer,
    read: Arc<dyn BearerProvider>,
    write: Arc<dyn BearerProvider>,
    cache: Arc<Cache>,
) -> GraphClient {
    GraphClient::with_base_url(
        "tenant-test",
        read,
        write,
        cache,
        format!("{}/v1.0", server.uri()),
    )
}

/// A fresh mock server plus an [`AppState`] whose Graph client for `tenant` is
/// rooted at it (`{mock}/v1.0`, via [`AppState::for_test`]).
pub(crate) async fn mock_state(tenant: &str) -> (MockServer, AppState) {
    let server = MockServer::start().await;
    let state = AppState::for_test(tenant, &server.uri());
    (server, state)
}

/// [`mock_state`] whose Graph client writes with `write` (reads keep a static
/// bearer) — pair it with [`dies_after`] to drive a session that dies partway.
pub(crate) async fn mock_state_with_write_token(
    tenant: &str,
    write: Arc<dyn BearerProvider>,
) -> (MockServer, AppState) {
    let server = MockServer::start().await;
    let state = AppState::for_test_with_write_token(tenant, &server.uri(), write);
    (server, state)
}

/// One application as Graph returns it: `obj-1` / `app-1` / "Demo App", no
/// credentials, nothing declared.
///
/// Copied once from the graph crate's
/// `crates/azapptoolkit-graph/src/client/tests/common.rs`
/// (`sample_apps_json().value[0]`), which is not reachable from here.
pub(crate) fn sample_app_json() -> serde_json::Value {
    serde_json::json!({
        "id": "obj-1",
        "appId": "app-1",
        "displayName": "Demo App",
        "signInAudience": "AzureADMyOrg",
        "passwordCredentials": [],
        "keyCredentials": [],
        "requiredResourceAccess": []
    })
}

/// Records what a driver would have emitted over IPC: every `(event, payload)`
/// in order, the payload kept as JSON so one recorder serves every payload type.
#[derive(Default)]
pub(crate) struct Recorder(Mutex<Vec<(&'static str, serde_json::Value)>>);

impl ProgressSink for Recorder {
    fn emit_event<P: Serialize + Clone>(&self, event: &'static str, payload: P) {
        let value = serde_json::to_value(&payload).expect("progress payloads serialize");
        self.0.lock().push((event, value));
    }
}

impl Recorder {
    /// Every event name, in emission order.
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.0.lock().iter().map(|(name, _)| *name).collect()
    }

    /// The payloads emitted on `event`, in order, decoded as `T`.
    pub(crate) fn payloads<T: DeserializeOwned>(&self, event: &str) -> Vec<T> {
        self.0
            .lock()
            .iter()
            .filter(|(name, _)| *name == event)
            .map(|(_, value)| {
                serde_json::from_value(value.clone()).expect("payload decodes as the asked type")
            })
            .collect()
    }
}

/// Seeds what a single-app mutation must NOT drop (the two tenant-wide
/// indexes, which cost a full directory scan to rebuild) alongside what it
/// must drop (the app's detail row).
pub(crate) fn seed_indexes_and_detail(state: &AppState, tenant: &str, object_id: &str) {
    sp_index_store(&state.cache, tenant, vec![ServicePrincipal::default()]);
    app_name_index_store(&state.cache, tenant, vec![Application::default()]);
    state.cache.put(
        CacheKind::Lists,
        app_detail_key(tenant, object_id),
        &serde_json::json!({ "id": object_id }),
    );
}

/// Whether the app's detail row seeded by [`seed_indexes_and_detail`] survives.
pub(crate) fn detail_cached(state: &AppState, tenant: &str, object_id: &str) -> bool {
    state
        .cache
        .get::<serde_json::Value>(CacheKind::Lists, &app_detail_key(tenant, object_id))
        .is_some()
}

/// Whether BOTH tenant-wide indexes seeded by [`seed_indexes_and_detail`]
/// survive.
pub(crate) fn indexes_intact(state: &AppState, tenant: &str) -> bool {
    sp_index_hit(&state.cache, tenant).is_some()
        && app_name_index_hit(&state.cache, tenant).is_some()
}
