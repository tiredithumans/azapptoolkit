//! Proving a tenant has a session, for commands that can answer without one.
//!
//! Every ordinary read reaches a service through a client factory, so a tenant
//! with no session fails at the token and no data comes back — the session
//! check is implicit in the round trip. A command that can return **before**
//! building a client skips that entirely, and then the `tenant_id` *argument*
//! is the only thing deciding whose directory data is returned. A stale or
//! wrong id from the webview (a tenant switch mid-flight is the realistic one)
//! serves another tenant's data: the cross-tenant leak AGENTS.md calls the #1
//! footgun.
//!
//! Two shapes need this, and both are easy to miss:
//!
//! * commands that answer **only** from cache (`get_cached_*`, `save_audit_to_file`);
//! * read-through commands whose cache **hit** path returns before `graph_for`.
//!
//! The second is why the proof must come first in the body, not merely appear
//! somewhere in it. Pinned by
//! `repo_invariants::cache::a_command_answering_from_cache_alone_checks_the_session`.

use crate::state::AppState;
use azapptoolkit_dto::UiError;

/// Refuses unless `tenant_id` signed in this session. Cheap — a lock and a map
/// lookup, no IO — so it belongs ahead of the cache read, not after it.
pub(crate) fn prove_tenant_session(state: &AppState, tenant_id: &str) -> Result<(), UiError> {
    state
        .auth
        .tenant_context(tenant_id)
        .map(|_| ())
        .ok_or_else(|| {
            UiError::validation(
                "not_signed_in",
                format!("not signed in to tenant {tenant_id}"),
            )
        })
}
