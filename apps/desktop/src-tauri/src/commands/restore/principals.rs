//! Resolving a backed-up principal (owner, assignee, group) to its object id in
//! the destination, memoized for the run.

use std::collections::HashMap;

use azapptoolkit_core::models::DirectoryObject;
use azapptoolkit_graph::GraphClient;

use crate::commands::dispatch::SessionDead;
use crate::dto::backup::PrincipalRef;

/// Which directory collection a backed-up principal is looked up in by display
/// name, from its recorded `principal_type` — an owner's `@odata.type`
/// (`#microsoft.graph.user`) or an assignment's `principalType` (`User`).
#[derive(Debug, Clone, PartialEq)]
pub(super) enum PrincipalKind {
    User,
    Group,
    /// No type recorded (an older backup): both collections are searched and
    /// exactly one match across them is required.
    Either,
    /// A type the restore cannot look up by name (a service principal, …).
    Other(String),
}

pub(super) fn principal_kind(principal: &PrincipalRef) -> PrincipalKind {
    let Some(raw) = principal
        .principal_type
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return PrincipalKind::Either;
    };
    let bare = raw.strip_prefix("#microsoft.graph.").unwrap_or(raw);
    match bare.to_ascii_lowercase().as_str() {
        "user" => PrincipalKind::User,
        "group" => PrincipalKind::Group,
        _ => PrincipalKind::Other(bare.to_string()),
    }
}

/// Why a backed-up principal did not resolve in the destination.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Unresolved {
    /// No exact match.
    NotFound,
    /// More than one exact match, so none is taken: binding an owner or a role
    /// to the wrong one of two same-named principals grants it to someone the
    /// backup never named.
    Ambiguous(usize),
    /// A lookup failed. Never a reason to try another collection: a group
    /// search that errored is not a group that does not exist.
    LookupFailed,
    /// Its type cannot be looked up by name.
    UnsupportedType(String),
}

impl Unresolved {
    /// The principal's report label, with the reason when it is not plain
    /// "not found".
    pub(super) fn label(&self, principal: &PrincipalRef) -> String {
        let name = owner_label(principal);
        match self {
            Self::NotFound => name,
            Self::Ambiguous(n) => format!("{name} (ambiguous: {n} matches)"),
            Self::LookupFailed => format!("{name} (lookup failed)"),
            Self::UnsupportedType(t) => format!("{name} (a {t}, not a user or group)"),
        }
    }
}

/// A resolution: the destination object id, or why there is none.
type Resolution = Result<String, Unresolved>;

/// The per-run principal memo ([`resolve_principal`]).
pub(super) type PrincipalMemo = HashMap<String, Resolution>;

/// Cache key for a principal: its UPN (lowercased) when present, else its
/// [`PrincipalKind`] and display name. `None` when neither is set (nothing to
/// resolve). Mirrors the lookup branch order in [`resolve_principal_uncached`].
pub(super) fn principal_cache_key(principal: &PrincipalRef) -> Option<String> {
    if let Some(upn) = principal
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        return Some(format!("upn:{}", upn.to_ascii_lowercase()));
    }
    let kind = match principal_kind(principal) {
        PrincipalKind::User => "user".to_string(),
        PrincipalKind::Group => "group".to_string(),
        PrincipalKind::Either => "any".to_string(),
        PrincipalKind::Other(t) => t,
    };
    principal
        .display_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|name| format!("name:{kind}:{name}"))
}

/// Resolves a backed-up principal to its destination object id, memoizing the
/// result for the whole restore run. The same UPN or group is reused across
/// owners, app-role assignees, and group memberships, so without the memo a
/// multi-app restore re-runs identical `search_users`/`search_groups` calls many
/// times. The cache is per-run and keyed by [`principal_cache_key`]; negative
/// results are cached too (a principal absent now stays absent for the run).
/// A failed lookup is noted on `session` like every other read, so a dead
/// session trips the latch here rather than at the next noted call.
pub(super) async fn resolve_principal(
    client: &GraphClient,
    cache: &mut PrincipalMemo,
    principal: &PrincipalRef,
    session: &SessionDead,
) -> Resolution {
    let Some(key) = principal_cache_key(principal) else {
        return Err(Unresolved::NotFound);
    };
    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }
    let resolved = resolve_principal_uncached(client, principal, session).await;
    cache.insert(key, resolved.clone());
    resolved
}

/// Exactly one id, or why not.
fn exactly_one(ids: Vec<String>) -> Resolution {
    match <[String; 1]>::try_from(ids) {
        Ok([id]) => Ok(id),
        Err(ids) if ids.is_empty() => Err(Unresolved::NotFound),
        Err(ids) => Err(Unresolved::Ambiguous(ids.len())),
    }
}

/// The ids of every hit whose display name equals `name` ignoring case — as
/// Graph's `eq` does, so "Ops" and "OPS" are two matches (ambiguous), never one
/// resolved by a stricter client-side comparison.
fn exact_name_matches(hits: Vec<DirectoryObject>, name: &str) -> Vec<String> {
    let want = name.to_lowercase();
    hits.into_iter()
        .filter(|h| h.display_name.as_deref().map(str::to_lowercase) == Some(want.clone()))
        .map(|h| h.id)
        .collect()
}

/// Resolves a backed-up principal to its object id in the destination tenant:
/// by UPN when it has one (`find_user_by_upn`, an exact `eq`), else by exact
/// display name (`displayName eq`, every page) in the collection its recorded
/// type names ([`PrincipalKind`]) — no cross-kind fallback, and every match
/// counted, so it resolves only when exactly one principal fits.
/// Best-effort: an unresolved principal is reported, never a run failure.
pub(super) async fn resolve_principal_uncached(
    client: &GraphClient,
    principal: &PrincipalRef,
    session: &SessionDead,
) -> Resolution {
    if let Some(upn) = principal
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        return match client.find_user_by_upn(upn).await {
            Ok(Some(user)) => Ok(user.id),
            Ok(None) => Err(Unresolved::NotFound),
            Err(e) => {
                session.note_code(e.ui_code());
                Err(Unresolved::LookupFailed)
            }
        };
    }
    let Some(name) = principal.display_name.as_deref().filter(|s| !s.is_empty()) else {
        return Err(Unresolved::NotFound);
    };
    let (users, groups) = match principal_kind(principal) {
        PrincipalKind::User => (true, false),
        PrincipalKind::Group => (false, true),
        PrincipalKind::Either => (true, true),
        PrincipalKind::Other(t) => return Err(Unresolved::UnsupportedType(t)),
    };
    let mut ids = Vec::new();
    if groups {
        let hits = client
            .find_groups_by_display_name(name)
            .await
            .map_err(|e| {
                session.note_code(e.ui_code());
                Unresolved::LookupFailed
            })?;
        ids.extend(exact_name_matches(hits, name));
    }
    if users {
        let hits = client.find_users_by_display_name(name).await.map_err(|e| {
            session.note_code(e.ui_code());
            Unresolved::LookupFailed
        })?;
        ids.extend(exact_name_matches(hits, name));
    }
    exactly_one(ids)
}

pub(super) fn owner_label(p: &PrincipalRef) -> String {
    p.user_principal_name
        .clone()
        .or_else(|| p.display_name.clone())
        .unwrap_or_else(|| p.source_id.clone())
}
