//! Granted-vs-used Graph activity analysis.
//!
//! `MicrosoftGraphActivityLogs` (every Graph request, with the calling appId)
//! only exists when a tenant admin has configured Microsoft Entra diagnostic
//! settings exporting it to a Log Analytics workspace — there is no Graph API
//! for it. [`get_app_graph_usage`] discovers such a workspace once per tenant
//! (cached), then summarizes one app's observed calls by (method, normalized
//! path) so an admin can compare what an app *does* against what it *holds*
//! (e.g. `Mail.ReadWrite` granted but only GETs observed → the Downgrade…
//! action applies). Everything degrades to a typed, actionable error — never a
//! hard failure of the surrounding view.

use azapptoolkit_arm::LogsQueryTable;
use azapptoolkit_core::cache::CacheKind;
use futures::stream::{self, StreamExt};
use tauri::State;

use crate::dto::UiError;
use crate::dto::usage::{GraphUsageResult, GraphUsageRow};
use crate::state::AppState;

/// Result-row cap per query — keeps the IPC payload and the panel readable;
/// `truncated` tells the UI when the long tail was cut.
const USAGE_ROW_CAP: usize = 200;
/// Safety cap on workspace table-presence probes per discovery run.
const MAX_WORKSPACES_PROBED: usize = 50;

/// Bounded fan-out width for the ARM control-plane sweep, matching the shared
/// value the Key Vault picker / readiness / managed-identity sweeps use.
const ARM_CONCURRENCY: usize = 8;

/// Tenant-prefixed cache key for the discovered workspace (cross-tenant
/// leakage guard, same convention as the list caches).
///
/// **Read-only until TTL / sign-out, by design.** The workspace exporting
/// `MicrosoftGraphActivityLogs` is effectively immutable for a tenant, so no
/// mutation busts this key — it's cleared only by the 60-min `Permissions` TTL
/// and the sign-out tenant sweep (`invalidate_tenant`). If a workspace is
/// re-pointed mid-session, "Clear all" in Cache diagnostics forces re-discovery.
///
/// Caches the **negative** outcome as well as the positive one (see
/// [`WorkspaceLookup`]): most tenants have no Graph-activity export at all, and
/// that is precisely the case where discovery is most expensive.
fn workspace_cache_key(tenant_id: &str) -> String {
    format!("{tenant_id}|graph_activity_ws")
}

/// Cached discovery outcome. `None` — "this tenant exports no
/// `MicrosoftGraphActivityLogs`" — is a real, cacheable answer: without it every
/// visit to the usage panel re-ran the whole subscription × workspace sweep
/// (up to [`MAX_WORKSPACES_PROBED`] multi-second Log Analytics probes) only to
/// report "unavailable" again. Same TTL/sweep semantics as the positive hit.
type WorkspaceLookup = Option<(String, String)>;

/// Finds a Log Analytics workspace containing `MicrosoftGraphActivityLogs`:
/// enumerate the subscriptions the signed-in user can reach, list each one's
/// workspaces, and probe each with a cheap `take 1` query — a workspace
/// without the table answers 400 (semantic error), which simply means "not
/// here". The first hit is cached per tenant (`CacheKind::Permissions`) so
/// subsequent usage queries skip discovery. `None` = no workspace found,
/// which the caller turns into setup guidance.
async fn discover_workspace(
    state: &AppState,
    tenant_id: &str,
) -> Result<Option<(String, String)>, UiError> {
    let cache_key = workspace_cache_key(tenant_id);
    if let Some(hit) = state
        .cache
        .get::<WorkspaceLookup>(CacheKind::Permissions, &cache_key)
    {
        return Ok(hit);
    }

    // Typed ARM consent probe first, so a missing-consent rejection surfaces
    // as `consent_required` rather than a generic token error mid-discovery.
    state
        .ensure_arm_token(tenant_id)
        .await
        .map_err(UiError::from)?;
    let arm = state.arm_for(tenant_id);
    let la = state.log_analytics_for(tenant_id);

    let subscriptions = arm.list_subscriptions().await.map_err(UiError::from)?;

    // Bounded fan-out over subscriptions, matching the Key Vault picker and
    // readiness sweeps. The serial form paid one ARM round trip per
    // subscription back-to-back before any probe could start, so discovery
    // scaled with the operator's subscription count. A subscription we can't
    // read is skipped, not fatal.
    let workspaces: Vec<_> = stream::iter(subscriptions)
        .map(|sub| {
            let arm = arm.clone();
            async move {
                match arm
                    .list_log_analytics_workspaces(&sub.subscription_id)
                    .await
                {
                    Ok(ws) => ws,
                    Err(err) => {
                        tracing::info!(
                            sub = %sub.subscription_id,
                            code = err.ui_code(),
                            "usage: workspace listing failed; skipping subscription"
                        );
                        Vec::new()
                    }
                }
            }
        })
        .buffer_unordered(ARM_CONCURRENCY)
        .collect::<Vec<Vec<_>>>()
        .await
        .into_iter()
        .flatten()
        .collect();

    let mut probed = 0usize;
    let mut found: WorkspaceLookup = None;
    let mut hit_cap = false;
    for ws in workspaces {
        if probed >= MAX_WORKSPACES_PROBED {
            tracing::warn!(
                cap = MAX_WORKSPACES_PROBED,
                "usage: workspace probe cap reached without a hit"
            );
            hit_cap = true;
            break;
        }
        let Some(customer_id) = ws.properties.customer_id.clone() else {
            continue;
        };
        probed += 1;
        // Probes stay SERIAL: the first hit wins and the common tenant has one
        // or two workspaces, so fanning these out would mostly buy extra Log
        // Analytics load on a query surface that is already the slow one.
        match la
            .query(&customer_id, "MicrosoftGraphActivityLogs | take 1", "P1D")
            .await
        {
            Ok(_) => {
                let name = ws.name.clone().unwrap_or_else(|| customer_id.clone());
                found = Some((customer_id, name));
                break;
            }
            Err(err) => {
                // Table absent (400) or no read access (403) — not this one.
                tracing::debug!(
                    ws = ws.name.as_deref().unwrap_or("?"),
                    code = err.ui_code(),
                    "usage: workspace probe negative"
                );
            }
        }
    }

    // Cache the outcome — including "no workspace". Skip only the truncated
    // case, where the answer is "we ran out of probe budget", not "there is
    // none", and caching it would hide a workspace past the cap until the TTL.
    if !hit_cap {
        state.cache.put(CacheKind::Permissions, cache_key, &found);
    }
    Ok(found)
}

/// KQL summarizing one app's Graph calls by (method, GUID-normalized path),
/// most frequent first.
///
/// This is the only caller of `LogAnalyticsClient::query`, which passes the KQL
/// straight into the request body — so it is the whole KQL trust boundary, and
/// the appId is escaped as defense in depth even though it is a GUID in
/// practice.
///
/// The literal is **verbatim** (`@'…'`), which is the form where doubling a
/// quote genuinely is the escape and a backslash is an ordinary character. In a
/// non-verbatim KQL literal an inner quote is escaped with a backslash, not by
/// doubling: `''` there closes the literal and opens another, and KQL silently
/// concatenates the two — so a value containing `'` filtered on the wrong
/// string and a backslash was not neutralised at all.
fn usage_kql(app_id: &str) -> String {
    let app = app_id.replace('\'', "''");
    format!(
        "MicrosoftGraphActivityLogs \
         | where AppId == @'{app}' \
         | extend Path = replace_regex(tostring(parse_url(RequestUri).Path), \
           @'[0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}}', '{{id}}') \
         | summarize Count = count(), LastSeen = max(TimeGenerated) by RequestMethod, Path \
         | order by Count desc \
         | take {USAGE_ROW_CAP}"
    )
}

/// Maps the query table to usage rows by **column name**, never position — the
/// service is free to reorder columns. Pure for unit-testing.
fn usage_rows(table: &LogsQueryTable) -> Vec<GraphUsageRow> {
    let (Some(method), Some(path), Some(count), last_seen) = (
        table.column_index("RequestMethod"),
        table.column_index("Path"),
        table.column_index("Count"),
        table.column_index("LastSeen"),
    ) else {
        return Vec::new();
    };
    table
        .rows
        .iter()
        .map(|r| GraphUsageRow {
            method: r
                .get(method)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            path: r
                .get(path)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            count: r.get(count).and_then(|v| v.as_u64()).unwrap_or(0),
            last_seen: last_seen
                .and_then(|i| r.get(i))
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
        .collect()
}

/// Summarizes `app_id`'s observed Graph calls over the last `days` (clamped to
/// 1–90, the table's default retention) from the tenant's
/// `MicrosoftGraphActivityLogs` workspace. Typed failures the panel acts on:
/// `consent_required` (Grant-consent button) and `usage_unavailable` (setup
/// guidance — no workspace exports the table, or none is readable).
#[tauri::command]
pub async fn get_app_graph_usage(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    days: u32,
) -> Result<GraphUsageResult, UiError> {
    let days = days.clamp(1, 90);
    // Typed consent probe for the query audience before any work.
    state
        .ensure_log_analytics_token(&tenant_id)
        .await
        .map_err(UiError::from)?;

    let Some((workspace_id, workspace_name)) = discover_workspace(&state, &tenant_id).await? else {
        return Err(UiError::validation(
            "usage_unavailable",
            "No Log Analytics workspace with MicrosoftGraphActivityLogs was found. Enable \
             Microsoft Entra diagnostic settings (category \"Microsoft Graph activity logs\") \
             exporting to a workspace you can read, wait for data to land, then retry.",
        ));
    };

    let la = state.log_analytics_for(&tenant_id);
    let table = la
        .query(&workspace_id, &usage_kql(&app_id), &format!("P{days}D"))
        .await
        .map_err(UiError::from)?;
    let rows = usage_rows(&table);
    let truncated = rows.len() >= USAGE_ROW_CAP;
    Ok(GraphUsageResult {
        app_id,
        days,
        workspace_name,
        rows,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_arm::models::LogsQueryColumn;

    #[test]
    fn usage_kql_filters_the_app_and_escapes_quotes() {
        let kql = usage_kql("11111111-2222-3333-4444-555555555555");
        assert!(kql.contains("AppId == @'11111111-2222-3333-4444-555555555555'"));
        assert!(kql.contains("MicrosoftGraphActivityLogs"));
        // The literal must be VERBATIM. `''` is the documented escape only
        // there; in a plain `'…'` literal KQL escapes an inner quote with a
        // backslash, and `''` instead closes the literal and opens another —
        // which KQL then silently concatenates, filtering on the wrong string.
        let kql = usage_kql("x' | union evil");
        assert!(kql.contains("AppId == @'x'' | union evil'"));
        // And a backslash is an ordinary character in a verbatim literal, so it
        // cannot start an escape sequence of its own.
        let kql = usage_kql(r"x\' | union evil");
        assert!(
            kql.contains(r"AppId == @'x\'' | union evil'"),
            "backslash must survive as a literal, not neutralise the doubled quote: {kql}"
        );
    }

    #[test]
    fn usage_rows_map_by_column_name_not_position() {
        // Columns deliberately out of the query's order.
        let table = LogsQueryTable {
            name: "PrimaryResult".into(),
            columns: ["LastSeen", "Count", "Path", "RequestMethod"]
                .iter()
                .map(|n| LogsQueryColumn {
                    name: (*n).to_string(),
                })
                .collect(),
            rows: vec![vec![
                serde_json::json!("2026-06-01T00:00:00Z"),
                serde_json::json!(42),
                serde_json::json!("/v1.0/users/{id}/messages"),
                serde_json::json!("GET"),
            ]],
        };
        let rows = usage_rows(&table);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].method, "GET");
        assert_eq!(rows[0].path, "/v1.0/users/{id}/messages");
        assert_eq!(rows[0].count, 42);
        assert_eq!(rows[0].last_seen.as_deref(), Some("2026-06-01T00:00:00Z"));

        // A schema missing an expected column yields no rows, never a panic.
        let missing = LogsQueryTable {
            name: "PrimaryResult".into(),
            columns: vec![LogsQueryColumn {
                name: "Other".into(),
            }],
            rows: vec![vec![serde_json::json!(1)]],
        };
        assert!(usage_rows(&missing).is_empty());
    }
}
