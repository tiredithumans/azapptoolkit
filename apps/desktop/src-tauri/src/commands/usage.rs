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
use tauri::State;

use crate::dto::usage::{GraphUsageResult, GraphUsageRow};
use crate::dto::UiError;
use crate::state::AppState;

/// Result-row cap per query — keeps the IPC payload and the panel readable;
/// `truncated` tells the UI when the long tail was cut.
const USAGE_ROW_CAP: usize = 200;
/// Safety cap on workspace table-presence probes per discovery run.
const MAX_WORKSPACES_PROBED: usize = 50;

/// Tenant-prefixed cache key for the discovered workspace (cross-tenant
/// leakage guard, same convention as the list caches).
///
/// **Read-only until TTL / sign-out, by design.** The workspace exporting
/// `MicrosoftGraphActivityLogs` is effectively immutable for a tenant, so no
/// mutation busts this key — it's cleared only by the 60-min `Permissions` TTL
/// and the sign-out tenant sweep (`invalidate_tenant`). If a workspace is
/// re-pointed mid-session, "Clear all" in Cache diagnostics forces re-discovery.
fn workspace_cache_key(tenant_id: &str) -> String {
    format!("{tenant_id}|graph_activity_ws")
}

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
    if let Some(hit) = state
        .cache
        .get::<(String, String)>(CacheKind::Permissions, &workspace_cache_key(tenant_id))
    {
        return Ok(Some(hit));
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
    let mut probed = 0usize;
    for sub in subscriptions {
        let workspaces = match arm
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
                continue;
            }
        };
        for ws in workspaces {
            if probed >= MAX_WORKSPACES_PROBED {
                tracing::warn!(
                    cap = MAX_WORKSPACES_PROBED,
                    "usage: workspace probe cap reached without a hit"
                );
                return Ok(None);
            }
            let Some(customer_id) = ws.properties.customer_id.clone() else {
                continue;
            };
            probed += 1;
            match la
                .query(&customer_id, "MicrosoftGraphActivityLogs | take 1", "P1D")
                .await
            {
                Ok(_) => {
                    let name = ws.name.clone().unwrap_or_else(|| customer_id.clone());
                    let hit = (customer_id, name);
                    state
                        .cache
                        .put(CacheKind::Permissions, workspace_cache_key(tenant_id), &hit);
                    return Ok(Some(hit));
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
    }
    Ok(None)
}

/// KQL summarizing one app's Graph calls by (method, GUID-normalized path),
/// most frequent first. The appId is escaped for the KQL single-quote literal
/// (defense in depth — it's a GUID in practice).
fn usage_kql(app_id: &str) -> String {
    let app = app_id.replace('\'', "''");
    format!(
        "MicrosoftGraphActivityLogs \
         | where AppId == '{app}' \
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
        assert!(kql.contains("AppId == '11111111-2222-3333-4444-555555555555'"));
        assert!(kql.contains("MicrosoftGraphActivityLogs"));
        // A single quote can't break out of the KQL string literal.
        let kql = usage_kql("x' | union evil");
        assert!(kql.contains("AppId == 'x'' | union evil'"));
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
