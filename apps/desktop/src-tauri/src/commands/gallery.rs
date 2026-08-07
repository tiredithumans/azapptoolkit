//! The **application gallery**: Microsoft's global catalog of pre-integrated
//! app templates, plus the corpus cache and ranker behind the "add from gallery"
//! picker.
//!
//! Split out of `enterprise_application.rs`, which had grown to 20 Tauri
//! commands across two unrelated subsystems — service-principal CRUD /
//! assignment / membership on one side, and this on the other. Nothing here
//! touches a service principal: the gallery is a read-only global catalog with
//! its own cache key, its own ranking rules, and exactly one mutation
//! (`create_gallery_application`, which instantiates a template). The only
//! shared surface is `AppState`.

use std::sync::Arc;

use tauri::State;

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::ApplicationTemplate;

use crate::commands::applications::invalidate_app_lists;
use crate::dto::UiError;
use crate::dto::enterprise_application::{
    ApplicationTemplateDto, GalleryAppSummary, GallerySearchResultsDto,
};
use crate::state::AppState;

/// Display cap on gallery matches returned to the picker. The corpus is the
/// whole gallery (~3k templates), so a broad query ("a") can match hundreds;
/// the response carries `total_matches`/`truncated` so the UI says results were
/// narrowed instead of silently showing a subset.
const GALLERY_TOP: usize = 50;

/// Minimum query length, in **characters**. Deliberately not `str::len()`:
/// that counts bytes, so a single-character CJK query (3 bytes) would slip past
/// a gate the UI labels "2+ characters".
const GALLERY_MIN_QUERY_CHARS: usize = 2;

/// Cache key for the whole-gallery corpus — the ranker's in-memory haystack,
/// fetched once and reused across every keystroke. Tenant-scoped by the
/// universal `{tenant_id}|…` convention even though the gallery is Microsoft's
/// global catalog and not tenant data — so the sign-out prefix sweep collects
/// it like everything else. Rides `CacheKind::Lists` (60-min TTL); no mutation
/// in this app can change the gallery, so no invalidation path needs to name it,
/// and the LRU bounds it to one entry per tenant.
fn gallery_corpus_key(tenant_id: &str) -> String {
    format!("{tenant_id}|gallery_corpus")
}

/// One pre-lowercased gallery row: the DTO the picker renders plus the
/// lowercased haystacks, computed once at corpus-build time rather than on
/// every keystroke.
struct GalleryRow {
    dto: ApplicationTemplateDto,
    name_lc: String,
    publisher_lc: String,
}

/// Maps one fetched template into the ranker's row shape, lowercasing the
/// haystacks once.
fn gallery_row(t: ApplicationTemplate) -> GalleryRow {
    // A gallery template with no `displayName` is rare but real. The
    // previous code dropped it silently, shrinking results for reasons
    // invisible to the operator; fall back to the publisher, then the
    // id, so the row stays findable and pickable (the confirm stage
    // lets the operator rename it anyway).
    let display_name = t
        .display_name
        .filter(|n| !n.trim().is_empty())
        .or_else(|| t.publisher.clone())
        .unwrap_or_else(|| t.id.clone());
    let publisher_lc = t.publisher.as_deref().unwrap_or_default().to_lowercase();
    GalleryRow {
        name_lc: display_name.to_lowercase(),
        publisher_lc,
        dto: ApplicationTemplateDto {
            id: t.id,
            display_name,
            publisher: t.publisher,
            description: t.description,
            categories: t.categories,
            logo_url: t.logo_url,
            supported_single_sign_on_modes: t.supported_single_sign_on_modes,
        },
    }
}

/// Loads the whole gallery corpus for `tenant_id` — from the typed cache when
/// warm, otherwise fetching the entire catalog once
/// ([`GraphClient::list_all_application_templates`]), pre-lowercasing every row,
/// and caching the `Arc<Vec<GalleryRow>>` for reuse.
///
/// This is what makes the picker fast: the gallery is a static, tenant-
/// independent catalog, so one fetch backs every subsequent keystroke's match
/// **in memory** instead of a non-indexable `contains(tolower(…))` server scan
/// per query (the old per-keystroke round trip that made this "really slow").
/// The lowercasing happens here, once per corpus load — not per search.
async fn load_gallery_corpus(
    state: &AppState,
    tenant_id: &str,
) -> Result<Arc<Vec<GalleryRow>>, UiError> {
    let key = gallery_corpus_key(tenant_id);
    if let Some(hit) = state
        .cache
        .get_typed::<Vec<GalleryRow>>(CacheKind::Lists, &key)
    {
        return Ok(hit);
    }
    // Single-flight. The dialog fires `prefetch_application_gallery` on open
    // while the first debounced keystroke calls in here too; without the gate
    // both miss and both fetch the whole ~39 000-row catalog, so the prewarm
    // *doubled* the very cost it exists to hide.
    let gate = state.single_flight(&key);
    let _held = gate.lock().await;
    // Re-check: the fetch we were queued behind has already populated the cache.
    if let Some(hit) = state
        .cache
        .get_typed::<Vec<GalleryRow>>(CacheKind::Lists, &key)
    {
        return Ok(hit);
    }
    let templates = state
        .graph_for(tenant_id)
        .list_all_application_templates()
        .await?;
    tracing::debug!(templates = templates.len(), "gallery corpus fetched");
    let rows: Arc<Vec<GalleryRow>> = Arc::new(templates.into_iter().map(gallery_row).collect());
    // Pinned: the catalog is tens of thousands of rows and one fetch backs every
    // subsequent keystroke.
    //
    // Deliberately the UNGUARDED `put_typed_index`, and the only one left in the
    // tree: the store-after-invalidate race this codebase guards everywhere else
    // needs an invalidation to race, and nothing invalidates this key. The
    // gallery is a static, tenant-INDEPENDENT Microsoft catalog that no mutation
    // in this app can change, so there is no window in which a fetched snapshot
    // could go stale mid-flight. `repo_invariants::
    // pinned_index_writes_are_guarded_except_the_static_gallery_corpus` encodes
    // that exemption by name — if this ever becomes tenant-scoped or
    // invalidatable, move it onto `put_typed_index_if_current` and drop the
    // allowlist entry.
    state
        .cache
        .put_typed_index(CacheKind::Lists, key, Arc::clone(&rows));
    Ok(rows)
}

/// Warms the gallery corpus cache for `tenant_id` without ranking anything — the
/// "Browse the gallery" dialog fires this on open (fire-and-forget) so the
/// one-time full-catalog fetch overlaps the operator typing their first query,
/// leaving the first real search warm. Idempotent: a no-op once the corpus is
/// cached. Best-effort — a failure here just means the first search pays the
/// fetch itself.
#[tauri::command]
pub async fn prefetch_application_gallery(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<(), UiError> {
    load_gallery_corpus(&state, &tenant_id).await.map(|_| ())
}

/// Searches the Entra application gallery for the "Browse the gallery" picker in
/// the New-application flow, matching **anywhere** in the template's display name
/// or publisher and ranking the hits (exact → prefix → word-boundary →
/// substring), capped at [`GALLERY_TOP`] for display.
///
/// The match runs **locally** over the whole gallery, fetched once and cached by
/// [`load_gallery_corpus`]: the catalog is tens of thousands of static, tenant-
/// independent rows, so one fetch beats a non-indexable `contains(tolower(…))`
/// server scan on every keystroke. `total_matches`/`truncated` are exact — they
/// count the full corpus, not a capped fetch pool — so "showing the closest 50
/// of N" is honest.
///
/// A query under [`GALLERY_MIN_QUERY_CHARS`] returns nothing without a fetch.
/// Errors propagate: a failed corpus fetch must surface as an error, not as an
/// empty result set that reads as "no such app".
#[tauri::command]
pub async fn search_application_templates(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<GallerySearchResultsDto, UiError> {
    let trimmed = query.trim();
    if trimmed.chars().count() < GALLERY_MIN_QUERY_CHARS {
        return Ok(GallerySearchResultsDto::default());
    }
    let corpus = load_gallery_corpus(&state, &tenant_id).await?;
    // The corpus holds the whole catalog, so the counts are exact and the
    // catalog is never partial (a short fetch is an `Err`, not a partial `Ok`).
    Ok(rank_gallery(&corpus, trimmed, false))
}

/// Ranks `rows` against `query` and packages the best [`GALLERY_TOP`] with the
/// counts the picker renders. Split out from the command (which needs a tenant
/// and a live `AppState`) so the ranking, the cap, and the truncation signal are
/// unit-testable — the counts are shown to operators verbatim, so "showing the
/// closest 50 of 200" being wrong is a user-visible lie.
fn rank_gallery(
    rows: &[GalleryRow],
    query: &str,
    partial_catalog: bool,
) -> GallerySearchResultsDto {
    let needle = query.trim().to_lowercase();
    let tokens: Vec<&str> = needle.split_whitespace().collect();

    let mut hits: Vec<(u8, &GalleryRow)> = rows
        .iter()
        .filter_map(|row| {
            gallery_relevance(&needle, &tokens, &row.name_lc, &row.publisher_lc).map(|r| (r, row))
        })
        .collect();
    // Rank, then name, then id — a total order, so equal-ranked rows don't
    // reshuffle between identical queries.
    hits.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.name_lc.cmp(&b.1.name_lc))
            .then_with(|| a.1.dto.id.cmp(&b.1.dto.id))
    });

    let total_matches = hits.len();
    GallerySearchResultsDto {
        results: hits
            .iter()
            .take(GALLERY_TOP)
            .map(|(_, row)| row.dto.clone())
            .collect(),
        total_matches,
        truncated: total_matches > GALLERY_TOP,
        partial_catalog,
    }
}

/// Relevance rank for a gallery match (lower = better), or `None` when the
/// query doesn't match at all.
///
/// Two independent decisions. **Whether** a row matches: every whitespace-
/// separated token must appear somewhere in the name or publisher — AND, not
/// OR, so "office 365" doesn't drag in every app containing "365", while
/// "teams microsoft" still finds "Microsoft Teams" despite the word order.
/// **How well** it matches: the tier is set by how the whole query sits in the
/// name — exact, name prefix, word-boundary, substring anywhere — with a
/// publisher-only/token-only match ranking last.
///
/// All inputs are pre-lowercased (the needle by the caller, the fields at
/// corpus-build time), so this only compares — no per-call allocation.
fn gallery_relevance(
    needle: &str,
    tokens: &[&str],
    name_lc: &str,
    publisher_lc: &str,
) -> Option<u8> {
    if !tokens
        .iter()
        .all(|t| name_lc.contains(t) || publisher_lc.contains(t))
    {
        return None;
    }
    if name_lc == needle {
        Some(0)
    } else if name_lc.starts_with(needle) {
        Some(1)
    } else if starts_word(name_lc, needle) {
        Some(2)
    } else if name_lc.contains(needle) {
        Some(3)
    } else {
        // Matched only via the publisher and/or individually-placed tokens.
        Some(4)
    }
}

/// True when `needle` starts a word inside `hay` (both lowercased) — the tier
/// that floats "Microsoft Teams" for "teams" above a mid-word coincidence like
/// "Steamship". `match_indices` yields char-boundary byte offsets, so slicing
/// at one is safe for non-ASCII names.
fn starts_word(hay: &str, needle: &str) -> bool {
    hay.match_indices(needle).any(|(i, _)| {
        hay[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Creates an enterprise application from a gallery template by instantiating it
/// (`applicationTemplates/{id}/instantiate`) — one call that provisions the app +
/// service principal preconfigured for that gallery app. SSO is then finished on
/// the app's SSO tab (the template seeds the metadata). Reuses the same
/// `Application.ReadWrite.All` write scope as the custom SSO create; busts the app
/// lists on success so the new SP appears.
#[tauri::command]
pub async fn create_gallery_application(
    state: State<'_, AppState>,
    tenant_id: String,
    template_id: String,
    display_name: String,
) -> Result<GalleryAppSummary, UiError> {
    let name = display_name.trim();
    if name.is_empty() {
        return Err(UiError::validation(
            "invalid_display_name",
            "Enter a name for the application.",
        ));
    }
    let client = state.graph_for(&tenant_id);
    let pair = client
        .instantiate_application_template(&template_id, name)
        .await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(GalleryAppSummary {
        object_id: pair.application.id,
        service_principal_id: pair.service_principal.id,
        app_id: pair.application.app_id,
        display_name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// `gallery_relevance` with the tokenization the command does, so the tests
    /// exercise the same entry point a keystroke does.
    fn rank(query: &str, name: &str, publisher: &str) -> Option<u8> {
        let needle = query.trim().to_lowercase();
        let tokens: Vec<&str> = needle.split_whitespace().collect();
        let (name_lc, pub_lc) = (name.to_lowercase(), publisher.to_lowercase());
        gallery_relevance(&needle, &tokens, &name_lc, &pub_lc)
    }

    #[test]
    fn gallery_matches_substring_anywhere() {
        // THE regression. Every one of these was unreachable under the old
        // server-side `startswith(displayName,…)` filter, which is exactly what
        // "search doesn't return apps that should be there" looked like.
        assert!(rank("force", "Salesforce", "Salesforce.com").is_some());
        assert!(rank("365", "Office 365", "Microsoft").is_some());
        assert!(rank("now", "ServiceNow", "ServiceNow").is_some());
        // Non-matches must still be rejected — substring matching isn't a
        // licence to return the whole gallery.
        assert!(rank("zzz", "Salesforce", "Salesforce.com").is_none());
    }

    #[test]
    fn gallery_ranks_exact_then_prefix_then_word_then_substring() {
        assert_eq!(rank("salesforce", "Salesforce", ""), Some(0)); // exact
        assert_eq!(rank("sales", "Salesforce", ""), Some(1)); // name prefix
        assert_eq!(rank("teams", "Microsoft Teams", ""), Some(2)); // word start
        assert_eq!(rank("force", "Salesforce", ""), Some(3)); // mid-word
        // Publisher-only matches rank last, but still surface: an operator
        // searching a vendor name should find that vendor's apps.
        assert_eq!(rank("okta", "Single Sign-On", "Okta Inc"), Some(4));
    }

    #[test]
    fn gallery_word_boundary_beats_mid_word_coincidence() {
        // "Microsoft Teams" must outrank "Steamship" for "teams" — the reason
        // `starts_word` exists as a tier between prefix and substring.
        let teams = rank("teams", "Microsoft Teams", "Microsoft").unwrap();
        let steam = rank("teams", "Steamship Co", "Steamship").unwrap();
        assert!(teams < steam, "word-boundary {teams} should beat {steam}");
    }

    #[test]
    fn gallery_requires_every_token_to_match() {
        // Tokens are ANDed, so word order doesn't matter...
        assert!(rank("teams microsoft", "Microsoft Teams", "Microsoft").is_some());
        // ...but a query with an unmatched token is not a hit. Were tokens ORed,
        // "office 365" would drag in every unrelated app containing "365".
        assert!(rank("office 365", "Dynamics 365", "Microsoft").is_none());
        assert!(rank("office 365", "Office 365", "Microsoft").is_some());
    }

    #[test]
    fn gallery_matching_is_case_insensitive() {
        assert!(rank("SALESFORCE", "salesforce", "").is_some());
        assert!(rank("sAlEs", "Salesforce", "").is_some());
    }

    /// A candidate row, built the way `gallery_row` builds one.
    fn grow(id: &str, name: &str, publisher: &str) -> GalleryRow {
        GalleryRow {
            name_lc: name.to_lowercase(),
            publisher_lc: publisher.to_lowercase(),
            dto: ApplicationTemplateDto {
                id: id.to_string(),
                display_name: name.to_string(),
                publisher: Some(publisher.to_string()),
                description: None,
                categories: Vec::new(),
                logo_url: None,
                supported_single_sign_on_modes: Vec::new(),
            },
        }
    }

    #[test]
    fn rank_gallery_orders_by_relevance_not_alphabetically() {
        let rows = vec![
            grow("t1", "Zoom", "Zoom Video"),
            grow("t2", "Salesforce Sandbox", "Salesforce.com"),
            grow("t3", "Salesforce", "Salesforce.com"),
        ];
        let out = rank_gallery(&rows, "salesforce", false);

        // Both Salesforce rows surface and the exact match leads. The old path
        // ordered by `$orderby=displayName`, which would have put "Salesforce
        // Sandbox" first; relevance ranking is the point.
        assert_eq!(out.total_matches, 2);
        assert_eq!(out.results[0].display_name, "Salesforce");
        assert_eq!(out.results[1].display_name, "Salesforce Sandbox");
        assert!(!out.truncated);
        assert!(!out.partial_catalog);
    }

    #[test]
    fn rank_gallery_finds_by_mid_word_and_by_publisher() {
        let rows = vec![
            grow("t1", "Salesforce", "Salesforce.com"),
            grow("t2", "Widget", "Okta Inc"),
        ];
        // Mid-word: unreachable under the old prefix filter.
        assert_eq!(rank_gallery(&rows, "force", false).total_matches, 1);
        // Publisher-only: an operator searching a vendor finds its apps.
        let by_pub = rank_gallery(&rows, "okta", false);
        assert_eq!(by_pub.total_matches, 1);
        assert_eq!(by_pub.results[0].display_name, "Widget");
    }

    #[test]
    fn rank_gallery_caps_results_and_reports_the_true_total() {
        // More matches than the display cap: the picker must be told the real
        // total, or "showing the closest N of M" prints a wrong M.
        let rows: Vec<GalleryRow> = (0..GALLERY_TOP + 7)
            .map(|i| grow(&format!("t{i}"), &format!("Contoso App {i:03}"), "Contoso"))
            .collect();
        let out = rank_gallery(&rows, "contoso", false);

        assert_eq!(out.results.len(), GALLERY_TOP, "results are capped");
        assert_eq!(
            out.total_matches,
            GALLERY_TOP + 7,
            "the total counts every match, before the cap"
        );
        assert!(out.truncated);
    }

    #[test]
    fn rank_gallery_reports_no_matches_without_claiming_truncation() {
        let rows = vec![grow("t1", "Salesforce", "Salesforce.com")];
        let out = rank_gallery(&rows, "nonesuch", false);
        assert!(out.results.is_empty());
        assert_eq!(out.total_matches, 0);
        assert!(!out.truncated);
    }

    #[test]
    fn rank_gallery_propagates_partial_catalog() {
        // A partial catalog must ride along even on a hit, so an operator who
        // can't find their app learns the gallery was only partly loaded.
        let rows = vec![grow("t1", "Salesforce", "Salesforce.com")];
        assert!(rank_gallery(&rows, "sales", true).partial_catalog);
    }

    #[test]
    fn gallery_min_query_length_counts_chars_not_bytes() {
        // The gate the UI labels "2+ characters". A single CJK char is 3 bytes,
        // so a byte-length gate would wave it through; a 2-char one must pass.
        assert_eq!("微".len(), 3, "premise: one char, three bytes");
        assert!("微".chars().count() < GALLERY_MIN_QUERY_CHARS);
        assert!("微软".chars().count() >= GALLERY_MIN_QUERY_CHARS);
    }
}
