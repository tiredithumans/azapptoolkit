//! Transport core for the Exchange Online Admin API: the `CmdletInput`
//! envelope POST with its diagnostics-header capture (the bodyless-403
//! semantics live here), and the shared result projections. Retries go through
//! `azapptoolkit_core::http_retry::with_retries`, with the `RetryClass` taken
//! from the cmdlet verb (`retry_class_for`) — every call is a POST, so the
//! HTTP method says nothing about whether a replay is safe.

use std::fmt::Write;

use azapptoolkit_core::net::{redacted_host, same_origin};
use azapptoolkit_core::token::TokenError;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::json;

use azapptoolkit_core::http_error::{describe_error_chain, sanitize_error_body};
use azapptoolkit_core::http_retry::{
    Attempt, RetryClass, RetryReason, parse_retry_after_seconds, with_retries,
};

use super::{ADMIN_API_VERSION, ExchangeClient, INVOKE_ENDPOINT, X_ANCHOR_MAILBOX};
use crate::error::{ExchangeError, Result, is_not_found_body};

/// Upper bound on pages followed for one cmdlet, as a runaway guard rather than
/// a coverage limit: the admin API returns up to 1000 entries per page, so this
/// covers 200 000 objects. Hitting it is surfaced as an error — never a short
/// list — because every caller of a collection read here feeds a scoping
/// decision that is only sound on a complete set.
const MAX_PAGES: usize = 200;

impl ExchangeClient {
    /// POSTs a `CmdletInput` envelope and returns the parsed `value` array,
    /// following `@odata.nextLink` until the collection is exhausted.
    ///
    /// **Paging is not optional here.** The admin API caps a response at 1000
    /// entries by default and signals more with `@odata.nextLink`; this used to
    /// deserialize `value` alone and drop the link, so every unbounded read
    /// (group members, management scopes, service principals) silently returned
    /// a first page indistinguishable from a complete collection. The
    /// consolidation planner's "unverified == 0" check and the reverse
    /// "which scopes reference this group" lookup both treat a short list as
    /// proof of absence, so a truncated read widens access rather than failing.
    ///
    /// Continuation is a POST to the `@odata.nextLink` URL with the *same* body
    /// and headers (not a GET, unlike Microsoft Graph), and the link is only
    /// valid for 5-10 minutes — hence no delay between pages. The continuation
    /// contract is the same nextLink / POST-continuation one Microsoft documents
    /// for the v2.0 Admin API; see
    /// <https://learn.microsoft.com/exchange/reference/admin-api-get-started#pagination>.
    pub(crate) async fn invoke_command(
        &self,
        cmdlet: &str,
        parameters: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "{}/adminapi/{}/{}/{}",
            self.base_url.trim_end_matches('/'),
            ADMIN_API_VERSION,
            self.tenant_id,
            INVOKE_ENDPOINT
        );
        let body = json!({
            "CmdletInput": { "CmdletName": cmdlet, "Parameters": parameters }
        });
        #[derive(serde::Deserialize)]
        struct Envelope {
            #[serde(default)]
            value: Vec<serde_json::Value>,
            #[serde(rename = "@odata.nextLink")]
            next_link: Option<String>,
        }

        let mut out: Vec<serde_json::Value> = Vec::new();
        let mut target = url;
        for page in 1..=MAX_PAGES {
            let bytes = match self.send_core(cmdlet, &target, &body).await {
                Ok(bytes) => bytes,
                // A "not found" while following an `@odata.nextLink` is not
                // "this object does not exist" — pages of it have already been
                // read. Reclassifying it is what stops `invoke_optional` mapping
                // a mid-pagination `NotFound` to an empty collection, which every
                // caller reads as proof of absence. A short list widens access
                // on the consolidation and reverse-scope paths, so this must
                // fail rather than truncate.
                //
                // Only the not-found shapes are reclassified (the exact two
                // `invoke_optional` swallows). Every other error already stops
                // a truncated `Ok`, and must keep its class: a `Token` carrying
                // a re-auth-fatal code is what halts a fan-out on a dead
                // session, and a 401/403 drives the audit's Exchange breaker and
                // the sign-in / role guidance in `ui_hint`.
                Err(err) if page > 1 && err.is_missing_object() => {
                    return Err(ExchangeError::Protocol(format!(
                        "{cmdlet} failed on page {page} while following @odata.nextLink \
                         ({err}); refusing to return a truncated collection"
                    )));
                }
                Err(err) => return Err(err),
            };
            if bytes.is_empty() {
                if page > 1 {
                    // The previous page promised a continuation, so an empty
                    // body here is a broken response, not the end of the
                    // collection.
                    return Err(ExchangeError::Protocol(format!(
                        "{cmdlet} returned an empty body for page {page} after an \
                         @odata.nextLink; refusing to return a truncated collection"
                    )));
                }
                return Ok(out);
            }
            let env: Envelope = serde_json::from_slice(&bytes)
                .map_err(|e| ExchangeError::Deserialize(e.to_string()))?;
            out.extend(env.value);
            match env.next_link.as_deref().map(str::trim) {
                Some(link) if !link.is_empty() => {
                    // A paging `nextLink` is attacker-influenced server output,
                    // so it never carries the Exchange admin bearer to another
                    // host. Graph enforces this at four sites, ARM at one and
                    // Key Vault at one; this client was the gap — `net.rs`'s own
                    // doc header listed only "(Graph, Key Vault, ARM)", which is
                    // how it stayed invisible.
                    if !same_origin(&self.base_url, link) {
                        return Err(ExchangeError::Protocol(format!(
                            "{cmdlet} returned an @odata.nextLink on a different origin \
                             (host: {}); refusing to follow it",
                            redacted_host(link)
                        )));
                    }
                    tracing::debug!(cmdlet, page, "following @odata.nextLink");
                    target = link.to_string();
                }
                _ => return Ok(out),
            }
        }
        Err(ExchangeError::Protocol(format!(
            "{cmdlet} returned more than {MAX_PAGES} pages; refusing to return a truncated collection"
        )))
    }

    /// Like [`Self::invoke_command`] but maps a "not found" cmdlet error (the
    /// EXO `Get-*` cmdlets throw when an `-Identity` doesn't resolve) to an
    /// empty result, so callers can treat a missing object as `None`.
    ///
    /// Only for a lookup keyed on an `-Identity`/assignee that may not resolve.
    /// Never route an identity-less list-all through this; see
    /// `list_service_principals`. A list-all has no object to be missing, so a
    /// "not found" rejection of it would read as an empty tenant.
    ///
    /// Only a **first-page** `NotFound` can reach these arms:
    /// [`Self::invoke_command`] reclassifies a mid-pagination not-found error as
    /// `Protocol` (other mid-pagination errors keep their own class — they
    /// cannot reach these arms anyway). Without that, a continuation that 404'd
    /// turned a partially read collection into "this object has nothing", which
    /// the consolidation planner and the per-assignee role lookup both read as
    /// proof of absence.
    pub(crate) async fn invoke_optional(
        &self,
        cmdlet: &str,
        parameters: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        match self.invoke_command(cmdlet, parameters).await {
            Ok(values) => Ok(values),
            Err(ExchangeError::NotFound(_)) => Ok(Vec::new()),
            Err(ExchangeError::Api { body, .. }) if is_not_found_body(&body) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    async fn send_core(
        &self,
        cmdlet: &str,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<bytes::Bytes> {
        let bearer = self.token.bearer().await.map_err(ExchangeError::Token)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| ExchangeError::Token(TokenError::opaque(e.to_string())))?,
        );
        headers.insert(
            X_ANCHOR_MAILBOX,
            HeaderValue::from_str(&self.anchor_mailbox)
                .map_err(|e| ExchangeError::Protocol(e.to_string()))?,
        );

        // Retry budget, backoff and `Retry-After` handling all live in
        // `http_retry::with_retries`; this closure only classifies one attempt.
        // `cmdlet` is the label, so the shared "retrying" warning names it.
        with_retries(cmdlet, retry_class_for(cmdlet), |_| {
            let headers = headers.clone();
            async move {
                let resp = match self.http.post(url).headers(headers).json(body).send().await {
                    Ok(r) => r,
                    // No response means no `Retry-After` to honor — the shared
                    // loop falls back to jittered exponential backoff.
                    Err(err) => {
                        return attempt_for(
                            ExchangeError::Network(describe_error_chain(&err)),
                            None,
                            None,
                        );
                    }
                };

                let status = resp.status();
                if status.is_success() {
                    // Terminal even when the body read fails: after a 2xx the
                    // write has committed, so it is never replayed.
                    return Attempt::Done(
                        resp.bytes()
                            .await
                            .map_err(|e| ExchangeError::Network(describe_error_chain(&e))),
                    );
                }

                let retry_after = parse_retry_after_seconds(
                    resp.headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok()),
                );
                // The EXO admin endpoint returns its real authorization reason in
                // the `x-ms-diagnostics` header, not the body (a 403 body is
                // typically a NUL-padded blob). Capture the diagnostic headers so
                // the surfaced error names *why* and *which request*, not just
                // `<no body>`.
                let header_str = |name: &str| {
                    resp.headers()
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                };
                let diagnostics = header_str("x-ms-diagnostics");
                let request_id = header_str("request-id").or_else(|| header_str("x-ms-request-id"));
                // On a bodyless rejection the auth middleware's reason (if any)
                // rides `WWW-Authenticate` — captured for the log line below.
                let www_authenticate = header_str("www-authenticate");
                let raw_body = resp.text().await.unwrap_or_default();
                let body_text = compose_error_detail(
                    cmdlet,
                    &raw_body,
                    diagnostics.as_deref(),
                    request_id.as_deref(),
                );
                let code = status.as_u16();
                // Any non-429 4xx is a terminal client error (401/403/404 get
                // their own variants below; everything else falls through to
                // `Api`).
                let is_client_4xx = (400..500).contains(&code) && code != 429;

                let err = if code == 401 {
                    ExchangeError::Unauthorized
                } else {
                    if is_client_4xx {
                        tracing::warn!(
                            cmdlet,
                            status = code,
                            diagnostics = diagnostics.as_deref().unwrap_or(""),
                            request_id = request_id.as_deref().unwrap_or(""),
                            www_authenticate = www_authenticate.as_deref().unwrap_or(""),
                            "exchange admin cmdlet rejected"
                        );
                    }
                    if code == 403 {
                        // Whether EXO named an RBAC reason (`x-ms-diagnostics`)
                        // vs. a bodyless/reasonless 403 — `ui_hint` branches on
                        // this so a stale role token isn't misreported as a
                        // definite Exchange RBAC gap.
                        let had_diagnostics = diagnostics
                            .as_deref()
                            .map(str::trim)
                            .is_some_and(|d| !d.is_empty());
                        ExchangeError::Forbidden {
                            detail: body_text,
                            had_diagnostics,
                        }
                    } else if code == 404 {
                        ExchangeError::NotFound(body_text)
                    } else if is_client_4xx {
                        ExchangeError::Api {
                            status: code,
                            body: body_text,
                        }
                    } else if code == 429 {
                        ExchangeError::Throttled {
                            retry_after_secs: retry_after,
                        }
                    } else {
                        ExchangeError::Server {
                            status: code,
                            body: body_text,
                        }
                    }
                };
                // 429 and 5xx are retried (an explicit `Retry-After` is waited
                // exactly); every other status is terminal.
                attempt_for(err, retry_after, Some(code))
            }
        })
        .await
    }
}

/// Classifies one failed attempt for [`with_retries`].
///
/// The shared policy decides what is transient: `is_retryable()` is
/// `http_retry::is_retryable_code(ui_code())`, not a status list re-derived
/// here. A throttle is the one reason every cmdlet may replay (the service
/// refused before doing the work); anything else transient is replayed only
/// for an idempotent cmdlet — see [`retry_class_for`]. `status` is `None` for a
/// failure with no response (a network error).
fn attempt_for(
    err: ExchangeError,
    retry_after_secs: Option<u64>,
    status: Option<u16>,
) -> Attempt<bytes::Bytes, ExchangeError> {
    if !err.is_retryable() {
        return Attempt::Done(Err(err));
    }
    let reason = if matches!(err, ExchangeError::Throttled { .. }) {
        RetryReason::Throttled
    } else {
        RetryReason::Transient
    };
    Attempt::Retry {
        reason,
        status,
        retry_after_secs,
        err,
    }
}

/// The retry class for an Exchange cmdlet.
///
/// Every Exchange call is a POST to `InvokeCommand`, so — unlike Graph, ARM and
/// Key Vault — the HTTP method says nothing; the class comes from the cmdlet's
/// verb. A paging continuation re-sends the same envelope, so it inherits the
/// class of the cmdlet it continues.
///
/// Exchange objects are name-keyed, so replaying a write that already
/// committed does not double it: it **fails**, and that false failure is the
/// harm. A replayed `New-ManagementRoleAssignment` after a 502 fails as a
/// duplicate, the scoped-grant path reports "failed to assign" and keeps the
/// org-wide grant ("scoping is NOT effective") although the scoped role landed;
/// a replayed `Remove-ApplicationAccessPolicy` fails as not-found and the AAP
/// migration reports "partial" although the policy is gone. So only reads —
/// and the two membership mutators, whose "already a member" / "not a member"
/// replies `groups.rs` already treats as success — are replayed after a server
/// or network error. Every other verb, and any unknown one, is
/// [`RetryClass::NonIdempotent`]: only a throttle is replayed.
fn retry_class_for(cmdlet: &str) -> RetryClass {
    const READ_VERBS: [&str; 3] = ["Get-", "Test-", "Search-"];
    // A replay is harmless: `add_group_member` / `remove_group_member`
    // (groups.rs) swallow the already-a-member / not-a-member reply.
    const REPLAY_SAFE_WRITES: [&str; 2] = [
        "Add-DistributionGroupMember",
        "Remove-DistributionGroupMember",
    ];
    if READ_VERBS.iter().any(|verb| cmdlet.starts_with(verb))
        || REPLAY_SAFE_WRITES.contains(&cmdlet)
    {
        RetryClass::Idempotent
    } else {
        RetryClass::NonIdempotent
    }
}

/// Builds the human-readable detail stored in a client/server `ExchangeError`.
/// EXO puts the real authorization reason in `x-ms-diagnostics` rather than the
/// (often NUL-padded, empty) response body, so prefer the diagnostics header and
/// fall back to the body, both through the shared
/// `azapptoolkit_core::http_error::sanitize_error_body`. The detail is prefixed
/// with the originating `cmdlet` and suffixed with the `request-id` (when
/// present) so a 403 names both *why* and *which request* instead of the old
/// opaque `<no body>`.
fn compose_error_detail(
    cmdlet: &str,
    raw_body: &str,
    diagnostics: Option<&str>,
    request_id: Option<&str>,
) -> String {
    let reason = match diagnostics.map(str::trim) {
        Some(d) if !d.is_empty() => sanitize_error_body(d),
        _ => sanitize_error_body(raw_body),
    };
    let mut out = format!("[{cmdlet}] {reason}");
    if let Some(id) = request_id.map(str::trim)
        && !id.is_empty()
    {
        let _ = write!(out, " (request-id: {id})");
    }
    out
}

/// Projects the single object a `New-*`/`Test-*` cmdlet must return. An empty
/// `value` array is a broken-contract response, not an HTTP failure — surfaced
/// as [`ExchangeError::Protocol`] (it used to fabricate `Api { status: 200 }`,
/// which anything reasoning about HTTP status would misread).
pub(crate) fn first_as<T: DeserializeOwned>(
    values: Vec<serde_json::Value>,
    cmdlet: &str,
) -> Result<T> {
    let v = values
        .into_iter()
        .next()
        .ok_or_else(|| ExchangeError::Protocol(format!("{cmdlet} returned no object")))?;
    serde_json::from_value(v).map_err(|e| ExchangeError::Deserialize(e.to_string()))
}

/// Projects the first returned object to `T`, or `None` when the cmdlet
/// returned nothing — the shared tail of every optional `Get-*` lookup
/// (paired with [`ExchangeClient::invoke_optional`]).
pub(crate) fn first_optional_as<T: DeserializeOwned>(
    values: Vec<serde_json::Value>,
) -> Result<Option<T>> {
    values
        .into_iter()
        .next()
        .map(|v| serde_json::from_value(v).map_err(|e| ExchangeError::Deserialize(e.to_string())))
        .transpose()
}

/// Projects every returned object to `T`.
pub(crate) fn all_as<T: DeserializeOwned>(values: Vec<serde_json::Value>) -> Result<Vec<T>> {
    values
        .into_iter()
        .map(|v| serde_json::from_value(v).map_err(|e| ExchangeError::Deserialize(e.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_error_detail_prefers_diagnostics_and_names_cmdlet() {
        // Empty body but a populated x-ms-diagnostics header: the reason comes
        // from the header, the cmdlet is named, and the request id is appended.
        let detail = compose_error_detail(
            "New-ManagementRoleAssignment",
            &"\0".repeat(64),
            Some("2000003;reason=\"role required\""),
            Some("abc-123"),
        );
        assert!(detail.starts_with("[New-ManagementRoleAssignment] "));
        assert!(detail.contains("role required"));
        assert!(detail.contains("(request-id: abc-123)"));
        assert!(!detail.contains("<no body>"));
    }

    #[test]
    fn compose_error_detail_falls_back_to_no_body_when_nothing_present() {
        // No diagnostics and an empty/NUL body: still `<no body>`, but now the
        // failing cmdlet is identified.
        let detail = compose_error_detail("Get-Group", &"\0".repeat(16), None, None);
        assert_eq!(detail, "[Get-Group] <no body>");
    }

    #[test]
    fn retry_class_for_derives_from_the_cmdlet_verb() {
        // Every cmdlet string this crate sends, plus the fail-safe default for
        // an unknown verb: a class this table does not name is a replayed write.
        let table: &[(&str, RetryClass)] = &[
            ("Get-ApplicationAccessPolicy", RetryClass::Idempotent),
            ("Get-DistributionGroup", RetryClass::Idempotent),
            ("Get-DistributionGroupMember", RetryClass::Idempotent),
            ("Get-Group", RetryClass::Idempotent),
            ("Get-ManagementRoleAssignment", RetryClass::Idempotent),
            ("Get-ManagementScope", RetryClass::Idempotent),
            ("Get-ServicePrincipal", RetryClass::Idempotent),
            ("Test-ApplicationAccessPolicy", RetryClass::Idempotent),
            ("Test-ServicePrincipalAuthorization", RetryClass::Idempotent),
            // Membership mutators: groups.rs treats the replay reply as success.
            ("Add-DistributionGroupMember", RetryClass::Idempotent),
            ("Remove-DistributionGroupMember", RetryClass::Idempotent),
            ("New-DistributionGroup", RetryClass::NonIdempotent),
            ("New-ManagementRoleAssignment", RetryClass::NonIdempotent),
            ("New-ManagementScope", RetryClass::NonIdempotent),
            ("New-ServicePrincipal", RetryClass::NonIdempotent),
            ("Remove-ApplicationAccessPolicy", RetryClass::NonIdempotent),
            ("Remove-DistributionGroup", RetryClass::NonIdempotent),
            ("Remove-ManagementRoleAssignment", RetryClass::NonIdempotent),
            ("Set-ManagementScope", RetryClass::NonIdempotent),
            ("Frobnicate-X", RetryClass::NonIdempotent),
            ("", RetryClass::NonIdempotent),
        ];
        for (cmdlet, want) in table {
            assert_eq!(retry_class_for(cmdlet), *want, "{cmdlet:?}");
        }
    }

    #[test]
    fn first_as_reports_empty_result_as_protocol_error() {
        let err = first_as::<serde_json::Value>(Vec::new(), "New-ServicePrincipal").unwrap_err();
        assert!(
            matches!(err, ExchangeError::Protocol(ref m) if m.contains("New-ServicePrincipal")),
            "got {err:?}"
        );
    }
}
