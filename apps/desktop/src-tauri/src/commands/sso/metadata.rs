//! Federation-metadata probing: the public metadata fetch and the small XML
//! scanners that read signing keys out of it.

use std::time::Duration;

use tauri::State;

use crate::commands::guid::is_guid;
use crate::dto::UiError;
use crate::dto::sso::MetadataProbeDto;
use crate::state::AppState;

use super::saml_summary_urls;

/// **Phase 2** — fetches the app's federation metadata and reports the signing
/// certificates Entra publishes for it.
///
/// Unauthenticated GET to the public metadata endpoint (a backend `reqwest`
/// call, so no CSP change — `connect-src` governs the webview only). A transport
/// or parse failure is returned as a populated [`MetadataProbeDto`] with
/// `http_status: None`, never as a command error: "we couldn't check" and "Entra
/// isn't publishing it" must not look the same to the operator.
#[tauri::command]
pub async fn probe_federation_metadata(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<MetadataProbeDto, UiError> {
    // Prove the session before reaching out: this command takes no token, so
    // without it a signed-out window could still drive tenant-shaped requests.
    state.auth.tenant_context(&tenant_id).ok_or_else(|| {
        UiError::validation(
            "not_signed_in",
            format!("not signed in to tenant {tenant_id}"),
        )
    })?;
    // The id lands in the metadata URL's query string; anything but a GUID is
    // not an application (client) id.
    if !is_guid(&app_id) {
        return Err(UiError::validation(
            "invalid_app_id",
            "The application (client) ID must be a GUID.",
        ));
    }
    let (_, _, _, metadata_url) = saml_summary_urls(state.auth.cloud(), &tenant_id, &app_id);
    let fetched_at = chrono::Utc::now().to_rfc3339();

    let response = metadata_http_client().get(&metadata_url).send().await;
    let (status, body) = match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.text().await {
                Ok(body) => (status, Some(body)),
                Err(err) => {
                    return Ok(MetadataProbeDto {
                        fetched_at,
                        error: Some(format!("Could not read the metadata response: {err}")),
                        ..Default::default()
                    });
                }
            }
        }
        Err(err) => {
            return Ok(MetadataProbeDto {
                fetched_at,
                error: Some(format!("Could not reach the metadata endpoint: {err}")),
                ..Default::default()
            });
        }
    };

    let certs = body.as_deref().map(parse_signing_certs).unwrap_or_default();
    let error = (!(200..300).contains(&status))
        .then(|| format!("The metadata endpoint returned HTTP {status}."));
    Ok(MetadataProbeDto {
        fetched_at,
        signing_key_count: certs.len(),
        published_certs: certs,
        http_status: Some(status),
        error,
    })
}

/// Shared `reqwest` client for federation-metadata probes. The endpoint is
/// public and unauthenticated, so this never carries a token — it exists only so
/// repeated probes reuse one connection pool.
fn metadata_http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        // `expect`, not `unwrap_or_default()`: the default client has no
        // timeout at all, so a failed build would silently lose both budgets.
        reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .connect_timeout(azapptoolkit_core::http_retry::CONNECT_TIMEOUT)
            .build()
            .expect("reqwest client builds")
    })
}

/// Extracts the base64 DER bodies of the `<KeyDescriptor use="signing">`
/// certificates from a federation metadata document, deduped and whitespace
/// stripped.
///
/// Scans for the elements directly rather than pulling in an XML parser: the
/// document is a fixed-shape Microsoft-generated file, and the only thing read
/// out of it is a count and a set of opaque base64 bodies. A malformed document
/// yields an empty list, which the caller reports as "0 published" alongside the
/// HTTP status — it never fabricates a match.
///
/// A `KeyDescriptor` with no `use` attribute is signing-capable per the SAML
/// metadata spec, so those count too; an explicit `use="encryption"` does not.
/// True when `local` starts an element open tag at `at`, allowing a namespace
/// prefix (`md:KeyDescriptor`, `ds:X509Certificate`).
///
/// SAML metadata in the wild is namespace-prefixed — Microsoft's own federation
/// metadata is — and matching the bare `<KeyDescriptor` literal returned ZERO
/// certificates for every such document. `probe_federation_metadata` then
/// reported "0 published", indistinguishable from an app that genuinely
/// publishes none.
fn element_open_at(xml: &str, local: &str, at: usize) -> bool {
    if !xml[at..].starts_with(local) {
        return false;
    }
    // The name must END here — otherwise `X509Certificates` would match
    // `X509Certificate`.
    match xml[at + local.len()..].chars().next() {
        Some(c) if c.is_whitespace() || c == '>' || c == '/' => {}
        _ => return false,
    }
    // Walk back over an optional `prefix:` to the `<`.
    let before = &xml[..at];
    if let Some(stripped) = before.strip_suffix('<') {
        return !stripped.ends_with("</");
    }
    let Some(colon) = before.strip_suffix(':') else {
        return false;
    };
    let prefix_start = colon.rfind('<').filter(|lt| {
        colon[lt + 1..]
            .chars()
            .all(|c| c != '>' && !c.is_whitespace())
    });
    match prefix_start {
        Some(lt) => !colon[..lt + 1].ends_with("</") && !colon[lt + 1..].is_empty(),
        None => false,
    }
}

/// Index of the next `<Local`/`<prefix:Local` open tag at or after `from`.
fn find_element_open(xml: &str, local: &str, from: usize) -> Option<usize> {
    let mut i = from;
    while let Some(rel) = xml[i..].find(local) {
        let at = i + rel;
        if element_open_at(xml, local, at) {
            return Some(at);
        }
        i = at + local.len();
    }
    None
}

/// Index of the next `</Local>`/`</prefix:Local>` close tag at or after `from`.
fn find_element_close(xml: &str, local: &str, from: usize) -> Option<usize> {
    let mut i = from;
    while let Some(rel) = xml[i..].find(local) {
        let at = i + rel;
        let before = &xml[..at];
        let closes = before.ends_with("</")
            || before
                .strip_suffix(':')
                .and_then(|c| c.rfind("</").map(|lt| (c, lt)))
                .is_some_and(|(c, lt)| {
                    !c[lt + 2..].is_empty()
                        && c[lt + 2..]
                            .chars()
                            .all(|ch| ch != '>' && !ch.is_whitespace())
                });
        if closes && xml[at + local.len()..].starts_with('>') {
            return Some(at);
        }
        i = at + local.len();
    }
    None
}

pub(crate) fn parse_signing_certs(xml: &str) -> Vec<String> {
    const DESCRIPTOR: &str = "KeyDescriptor";
    const CERT: &str = "X509Certificate";

    // Descriptor boundaries, so a certificate is attributed to the descriptor it
    // actually sits in and an `use="encryption"` block can be skipped whole.
    let mut bounds: Vec<usize> = Vec::new();
    let mut from = 0usize;
    while let Some(at) = find_element_open(xml, DESCRIPTOR, from) {
        bounds.push(at);
        from = at + DESCRIPTOR.len();
    }

    let mut out: Vec<String> = Vec::new();
    for (n, start) in bounds.iter().enumerate() {
        let end = bounds.get(n + 1).copied().unwrap_or(xml.len());
        let block = &xml[*start..end];
        // The attributes run up to the element's own `>`; anything after that
        // belongs to the children.
        let attrs = block.split('>').next().unwrap_or_default();
        if attrs.contains("use=\"encryption\"") || attrs.contains("use='encryption'") {
            continue;
        }
        let mut at = 0usize;
        while let Some(open) = find_element_open(block, CERT, at) {
            let Some(body_start) = block[open..].find('>').map(|i| open + i + 1) else {
                break;
            };
            let Some(close) = find_element_close(block, CERT, body_start) else {
                break;
            };
            // `</` sits two chars before the local name; a prefixed close tag
            // puts the prefix in between, so trim back to the `<`.
            let text_end = block[body_start..close]
                .rfind('<')
                .map_or(close, |i| body_start + i);
            let body: String = block[body_start..text_end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if !body.is_empty() && !out.iter().any(|existing| existing == &body) {
                out.push(body);
            }
            at = close + CERT.len();
        }
    }
    out
}
