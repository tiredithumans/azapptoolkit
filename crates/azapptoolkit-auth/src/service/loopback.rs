//! Loopback redirect listener + system-browser launch for the interactive
//! authorization-code flows. The caller (`run_auth_code_flow`) bounds the
//! whole wait with `REDIRECT_WAIT` (300s); nothing here needs its own deadline.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{AuthError, Result};

/// How long one connection may hold the accept loop before it is dropped.
///
/// Generous next to a redirect that arrives in milliseconds, and short next to
/// the caller's 300s sign-in timeout — which is what an idle preconnect used to
/// consume in full.
const PER_CONNECTION_READ_TIMEOUT_SECS: u64 = 5;

/// Waits on `listener` for the browser's OAuth redirect and extracts the
/// authorization code (validating the CSRF `state` against `expected_state`).
///
/// Robustness over a bare accept-and-read: browsers open speculative
/// ("preconnect") sockets and fire stray requests (`/favicon.ico`) at loopback
/// servers — with a single `accept()`, one consumes the slot and the real
/// redirect is lost until the caller's timeout ("sign-in hangs"). So this
/// loops: a connection that closes without sending, or whose request carries
/// none of `code`/`state`/`error`, or that is not a `GET` (a CORS/PNA
/// `OPTIONS` preflight), gets a 404 and the listener keeps waiting.
///
/// Only a redirect carrying the pending `state` ends the wait. Any local
/// process — or any web page via a blind cross-origin request — can reach the
/// ephemeral port, so a request whose `state` is missing or foreign (including
/// a bare `error=`) is answered 400 with a neutral page, logged at warn, and
/// ignored: it can neither abort the sign-in nor choose the error text the app
/// shows. Deliberate consequence: a genuinely mismatched redirect no longer
/// fails fast as [`AuthError::StateMismatch`]; it waits out the caller's
/// `REDIRECT_WAIT` and surfaces as [`AuthError::Cancelled`]. The browser page
/// is written only after `state` validates, and says what is true at that
/// point (the code exchange still follows).
pub(super) async fn listen_for_code(listener: TcpListener, expected_state: &str) -> Result<String> {
    loop {
        let (mut socket, _peer) = listener
            .accept()
            .await
            .map_err(|e| AuthError::Loopback(e.to_string()))?;

        // Each connection is bounded INDEPENDENTLY, not just the batch.
        //
        // The accept loop reads one connection to completion before accepting
        // the next, and `read_request_head` returns only on EOF, a complete
        // head, or 16 KiB. That covered a preconnect that *closes*; it did not
        // cover one that stays open idle — which is what browsers actually do,
        // holding speculative sockets in the pool for seconds. The browser
        // opens an idle socket, sends the redirect on a second one, and this
        // loop sits parked on the first until the caller's 300s timeout fires:
        // sign-in hangs after a successful consent.
        let read = tokio::time::timeout(
            Duration::from_secs(PER_CONNECTION_READ_TIMEOUT_SECS),
            read_request_head(&mut socket),
        )
        .await;
        // A silent or stalled peer is dropped and we go back to `accept()`.
        let Ok(Ok(request)) = read else {
            continue;
        };

        let first_line = request.lines().next().unwrap_or_default();
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        let query = path.split('?').nth(1).unwrap_or("");
        let mut code: Option<String> = None;
        let mut state: Option<String> = None;
        let mut error: Option<String> = None;
        let mut error_subcode: Option<String> = None;
        let mut error_description: Option<String> = None;
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                "error_subcode" => error_subcode = Some(v.into_owned()),
                "error_description" => error_description = Some(v.into_owned()),
                _ => {}
            }
        }

        // Not the OAuth redirect (favicon probe, unrelated request, a CORS/PNA
        // preflight): answer and keep waiting for the real one.
        if method != "GET" || (code.is_none() && state.is_none() && error.is_none()) {
            respond(&mut socket, "404 Not Found", "").await;
            continue;
        }

        // A request that does not carry the pending `state` is not our
        // redirect, whatever else it claims: ignore it rather than let it end
        // the wait. Never log the values — only which parameters were present.
        if state.as_deref() != Some(expected_state) {
            tracing::warn!(
                target: "auth",
                has_code = code.is_some(),
                has_error = error.is_some(),
                "ignoring a loopback request whose state does not match the pending sign-in"
            );
            respond(
                &mut socket,
                "400 Bad Request",
                "<html><body><h2>This request doesn't match a pending azapptoolkit sign-in.</h2><p>You can close this window.</p></body></html>",
            )
            .await;
            continue;
        }

        let outcome = match (error, code) {
            (Some(err), _) => Err(redirect_error(
                &err,
                error_subcode.as_deref(),
                error_description.as_deref(),
            )),
            (None, Some(code)) => Ok(code),
            (None, None) => Err(AuthError::Authorization("no code returned".into())),
        };
        let body = if outcome.is_ok() {
            "<html><body><h2>azapptoolkit received your sign-in.</h2><p>You can close this window and return to the app.</p></body></html>"
        } else {
            "<html><body><h2>Sign-in failed.</h2><p>You can close this window.</p></body></html>"
        };
        respond(&mut socket, "200 OK", body).await;
        return outcome;
    }
}

/// Writes one complete `Connection: close` response and shuts the socket down.
/// Best effort: the browser may already have gone, which changes nothing here.
async fn respond(socket: &mut TcpStream, status: &str, body: &str) {
    let content_type = if body.is_empty() {
        ""
    } else {
        "Content-Type: text/html; charset=utf-8\r\n"
    };
    let response = format!(
        "HTTP/1.1 {status}\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.shutdown().await;
}

/// The [`AuthError`] for an `error=` redirect whose `state` matched. A user
/// cancel is [`AuthError::Cancelled`]; anything else keeps the OAuth error code
/// and the AADSTS code from `error_description` (redacted exactly like a
/// `/token` error, so the sign-in card's AADSTS hint fires). The error value is
/// gated to `[a-z_]{1,64}` — every OAuth/Entra code has that shape, so a new
/// code still passes, while anything else is never echoed into the UI.
fn redirect_error(error: &str, subcode: Option<&str>, description: Option<&str>) -> AuthError {
    if is_user_cancel(error, subcode, description) {
        return AuthError::Cancelled;
    }
    let well_formed = (1..=64).contains(&error.len())
        && error.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    let gated = if well_formed {
        error
    } else {
        "unrecognized_error"
    };
    AuthError::Authorization(super::wire::redact_aad_error(gated, description))
}

/// Whether an `error=` redirect is the operator walking away at Entra rather
/// than a refusal. Entra reports a cancel as `access_denied` with MSAL's
/// `error_subcode=cancel`, or (Learn's example) with a plain-prose
/// `error_description` that carries no AADSTS code. A coded `access_denied`
/// (e.g. AADSTS65004 "user declined consent") stays an authorization error —
/// the sign-in hints already read it as a decline.
fn is_user_cancel(error: &str, subcode: Option<&str>, description: Option<&str>) -> bool {
    error == "access_denied"
        && (subcode == Some("cancel")
            || description.is_some_and(|d| super::wire::extract_aadsts_code(d).is_none()))
}

/// Reads until the end of the request head (`\r\n\r\n`) or EOF, capped at
/// 16 KiB. The redirect's query string arrives in the request line, so a
/// complete head is all the parsing above needs — the old single-`read()`
/// assumed the whole line landed in the first TCP segment, which is usual but
/// not guaranteed. Errors only when the peer sent nothing at all.
async fn read_request_head(socket: &mut TcpStream) -> Result<String> {
    const MAX_HEAD: usize = 16 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        let n = socket
            .read(&mut chunk)
            .await
            .map_err(|e| AuthError::Loopback(e.to_string()))?;
        if n == 0 {
            break; // EOF
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > MAX_HEAD {
            break;
        }
    }
    if buf.is_empty() {
        return Err(AuthError::Loopback(
            "connection closed before a request arrived".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub(super) fn open_system_browser(url: &str) -> Result<()> {
    webbrowser::open(url)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure mode this pins: a browser preconnect that CLOSES, one that
    /// stays open IDLE, and a stray probe (favicon) all arrive before the real
    /// redirect. The old single-accept implementation lost the redirect to the
    /// first connection; an unbounded per-connection read then parked the loop
    /// on the idle one. It must survive all three and still deliver the code —
    /// including when the redirect's request line is split across TCP segments.
    #[tokio::test]
    async fn stray_connections_do_not_consume_the_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wait = tokio::spawn(async move { listen_for_code(listener, "st4te").await });

        // 1: speculative preconnect — opens and closes without sending.
        drop(TcpStream::connect(addr).await.unwrap());

        // 1b: the case the old mitigation did NOT cover — a socket that opens
        // and stays open, sending nothing. Chrome and Edge hold speculative
        // sockets in the pool for seconds, so this is what browsers actually
        // do. Held for the whole test: without a per-connection read bound the
        // accept loop parks here and never reaches the real redirect below.
        let _idle = TcpStream::connect(addr).await.unwrap();

        // 2: stray probe — must get a 404, not steal the redirect slot.
        {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let mut resp = Vec::new();
            let _ = s.read_to_end(&mut resp).await;
            assert!(
                String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 404"),
                "probe should get a 404"
            );
        }

        // 3: the real redirect, request line split across two writes.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /?code=c0de&state=st4te HTT")
            .await
            .unwrap();
        s.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        s.write_all(b"P/1.1\r\nHost: x\r\n\r\n").await.unwrap();

        let code = wait.await.unwrap().unwrap();
        assert_eq!(code, "c0de");
    }

    /// Sends one raw redirect `query` to a fresh listener (expecting state
    /// `"s"`) and returns what `listen_for_code` made of it, plus the response
    /// the browser saw.
    async fn redirect_exchange(query: &str) -> (Result<String>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wait = tokio::spawn(async move { listen_for_code(listener, "s").await });
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET /?{query} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut resp = Vec::new();
        let _ = s.read_to_end(&mut resp).await;
        (
            wait.await.unwrap(),
            String::from_utf8_lossy(&resp).into_owned(),
        )
    }

    /// [`redirect_exchange`] without the response text.
    async fn redirect_outcome(query: &str) -> Result<String> {
        redirect_exchange(query).await.0
    }

    #[tokio::test]
    async fn a_cancelled_sign_in_maps_to_cancelled() {
        // MSAL's user-cancel signal.
        let out = redirect_outcome("error=access_denied&error_subcode=cancel&state=s").await;
        assert!(matches!(out, Err(AuthError::Cancelled)), "{out:?}");
        // Learn's example: a prose description with no AADSTS code.
        let out = redirect_outcome(
            "error=access_denied&error_description=the%20user%20canceled%20the%20authentication&state=s",
        )
        .await;
        assert!(matches!(out, Err(AuthError::Cancelled)), "{out:?}");
    }

    #[tokio::test]
    async fn a_declined_consent_stays_an_authorization_error() {
        let out = redirect_outcome(
            "error=access_denied&error_description=AADSTS65004%3A%20User%20declined&state=s",
        )
        .await;
        assert!(
            matches!(&out, Err(AuthError::Authorization(e)) if e == "access_denied (AADSTS65004)"),
            "{out:?}"
        );
        let out = redirect_outcome("error=invalid_request&state=s").await;
        assert!(
            matches!(&out, Err(AuthError::Authorization(e)) if e == "invalid_request"),
            "{out:?}"
        );
    }

    /// The AADSTS code survives (so the sign-in hint fires); the rest of the
    /// description — trace ids, prose — does not.
    #[tokio::test]
    async fn a_redirect_error_keeps_only_its_aadsts_code() {
        let out = redirect_outcome(
            "error=access_denied&error_description=AADSTS53003%3A%20Access%20blocked%20by%20CA%20Trace%20ID%3A%20abc&state=s",
        )
        .await;
        assert!(
            matches!(&out, Err(AuthError::Authorization(e)) if e == "access_denied (AADSTS53003)"),
            "{out:?}"
        );
    }

    #[tokio::test]
    async fn an_unrecognised_error_value_is_not_echoed() {
        let too_long = "a".repeat(65);
        for query in [
            "error=%3Cb%3Ex%3C%2Fb%3E&state=s".to_string(),
            format!("error={too_long}&state=s"),
        ] {
            let out = redirect_outcome(&query).await;
            assert!(
                matches!(&out, Err(AuthError::Authorization(e)) if e == "unrecognized_error"),
                "{query}: {out:?}"
            );
        }
    }

    /// The page is written after `state` validates and matches the outcome.
    #[tokio::test]
    async fn the_browser_page_matches_the_outcome() {
        let (out, page) = redirect_exchange("code=c0de&state=s").await;
        assert_eq!(out.unwrap(), "c0de");
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        assert!(page.contains("received your sign-in"), "{page}");

        let (out, page) = redirect_exchange("error=invalid_request&state=s").await;
        assert!(out.is_err());
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        assert!(page.contains("Sign-in failed"), "{page}");
        assert!(!page.contains("received your sign-in"), "{page}");
    }

    /// Any local process (or a web page's blind cross-origin request) can hit
    /// the port. A request without the pending `state` must neither end the
    /// wait nor get the success page — and the real redirect still lands.
    #[tokio::test]
    async fn a_forged_redirect_is_ignored_and_the_real_one_still_lands() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wait = tokio::spawn(async move { listen_for_code(listener, "expected").await });

        for forged in [
            "code=c0de&state=forged",
            "error=access_denied&state=forged",
            "error=boom",
            "code=c0de",
        ] {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET /?{forged} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut resp = Vec::new();
            let _ = s.read_to_end(&mut resp).await;
            let resp = String::from_utf8_lossy(&resp);
            assert!(resp.starts_with("HTTP/1.1 400"), "{forged}: {resp}");
            assert!(!resp.contains("received your sign-in"), "{forged}: {resp}");
            assert!(!wait.is_finished(), "{forged} ended the wait");
        }

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /?code=real&state=expected HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(wait.await.unwrap().unwrap(), "real");
    }

    /// A CORS/PNA preflight carrying redirect-shaped parameters is not the
    /// redirect: 404, and the loop keeps waiting.
    #[tokio::test]
    async fn a_non_get_request_is_not_the_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wait = tokio::spawn(async move { listen_for_code(listener, "expected").await });

        {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(b"OPTIONS /?error=x&state=expected HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let mut resp = Vec::new();
            let _ = s.read_to_end(&mut resp).await;
            assert!(
                String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 404"),
                "a preflight should get a 404"
            );
            assert!(!wait.is_finished(), "a preflight ended the wait");
        }

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /?code=c&state=expected HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(wait.await.unwrap().unwrap(), "c");
    }
}
