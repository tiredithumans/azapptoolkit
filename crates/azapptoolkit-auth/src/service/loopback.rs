//! Loopback redirect listener + system-browser launch for the interactive
//! authorization-code flows. The caller (`run_auth_code_flow`) bounds the
//! whole wait with a 300s timeout; nothing here needs its own deadline.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{AuthError, Result};

/// Waits on `listener` for the browser's OAuth redirect and extracts the
/// authorization code (validating the CSRF `state` against `expected_state`).
///
/// Robustness over a bare accept-and-read: browsers open speculative
/// ("preconnect") sockets and fire stray requests (`/favicon.ico`) at loopback
/// servers — with a single `accept()`, one of those consumes the slot and the
/// real redirect is lost until the caller's timeout ("sign-in hangs"). So this
/// loops: a connection that closes without sending, or whose request carries
/// none of `code`/`state`/`error`, gets a 404 and the listener keeps waiting.
pub(super) async fn listen_for_code(listener: TcpListener, expected_state: &str) -> Result<String> {
    loop {
        let (mut socket, _peer) = listener
            .accept()
            .await
            .map_err(|e| AuthError::Loopback(e.to_string()))?;

        // A speculative preconnect that closed without sending anything —
        // keep listening for the real redirect.
        let Ok(request) = read_request_head(&mut socket).await else {
            continue;
        };

        let first_line = request.lines().next().unwrap_or_default();
        let mut parts = first_line.split_whitespace();
        let _method = parts.next();
        let path = parts.next().unwrap_or("");

        let query = path.split('?').nth(1).unwrap_or("");
        let mut code: Option<String> = None;
        let mut state: Option<String> = None;
        let mut error: Option<String> = None;
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                _ => {}
            }
        }

        // Not the OAuth redirect (favicon probe, unrelated request): answer
        // and keep waiting for the real one.
        if code.is_none() && state.is_none() && error.is_none() {
            let _ = socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = socket.shutdown().await;
            continue;
        }

        let body = if error.is_some() {
            "<html><body><h2>Sign-in failed.</h2><p>You can close this window.</p></body></html>"
        } else {
            "<html><body><h2>azapptoolkit sign-in complete.</h2><p>You can close this window.</p></body></html>"
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;

        if let Some(err) = error {
            return Err(AuthError::Authorization(err));
        }

        let got_state = state.ok_or(AuthError::StateMismatch)?;
        if got_state != expected_state {
            return Err(AuthError::StateMismatch);
        }
        return code.ok_or_else(|| AuthError::Authorization("no code returned".into()));
    }
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

    /// The failure mode this pins: a browser preconnect (opens, sends nothing)
    /// and a stray probe (favicon) arrive before the real redirect. The old
    /// single-accept implementation lost the redirect to the first connection;
    /// the loop must survive both and still deliver the code — including when
    /// the redirect's request line is split across TCP segments.
    #[tokio::test]
    async fn stray_connections_do_not_consume_the_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wait = tokio::spawn(async move { listen_for_code(listener, "st4te").await });

        // 1: speculative preconnect — opens and closes without sending.
        drop(TcpStream::connect(addr).await.unwrap());

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

    #[tokio::test]
    async fn state_mismatch_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wait = tokio::spawn(async move { listen_for_code(listener, "expected").await });

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /?code=c0de&state=forged HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();

        assert!(matches!(wait.await.unwrap(), Err(AuthError::StateMismatch)));
    }
}
