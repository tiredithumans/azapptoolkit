//! Loopback redirect listener + system-browser launch for the interactive
//! authorization-code flows. The caller (`run_auth_code_flow`) bounds the
//! whole wait with a 300s timeout; nothing here needs its own deadline.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::error::{AuthError, Result};

pub(super) async fn listen_for_code(listener: TcpListener, expected_state: &str) -> Result<String> {
    let (mut socket, _peer) = listener
        .accept()
        .await
        .map_err(|e| AuthError::Loopback(e.to_string()))?;

    let mut buf = vec![0u8; 8192];
    let n = socket
        .read(&mut buf)
        .await
        .map_err(|e| AuthError::Loopback(e.to_string()))?;
    let request = String::from_utf8_lossy(&buf[..n]);

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
    code.ok_or_else(|| AuthError::Authorization("no code returned".into()))
}

pub(super) fn open_system_browser(url: &str) -> Result<()> {
    webbrowser::open(url)?;
    Ok(())
}
