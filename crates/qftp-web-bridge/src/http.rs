//! Minimal HTTP/1.1 listener that serves the bundled single-page app.
//!
//! WebTransport cannot deliver the initial HTML/JS/CSS, so the bridge
//! exposes a tiny static file server for it. This handles only `GET`,
//! serves a fixed set of embedded routes plus a generated
//! `/config.json`, never touches the filesystem, and closes the
//! connection after every response -- it is deliberately not a
//! general-purpose web server. Put a reverse proxy (nginx) in front of
//! it for TLS termination in production.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const INDEX_HTML: &str = include_str!("../../../web/index.html");
const APP_JS: &str = include_str!("../../../web/app.js");
const STYLE_CSS: &str = include_str!("../../../web/style.css");

/// Largest request head we will buffer. We only ever read the request
/// line; headers and any body are ignored.
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// Wall-clock budget for a single connection, covering both reading the
/// request head and writing the response. Without it a client that
/// opens a socket and never sends a full request (slowloris) pins a
/// task and its buffer forever.
const CONN_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on connections served concurrently. The accept loop stops
/// pulling new connections once this is reached, so a connection flood
/// can't spawn tasks without limit.
const MAX_CONNECTIONS: usize = 128;

struct StaticFile {
    content_type: &'static str,
    body: &'static [u8],
}

/// Map a request target (path, query stripped) to an embedded file.
fn route(target: &str) -> Option<StaticFile> {
    let path = target.split('?').next().unwrap_or(target);
    match path {
        "/" | "/index.html" => Some(StaticFile {
            content_type: "text/html; charset=utf-8",
            body: INDEX_HTML.as_bytes(),
        }),
        "/app.js" => Some(StaticFile {
            content_type: "text/javascript; charset=utf-8",
            body: APP_JS.as_bytes(),
        }),
        "/style.css" => Some(StaticFile {
            content_type: "text/css; charset=utf-8",
            body: STYLE_CSS.as_bytes(),
        }),
        _ => None,
    }
}

/// Bind the SPA HTTP listener and serve it forever. `config_json` is
/// the body returned for `/config.json` (the WebTransport port and the
/// server-certificate hash the SPA needs).
pub async fn serve(bind: SocketAddr, config_json: String) -> Result<()> {
    let config_json: Arc<str> = Arc::from(config_json);
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind SPA HTTP listener on {bind}"))?;
    tracing::info!(%bind, "SPA HTTP listener ready");

    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        // Acquire before `accept` so a saturated listener leaves new
        // connections in the OS backlog instead of spawning unbounded
        // tasks.
        let permit = Arc::clone(&conn_limit)
            .acquire_owned()
            .await
            .expect("connection-limit semaphore is never closed");
        let (mut sock, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "SPA HTTP accept failed");
                continue;
            }
        };
        let config_json = Arc::clone(&config_json);
        tokio::spawn(async move {
            match tokio::time::timeout(CONN_TIMEOUT, handle_conn(&mut sock, &config_json)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::debug!(error = %e, "SPA HTTP connection error"),
                Err(_) => tracing::debug!("SPA HTTP connection timed out"),
            }
            drop(permit);
        });
    }
}

async fn handle_conn(sock: &mut TcpStream, config_json: &str) -> Result<()> {
    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(end) = find_head_end(&head) {
            head.truncate(end);
            break;
        }
        let n = sock.read(&mut tmp).await.context("HTTP read failed")?;
        if n == 0 {
            return Ok(()); // client closed before sending a full request
        }
        head.extend_from_slice(&tmp[..n]);
        anyhow::ensure!(head.len() <= MAX_HEAD_BYTES, "HTTP request head too large");
    }
    let text = String::from_utf8_lossy(&head);
    let response = build_response(text.lines().next().unwrap_or(""), config_json);
    sock.write_all(&response)
        .await
        .context("HTTP write failed")?;
    Ok(())
}

/// Offset of the byte just past the `\r\n\r\n` head terminator.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Build a complete HTTP/1.1 response for one request line.
fn build_response(request_line: &str, config_json: &str) -> Vec<u8> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "GET" {
        return http_response(
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"qftp web bridge: only GET is supported\n",
        );
    }
    if target.split('?').next() == Some("/config.json") {
        return http_response(
            200,
            "OK",
            "application/json; charset=utf-8",
            config_json.as_bytes(),
        );
    }
    match route(target) {
        Some(f) => http_response(200, "OK", f.content_type, f.body),
        None => http_response(
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            b"qftp web bridge: not found\n",
        ),
    }
}

fn http_response(status: u16, reason: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-cache\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "{\"certHash\":\"abcd\",\"webtransportPort\":4433}";

    fn head_of(resp: &[u8]) -> String {
        let text = String::from_utf8_lossy(resp);
        text.split("\r\n\r\n").next().unwrap_or("").to_string()
    }

    #[test]
    fn serves_index_at_root() {
        let resp = build_response("GET / HTTP/1.1", CFG);
        let head = head_of(&resp);
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert!(head.contains("text/html"), "{head}");
    }

    #[test]
    fn serves_app_js_with_query_string() {
        let resp = build_response("GET /app.js?v=2 HTTP/1.1", CFG);
        assert!(head_of(&resp).contains("text/javascript"));
    }

    #[test]
    fn serves_config_json() {
        let resp = build_response("GET /config.json HTTP/1.1", CFG);
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("application/json"));
        assert!(
            text.ends_with(CFG),
            "config body should be the JSON verbatim"
        );
    }

    #[test]
    fn unknown_path_is_404() {
        assert!(head_of(&build_response("GET /secret HTTP/1.1", CFG)).starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn non_get_is_405() {
        assert!(head_of(&build_response("POST / HTTP/1.1", CFG)).starts_with("HTTP/1.1 405"));
    }

    #[test]
    fn content_length_matches_body() {
        let resp = build_response("GET /style.css HTTP/1.1", CFG);
        let body_len = resp.len() - head_of(&resp).len() - 4;
        let head = head_of(&resp);
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, body_len);
    }

    #[test]
    fn finds_head_terminator() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }
}
