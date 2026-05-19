//! Prometheus-style metrics exporter and a /healthz endpoint.
//!
//! The HTTP server is a tiny purpose-built one rather than pulling in a
//! full HTTP crate; we only need to handle two GET paths and never write
//! a response body bigger than a few KB.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{info, warn};

/// All counters / gauges the server publishes. Atomics so the main loop
/// can update them without any locks while the HTTP serving thread reads
/// them.
#[derive(Default)]
pub struct Metrics {
    pub connections_open: AtomicU64,
    pub connections_total: AtomicU64,
    pub connections_rejected_caps: AtomicU64,
    pub connections_rejected_rate: AtomicU64,
    pub retries_issued: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub requests_total: AtomicU64,
    pub requests_failed: AtomicU64,
    pub requests_rate_limited: AtomicU64,
    pub uploads_completed: AtomicU64,
    pub downloads_completed: AtomicU64,
}

/// Prometheus metric kind. counter -> monotonically increasing; gauge ->
/// arbitrary up/down.
#[derive(Clone, Copy)]
enum Kind {
    Counter,
    Gauge,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
        }
    }
}

impl Metrics {
    pub fn render(&self) -> String {
        let mut out = String::new();
        let g = |out: &mut String, name: &str, help: &str, kind: Kind, v: u64| {
            use std::fmt::Write as _;
            writeln!(out, "# HELP {name} {help}").ok();
            writeln!(out, "# TYPE {name} {}", kind.as_str()).ok();
            writeln!(out, "{name} {v}").ok();
        };
        // connections_open is the one quantity that can go down (we
        // decrement it on close), so it needs to be a gauge -- exporting
        // a decreasing value as a counter would break rate()/increase()
        // queries in Prometheus.
        g(
            &mut out,
            "qftp_connections_open",
            "Currently open QUIC connections.",
            Kind::Gauge,
            self.connections_open.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_connections_total",
            "Total accepted QUIC connections since startup.",
            Kind::Counter,
            self.connections_total.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_connections_rejected_caps_total",
            "Connections dropped because per-IP or global caps were exceeded.",
            Kind::Counter,
            self.connections_rejected_caps.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_connections_rejected_rate_total",
            "Connections dropped by the rate limiter.",
            Kind::Counter,
            self.connections_rejected_rate.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_retries_issued_total",
            "QUIC stateless retries issued for address validation.",
            Kind::Counter,
            self.retries_issued.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_bytes_received_total",
            "Bytes received in Put uploads.",
            Kind::Counter,
            self.bytes_received.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_bytes_sent_total",
            "Bytes sent in Get downloads.",
            Kind::Counter,
            self.bytes_sent.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_requests_total",
            "Protocol requests handled.",
            Kind::Counter,
            self.requests_total.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_requests_failed_total",
            "Protocol requests that returned Response::Err.",
            Kind::Counter,
            self.requests_failed.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_requests_rate_limited_total",
            "Per-request protocol calls rejected by the in-connection rate limiter.",
            Kind::Counter,
            self.requests_rate_limited.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_uploads_completed_total",
            "Successful Put uploads.",
            Kind::Counter,
            self.uploads_completed.load(Ordering::Relaxed),
        );
        g(
            &mut out,
            "qftp_downloads_completed_total",
            "Successful Get downloads.",
            Kind::Counter,
            self.downloads_completed.load(Ordering::Relaxed),
        );
        out
    }
}

/// Spawn the HTTP serving thread. Returns immediately; the thread runs
/// until `shutdown` is set. A daemon thread is acceptable here because
/// the listener is a blocking socket and we only need it to stop on
/// process exit (the main loop ignores the listener entirely).
pub fn spawn(metrics: Arc<Metrics>, bind: &str, shutdown: Arc<AtomicBool>) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .with_context(|| format!("failed to bind metrics listener on {bind}"))?;
    listener
        .set_nonblocking(true)
        .context("failed to set metrics listener nonblocking")?;
    info!(%bind, "metrics endpoint listening");

    thread::Builder::new()
        .name("qftp-metrics".to_string())
        .spawn(move || serve_loop(listener, metrics, shutdown))
        .context("failed to spawn metrics thread")?;
    Ok(())
}

fn serve_loop(listener: TcpListener, metrics: Arc<Metrics>, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let metrics = Arc::clone(&metrics);
                if let Err(e) = handle_request(stream, metrics) {
                    warn!(error = %e, "metrics request failed");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                warn!(error = %e, "metrics accept failed");
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn handle_request(mut stream: TcpStream, metrics: Arc<Metrics>) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();

    let (status, content_type, body) = match path.as_str() {
        "/metrics" => ("200 OK", "text/plain; version=0.0.4", metrics.render()),
        "/healthz" => ("200 OK", "text/plain", "ok\n".to_string()),
        _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}
