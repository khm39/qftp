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
    pub initials_dropped_bad_dcid: AtomicU64,
    pub retries_issued: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub requests_total: AtomicU64,
    pub requests_failed: AtomicU64,
    pub requests_rate_limited: AtomicU64,
    pub uploads_completed: AtomicU64,
    pub downloads_completed: AtomicU64,
    pub zero_rtt_accepted: AtomicU64,
    pub zero_rtt_rejected: AtomicU64,
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
    /// Thin wrappers over the underlying atomics. Callers should
    /// reach for these semantic helpers rather than poking the
    /// `AtomicU64` fields directly — that keeps the `Ordering::Relaxed`
    /// choice and the bump-vs-decrement direction in one place.
    pub fn inc_connections_open(&self) {
        self.connections_open.fetch_add(1, Ordering::Relaxed);
    }
    pub fn dec_connections_open(&self) {
        self.connections_open.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn inc_connections_total(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_retries_issued(&self) {
        self.retries_issued.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_requests_total(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_requests_failed(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_zero_rtt_accepted(&self) {
        self.zero_rtt_accepted.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_zero_rtt_rejected(&self) {
        self.zero_rtt_rejected.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_uploads_completed(&self) {
        self.uploads_completed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_downloads_completed(&self) {
        self.downloads_completed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }
    pub fn inc_connections_rejected_rate(&self) {
        self.connections_rejected_rate
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_connections_rejected_caps(&self) {
        self.connections_rejected_caps
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_initials_dropped_bad_dcid(&self) {
        self.initials_dropped_bad_dcid
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_requests_rate_limited(&self) {
        self.requests_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        macro_rules! metric {
            ($name:literal, $help:literal, $kind:expr, $field:ident) => {{
                let v = self.$field.load(Ordering::Relaxed);
                writeln!(out, "# HELP {} {}", $name, $help).ok();
                writeln!(out, "# TYPE {} {}", $name, $kind.as_str()).ok();
                writeln!(out, "{} {}", $name, v).ok();
            }};
        }
        // connections_open is the one quantity that can go down (we
        // decrement it on close), so it needs to be a gauge -- exporting
        // a decreasing value as a counter would break rate()/increase()
        // queries in Prometheus.
        metric!(
            "qftp_connections_open",
            "Currently open QUIC connections.",
            Kind::Gauge,
            connections_open
        );
        metric!(
            "qftp_connections_total",
            "Total accepted QUIC connections since startup.",
            Kind::Counter,
            connections_total
        );
        metric!(
            "qftp_connections_rejected_caps_total",
            "Connections dropped because per-IP or global caps were exceeded.",
            Kind::Counter,
            connections_rejected_caps
        );
        metric!(
            "qftp_connections_rejected_rate_total",
            "Connections dropped by the rate limiter.",
            Kind::Counter,
            connections_rejected_rate
        );
        metric!(
            "qftp_initials_dropped_bad_dcid_total",
            "Initials dropped because the client-chosen DCID was out of the RFC 9000 §7.2 range.",
            Kind::Counter,
            initials_dropped_bad_dcid
        );
        metric!(
            "qftp_retries_issued_total",
            "QUIC stateless retries issued for address validation.",
            Kind::Counter,
            retries_issued
        );
        metric!(
            "qftp_bytes_received_total",
            "Bytes received in Put uploads.",
            Kind::Counter,
            bytes_received
        );
        metric!(
            "qftp_bytes_sent_total",
            "Bytes sent in Get downloads.",
            Kind::Counter,
            bytes_sent
        );
        metric!(
            "qftp_requests_total",
            "Protocol requests handled.",
            Kind::Counter,
            requests_total
        );
        metric!(
            "qftp_requests_failed_total",
            "Protocol requests that returned Response::Err.",
            Kind::Counter,
            requests_failed
        );
        metric!(
            "qftp_requests_rate_limited_total",
            "Per-request protocol calls rejected by the in-connection rate limiter.",
            Kind::Counter,
            requests_rate_limited
        );
        metric!(
            "qftp_uploads_completed_total",
            "Successful Put uploads.",
            Kind::Counter,
            uploads_completed
        );
        metric!(
            "qftp_downloads_completed_total",
            "Successful Get downloads.",
            Kind::Counter,
            downloads_completed
        );
        metric!(
            "qftp_zero_rtt_accepted_total",
            "Requests accepted while the QUIC handshake was still in the early-data phase. These are read-only ops served at 0-RTT.",
            Kind::Counter,
            zero_rtt_accepted
        );
        metric!(
            "qftp_zero_rtt_rejected_total",
            "Requests refused because they arrived during 0-RTT and would have mutated server state. The client retries them under 1-RTT.",
            Kind::Counter,
            zero_rtt_rejected
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
    // The /metrics and /healthz endpoints are unauthenticated.
    // Surface a loud warning when the operator bound them to a
    // non-loopback address so this isn't silently exposed to the
    // internet. We log via the resolved local_addr rather than the
    // input string so `--metrics-bind localhost:9090` still resolves
    // to the loopback and stays quiet.
    if let Ok(addr) = listener.local_addr() {
        let is_loopback = match addr.ip() {
            std::net::IpAddr::V4(v4) => v4.is_loopback(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        };
        if !is_loopback {
            warn!(
                bind = %addr,
                "metrics endpoint bound to a non-loopback address; \
                 /metrics and /healthz are UNAUTHENTICATED. Bind to \
                 127.0.0.1 / [::1] or a management VLAN and scrape via \
                 reverse proxy / SSH tunnel (#143)"
            );
        }
    }
    info!(%bind, "metrics endpoint listening");

    thread::Builder::new()
        .name("qftp-metrics".to_string())
        .spawn(move || serve_loop(listener, metrics, shutdown))
        .context("failed to spawn metrics thread")?;
    Ok(())
}

/// Upper bound on concurrent in-flight metrics connections. Each accepted
/// connection is handled on its own short-lived thread so a slow client
/// (e.g. a slow-loris that opens a socket and never sends a request) can't
/// stall the accept loop for the duration of its read timeout. This cap
/// keeps an attacker from spawning unbounded threads by holding many such
/// sockets open at once; past the cap, excess connections are dropped.
const MAX_INFLIGHT: usize = 32;

fn serve_loop(listener: TcpListener, metrics: Arc<Metrics>, shutdown: Arc<AtomicBool>) {
    // Counts threads currently handling a connection. Bounded by
    // MAX_INFLIGHT so a flood of slow connections can't spawn threads
    // without limit.
    let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if inflight.load(Ordering::Relaxed) >= MAX_INFLIGHT {
                    // Drop the connection without reading: shedding load
                    // is better than letting slow clients exhaust threads.
                    drop(stream);
                    continue;
                }
                inflight.fetch_add(1, Ordering::Relaxed);
                let metrics = Arc::clone(&metrics);
                let inflight_thread = Arc::clone(&inflight);
                // A detached thread per connection: the accept loop never
                // blocks on a single connection's read/write timeout.
                let spawned = thread::Builder::new()
                    .name("qftp-metrics-conn".to_string())
                    .spawn(move || {
                        if let Err(e) = handle_request(stream, &metrics) {
                            warn!(error = %e, "metrics request failed");
                        }
                        inflight_thread.fetch_sub(1, Ordering::Relaxed);
                    });
                if spawned.is_err() {
                    // Couldn't spawn (resource exhaustion); undo the
                    // reservation so the counter doesn't leak.
                    inflight.fetch_sub(1, Ordering::Relaxed);
                    warn!("failed to spawn metrics connection thread; dropping request");
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

/// Decide the HTTP response for a raw request, independent of any socket.
/// Split out from `handle_request` so the path routing and the rendered
/// body can be unit-tested without a live `TcpStream`. Returns the status
/// line, the `Content-Type`, and the body.
fn route_request(request: &str, metrics: &Metrics) -> (&'static str, &'static str, String) {
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    match path {
        "/metrics" => ("200 OK", "text/plain; version=0.0.4", metrics.render()),
        "/healthz" => ("200 OK", "text/plain", "ok\n".to_string()),
        _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    }
}

/// Format a full HTTP/1.1 response (headers + body) for the routed result.
fn format_response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn handle_request(mut stream: TcpStream, metrics: &Metrics) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");

    let (status, content_type, body) = route_request(request, metrics);
    let response = format_response(status, content_type, &body);
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Parse a `render()` body into a name -> (type, value) map plus the
    /// set of HELP lines seen. Lets the tests assert on the Prometheus
    /// structure without baking in line order.
    fn parse_render(body: &str) -> (HashMap<String, (String, u64)>, usize) {
        let mut types: HashMap<String, String> = HashMap::new();
        let mut values: HashMap<String, u64> = HashMap::new();
        let mut help_lines = 0usize;
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("# HELP ") {
                assert!(
                    rest.split_whitespace().next().is_some(),
                    "HELP line missing metric name: {line:?}"
                );
                help_lines += 1;
            } else if let Some(rest) = line.strip_prefix("# TYPE ") {
                let mut it = rest.split_whitespace();
                let name = it.next().expect("TYPE name").to_string();
                let kind = it.next().expect("TYPE kind").to_string();
                types.insert(name, kind);
            } else if !line.is_empty() {
                let mut it = line.split_whitespace();
                let name = it.next().expect("value name").to_string();
                let val: u64 = it.next().expect("value").parse().expect("u64 value");
                values.insert(name, val);
            }
        }
        let mut out = HashMap::new();
        for (name, kind) in types {
            let v = *values
                .get(&name)
                .unwrap_or_else(|| panic!("metric {name} had a TYPE but no value line"));
            out.insert(name, (kind, v));
        }
        (out, help_lines)
    }

    #[test]
    fn render_emits_well_formed_prometheus_with_correct_types() {
        let m = Metrics::default();
        // Drive a few counters and the one gauge to distinct values so a
        // mix-up between fields would be caught.
        m.inc_connections_open();
        m.inc_connections_open();
        m.dec_connections_open(); // gauge ends at 1
        m.inc_connections_total();
        m.inc_connections_total();
        m.inc_connections_total(); // counter at 3
        m.add_bytes_received(4096);
        m.inc_requests_rate_limited();

        let body = m.render();
        let (metrics, help_lines) = parse_render(&body);

        // Every metric line has exactly one matching HELP + TYPE.
        assert_eq!(
            help_lines,
            metrics.len(),
            "each metric must have exactly one HELP line"
        );

        // The one quantity that can decrease is a gauge; everything else
        // is a cumulative counter. Exporting a decreasing value as a
        // counter would break Prometheus rate()/increase().
        let (open_kind, open_val) = &metrics["qftp_connections_open"];
        assert_eq!(open_kind, "gauge");
        assert_eq!(*open_val, 1);

        let (total_kind, total_val) = &metrics["qftp_connections_total"];
        assert_eq!(total_kind, "counter");
        assert_eq!(*total_val, 3);

        assert_eq!(
            metrics["qftp_bytes_received_total"],
            ("counter".into(), 4096)
        );
        assert_eq!(
            metrics["qftp_requests_rate_limited_total"],
            ("counter".into(), 1)
        );

        // Spot-check that every metric except the gauge is a counter.
        for (name, (kind, _)) in &metrics {
            if name == "qftp_connections_open" {
                continue;
            }
            assert_eq!(kind, "counter", "{name} should be a counter");
        }
    }

    #[test]
    fn route_metrics_path_renders_body() {
        let m = Metrics::default();
        let (status, content_type, body) = route_request("GET /metrics HTTP/1.1", &m);
        assert_eq!(status, "200 OK");
        assert_eq!(content_type, "text/plain; version=0.0.4");
        assert!(body.contains("qftp_connections_open"));
        assert!(body.contains("# TYPE qftp_connections_open gauge"));
    }

    #[test]
    fn route_healthz_path_is_ok() {
        let m = Metrics::default();
        let (status, content_type, body) = route_request("GET /healthz HTTP/1.1", &m);
        assert_eq!(status, "200 OK");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "ok\n");
    }

    #[test]
    fn route_unknown_path_is_404() {
        let m = Metrics::default();
        let (status, _ct, body) = route_request("GET /does-not-exist HTTP/1.1", &m);
        assert_eq!(status, "404 Not Found");
        assert_eq!(body, "not found\n");
    }

    #[test]
    fn route_malformed_request_defaults_to_404() {
        let m = Metrics::default();
        // No path token at all -> defaults to "/" -> not a known route.
        let (status, ..) = route_request("garbage", &m);
        assert_eq!(status, "404 Not Found");
    }

    #[test]
    fn format_response_sets_content_length_to_body_len() {
        let resp = format_response("200 OK", "text/plain", "ok\n");
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Type: text/plain\r\n"));
        assert!(resp.contains("Content-Length: 3\r\n"));
        assert!(resp.contains("Connection: close\r\n"));
        assert!(resp.ends_with("\r\n\r\nok\n"));
    }

    #[test]
    fn slow_client_does_not_block_accept_loop() {
        // Regression for the slow-loris DoS: a client that opens a socket
        // and never sends a request must not stall /healthz for the whole
        // read timeout. With the per-connection-thread serve_loop a second
        // client's GET /healthz returns promptly even while the first
        // socket sits idle. Pre-fix (sequential handling) this GET would
        // be delayed by ~5s (the read timeout) behind the silent socket.
        use std::io::{Read as _, Write as _};
        use std::net::TcpStream;
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        listener.set_nonblocking(true).expect("nonblocking");

        let metrics = Arc::new(Metrics::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let loop_shutdown = Arc::clone(&shutdown);
        let loop_metrics = Arc::clone(&metrics);
        let server = thread::spawn(move || serve_loop(listener, loop_metrics, loop_shutdown));

        // First client: connect and send nothing. handle_request's 5s read
        // timeout will keep its thread parked, but it must not park the
        // accept loop. Hold the stream open for the duration of the test.
        let _silent = TcpStream::connect(addr).expect("silent connect");

        // Give the accept loop a moment to pick up the silent socket and
        // (with the fix) hand it to its own thread.
        thread::sleep(Duration::from_millis(100));

        // Second client: a real GET /healthz. It must complete quickly.
        let start = Instant::now();
        let mut client = TcpStream::connect(addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        client
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("write request");
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).expect("read response");
        let elapsed = start.elapsed();

        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "unexpected: {text:?}");
        assert!(text.ends_with("ok\n"), "unexpected body: {text:?}");
        // Comfortably under the 5s read timeout the silent socket holds;
        // a generous bound keeps the test robust on loaded CI while still
        // failing loudly if the accept loop is serialized behind the
        // slow client.
        assert!(
            elapsed < Duration::from_secs(3),
            "GET /healthz took {elapsed:?}; accept loop appears blocked by the silent client"
        );

        shutdown.store(true, Ordering::Relaxed);
        // serve_loop polls shutdown every ~200ms; join with that in mind.
        let _ = server.join();
    }
}
