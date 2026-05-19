//! `qftp-client put-multi --to host1,host2,... LOCAL REMOTE_PATH`
//!
//! Upload one local file to N servers in parallel. Each target is
//! served by its own OS thread that runs the same connection +
//! upload path as one-shot mode; the threads run concurrently so the
//! wall-clock time is approximately `max(individual upload)`,
//! not `sum`. This is the QUIC angle the issue lists: cheap
//! connection setup means N independent connections actually beat
//! a serial scp loop.
//!
//! Failure modes:
//!   - `--strict`: one failure exits the process non-zero. Survivors
//!     finish; we don't try to roll them back.
//!   - default (best-effort): we keep going and report the survivor
//!     count at the end.

use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};

use crate::config::{self, Overrides};

#[derive(Debug)]
struct Outcome {
    host: String,
    ok: bool,
    elapsed_ms: u128,
    message: String,
}

pub fn run(
    local: &str,
    remote_path: &str,
    targets: &[String],
    strict: bool,
    overrides: &Overrides,
) -> Result<i32> {
    if targets.is_empty() {
        anyhow::bail!("put-multi: need at least one --to host");
    }
    let local_path = std::path::PathBuf::from(local);
    if !local_path.is_file() {
        anyhow::bail!("put-multi: not a regular file: {local}");
    }

    // Pre-compute BLAKE3 once so each thread doesn't re-hash.
    let checksum = hash_blake3(&local_path)?;
    tracing::info!(
        file = %local_path.display(),
        sha = ?hex_short(&checksum),
        "put-multi: pre-hashed"
    );

    let results: Arc<Mutex<Vec<Outcome>>> = Arc::new(Mutex::new(Vec::with_capacity(targets.len())));
    let mut handles = Vec::with_capacity(targets.len());

    for host in targets {
        let host = host.clone();
        let local_path = local_path.clone();
        let remote_path = remote_path.to_string();
        let overrides = clone_overrides(overrides);
        let results = Arc::clone(&results);
        let h = thread::Builder::new()
            .name(format!("fanout-{host}"))
            .spawn(move || {
                let t0 = Instant::now();
                let res = upload_to_host(&host, &local_path, &remote_path, &overrides, checksum);
                let elapsed_ms = t0.elapsed().as_millis();
                let outcome = match res {
                    Ok(()) => Outcome {
                        host: host.clone(),
                        ok: true,
                        elapsed_ms,
                        message: "ok".to_string(),
                    },
                    Err(e) => Outcome {
                        host: host.clone(),
                        ok: false,
                        elapsed_ms,
                        message: format!("{e:#}"),
                    },
                };
                results.lock().unwrap().push(outcome);
            })
            .context("spawn fanout worker")?;
        handles.push(h);
    }

    for h in handles {
        let _ = h.join();
    }
    let results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();

    let mut ok = 0;
    let mut fail = 0;
    let mut total_ms = 0u128;
    println!("put-multi results:");
    for o in &results {
        let status = if o.ok { "OK" } else { "FAIL" };
        println!(
            "  {status:5} {host:<32} {ms:>6} ms  {msg}",
            host = o.host,
            ms = o.elapsed_ms,
            msg = o.message
        );
        if o.ok {
            ok += 1;
        } else {
            fail += 1;
        }
        total_ms = total_ms.max(o.elapsed_ms);
    }
    println!(
        "summary: {ok} ok, {fail} fail, {n} total (wall-clock {total_ms} ms vs serial estimate {serial_ms} ms)",
        n = results.len(),
        serial_ms = results.iter().map(|o| o.elapsed_ms).sum::<u128>()
    );

    if strict && fail > 0 {
        return Ok(crate::oneshot::exit::DATA);
    }
    if ok == 0 {
        return Ok(crate::oneshot::exit::DATA);
    }
    Ok(crate::oneshot::exit::OK)
}

fn upload_to_host(
    host: &str,
    local: &std::path::Path,
    remote_path: &str,
    overrides: &Overrides,
    _checksum: [u8; 32],
) -> Result<()> {
    // Build a qftp:// URL pointing at this host + path; reuse the
    // existing one-shot Put path. It already pre-hashes inside
    // do_put; the pre-computed `_checksum` is reserved for a future
    // optimization that threads it through transfer::do_put without
    // re-reading the file. For now we just leverage the fact that
    // each thread independently re-reads (cheap once the file is in
    // page cache).
    let url = if !host.contains("://") {
        format!("qftp://{host}{remote_path}")
    } else {
        // Caller already passed a fully qualified URL; respect it.
        host.to_string()
    };
    let url_obj = config::parse_url(&url).with_context(|| format!("bad target URL {url}"))?;
    let host_port = format_host_port(&url_obj.host, url_obj.port);
    let path = url_obj.initial_path.unwrap_or_else(|| "/".to_string());
    let target = format!("qftp://{host_port}{path}");

    let spec = config::resolve(Some(&target), &config::ConfigFile::default(), overrides)
        .with_context(|| format!("resolve {target}"))?;

    // The actual upload reuses transfer::do_put via a hand-rolled
    // tiny client loop. We don't go through `oneshot::run` because
    // that one calls std::process::exit at the end.
    do_put_once(&spec, local, &path)
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn do_put_once(
    spec: &crate::config::ConnectionSpec,
    local: &std::path::Path,
    remote_path: &str,
) -> Result<()> {
    use mio::{Events, Interest, Poll};
    use qftp_common::transport::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    const TOK: mio::Token = mio::Token(0);

    let client_cert = match (&spec.client_cert, &spec.client_key) {
        (Some(c), Some(k)) => Some(qftp_common::transport::ClientCert {
            cert_pem: c.clone(),
            key_pem: k.clone(),
        }),
        _ => None,
    };
    let mut config = create_client_config(qftp_common::transport::ClientTlsConfig {
        verify_peer: !spec.insecure,
        ca_path: spec.ca.clone(),
        client_cert,
    })?;
    let peer_addr = spec
        .host
        .parse()
        .with_context(|| format!("bad host {}", spec.host))?;
    let std_socket = UdpSocket::bind("0.0.0.0:0")?;
    std_socket.set_nonblocking(true)?;
    std_socket.connect(peer_addr)?;
    qftp_common::transport::tune_udp_buffers(&std_socket);
    let local_addr = std_socket.local_addr()?;
    let mut socket = mio::net::UdpSocket::from_std(std_socket);

    let rng = ring::rand::SystemRandom::new();
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    use ring::rand::SecureRandom;
    rng.fill(&mut scid_bytes).unwrap();
    let scid = quiche::ConnectionId::from_vec(scid_bytes.to_vec());
    let mut conn = quiche::connect(
        Some(&spec.server_name),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )?;

    if let Some(dir) = crate::session_store::default_dir() {
        if let Some(ticket) = crate::session_store::load(&dir, &spec.host, None) {
            let _ = conn.set_session(&ticket);
        }
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    poll.registry()
        .register(&mut socket, TOK, Interest::READABLE)?;

    flush_egress(&mut conn, &socket)?;
    let mut buf = [0u8; 65535];
    loop {
        poll.poll(
            &mut events,
            conn.timeout().or(Some(Duration::from_millis(100))),
        )?;
        conn.on_timeout();
        handle_ingress(&mut conn, &socket, &mut buf)?;
        flush_egress(&mut conn, &socket)?;
        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            anyhow::bail!("connection closed during handshake");
        }
    }

    crate::transfer::do_put(
        &mut conn,
        &socket,
        &mut poll,
        &mut events,
        0,
        local,
        remote_path,
        0,
    )?;

    // Polite close.
    let _ = crate::transfer::do_put;
    let _ = send_message(&mut conn, 4, &qftp_common::protocol::Request::Quit);
    let _ = stream_send_all(&mut conn, 4, &[], true);
    let _ = flush_egress(&mut conn, &socket);

    if let Some(dir) = crate::session_store::default_dir() {
        let _ = crate::session_store::save_from_conn(&dir, &spec.host, &conn);
    }

    Ok(())
}

fn hash_blake3(path: &std::path::Path) -> Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hex_short(b: &[u8]) -> String {
    let mut s = String::with_capacity(16);
    for byte in b.iter().take(8) {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Manual clone for `Overrides` since the struct isn't `Clone`.
fn clone_overrides(o: &Overrides) -> Overrides {
    Overrides {
        host: o.host.clone(),
        server_name: o.server_name.clone(),
        insecure: o.insecure,
        ca: o.ca.clone(),
        client_cert: o.client_cert.clone(),
        client_key: o.client_key.clone(),
    }
}
