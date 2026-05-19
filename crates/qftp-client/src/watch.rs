//! `qftp-client watch <local-dir> <remote-url>` — mirror filesystem
//! events under `<local-dir>` to the server in real time.
//!
//! - `notify` crate's recommended_watcher gives us inotify on Linux,
//!   FSEvents on macOS, and ReadDirectoryChangesW on Windows.
//! - Events are read off a channel, debounced for `debounce_ms`, and
//!   coalesced per-path (the last action wins, so a save→save→delete
//!   burst produces one `Rm`).
//! - The qftp connection is opened once and held for the lifetime of
//!   the watcher. On any transport error we drop it and reconnect
//!   with exponential backoff (1s → 2s → 4s → 8s → 16s → 30s cap).
//! - Ctrl-C / SIGTERM ends the loop cleanly after the current batch.

use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use mio::{Events, Interest, Poll, Token};
use notify::{EventKind, RecursiveMode, Watcher};
use qftp_common::protocol::*;
use qftp_common::transport::*;

use crate::config::{self, ConnectionSpec, Overrides};
use crate::session_store;
use crate::transfer;

const CLIENT: Token = Token(0);

/// What we want done with one path after collapsing a burst of
/// inotify events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Upload,
    Delete,
}

pub fn run(local: &str, remote_url: &str, debounce_ms: u64, overrides: &Overrides) -> Result<i32> {
    let local_root = std::fs::canonicalize(local)
        .with_context(|| format!("watch: cannot canonicalize {local}"))?;
    if !local_root.is_dir() {
        return Err(anyhow!(
            "watch: {} is not a directory",
            local_root.display()
        ));
    }

    // Parse the remote URL. We hand the URL through the same resolver
    // the rest of the client uses so flags / aliases / TOFU behaviour
    // stay consistent.
    let url = config::parse_url(remote_url)
        .with_context(|| format!("watch: invalid remote URL {remote_url}"))?;
    let host_port = format_host_port(&url.host, url.port);
    let target = format!(
        "qftp://{host_port}{}",
        url.initial_path.as_deref().unwrap_or("/")
    );
    let spec = config::resolve(Some(&target), &config::ConfigFile::default(), overrides)?;
    let remote_prefix = url.initial_path.unwrap_or_else(|| "/".to_string());

    eprintln!(
        "watching {} -> {} (debounce {debounce_ms}ms; Ctrl-C to stop)",
        local_root.display(),
        target,
    );

    // notify crate produces events on a channel.
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let _ = tx.send(ev);
        }
    })
    .context("failed to create filesystem watcher")?;
    watcher
        .watch(&local_root, RecursiveMode::Recursive)
        .with_context(|| format!("failed to watch {}", local_root.display()))?;

    let stop = install_sigint()?;

    let mut backoff = 1u64;
    while !stop.load(Ordering::Relaxed) {
        match run_session(&spec, &rx, &local_root, &remote_prefix, debounce_ms, &stop) {
            Ok(()) => {
                tracing::info!("watch: clean exit");
                break;
            }
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                tracing::warn!(error = %e, backoff_secs = backoff, "watch: connection lost; reconnecting");
                let mut slept = 0;
                while slept < backoff && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_secs(1));
                    slept += 1;
                }
                backoff = (backoff * 2).min(30);
            }
        }
    }
    Ok(0)
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn install_sigint() -> Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    ctrlc_handler(move || {
        s.store(true, Ordering::Relaxed);
    });
    Ok(stop)
}

/// Tiny stand-in for the `ctrlc` crate: spawns a thread that blocks
/// on `signal_hook`'s SIGINT/SIGTERM iterator. We already depend on
/// the equivalent on the server side; here we keep the wrapper
/// inline so qftp-client doesn't pull in another crate.
fn ctrlc_handler(cb: impl Fn() + Send + 'static) {
    #[cfg(unix)]
    {
        std::thread::spawn(move || unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            let mut sig: i32 = 0;
            libc::sigwait(&set, &mut sig);
            cb();
        });
    }
    #[cfg(not(unix))]
    {
        // On non-Unix we degrade to "no Ctrl-C handling"; the OS
        // default will simply kill the process.
        let _ = cb;
    }
}

/// One full QUIC connection's worth of watching. Returns when the
/// stop flag fires or when something in transport / I/O goes wrong;
/// the caller then backs off and re-enters us.
fn run_session(
    spec: &ConnectionSpec,
    rx: &mpsc::Receiver<notify::Event>,
    local_root: &Path,
    remote_prefix: &str,
    debounce_ms: u64,
    stop: &AtomicBool,
) -> Result<()> {
    let (mut conn, socket, mut poll, mut events) = connect(spec)?;
    let mut next_stream_id: u64 = 0;
    let mut pending: HashMap<PathBuf, Action> = HashMap::new();
    let mut last_event_at: Option<Instant> = None;

    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        // Drain any new events with a short timeout so we can also
        // service the QUIC connection (and the stop flag).
        let wait = Duration::from_millis(debounce_ms.min(200));
        match rx.recv_timeout(wait) {
            Ok(ev) => {
                let action = match ev.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => Some(Action::Upload),
                    EventKind::Remove(_) => Some(Action::Delete),
                    _ => None,
                };
                if let Some(a) = action {
                    for p in ev.paths {
                        // Last action per path wins.
                        pending.insert(p, a);
                    }
                    last_event_at = Some(Instant::now());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow!("watcher channel closed"));
            }
        }

        // Pump QUIC even if there's nothing to do — keep the
        // connection healthy.
        conn.on_timeout();
        let mut buf = [0u8; 65535];
        handle_ingress(&mut conn, &socket, &mut buf)?;
        flush_egress(&mut conn, &socket)?;
        if conn.is_closed() {
            return Err(anyhow!("server closed the connection"));
        }

        // Once `debounce_ms` has elapsed since the last event, flush
        // the pending map.
        let ready = match last_event_at {
            Some(t) if t.elapsed() >= Duration::from_millis(debounce_ms) => true,
            None => false,
            _ => false,
        };
        if !ready {
            continue;
        }

        // #115: notify follows symlinks under the watched tree on
        // Linux. A symlink planted inside `local_root` could point at
        // `/home/user/.ssh/` and be silently uploaded. Resolve each
        // event path through `canonicalize` and confirm the *real*
        // path is still under the canonical root before acting.
        let canonical_root = local_root
            .canonicalize()
            .with_context(|| format!("canonicalize watch root {}", local_root.display()))?;
        for (path, action) in pending.drain() {
            let canonical = match path.canonicalize() {
                Ok(p) => p,
                Err(e) if matches!(action, Action::Delete) => {
                    // Removed paths can't be canonicalized — but their
                    // location can be, by taking the parent. If even
                    // the parent disappeared, just trust the strip
                    // prefix check; we're only sending an Rm.
                    path.parent()
                        .and_then(|p| p.canonicalize().ok())
                        .filter(|p| p.starts_with(&canonical_root))
                        .map(|_| path.clone())
                        .unwrap_or_else(|| {
                            tracing::warn!(error=%e, path=%path.display(),
                                "watch: cannot canonicalize delete target; skipping");
                            PathBuf::new()
                        })
                }
                Err(e) => {
                    tracing::warn!(error=%e, path=%path.display(),
                        "watch: cannot canonicalize event path; skipping");
                    continue;
                }
            };
            if canonical.as_os_str().is_empty() {
                continue;
            }
            if !canonical.starts_with(&canonical_root) {
                tracing::warn!(
                    path = %path.display(),
                    resolved = %canonical.display(),
                    "watch: ignoring event whose real path escapes the watched root (#115)"
                );
                continue;
            }
            let rel = match canonical.strip_prefix(&canonical_root) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let remote_path = join_remote(remote_prefix, rel);
            match action {
                Action::Upload => {
                    if !path.is_file() {
                        // create-then-delete arrived in the same
                        // window; skip silently.
                        continue;
                    }
                    let stream_id = take_stream(&mut next_stream_id);
                    if let Err(e) = transfer::do_put(
                        &mut conn,
                        &socket,
                        &mut poll,
                        &mut events,
                        stream_id,
                        &path,
                        &remote_path,
                        0,
                    ) {
                        tracing::warn!(error = %e, path = %path.display(), "watch: put failed");
                    } else {
                        tracing::info!(path = %remote_path, "watch: uploaded");
                    }
                }
                Action::Delete => {
                    let stream_id = take_stream(&mut next_stream_id);
                    let req = Request::Rm {
                        path: remote_path.clone(),
                    };
                    if let Err(e) = send_message(&mut conn, stream_id, &req) {
                        tracing::warn!(error = %e, "watch: rm send failed");
                        return Err(anyhow!(e));
                    }
                    let _ = stream_send_all(&mut conn, stream_id, &[], true);
                    flush_egress(&mut conn, &socket)?;
                    match poll_response(&mut conn, &socket, &mut poll, &mut events, stream_id) {
                        Ok(Response::Ok) => {
                            tracing::info!(path = %remote_path, "watch: removed");
                        }
                        Ok(Response::Err(e)) => {
                            tracing::warn!(?e.code, msg = %e.message, "watch: rm rejected");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "watch: poll_response");
                            return Err(e);
                        }
                    }
                }
            }
        }
        last_event_at = None;
    }
}

fn join_remote(prefix: &str, rel: &Path) -> String {
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    if prefix.is_empty() || prefix == "/" {
        format!("/{rel_str}")
    } else if prefix.ends_with('/') {
        format!("{prefix}{rel_str}")
    } else {
        format!("{prefix}/{rel_str}")
    }
}

fn take_stream(next: &mut u64) -> u64 {
    let cur = *next;
    *next += 4;
    cur
}

fn connect(
    spec: &ConnectionSpec,
) -> Result<(quiche::Connection, mio::net::UdpSocket, Poll, Events)> {
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
        .with_context(|| format!("watch: bad host {}", spec.host))?;
    let std_socket = UdpSocket::bind("0.0.0.0:0").context("watch: UDP bind")?;
    std_socket.set_nonblocking(true)?;
    std_socket.connect(peer_addr)?;
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

    // 0-RTT resume if we have a ticket — fast reconnect after a
    // network blip is exactly what watch mode needs.
    if let Some(dir) = session_store::default_dir() {
        if let Some(ticket) = session_store::load(&dir, &spec.host) {
            let _ = conn.set_session(&ticket);
        }
    }

    let mut poll = Poll::new()?;
    let events = Events::with_capacity(1024);
    poll.registry()
        .register(&mut socket, CLIENT, Interest::READABLE)?;

    let mut events_local = Events::with_capacity(1024);
    flush_egress(&mut conn, &socket)?;
    let mut buf = [0u8; 65535];
    loop {
        poll.poll(
            &mut events_local,
            conn.timeout().or(Some(Duration::from_millis(100))),
        )?;
        conn.on_timeout();
        handle_ingress(&mut conn, &socket, &mut buf)?;
        flush_egress(&mut conn, &socket)?;
        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            return Err(anyhow!("watch: connection closed during handshake"));
        }
    }

    Ok((conn, socket, poll, events))
}

fn poll_response(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
) -> Result<Response> {
    let mut buf = Vec::new();
    loop {
        poll.poll(events, conn.timeout().or(Some(Duration::from_millis(100))))?;
        conn.on_timeout();
        handle_ingress(conn, socket, &mut [0u8; 65535])?;
        match recv_message::<Response>(conn, stream_id, &mut buf)? {
            Some(r) => {
                flush_egress(conn, socket)?;
                return Ok(r);
            }
            None => {
                flush_egress(conn, socket)?;
            }
        }
        if conn.is_closed() {
            return Err(anyhow!("watch: connection closed mid-request"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_remote_root() {
        assert_eq!(join_remote("/", Path::new("a/b.txt")), "/a/b.txt");
    }
    #[test]
    fn join_remote_prefix() {
        assert_eq!(join_remote("/dst", Path::new("a/b.txt")), "/dst/a/b.txt");
        assert_eq!(join_remote("/dst/", Path::new("a/b.txt")), "/dst/a/b.txt");
    }
}
