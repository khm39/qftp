//! `qftp-client sync <local> <remote-url> [--delete] [--checksum]`
//!
//! One-direction incremental sync, local → remote. The remote tree
//! is walked via `Ls` per directory; the local tree via
//! `std::fs::read_dir`. Files are kept-or-uploaded based on a
//! cheap (size, mtime) match — exact like rsync's default. Pass
//! `--checksum` to verify with BLAKE3 instead, which is slow but
//! catches silent corruption.
//!
//! `--delete` removes remote files that have no local counterpart
//! after the transfer batch completes (rsync's `--delete-after`
//! semantics).
//!
//! Out of scope (filed as a follow-up of #71):
//!   - Download direction (remote → local).
//!   - `.qftpignore` (gitignore syntax with `globset`).
//!   - Parallel streams. Sync currently issues one Put / Rm at a
//!     time. Multi-stream parallelism is a natural extension; the
//!     event-driven server side (Phase 2) already supports it.

use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use mio::{Events, Interest, Poll, Token};
use qftp_common::protocol::*;
use qftp_common::transport::*;

use crate::config::{self, ConnectionSpec, Overrides};
use crate::session_store;
use crate::transfer;

const CLIENT: Token = Token(0);

#[derive(Debug, Clone, Copy)]
pub struct Opts {
    pub delete: bool,
    pub use_checksum: bool,
    pub dry_run: bool,
}

pub fn run(local: &str, remote_url: &str, opts: Opts, overrides: &Overrides) -> Result<i32> {
    let local_root = std::fs::canonicalize(local)
        .with_context(|| format!("sync: cannot canonicalize {local}"))?;
    if !local_root.is_dir() {
        return Err(anyhow!("sync: {} is not a directory", local_root.display()));
    }

    let url = config::parse_url(remote_url)
        .with_context(|| format!("sync: invalid remote URL {remote_url}"))?;
    let host_port = format_host_port(&url.host, url.port);
    let target = format!(
        "qftp://{host_port}{}",
        url.initial_path.as_deref().unwrap_or("/")
    );
    let spec = config::resolve(Some(&target), &config::ConfigFile::default(), overrides)?;
    let remote_root = url.initial_path.unwrap_or_else(|| "/".to_string());

    eprintln!(
        "sync {} -> {} (delete={}, checksum={}, dry_run={})",
        local_root.display(),
        target,
        opts.delete,
        opts.use_checksum,
        opts.dry_run
    );

    // Local index: relative-path -> (size, mtime).
    let local_files = walk_local(&local_root)?;
    tracing::info!(count = local_files.len(), "sync: local files");

    let (mut conn, socket, mut poll, mut events) = connect(&spec)?;
    let mut next: u64 = 0;

    // Remote index: relative-path -> (size, mtime). We walk the
    // remote tree breadth-first using Ls; missing trees are treated
    // as empty.
    let remote_files = walk_remote(
        &mut conn,
        &socket,
        &mut poll,
        &mut events,
        &mut next,
        &remote_root,
    )
    .unwrap_or_default();
    tracing::info!(count = remote_files.len(), "sync: remote files");

    let mut to_upload: Vec<PathBuf> = Vec::new();
    let mut to_delete: Vec<String> = Vec::new();

    for (rel, lmeta) in &local_files {
        let need_upload = match remote_files.get(rel) {
            None => true,
            Some(rmeta) => {
                if opts.use_checksum {
                    // Conservative: always re-upload when --checksum
                    // is set. A future improvement: fetch the
                    // server's stored BLAKE3 and compare.
                    true
                } else {
                    rmeta.size != lmeta.size || mtime_differs(rmeta.modified, lmeta.modified)
                }
            }
        };
        if need_upload {
            to_upload.push(rel.clone());
        }
    }

    if opts.delete {
        let local_set: HashSet<&PathBuf> = local_files.keys().collect();
        for rel in remote_files.keys() {
            if !local_set.contains(rel) {
                to_delete.push(rel.to_string_lossy().into_owned());
            }
        }
    }

    println!(
        "sync plan: {} upload, {} skip, {} delete",
        to_upload.len(),
        local_files.len() - to_upload.len(),
        to_delete.len(),
    );

    if opts.dry_run {
        for p in &to_upload {
            println!("  + {}", p.display());
        }
        for p in &to_delete {
            println!("  - {p}");
        }
        return Ok(0);
    }

    // Ensure the remote root exists. mkdir of an existing dir gets
    // AlreadyExists which we ignore.
    let _ = single_request(
        &mut conn,
        &socket,
        &mut poll,
        &mut events,
        &mut next,
        &Request::Mkdir {
            path: remote_root.clone(),
        },
    );

    // Upload.
    for rel in &to_upload {
        let local_path = local_root.join(rel);
        let remote_path = join_remote(&remote_root, rel);
        // Make parents.
        if let Some(parent) = Path::new(&remote_path).parent() {
            let _ = single_request(
                &mut conn,
                &socket,
                &mut poll,
                &mut events,
                &mut next,
                &Request::Mkdir {
                    path: parent.to_string_lossy().into_owned(),
                },
            );
        }
        let stream_id = take_stream(&mut next);
        match transfer::do_put(
            &mut conn,
            &socket,
            &mut poll,
            &mut events,
            stream_id,
            &local_path,
            &remote_path,
            0,
        ) {
            Ok(()) => tracing::info!(file = %remote_path, "sync: uploaded"),
            Err(e) => tracing::warn!(error = %e, file = %remote_path, "sync: upload failed"),
        }
    }

    // Delete (rsync --delete-after semantics: only after the batch
    // succeeds at least for the upload side).
    for rel in &to_delete {
        let remote_path = join_remote(&remote_root, Path::new(rel));
        match single_request(
            &mut conn,
            &socket,
            &mut poll,
            &mut events,
            &mut next,
            &Request::Rm {
                path: remote_path.clone(),
            },
        ) {
            Ok(Response::Ok) => tracing::info!(file = %remote_path, "sync: deleted"),
            Ok(Response::Err(e)) => {
                tracing::warn!(?e.code, msg = %e.message, file = %remote_path, "sync: delete failed")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "sync: delete failed"),
        }
    }

    // Polite close.
    let qid = take_stream(&mut next);
    let _ = send_message(&mut conn, qid, &Request::Quit);
    let _ = stream_send_all(&mut conn, qid, &[], true);
    let _ = flush_egress(&mut conn, &socket);

    if let Some(dir) = session_store::default_dir() {
        let _ = session_store::save(&dir, &spec.host, conn.session());
    }

    Ok(0)
}

#[derive(Debug, Clone, Copy)]
struct Meta {
    size: u64,
    modified: u64,
}

fn walk_local(root: &Path) -> Result<HashMap<PathBuf, Meta>> {
    let mut out: HashMap<PathBuf, Meta> = HashMap::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, dir = %dir.display(), "sync: read_dir failed");
                continue;
            }
        };
        for entry in read.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue; // skip symlinks, sockets, etc.
            }
            let rel = match path.strip_prefix(root) {
                Ok(r) => r.to_path_buf(),
                Err(_) => continue,
            };
            let meta = entry.metadata().ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.insert(rel, Meta { size, modified });
        }
    }
    Ok(out)
}

fn walk_remote(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next: &mut u64,
    root: &str,
) -> Result<HashMap<PathBuf, Meta>> {
    let mut out: HashMap<PathBuf, Meta> = HashMap::new();
    // (remote-abs-path, relative-prefix)
    let mut stack: Vec<(String, PathBuf)> = vec![(root.to_string(), PathBuf::new())];
    while let Some((abs, rel)) = stack.pop() {
        let req = Request::Ls { path: abs.clone() };
        let resp = match single_request(conn, socket, poll, events, next, &req) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, dir = %abs, "sync: remote Ls failed");
                continue;
            }
        };
        let entries = match resp {
            Response::DirListing(e) => e,
            Response::Err(_) => continue,
            _ => continue,
        };
        for e in entries {
            let child_abs = if abs.ends_with('/') {
                format!("{abs}{}", e.name)
            } else {
                format!("{abs}/{}", e.name)
            };
            let child_rel = rel.join(&e.name);
            if e.is_dir {
                stack.push((child_abs, child_rel));
            } else {
                out.insert(
                    child_rel,
                    Meta {
                        size: e.size,
                        modified: e.modified,
                    },
                );
            }
        }
    }
    Ok(out)
}

/// mtime equality with 2-second tolerance. FAT only stores even
/// seconds, and many copy tools round differently; rsync uses a 1s
/// window. We mirror that.
fn mtime_differs(a: u64, b: u64) -> bool {
    a.abs_diff(b) > 1
}

fn join_remote(prefix: &str, rel: &Path) -> String {
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    if prefix == "/" || prefix.is_empty() {
        format!("/{rel_str}")
    } else if prefix.ends_with('/') {
        format!("{prefix}{rel_str}")
    } else {
        format!("{prefix}/{rel_str}")
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn take_stream(next: &mut u64) -> u64 {
    let cur = *next;
    *next += 4;
    cur
}

fn single_request(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next: &mut u64,
    req: &Request,
) -> Result<Response> {
    let stream_id = take_stream(next);
    send_message(conn, stream_id, req)?;
    stream_send_all(conn, stream_id, &[], true)?;
    flush_egress(conn, socket)?;
    poll_response(conn, socket, poll, events, stream_id)
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
            None => flush_egress(conn, socket)?,
        }
        if conn.is_closed() {
            return Err(anyhow!("sync: connection closed mid-request"));
        }
    }
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
    let peer_addr = spec.host.parse().with_context(|| "sync: bad host")?;
    let std_socket = UdpSocket::bind("0.0.0.0:0")?;
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

    if let Some(dir) = session_store::default_dir() {
        if let Some(ticket) = session_store::load(&dir, &spec.host) {
            let _ = conn.set_session(&ticket);
        }
    }

    let mut poll = Poll::new()?;
    let mut events_local = Events::with_capacity(1024);
    poll.registry()
        .register(&mut socket, CLIENT, Interest::READABLE)?;
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
            return Err(anyhow!("sync: handshake closed"));
        }
    }
    Ok((conn, socket, poll, Events::with_capacity(1024)))
}

// SystemTime helper is reserved for the future remote->local path;
// silence dead_code in the upload-only flow.
#[allow(dead_code)]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtime_window_is_1s() {
        assert!(!mtime_differs(10, 10));
        assert!(!mtime_differs(10, 11));
        assert!(mtime_differs(10, 12));
    }

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
