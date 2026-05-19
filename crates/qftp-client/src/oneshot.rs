//! One-shot subcommand handlers. Each maps a `qftp <verb> URL …`
//! invocation to a single protocol round, sets up a connection,
//! performs the operation, and exits with a sysexits-style code.
//!
//! The dispatch point is [`run`], which the `main` function calls
//! when `Args::command` is `Some(_)`. REPL mode and one-shot mode
//! share the same connection setup so they behave identically with
//! respect to TLS, config-file aliases, and CLI overrides.

use std::io::{IsTerminal, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use mio::{Events, Interest, Poll, Token};
use qftp_common::protocol::*;
use qftp_common::transport::*;

use crate::config::{self, ConnectionSpec, Overrides};
use crate::session_store;
use crate::transfer;
use crate::OneShot;

const CLIENT: Token = Token(0);

/// sysexits.h-style exit codes. We return them via
/// `std::process::exit` so a script driver can branch on them.
pub mod exit {
    pub const OK: i32 = 0;
    pub const USAGE: i32 = 64;
    pub const DATA: i32 = 65;
    pub const NOPERM: i32 = 77;
}

/// Parsed `qftp://host[:port]/path` URL with the host/port split out
/// for connection setup and the path retained for the operation
/// itself.
#[derive(Debug, Clone)]
struct RemoteRef {
    host_port: String,
    /// SNI / cert CN expected on the server. Currently unused —
    /// `spec_from_url` rebuilds it via `config::resolve` — but kept
    /// in the struct for clarity and for future per-URL overrides.
    #[allow(dead_code)]
    server_name: String,
    user: Option<String>,
    path: String,
}

fn parse_remote(input: &str) -> Result<RemoteRef> {
    let url = config::parse_url(input).with_context(|| format!("invalid remote URL: {input}"))?;
    let path = url.initial_path.unwrap_or_else(|| "/".to_string());
    Ok(RemoteRef {
        host_port: format_host_port(&url.host, url.port),
        server_name: url.host.clone(),
        user: url.user,
        path,
    })
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Resolve a `ConnectionSpec` from a one-shot URL + overrides. The
/// URL host/port wins; CLI flags still override on top, mirroring
/// the REPL flow.
fn spec_from_url(remote: &RemoteRef, overrides: &Overrides) -> Result<ConnectionSpec> {
    // We feed the URL through the resolver so CLI overrides
    // (--host, --ca, …) follow identical precedence as REPL mode.
    let target = if let Some(u) = &remote.user {
        format!("qftp://{u}@{}{}", remote.host_port, remote.path)
    } else {
        format!("qftp://{}{}", remote.host_port, remote.path)
    };
    config::resolve(Some(&target), &config::ConfigFile::default(), overrides)
}

/// Open a connection and run a callback against the established
/// `quiche::Connection`. Returns the callback's exit code.
fn with_connection<F>(spec: &ConnectionSpec, body: F) -> Result<i32>
where
    F: FnOnce(
        &mut quiche::Connection,
        &mio::net::UdpSocket,
        &mut Poll,
        &mut Events,
        &mut u64,
    ) -> Result<i32>,
{
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
        .with_context(|| format!("failed to parse host address: {}", spec.host))?;
    let std_socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
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

    // 0-RTT session resumption. Wired exactly like the REPL path
    // (see main.rs); rejected tickets fall back silently to 1-RTT.
    // This is what makes one-shot bursts like
    //     for f in *.log; do qftp put "$f" qftp://host/logs/; done
    // skip the TLS handshake after the first iteration.
    let ticket_dir = session_store::default_dir();
    if let Some(dir) = &ticket_dir {
        if let Some(ticket) = session_store::load(dir, &spec.host) {
            match conn.set_session(&ticket) {
                Ok(()) => {
                    tracing::info!(host = %spec.host, "one-shot: 0-RTT resuming");
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "stale session ticket; falling back to 1-RTT");
                    let _ = session_store::forget(dir, &spec.host);
                }
            }
        }
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    poll.registry()
        .register(&mut socket, CLIENT, Interest::READABLE)?;

    flush_egress(&mut conn, &socket)?;
    loop {
        poll.poll(
            &mut events,
            conn.timeout().or(Some(Duration::from_millis(100))),
        )?;
        conn.on_timeout();
        handle_ingress(&mut conn, &socket, &mut [0u8; 65535])?;
        flush_egress(&mut conn, &socket)?;

        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            anyhow::bail!("Connection closed during handshake");
        }
    }

    let mut next_stream_id: u64 = 0;
    let code = body(
        &mut conn,
        &socket,
        &mut poll,
        &mut events,
        &mut next_stream_id,
    )?;

    // Polite close.
    let qid = take_stream(&mut next_stream_id);
    let _ = send_message(&mut conn, qid, &Request::Quit);
    let _ = stream_send_all(&mut conn, qid, &[], true);
    let _ = flush_egress(&mut conn, &socket);

    // Save the latest session ticket so the *next* one-shot can
    // 0-RTT-resume. Best-effort: a write failure means the next
    // invocation pays the 1-RTT cost, nothing worse.
    if let Some(dir) = &ticket_dir {
        if let Err(e) = session_store::save(dir, &spec.host, conn.session()) {
            tracing::warn!(error = ?e, "failed to persist session ticket");
        }
    }

    Ok(code)
}

fn take_stream(next: &mut u64) -> u64 {
    let cur = *next;
    *next += 4;
    cur
}

/// Single round-trip request that expects a single `Response`.
fn one_request(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    req: &Request,
) -> Result<Response> {
    let stream_id = take_stream(next_stream_id);
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
            Some(resp) => {
                flush_egress(conn, socket)?;
                return Ok(resp);
            }
            None => {
                flush_egress(conn, socket)?;
            }
        }
        if conn.is_closed() {
            anyhow::bail!("Connection closed");
        }
    }
}

/// Map a `Response::Err` ErrorCode to a sysexits-style exit code so a
/// shell script can branch on the failure reason.
fn err_to_exit(code: &ErrorCode) -> i32 {
    use ErrorCode::*;
    match code {
        Unauthorized | PermissionDenied => exit::NOPERM,
        Malformed => exit::USAGE,
        _ => exit::DATA,
    }
}

fn report_response_for_status(resp: &Response) -> i32 {
    match resp {
        Response::Ok => exit::OK,
        Response::Err(e) => {
            eprintln!("Error [{:?}]: {}", e.code, e.message);
            err_to_exit(&e.code)
        }
        other => {
            eprintln!("Unexpected response: {other:?}");
            exit::DATA
        }
    }
}

/// Dispatch entry point called from `main`. Returns the process
/// exit code; `main` calls `std::process::exit` with it.
pub fn run(cmd: OneShot, overrides: Overrides) -> Result<i32> {
    match cmd {
        OneShot::Put {
            local,
            remote,
            recursive,
        } => run_put(&local, &remote, recursive, &overrides),
        OneShot::Get {
            remote,
            local,
            recursive,
        } => run_get(&remote, local.as_deref(), recursive, &overrides),
        OneShot::Ls { remote } => run_remote_oneshot(&remote, &overrides, |path| Request::Ls {
            path: path.into(),
        }),
        OneShot::Rm { remote } => run_remote_oneshot(&remote, &overrides, |path| Request::Rm {
            path: path.into(),
        }),
        OneShot::Mkdir { remote } => run_remote_oneshot(&remote, &overrides, |path| {
            Request::Mkdir { path: path.into() }
        }),
        OneShot::Rmdir { remote } => run_remote_oneshot(&remote, &overrides, |path| {
            Request::Rmdir { path: path.into() }
        }),
        OneShot::Rename { from, to } => run_rename(&from, &to, &overrides),
        OneShot::Stat { remote } => run_stat(&remote, &overrides),
        OneShot::Watch {
            local,
            remote,
            debounce_ms,
        } => crate::watch::run(&local, &remote, debounce_ms, &overrides),
        OneShot::Sync {
            local,
            remote,
            delete,
            checksum,
            dry_run,
        } => crate::sync::run(
            &local,
            &remote,
            crate::sync::Opts {
                delete,
                use_checksum: checksum,
                dry_run,
            },
            &overrides,
        ),
        OneShot::PutMulti {
            local,
            remote_path,
            to,
            strict,
        } => crate::fanout::run(&local, &remote_path, &to, strict, &overrides),
    }
}

/// Generic "URL -> single request -> single response -> exit code".
fn run_remote_oneshot(
    url: &str,
    overrides: &Overrides,
    build: impl FnOnce(&str) -> Request,
) -> Result<i32> {
    let r = parse_remote(url)?;
    let spec = spec_from_url(&r, overrides)?;
    let req = build(&r.path);
    with_connection(&spec, |conn, socket, poll, events, next| {
        let resp = one_request(conn, socket, poll, events, next, &req)?;
        // Special-case Response::Path for Pwd / Stat-like reads:
        // print the value so the user actually sees something.
        if let Response::Path(p) = &resp {
            println!("{p}");
        } else if let Response::DirListing(entries) = &resp {
            for e in entries {
                println!("{} {} {}", if e.is_dir { 'd' } else { '-' }, e.size, e.name);
            }
        }
        Ok(report_response_for_status(&resp))
    })
}

fn run_stat(url: &str, overrides: &Overrides) -> Result<i32> {
    let r = parse_remote(url)?;
    let spec = spec_from_url(&r, overrides)?;
    let req = Request::Stat {
        path: r.path.clone(),
    };
    with_connection(&spec, |conn, socket, poll, events, next| {
        let resp = one_request(conn, socket, poll, events, next, &req)?;
        match &resp {
            Response::FileStat(s) => {
                println!("size  {}", s.size);
                println!("kind  {}", if s.is_dir { "directory" } else { "file" });
                println!("mode  {:o}", s.mode & 0o777);
                println!("mtime {}", s.modified);
                Ok(exit::OK)
            }
            _ => Ok(report_response_for_status(&resp)),
        }
    })
}

fn run_rename(from_url: &str, to_url: &str, overrides: &Overrides) -> Result<i32> {
    let from = parse_remote(from_url)?;
    let to = parse_remote(to_url)?;
    if from.host_port != to.host_port {
        return Err(anyhow!(
            "rename across hosts is not supported ({} vs {})",
            from.host_port,
            to.host_port
        ));
    }
    let spec = spec_from_url(&from, overrides)?;
    let req = Request::Rename {
        from: from.path.clone(),
        to: to.path.clone(),
    };
    with_connection(&spec, |conn, socket, poll, events, next| {
        let resp = one_request(conn, socket, poll, events, next, &req)?;
        Ok(report_response_for_status(&resp))
    })
}

fn run_get(
    remote_url: &str,
    local: Option<&str>,
    recursive: bool,
    overrides: &Overrides,
) -> Result<i32> {
    if recursive {
        // For now, surface a clear message rather than partially
        // implementing recursive walking in one-shot. The REPL form
        // (`get -r`) covers this case; #67 follow-up can wire it up
        // here once the REPL/BFS helper is extracted.
        return Err(anyhow!(
            "one-shot `get -r` is not yet implemented (use the REPL: \
             qftp-client qftp://host -e 'get -r remote local')"
        ));
    }
    let r = parse_remote(remote_url)?;
    let spec = spec_from_url(&r, overrides)?;
    let local_path = match local {
        Some(p) => PathBuf::from(p),
        None => {
            // Mirror REPL behaviour: take the remote basename.
            let name = Path::new(&r.path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "download".to_string());
            PathBuf::from(name)
        }
    };
    with_connection(&spec, |conn, socket, poll, events, next| {
        let stream_id = take_stream(next);
        match transfer::do_get(conn, socket, poll, events, stream_id, &r.path, &local_path) {
            Ok(()) => Ok(exit::OK),
            Err(e) => {
                eprintln!("get failed: {e}");
                Ok(exit::DATA)
            }
        }
    })
}

fn run_put(
    locals: &[String],
    remote_url: &str,
    recursive: bool,
    overrides: &Overrides,
) -> Result<i32> {
    if locals.is_empty() {
        return Err(anyhow!("put requires at least one local file"));
    }
    if recursive {
        return Err(anyhow!(
            "one-shot `put -r` is not yet implemented (use the REPL: \
             qftp-client qftp://host -e 'put -r src/ dst/')"
        ));
    }
    let r = parse_remote(remote_url)?;
    let spec = spec_from_url(&r, overrides)?;

    // The remote URL path can be either a directory (every local
    // file lands under it with its original basename) or a single
    // file name (only valid for a single local). We treat a
    // trailing '/' or multiple locals as the "directory target"
    // case.
    let multiple = locals.len() > 1;
    let target_is_dir = r.path.ends_with('/') || multiple;

    with_connection(&spec, |conn, socket, poll, events, next| {
        let mut worst = exit::OK;
        for local in locals {
            let local_path = PathBuf::from(local);
            let dest = if target_is_dir {
                let base = Path::new(local)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "uploaded".to_string());
                if r.path.ends_with('/') {
                    format!("{}{}", r.path, base)
                } else if r.path.is_empty() {
                    base
                } else {
                    format!("{}/{}", r.path, base)
                }
            } else {
                r.path.clone()
            };
            let stream_id = take_stream(next);
            match transfer::do_put(conn, socket, poll, events, stream_id, &local_path, &dest, 0) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("put {local} -> {dest} failed: {e}");
                    worst = exit::DATA;
                }
            }
        }
        Ok(worst)
    })
}

// Suppress dead-code warning until additional UX features (#73,
// #80) use this; keeps the helper public to other modules without
// triggering clippy on this PR alone.
#[allow(dead_code)]
fn is_tty() -> bool {
    std::io::stdout().is_terminal()
}

#[allow(dead_code)]
fn flush_stdout() {
    let _ = std::io::stdout().flush();
}
