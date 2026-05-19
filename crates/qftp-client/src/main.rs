use std::io::{BufRead, IsTerminal};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use mio::{Events, Interest, Poll, Token};
use qftp_common::protocol::*;
use qftp_common::transport::*;

mod config;
mod known_hosts;
mod repl;
mod session_store;
mod transfer;

const CLIENT: Token = Token(0);

#[derive(Parser)]
#[command(
    name = "qftp-client",
    about = "QUIC File Transfer Protocol Client",
    long_about = "Connect to a qftp server. The positional TARGET is either a \
        qftp:// URL (e.g. qftp://user@host:4433/path) or the name of a host \
        alias defined in ~/.qftp/config.toml. Flag overrides have the highest \
        precedence; URL fields beat alias fields; builtin defaults are last."
)]
struct Args {
    /// `qftp://[user@]host[:port][/path]`, `qftps://...`, or a host
    /// alias defined in the config file. When omitted, falls back to
    /// the legacy `--host` / `--server-name` flags and defaults.
    target: Option<String>,
    /// Path to the client config file. Defaults to
    /// `~/.qftp/config.toml`.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override host (and optionally port) as `ip:port`. Beats URL /
    /// alias.
    #[arg(long)]
    host: Option<String>,
    /// Override SNI / certificate name expected on the server cert.
    #[arg(long)]
    server_name: Option<String>,
    #[arg(long)]
    ca: Option<String>,
    /// Skip server certificate verification. Development only.
    #[arg(long)]
    insecure: bool,
    /// Pin the server's TLS leaf certificate on first connect
    /// (SSH-style known_hosts). Subsequent connects refuse to
    /// continue if the fingerprint changes. Use this instead of
    /// `--insecure` when there is no CA infrastructure.
    #[arg(long = "trust-on-first-use", short = 'T')]
    trust_on_first_use: bool,
    /// Override the known_hosts file location.
    /// Defaults to `~/.qftp/known_hosts`.
    #[arg(long)]
    known_hosts: Option<PathBuf>,
    /// Disable 0-RTT session resumption. The client will still
    /// receive new tickets but won't replay them. Useful for
    /// debugging and when you need to ensure a fresh handshake.
    #[arg(long, default_value_t = false)]
    no_zero_rtt: bool,
    /// Override the session-ticket directory.
    /// Defaults to `~/.qftp/session-tickets/`.
    #[arg(long)]
    session_ticket_dir: Option<PathBuf>,
    #[arg(long, requires = "client_key")]
    client_cert: Option<String>,
    #[arg(long, requires = "client_cert")]
    client_key: Option<String>,
    /// Run a single command non-interactively and exit. Repeatable.
    #[arg(long = "execute", short = 'e')]
    execute: Vec<String>,
    /// Read commands from stdin (one per line) instead of opening an
    /// interactive REPL. Useful for scripted batch transfers.
    #[arg(long, default_value_t = false)]
    batch: bool,
    /// Path to the command history file. Defaults to
    /// `~/.qftp_history`.
    #[arg(long)]
    history: Option<PathBuf>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let config_path = args
        .config
        .as_ref()
        .map(|p| PathBuf::from(config::expand_tilde(&p.to_string_lossy())))
        .or_else(config::default_config_path);
    let cfg_file = match &config_path {
        Some(p) => config::ConfigFile::load(p)?,
        None => config::ConfigFile::default(),
    };

    let overrides = config::Overrides {
        host: args.host.clone(),
        server_name: args.server_name.clone(),
        insecure: if args.insecure { Some(true) } else { None },
        ca: args.ca.clone(),
        client_cert: args.client_cert.clone(),
        client_key: args.client_key.clone(),
    };

    let spec = config::resolve(args.target.as_deref(), &cfg_file, &overrides)?;

    let client_cert = match (&spec.client_cert, &spec.client_key) {
        (Some(c), Some(k)) => Some(qftp_common::transport::ClientCert {
            cert_pem: c.clone(),
            key_pem: k.clone(),
        }),
        _ => None,
    };

    // TOFU is only meaningful when the user has *not* supplied a CA
    // bundle. A `--ca` overrides it (we trust the PKI chain). When
    // TOFU is active we ask quiche to skip its own peer verification
    // and run the fingerprint check ourselves after the handshake.
    let tofu_active = args.trust_on_first_use && spec.ca.is_none() && !spec.insecure;
    let effective_verify_peer = !spec.insecure && !tofu_active;

    let mut config = create_client_config(qftp_common::transport::ClientTlsConfig {
        verify_peer: effective_verify_peer,
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

    // 0-RTT session resumption. If a fresh ticket exists for this
    // host:port, hand it to quiche before any I/O so the first
    // outgoing Initial carries 0-RTT data. A rejected ticket is a
    // silent fallback to 1-RTT; we delete it so we don't keep
    // replaying a bad blob.
    let ticket_dir = args
        .session_ticket_dir
        .clone()
        .or_else(session_store::default_dir);
    let mut resumed = false;
    if !args.no_zero_rtt {
        if let Some(dir) = &ticket_dir {
            if let Some(ticket) = session_store::load(dir, &spec.host) {
                match conn.set_session(&ticket) {
                    Ok(()) => {
                        resumed = true;
                        tracing::info!(host = %spec.host, "0-RTT: resuming session");
                    }
                    Err(e) => {
                        tracing::warn!(error = ?e, "stale session ticket; falling back to 1-RTT");
                        let _ = session_store::forget(dir, &spec.host);
                    }
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

    if tofu_active {
        let kh_path = args
            .known_hosts
            .clone()
            .or_else(known_hosts::default_path)
            .context("$HOME is not set; --known-hosts must be provided for TOFU")?;
        let der = conn
            .peer_cert()
            .context("server presented no certificate; cannot pin")?;
        let seen = known_hosts::fingerprint_hex(der);
        let kh = known_hosts::KnownHosts::load(&kh_path)?;
        match kh.lookup(&spec.host, &seen) {
            known_hosts::Verdict::Match => {
                tracing::info!(
                    host = %spec.host,
                    fingerprint = %format!("sha256:{seen}"),
                    "TOFU: pinned, matched"
                );
            }
            known_hosts::Verdict::New => {
                known_hosts::KnownHosts::append_to_file(&kh_path, &spec.host, &seen)?;
                eprintln!(
                    "The authenticity of host '{}' can't be established.",
                    spec.host
                );
                eprintln!("Server cert fingerprint is sha256:{seen}");
                eprintln!("Pinned in {}.", kh_path.display());
            }
            known_hosts::Verdict::Mismatch { pinned } => {
                conn.close(true, 0x0, b"server cert pin mismatch").ok();
                let _ = flush_egress(&mut conn, &socket);
                return Err(known_hosts::mismatch_error(&spec.host, &pinned, &seen));
            }
        }
    }

    if resumed && conn.is_resumed() {
        eprintln!("Connected to {} (0-RTT resumed)", spec.host);
    } else {
        eprintln!("Connected to {}", spec.host);
    }

    // Determine the source of commands: --execute > --batch/stdin
    // pipeline > interactive TTY.
    let mut next_stream_id: u64 = 0;
    let mut quit_requested = false;

    if let Some(path) = &spec.initial_path {
        let stream_id = take_stream(&mut next_stream_id);
        send_message(&mut conn, stream_id, &Request::Cd { path: path.clone() })?;
        stream_send_all(&mut conn, stream_id, &[], true)?;
        flush_egress(&mut conn, &socket)?;
        match poll_response(&mut conn, &socket, &mut poll, &mut events, stream_id)? {
            Response::Ok => {}
            Response::Err(e) => {
                eprintln!("initial cd {} failed: [{:?}] {}", path, e.code, e.message);
            }
            other => {
                eprintln!("initial cd: unexpected response {other:?}");
            }
        }
    }

    if !args.execute.is_empty() {
        for line in &args.execute {
            if quit_requested {
                break;
            }
            run_one_line(
                line,
                &mut conn,
                &socket,
                &mut poll,
                &mut events,
                &mut next_stream_id,
                &mut quit_requested,
            )?;
        }
    } else if args.batch || !std::io::stdin().is_terminal() {
        let stdin = std::io::stdin();
        let handle = stdin.lock();
        for line in handle.lines() {
            if quit_requested {
                break;
            }
            let line = line.context("reading stdin")?;
            run_one_line(
                &line,
                &mut conn,
                &socket,
                &mut poll,
                &mut events,
                &mut next_stream_id,
                &mut quit_requested,
            )?;
        }
    } else {
        run_interactive(
            &args,
            &mut conn,
            &socket,
            &mut poll,
            &mut events,
            &mut next_stream_id,
        )?;
    }

    if !quit_requested {
        // Try a polite Quit so the server logs a clean close.
        let stream_id = take_stream(&mut next_stream_id);
        let _ = send_message(&mut conn, stream_id, &Request::Quit);
        let _ = stream_send_all(&mut conn, stream_id, &[], true);
        let _ = flush_egress(&mut conn, &socket);
    }

    // Persist the latest session ticket so the next connect can
    // 0-RTT-resume. `conn.session()` returns the freshest ticket
    // received during this connection; saving on every clean exit
    // means we keep the post-handshake-rotated ticket too.
    if !args.no_zero_rtt {
        if let Some(dir) = &ticket_dir {
            if let Err(e) = session_store::save(dir, &spec.host, conn.session()) {
                tracing::warn!(error = ?e, "failed to persist session ticket");
            }
        }
    }

    eprintln!("Goodbye.");
    Ok(())
}

fn run_interactive(
    args: &Args,
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
) -> Result<()> {
    let mut rl = rustyline::DefaultEditor::new()?;
    let hist_path = history_path(args);
    if let Some(p) = &hist_path {
        let _ = rl.load_history(p);
    }
    let mut quit = false;
    loop {
        if quit {
            break;
        }
        let line = match rl.readline("qftp> ") {
            Ok(l) => l,
            Err(
                rustyline::error::ReadlineError::Interrupted | rustyline::error::ReadlineError::Eof,
            ) => break,
            Err(e) => {
                println!("readline error: {e}");
                break;
            }
        };
        let _ = rl.add_history_entry(&line);
        run_one_line(&line, conn, socket, poll, events, next_stream_id, &mut quit)?;
    }
    if let Some(p) = hist_path {
        let _ = rl.save_history(&p);
    }
    Ok(())
}

fn history_path(args: &Args) -> Option<PathBuf> {
    if let Some(p) = &args.history {
        return Some(p.clone());
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".qftp_history"))
}

fn run_one_line(
    line: &str,
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    quit_out: &mut bool,
) -> Result<()> {
    let cmd = match repl::parse_command(line) {
        Some(c) => c,
        None => return Ok(()),
    };

    match cmd {
        repl::Command::Remote(req) => {
            let is_quit = matches!(req, Request::Quit);
            let stream_id = take_stream(next_stream_id);
            send_message(conn, stream_id, &req)?;
            stream_send_all(conn, stream_id, &[], true)?;
            flush_egress(conn, socket)?;
            let resp = poll_response(conn, socket, poll, events, stream_id)?;
            repl::display_response(&resp);
            if is_quit {
                *quit_out = true;
            }
        }
        repl::Command::Get {
            remote,
            local,
            recursive,
        } => {
            if recursive {
                do_recursive_get(conn, socket, poll, events, next_stream_id, &remote, local)?;
            } else {
                let stream_id = take_stream(next_stream_id);
                let local_path = local.map(PathBuf::from).unwrap_or_else(|| {
                    Path::new(&remote)
                        .file_name()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from(remote.clone()))
                });
                if let Err(e) =
                    transfer::do_get(conn, socket, poll, events, stream_id, &remote, &local_path)
                {
                    println!("get failed: {e}");
                }
            }
        }
        repl::Command::Put {
            local,
            remote,
            recursive,
        } => {
            // Expand local glob first (recursive or not).
            let locals = expand_glob(&local);
            if locals.is_empty() {
                println!("no local files match {local}");
                return Ok(());
            }
            if recursive {
                for path in locals {
                    let remote_root = remote.clone().unwrap_or_else(|| {
                        path.file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| ".".to_string())
                    });
                    if let Err(e) = do_recursive_put(
                        conn,
                        socket,
                        poll,
                        events,
                        next_stream_id,
                        &path,
                        &remote_root,
                    ) {
                        println!("put -r {} failed: {e}", path.display());
                    }
                }
            } else {
                for path in locals {
                    let stream_id = take_stream(next_stream_id);
                    let target = remote.clone().unwrap_or_else(|| {
                        path.file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "uploaded".to_string())
                    });
                    if let Err(e) =
                        transfer::do_put(conn, socket, poll, events, stream_id, &path, &target, 0)
                    {
                        println!("put {} failed: {e}", path.display());
                    }
                }
            }
        }
    }
    Ok(())
}

fn take_stream(next: &mut u64) -> u64 {
    let cur = *next;
    *next += 4;
    cur
}

fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => paths.filter_map(|p| p.ok()).collect(),
        Err(_) => vec![PathBuf::from(pattern)],
    }
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

/// Walk the remote directory tree, downloading every file under `remote`
/// into `local_root`. The remote layout is preserved relative to
/// `remote`.
fn do_recursive_get(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    remote: &str,
    local_root: Option<String>,
) -> Result<()> {
    let local_root = local_root.map(PathBuf::from).unwrap_or_else(|| {
        Path::new(remote)
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(remote))
    });
    std::fs::create_dir_all(&local_root).ok();

    // BFS via Ls.
    let mut queue: Vec<(String, PathBuf)> = vec![(remote.to_string(), local_root.clone())];
    while let Some((rdir, ldir)) = queue.pop() {
        let stream_id = take_stream(next_stream_id);
        let req = Request::Ls { path: rdir.clone() };
        send_message(conn, stream_id, &req)?;
        stream_send_all(conn, stream_id, &[], true)?;
        flush_egress(conn, socket)?;
        let resp = poll_response(conn, socket, poll, events, stream_id)?;
        let entries = match resp {
            Response::DirListing(e) => e,
            Response::Err(e) => {
                repl::display_error(&e);
                continue;
            }
            other => {
                println!("unexpected response listing {rdir}: {other:?}");
                continue;
            }
        };
        std::fs::create_dir_all(&ldir).ok();
        for entry in entries {
            let remote_child = if rdir.ends_with('/') {
                format!("{rdir}{}", entry.name)
            } else {
                format!("{rdir}/{}", entry.name)
            };
            let local_child = ldir.join(&entry.name);
            if entry.is_dir {
                queue.push((remote_child, local_child));
            } else {
                let stream_id = take_stream(next_stream_id);
                if let Err(e) = transfer::do_get(
                    conn,
                    socket,
                    poll,
                    events,
                    stream_id,
                    &remote_child,
                    &local_child,
                ) {
                    println!("get {} failed: {e}", remote_child);
                }
            }
        }
    }
    Ok(())
}

/// Walk a local directory and upload every regular file under it,
/// mirroring its structure under `remote_root`.
fn do_recursive_put(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    local: &Path,
    remote_root: &str,
) -> Result<()> {
    if !local.is_dir() {
        // -r on a file degrades to a normal put.
        let stream_id = take_stream(next_stream_id);
        return transfer::do_put(conn, socket, poll, events, stream_id, local, remote_root, 0);
    }
    // Ensure top-level mkdir.
    let stream_id = take_stream(next_stream_id);
    send_message(
        conn,
        stream_id,
        &Request::Mkdir {
            path: remote_root.to_string(),
        },
    )?;
    stream_send_all(conn, stream_id, &[], true)?;
    flush_egress(conn, socket)?;
    let _ = poll_response(conn, socket, poll, events, stream_id)?;

    // BFS local.
    let mut queue: Vec<(PathBuf, String)> = vec![(local.to_path_buf(), remote_root.to_string())];
    while let Some((dir, rremote)) = queue.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                println!("read_dir {} failed: {e}", dir.display());
                continue;
            }
        };
        for entry in read.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy().into_owned();
            let remote_child = if rremote.ends_with('/') {
                format!("{rremote}{name_str}")
            } else {
                format!("{rremote}/{name_str}")
            };
            if path.is_dir() {
                let stream_id = take_stream(next_stream_id);
                send_message(
                    conn,
                    stream_id,
                    &Request::Mkdir {
                        path: remote_child.clone(),
                    },
                )?;
                stream_send_all(conn, stream_id, &[], true)?;
                flush_egress(conn, socket)?;
                let _ = poll_response(conn, socket, poll, events, stream_id)?;
                queue.push((path, remote_child));
            } else {
                let stream_id = take_stream(next_stream_id);
                if let Err(e) = transfer::do_put(
                    conn,
                    socket,
                    poll,
                    events,
                    stream_id,
                    &path,
                    &remote_child,
                    0,
                ) {
                    println!("put {} failed: {e}", path.display());
                }
            }
        }
    }
    Ok(())
}
