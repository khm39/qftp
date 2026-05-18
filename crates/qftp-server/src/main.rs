use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use clap::Parser;
use mio::{Events, Interest, Poll, Token};
use qftp_common::protocol::*;
use qftp_common::transport::*;
use tracing::{debug, info, warn};

mod handler;

const SERVER: Token = Token(0);

/// Maximum file size accepted by Get/Put.
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Chunk size used for streaming file reads and stream sends.
const FILE_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Parser)]
#[command(name = "qftp-server", about = "QUIC File Transfer Protocol Server")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    bind: String,
    #[arg(long, default_value = ".")]
    root: String,
    /// PEM-encoded server certificate chain. Required unless --self-signed.
    #[arg(long, required_unless_present = "self_signed")]
    cert: Option<String>,
    /// PEM-encoded server private key. Required unless --self-signed.
    #[arg(long, required_unless_present = "self_signed")]
    key: Option<String>,
    /// Generate a fresh self-signed certificate at startup. Development only.
    #[arg(long, default_value_t = false)]
    self_signed: bool,
    /// Path to a PEM CA bundle. When set, clients must present a certificate
    /// signed by this CA (mTLS).
    #[arg(long)]
    client_ca: Option<String>,
    /// Log format: "text" or "json".
    #[arg(long, default_value = "text")]
    log_format: String,
}

/// Per-stream server state.
enum StreamState {
    /// Reading a protocol request from the stream.
    ReadingRequest { buf: Vec<u8> },
    /// Receiving file bytes (Put) and streaming them straight to disk.
    /// The temp file is renamed to `final_path` on success; on drop without
    /// completion it is deleted.
    ReadingFileData {
        final_path: PathBuf,
        temp_path: PathBuf,
        writer: BufWriter<File>,
        remaining: u64,
        mode: u32,
        completed: bool,
    },
    /// Terminal state. The retain() sweep removes streams in this state.
    Done,
}

impl Drop for StreamState {
    fn drop(&mut self) {
        if let StreamState::ReadingFileData {
            temp_path,
            completed,
            ..
        } = self
        {
            if !*completed {
                if let Err(e) = std::fs::remove_file(&temp_path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(path = %temp_path.display(), error = %e, "failed to clean up partial upload");
                    }
                }
            }
        }
    }
}

fn init_tracing(format: &str) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match format {
        "json" => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init(),
        "text" => tracing_subscriber::fmt().with_env_filter(filter).init(),
        other => anyhow::bail!("unknown log format: {other} (expected 'text' or 'json')"),
    }
    Ok(())
}

fn load_or_make_tls(args: &Args) -> Result<ServerTlsConfig> {
    if args.self_signed {
        warn!("Generating ephemeral self-signed certificate (--self-signed). Do not use in production.");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("failed to generate self-signed certificate")?;
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let cert_path =
            std::env::temp_dir().join(format!("qftp-server-cert-{}.pem", std::process::id()));
        let key_path =
            std::env::temp_dir().join(format!("qftp-server-key-{}.pem", std::process::id()));
        fs::write(&cert_path, &cert_pem).context("failed to write cert PEM")?;
        fs::write(&key_path, &key_pem).context("failed to write key PEM")?;
        #[cfg(unix)]
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .context("failed to set key file permissions")?;

        Ok(ServerTlsConfig {
            cert_pem: cert_path.to_string_lossy().to_string(),
            key_pem: key_path.to_string_lossy().to_string(),
            client_ca_pem: args.client_ca.clone(),
        })
    } else {
        let cert = args
            .cert
            .as_ref()
            .context("--cert is required (or pass --self-signed for dev)")?;
        let key = args
            .key
            .as_ref()
            .context("--key is required (or pass --self-signed for dev)")?;
        check_key_permissions(key)?;
        Ok(ServerTlsConfig {
            cert_pem: cert.clone(),
            key_pem: key.clone(),
            client_ca_pem: args.client_ca.clone(),
        })
    }
}

#[cfg(unix)]
fn check_key_permissions(path: &str) -> Result<()> {
    let meta = fs::metadata(path).context("failed to stat key file")?;
    let mode = meta.permissions().mode();
    // Anything readable / writable by group or other is rejected.
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "key file {} has permissions {:o}; expected owner-only (e.g. 0600)",
            path,
            mode & 0o777
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(_path: &str) -> Result<()> {
    Ok(())
}

fn install_signal_handler() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown.clone())
        .context("failed to register SIGINT handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())
        .context("failed to register SIGTERM handler")?;
    Ok(shutdown)
}

/// Allocate a temp path next to the eventual destination so the final
/// `rename` is atomic (same filesystem).
fn temp_path_for(final_path: &Path, stream_id: u64) -> PathBuf {
    let mut name = final_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(
        ".qftp.partial.{}.{}",
        std::process::id(),
        stream_id
    ));
    final_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

/// Stream a file from disk to the peer in chunks, flushing UDP egress
/// between chunks so the stream-level flow-control window can be reopened
/// by incoming ACKs. Blocks the main loop for the duration of the
/// transfer; that is acceptable for the Phase 1 single-connection server.
fn send_file_streaming(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    stream_id: u64,
    path: &Path,
    total_size: u64,
) -> Result<()> {
    let file = File::open(path).context("failed to open file for send")?;
    let mut reader = BufReader::with_capacity(FILE_CHUNK_SIZE, file);
    let mut chunk = vec![0u8; FILE_CHUNK_SIZE];
    let mut sent: u64 = 0;
    let mut net_buf = [0u8; 65536];

    while sent < total_size {
        let to_read = ((total_size - sent) as usize).min(chunk.len());
        reader
            .read_exact(&mut chunk[..to_read])
            .context("failed to read file chunk")?;

        let fin = sent + to_read as u64 == total_size;

        let mut chunk_off = 0;
        while chunk_off < to_read {
            match conn.stream_send(stream_id, &chunk[chunk_off..to_read], fin) {
                Ok(0) => {
                    // Stream-level flow control is exhausted. Push out what
                    // we have, pull in any acks the peer has sent, and try
                    // again on the next loop iteration.
                    flush_egress(conn, socket)?;
                    handle_ingress(conn, socket, &mut net_buf)?;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(n) => {
                    chunk_off += n;
                    sent += n as u64;
                }
                Err(e) => return Err(e).context("stream_send during file send failed"),
            }
        }

        flush_egress(conn, socket)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(&args.log_format)?;

    let root = fs::canonicalize(&args.root).context("failed to canonicalize root directory")?;
    let tls = load_or_make_tls(&args)?;
    let mut config = create_server_config(&tls)?;

    let addr: std::net::SocketAddr = args.bind.parse().context("invalid bind address")?;
    let std_socket = std::net::UdpSocket::bind(addr).context("failed to bind UDP socket")?;
    std_socket
        .set_nonblocking(true)
        .context("failed to set nonblocking")?;
    let mut socket = mio::net::UdpSocket::from_std(std_socket);

    info!(
        %addr,
        root = %root.display(),
        mtls = args.client_ca.is_some(),
        "QFTP server listening"
    );

    let mut poll = Poll::new().context("failed to create mio Poll")?;
    poll.registry()
        .register(&mut socket, SERVER, Interest::READABLE)
        .context("failed to register socket with poll")?;
    let mut events = Events::with_capacity(1024);

    let shutdown = install_signal_handler()?;

    let mut conn: Option<quiche::Connection> = None;
    let mut cwd: PathBuf = root.clone();
    let mut streams: HashMap<u64, StreamState> = HashMap::new();
    let mut buf = [0u8; 65536];
    let rng = ring::rand::SystemRandom::new();
    let mut shutting_down = false;

    loop {
        // Handle graceful shutdown: close any open connection, then exit
        // once it has drained or after a short grace period.
        if shutdown.load(Ordering::Relaxed) && !shutting_down {
            info!("shutdown signal received, draining");
            shutting_down = true;
            if let Some(ref mut c) = conn {
                let _ = c.close(true, 0x00, b"server shutdown");
                flush_egress(c, &socket).ok();
            } else {
                break;
            }
        }

        let timeout = if shutting_down {
            Some(Duration::from_millis(250))
        } else {
            conn.as_ref().and_then(|c| c.timeout())
        };

        poll.poll(&mut events, timeout).context("poll failed")?;

        if let Some(ref mut c) = conn {
            if c.is_timed_out() {
                info!("connection timed out, resetting state");
                conn = None;
                cwd = root.clone();
                streams.clear();
                if shutting_down {
                    break;
                }
                continue;
            }
            c.on_timeout();
        }

        // Read incoming UDP packets.
        let local_addr = socket.local_addr().context("failed to get local addr")?;
        loop {
            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("UDP recv_from failed"),
            };

            if conn.is_none() {
                if shutting_down {
                    continue;
                }
                let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)
                {
                    Ok(hdr) => hdr,
                    Err(e) => {
                        warn!(error = ?e, "failed to parse QUIC header");
                        continue;
                    }
                };
                if hdr.ty != quiche::Type::Initial {
                    warn!("non-Initial packet without connection, ignoring");
                    continue;
                }
                let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
                ring::rand::SecureRandom::fill(&rng, &mut scid_bytes).unwrap();
                let scid = quiche::ConnectionId::from_vec(scid_bytes.to_vec());
                let new_conn = quiche::accept(&scid, None, local_addr, from, &mut config)
                    .context("failed to accept QUIC connection")?;
                info!(%from, "new QUIC connection");
                conn = Some(new_conn);
            } else if let Ok(hdr) =
                quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)
            {
                if hdr.ty == quiche::Type::Initial {
                    warn!(
                        %from,
                        "rejecting new connection (server only supports one concurrent connection)"
                    );
                    continue;
                }
            }

            if let Some(ref mut c) = conn {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                if let Err(e) = c.recv(&mut buf[..len], recv_info) {
                    warn!(error = ?e, "QUIC recv error");
                }
            }
        }

        // Process readable streams.
        if let Some(ref mut c) = conn {
            let readable: Vec<u64> = c.readable().collect();

            for stream_id in readable {
                let state = streams
                    .entry(stream_id)
                    .or_insert_with(|| StreamState::ReadingRequest { buf: Vec::new() });

                match state {
                    StreamState::ReadingRequest {
                        buf: ref mut stream_buf,
                    } => {
                        let req: Option<Request> = recv_message(c, stream_id, stream_buf)?;

                        if let Some(req) = req {
                            debug!(stream_id, ?req, "request received");

                            match req {
                                Request::Get { ref path } => {
                                    handle_get(c, &socket, &cwd, &root, stream_id, path)?;
                                    *state = StreamState::Done;
                                }

                                Request::Put {
                                    ref path,
                                    size,
                                    mode,
                                } => {
                                    if size > MAX_FILE_SIZE {
                                        send_message(
                                            c,
                                            stream_id,
                                            &Response::Err(format!(
                                                "Upload too large: {} bytes (max {} bytes)",
                                                size, MAX_FILE_SIZE
                                            )),
                                        )?;
                                        *state = StreamState::Done;
                                        continue;
                                    }
                                    let final_path =
                                        match handler::resolve_parent(&cwd, &root, path) {
                                            Ok(p) => p,
                                            Err(e) => {
                                                send_message(c, stream_id, &Response::Err(e))?;
                                                *state = StreamState::Done;
                                                continue;
                                            }
                                        };
                                    let temp_path = temp_path_for(&final_path, stream_id);
                                    let writer = match File::create(&temp_path) {
                                        Ok(f) => BufWriter::with_capacity(FILE_CHUNK_SIZE, f),
                                        Err(e) => {
                                            send_message(
                                                c,
                                                stream_id,
                                                &Response::Err(format!(
                                                    "Failed to create upload temp file: {e}"
                                                )),
                                            )?;
                                            *state = StreamState::Done;
                                            continue;
                                        }
                                    };

                                    // Drain any bytes that arrived after the
                                    // request frame into the writer up front.
                                    let leftover = std::mem::take(stream_buf);
                                    let mut new_state = StreamState::ReadingFileData {
                                        final_path,
                                        temp_path,
                                        writer,
                                        remaining: size,
                                        mode,
                                        completed: false,
                                    };
                                    if !leftover.is_empty() {
                                        if let StreamState::ReadingFileData {
                                            writer,
                                            remaining,
                                            ..
                                        } = &mut new_state
                                        {
                                            if leftover.len() as u64 > *remaining {
                                                send_message(
                                                    c,
                                                    stream_id,
                                                    &Response::Err(
                                                        "Upload exceeded declared size".into(),
                                                    ),
                                                )?;
                                                *state = StreamState::Done;
                                                continue;
                                            }
                                            if let Err(e) = writer.write_all(&leftover) {
                                                send_message(
                                                    c,
                                                    stream_id,
                                                    &Response::Err(format!(
                                                        "Failed to write file: {e}"
                                                    )),
                                                )?;
                                                *state = StreamState::Done;
                                                continue;
                                            }
                                            *remaining -= leftover.len() as u64;
                                        }
                                    }
                                    *state = new_state;
                                    // Don't continue -- fall through so we
                                    // immediately try to drain any remaining
                                    // file bytes already buffered by quiche.
                                    if let Some(resp) = drive_put(c, stream_id, state, &mut buf)? {
                                        send_message(c, stream_id, &resp)?;
                                        *state = StreamState::Done;
                                    }
                                }

                                Request::Quit => {
                                    send_message(c, stream_id, &Response::Ok)?;
                                    flush_egress(c, &socket)?;
                                    c.close(true, 0x00, b"bye").ok();
                                    *state = StreamState::Done;
                                }

                                other => {
                                    let response = handler::handle_request(&other, &mut cwd, &root);
                                    send_message(c, stream_id, &response)?;
                                    *state = StreamState::Done;
                                }
                            }
                        }
                    }

                    StreamState::ReadingFileData { .. } => {
                        if let Some(resp) = drive_put(c, stream_id, state, &mut buf)? {
                            send_message(c, stream_id, &resp)?;
                            *state = StreamState::Done;
                        }
                    }

                    StreamState::Done => {}
                }
            }

            flush_egress(c, &socket)?;

            if c.is_closed() {
                info!("connection closed, resetting state");
                conn = None;
                cwd = root.clone();
                streams.clear();
                if shutting_down {
                    break;
                }
                continue;
            }
        }

        streams.retain(|_, state| !matches!(state, StreamState::Done));
    }

    info!("QFTP server stopped");
    Ok(())
}

/// Pump bytes from the stream's receive buffer straight to disk. Returns
/// `Some(resp)` when the upload is complete (success or failure) so the
/// caller can send it and transition to Done.
fn drive_put(
    conn: &mut quiche::Connection,
    stream_id: u64,
    state: &mut StreamState,
    tmp: &mut [u8],
) -> Result<Option<Response>> {
    let StreamState::ReadingFileData {
        final_path,
        temp_path,
        writer,
        remaining,
        mode,
        completed,
    } = state
    else {
        return Ok(None);
    };

    loop {
        if *remaining == 0 {
            break;
        }
        match conn.stream_recv(stream_id, tmp) {
            Ok((len, _fin)) => {
                let to_take = (len as u64).min(*remaining) as usize;
                if let Err(e) = writer.write_all(&tmp[..to_take]) {
                    return Ok(Some(Response::Err(format!("Failed to write file: {e}"))));
                }
                *remaining -= to_take as u64;
                if to_take < len {
                    // Peer sent more bytes than declared. Reject.
                    return Ok(Some(Response::Err("Upload exceeded declared size".into())));
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!(stream_id, error = ?e, "stream_recv error during Put");
                return Ok(Some(Response::Err("Stream receive error".into())));
            }
        }
    }

    if *remaining == 0 {
        if let Err(e) = writer.flush() {
            return Ok(Some(Response::Err(format!("Failed to flush file: {e}"))));
        }
        if let Err(e) = fs::rename(temp_path, &final_path) {
            return Ok(Some(Response::Err(format!("Failed to finalize file: {e}"))));
        }
        #[cfg(unix)]
        {
            let perms = fs::Permissions::from_mode(*mode);
            if let Err(e) = fs::set_permissions(&final_path, perms) {
                warn!(path = %final_path.display(), error = %e, "failed to set permissions");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
        }
        *completed = true;
        return Ok(Some(Response::Ok));
    }

    Ok(None)
}

/// Open, size-check, and stream a file to the peer for a Get request.
fn handle_get(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    cwd: &Path,
    root: &Path,
    stream_id: u64,
    path: &str,
) -> Result<()> {
    let file_path = match handler::resolve(cwd, root, path) {
        Ok(p) => p,
        Err(e) => {
            send_message(conn, stream_id, &Response::Err(e))?;
            return Ok(());
        }
    };
    let meta = match fs::metadata(&file_path) {
        Ok(m) => m,
        Err(e) => {
            send_message(
                conn,
                stream_id,
                &Response::Err(format!("Failed to stat file: {e}")),
            )?;
            return Ok(());
        }
    };
    if meta.len() > MAX_FILE_SIZE {
        send_message(
            conn,
            stream_id,
            &Response::Err(format!(
                "File too large: {} bytes (max {} bytes)",
                meta.len(),
                MAX_FILE_SIZE
            )),
        )?;
        return Ok(());
    }
    send_message(conn, stream_id, &Response::FileReady { size: meta.len() })?;
    flush_egress(conn, socket)?;
    send_file_streaming(conn, socket, stream_id, &file_path, meta.len())?;
    Ok(())
}
