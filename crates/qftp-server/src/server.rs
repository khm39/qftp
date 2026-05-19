//! Multi-connection QUIC server main loop.
//!
//! The loop owns:
//!   * one UDP socket
//!   * a HashMap<ConnectionId, ConnectionContext>
//!   * a RateLimiter, a ConnectionCounter, and a RetryKey
//!   * an Arc<UserDirectory> and an Arc<Metrics>
//!
//! Per iteration:
//!   1. Compute the shortest QUIC timeout across all connections; poll.
//!   2. Drain incoming UDP packets and route each to its connection
//!      (or to the accept path for Initials).
//!   3. Run on_timeout for each connection.
//!   4. Process readable streams (incoming requests + Put body) on each
//!      connection.
//!   5. Drive sending streams (Get body) on each connection.
//!   6. Flush egress for each connection.
//!   7. Drop closed / drained connections.
//!
//! A single fatal stream error closes only that one stream; a single
//! malformed packet does nothing at all. Only socket-level errors abort
//! the loop.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mio::{Events, Interest, Poll, Token};
use qftp_common::protocol::*;
use qftp_common::transport::*;
use tracing::{debug, info, warn};

use crate::connection::{ConnectionContext, StreamState, FILE_CHUNK_SIZE, MAX_FILE_SIZE};
use crate::handler;
use crate::limits::{Caps, ConnectionCounter, RateLimiter};
use crate::metrics::Metrics;
use crate::retry::RetryKey;
use crate::user::{self, UserDirectory};

const SERVER_TOKEN: Token = Token(0);

/// Static knobs the loop reads on every iteration.
pub struct ServerConfig {
    pub caps: Caps,
    pub require_retry: bool,
}

pub fn run(
    mut quiche_config: quiche::Config,
    socket: mio::net::UdpSocket,
    server_config: ServerConfig,
    users: Arc<UserDirectory>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let mut poll = Poll::new().context("failed to create mio Poll")?;
    let mut socket = socket;
    poll.registry()
        .register(&mut socket, SERVER_TOKEN, Interest::READABLE)
        .context("failed to register socket")?;
    let mut events = Events::with_capacity(1024);

    let rng = ring::rand::SystemRandom::new();
    let mut rate_limiter = RateLimiter::new(50.0, 100.0);
    let mut counter = ConnectionCounter::default();
    let retry_key = RetryKey::new();

    // Per-process seed used to derive a deterministic server SCID from
    // each client's original DCID. Without this, every retransmitted
    // Initial during the handshake would look like a brand-new connection
    // because we'd hand out a random SCID each time.
    let mut conn_id_seed = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut conn_id_seed).expect("system RNG failed");

    // Connection table keyed by the SCID we issued (= derive_scid(seed, dcid)).
    let mut connections: HashMap<quiche::ConnectionId<'static>, ConnectionContext> = HashMap::new();

    let mut buf = [0u8; 65536];
    let mut out_pkt = [0u8; 1350];
    let mut closing = false;

    info!(
        max_total = server_config.caps.max_total_connections,
        max_per_ip = server_config.caps.max_per_ip_connections,
        require_retry = server_config.require_retry,
        "server loop started"
    );

    loop {
        if shutdown.load(Ordering::Relaxed) && !closing {
            info!(
                "shutdown signal received, draining {} connection(s)",
                connections.len()
            );
            closing = true;
            for c in connections.values_mut() {
                c.conn.close(true, 0x00, b"server shutdown").ok();
            }
        }

        let shortest_timeout = connections.values().filter_map(|c| c.conn.timeout()).min();
        let poll_timeout = match (closing, shortest_timeout) {
            (true, t) => Some(t.unwrap_or(Duration::from_millis(250))),
            (false, Some(t)) => Some(t),
            (false, None) => None,
        };
        poll.poll(&mut events, poll_timeout)
            .context("poll failed")?;

        // 1. Drain incoming UDP packets.
        let local_addr = socket.local_addr().context("failed to get local addr")?;
        loop {
            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("UDP recv_from failed"),
            };

            let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                Ok(h) => h,
                Err(e) => {
                    warn!(error = ?e, "failed to parse QUIC header");
                    continue;
                }
            };

            // Route to existing connection. For established connections
            // the peer's DCID is the SCID we issued. For Initial
            // retransmits during handshake the peer is still using their
            // original DCID, so also try its derived alias.
            let alias = derive_scid(&conn_id_seed, &hdr.dcid);
            let key = if connections.contains_key(&hdr.dcid) {
                Some(hdr.dcid.clone().into_owned())
            } else if connections.contains_key(&alias) {
                Some(alias.clone())
            } else {
                None
            };
            if let Some(k) = key {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                if let Some(ctx) = connections.get_mut(&k) {
                    if let Err(e) = ctx.conn.recv(&mut buf[..len], recv_info) {
                        warn!(peer = %from, error = ?e, "QUIC recv error");
                    }
                }
                continue;
            }

            // No matching connection. Only Initials can create one.
            if hdr.ty != quiche::Type::Initial {
                debug!(peer = %from, ty = ?hdr.ty, "stray non-Initial packet, ignoring");
                continue;
            }

            if closing {
                continue;
            }

            try_accept(
                &mut connections,
                &mut counter,
                &mut rate_limiter,
                &retry_key,
                &conn_id_seed,
                &server_config,
                &users,
                &metrics,
                &rng,
                &socket,
                &mut quiche_config,
                from,
                local_addr,
                &hdr,
                &mut buf[..len],
                &mut out_pkt,
            )?;
        }

        // 2. on_timeout.
        for ctx in connections.values_mut() {
            ctx.conn.on_timeout();
        }

        // 3-5. Per-connection work: streams + sending + egress.
        for ctx in connections.values_mut() {
            process_readable_streams(ctx, &socket, &users, &metrics, &mut buf)?;
            drive_sending_streams(ctx, &socket, &metrics)?;
            flush_egress(&mut ctx.conn, &socket)?;
        }

        // 6. Reap closed / timed-out connections.
        let before = connections.len();
        connections.retain(|_, ctx| {
            let alive = !ctx.conn.is_closed();
            if !alive {
                let peer_ip = ctx.peer_addr.ip();
                counter.release(peer_ip);
                metrics.connections_open.fetch_sub(1, Ordering::Relaxed);
                info!(peer = %ctx.peer_addr, user = %ctx.user.name, "connection closed");
            }
            alive
        });
        if connections.len() != before {
            debug!(open = connections.len(), "reaped connections");
        }

        // 7. Sweep Done streams.
        for ctx in connections.values_mut() {
            ctx.streams.retain(|_, s| !matches!(s, StreamState::Done));
        }

        if closing && connections.is_empty() {
            break;
        }
    }

    info!("server loop stopped");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn try_accept(
    connections: &mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
    counter: &mut ConnectionCounter,
    rate_limiter: &mut RateLimiter,
    retry_key: &RetryKey,
    conn_id_seed: &[u8; 32],
    cfg: &ServerConfig,
    users: &Arc<UserDirectory>,
    metrics: &Arc<Metrics>,
    rng: &ring::rand::SystemRandom,
    socket: &mio::net::UdpSocket,
    quiche_config: &mut quiche::Config,
    from: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    hdr: &quiche::Header,
    pkt: &mut [u8],
    out_pkt: &mut [u8; 1350],
) -> Result<()> {
    if !rate_limiter.try_consume(from.ip()) {
        metrics
            .connections_rejected_rate
            .fetch_add(1, Ordering::Relaxed);
        debug!(peer = %from, "Initial dropped by rate limiter");
        return Ok(());
    }

    // Stateless retry: when required, the very first Initial from a peer
    // has no token. Mint one and send it back as a RETRY; the client will
    // resend the Initial with the token attached.
    if cfg.require_retry {
        let has_token = hdr.token.as_ref().is_some_and(|t| !t.is_empty());
        if !has_token {
            send_retry(retry_key, rng, socket, hdr, from, out_pkt)?;
            metrics.retries_issued.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let token = hdr.token.as_ref().unwrap();
        if retry_key.verify(from, token).is_none() {
            debug!(peer = %from, "Initial with invalid retry token");
            return Ok(());
        }
        // Verified: fall through and accept with odcid set below.
    }

    if !counter.try_acquire(cfg.caps, from.ip()) {
        metrics
            .connections_rejected_caps
            .fetch_add(1, Ordering::Relaxed);
        debug!(peer = %from, "Initial dropped by connection cap");
        return Ok(());
    }

    // Derive the server SCID deterministically from the client's DCID +
    // process seed. Retransmitted Initials therefore land on the same
    // connection key instead of accidentally creating duplicates.
    let _ = rng;
    let scid = derive_scid(conn_id_seed, &hdr.dcid);

    // Recover odcid from the retry token if we issued one.
    let odcid_owned: Option<quiche::ConnectionId<'static>> = if cfg.require_retry {
        hdr.token
            .as_ref()
            .and_then(|t| retry_key.verify(from, t))
            .map(|c| quiche::ConnectionId::from_vec(c.as_ref().to_vec()))
    } else {
        None
    };

    let mut conn = quiche::accept(&scid, odcid_owned.as_ref(), local_addr, from, quiche_config)
        .context("quiche::accept failed")?;

    // Feed the original Initial in so the handshake actually starts.
    let recv_info = quiche::RecvInfo {
        from,
        to: local_addr,
    };
    if let Err(e) = conn.recv(pkt, recv_info) {
        warn!(peer = %from, error = ?e, "initial recv failed");
        counter.release(from.ip());
        return Ok(());
    }

    // mTLS identity isn't ready until the handshake completes; start the
    // connection as the anonymous user and upgrade later if we can.
    let ctx = ConnectionContext::new(conn, from, users.anonymous());
    info!(peer = %from, "connection accepted");
    metrics.connections_total.fetch_add(1, Ordering::Relaxed);
    metrics.connections_open.fetch_add(1, Ordering::Relaxed);

    // If a previous Initial from this peer already created the slot
    // (the deterministic SCID collapses retransmits onto the same key),
    // just drop the duplicate accept.
    if connections.contains_key(&scid) {
        counter.release(from.ip());
        return Ok(());
    }
    connections.insert(scid, ctx);
    Ok(())
}

/// Deterministically derive a server SCID from the client's DCID using
/// the process-lifetime seed. Truncated to quiche::MAX_CONN_ID_LEN bytes.
fn derive_scid(seed: &[u8; 32], dcid: &quiche::ConnectionId) -> quiche::ConnectionId<'static> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(seed).expect("hmac key");
    mac.update(dcid.as_ref());
    let bytes = mac.finalize().into_bytes();
    let take = quiche::MAX_CONN_ID_LEN.min(bytes.len());
    quiche::ConnectionId::from_vec(bytes[..take].to_vec())
}

fn send_retry(
    retry_key: &RetryKey,
    rng: &ring::rand::SystemRandom,
    socket: &mio::net::UdpSocket,
    hdr: &quiche::Header,
    from: std::net::SocketAddr,
    out: &mut [u8; 1350],
) -> Result<()> {
    let mut new_scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SecureRandom::fill(rng, &mut new_scid_bytes).expect("system RNG failed");
    let new_scid = quiche::ConnectionId::from_ref(&new_scid_bytes);
    let token = retry_key.mint(from, &hdr.dcid);
    let written = quiche::retry(
        &hdr.scid,
        &hdr.dcid,
        &new_scid,
        &token,
        hdr.version,
        out.as_mut_slice(),
    )
    .context("quiche::retry failed")?;
    socket
        .send_to(&out[..written], from)
        .context("UDP send_to for retry failed")?;
    Ok(())
}

/// Try to look up the authenticated user once the handshake is far enough
/// along that the peer cert is available. Idempotent: returns early if the
/// connection is already on a non-anonymous user.
fn upgrade_user_from_cert(ctx: &mut ConnectionContext, users: &UserDirectory) {
    if ctx.user.name != "anonymous" {
        return;
    }
    if !ctx.conn.is_established() {
        return;
    }
    let Some(der) = ctx.conn.peer_cert() else {
        return;
    };
    let Some(cn) = user::extract_cn(der) else {
        return;
    };
    let resolved = users.lookup(Some(&cn));
    if resolved.name == ctx.user.name {
        return;
    }
    info!(peer = %ctx.peer_addr, user = %resolved.name, "upgraded connection to authenticated user");
    ctx.cwd = resolved.home.clone();
    ctx.user = resolved;
}

/// Action collected during the readable-streams sweep. We can't act on a
/// new request while we still hold a &mut into ctx.streams[stream_id],
/// so each match arm picks the action and we execute the list afterward.
enum PendingAction {
    StartGet {
        stream_id: u64,
        path: String,
    },
    StartPut {
        stream_id: u64,
        path: String,
        size: u64,
        mode: u32,
        leftover: Vec<u8>,
    },
    HandleSimple {
        stream_id: u64,
        req: Request,
    },
    Quit {
        stream_id: u64,
    },
    AclReject {
        stream_id: u64,
        resp: Response,
    },
}

fn process_readable_streams(
    ctx: &mut ConnectionContext,
    socket: &mio::net::UdpSocket,
    users: &UserDirectory,
    metrics: &Arc<Metrics>,
    tmp: &mut [u8],
) -> Result<()> {
    upgrade_user_from_cert(ctx, users);
    let readable: Vec<u64> = ctx.conn.readable().collect();

    let mut actions: Vec<PendingAction> = Vec::new();

    for stream_id in readable {
        let state = ctx
            .streams
            .entry(stream_id)
            .or_insert_with(|| StreamState::ReadingRequest { buf: Vec::new() });

        match state {
            StreamState::ReadingRequest {
                buf: ref mut stream_buf,
            } => {
                let req: Option<Request> = recv_message(&mut ctx.conn, stream_id, stream_buf)?;
                if let Some(req) = req {
                    metrics.requests_total.fetch_add(1, Ordering::Relaxed);
                    debug!(
                        peer = %ctx.peer_addr,
                        user = %ctx.user.name,
                        stream_id,
                        ?req,
                        "request received"
                    );

                    if let Some(resp) = handler::acl_reject(&ctx.user, &req) {
                        actions.push(PendingAction::AclReject { stream_id, resp });
                        *state = StreamState::Done;
                        continue;
                    }

                    match req {
                        Request::Get { path } => {
                            actions.push(PendingAction::StartGet { stream_id, path });
                            *state = StreamState::Done;
                        }
                        Request::Put { path, size, mode } => {
                            let leftover = std::mem::take(stream_buf);
                            actions.push(PendingAction::StartPut {
                                stream_id,
                                path,
                                size,
                                mode,
                                leftover,
                            });
                            *state = StreamState::Done;
                        }
                        Request::Quit => {
                            actions.push(PendingAction::Quit { stream_id });
                            *state = StreamState::Done;
                        }
                        other => {
                            actions.push(PendingAction::HandleSimple {
                                stream_id,
                                req: other,
                            });
                            *state = StreamState::Done;
                        }
                    }
                }
            }
            StreamState::ReadingFileData { .. } => {
                if let Some(resp) = drive_put(&mut ctx.conn, stream_id, state, tmp, metrics)? {
                    if matches!(resp, Response::Err(_)) {
                        metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
                    }
                    send_message(&mut ctx.conn, stream_id, &resp)?;
                    *state = StreamState::Done;
                }
            }
            StreamState::SendingFileData { .. } => {
                // Drained by drive_sending_streams below.
            }
            StreamState::Done => {}
        }
    }

    // Now we own no borrows into ctx.streams; safe to mutate freely.
    for action in actions {
        match action {
            PendingAction::AclReject { stream_id, resp } => {
                send_message(&mut ctx.conn, stream_id, &resp)?;
                metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
            }
            PendingAction::StartGet { stream_id, path } => {
                start_get(ctx, stream_id, &path, metrics)?;
            }
            PendingAction::StartPut {
                stream_id,
                path,
                size,
                mode,
                leftover,
            } => {
                start_put(ctx, stream_id, &path, size, mode, leftover, metrics)?;
            }
            PendingAction::Quit { stream_id } => {
                send_message(&mut ctx.conn, stream_id, &Response::Ok)?;
                flush_egress(&mut ctx.conn, socket)?;
                ctx.conn.close(true, 0x00, b"bye").ok();
            }
            PendingAction::HandleSimple { stream_id, req } => {
                let response = handler::handle_request(&req, &mut ctx.cwd, &ctx.user.home);
                if matches!(response, Response::Err(_)) {
                    metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
                }
                send_message(&mut ctx.conn, stream_id, &response)?;
            }
        }
    }
    Ok(())
}

fn start_get(
    ctx: &mut ConnectionContext,
    stream_id: u64,
    path: &str,
    metrics: &Arc<Metrics>,
) -> Result<()> {
    let file_path = match handler::resolve(&ctx.cwd, &ctx.user.home, path) {
        Ok(p) => p,
        Err(e) => {
            send_message(&mut ctx.conn, stream_id, &Response::Err(e))?;
            metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
            ctx.streams.insert(stream_id, StreamState::Done);
            return Ok(());
        }
    };
    let meta = match fs::metadata(&file_path) {
        Ok(m) => m,
        Err(e) => {
            send_message(
                &mut ctx.conn,
                stream_id,
                &Response::Err(format!("Failed to stat file: {e}")),
            )?;
            metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
            ctx.streams.insert(stream_id, StreamState::Done);
            return Ok(());
        }
    };
    if meta.len() > MAX_FILE_SIZE {
        send_message(
            &mut ctx.conn,
            stream_id,
            &Response::Err(format!(
                "File too large: {} bytes (max {} bytes)",
                meta.len(),
                MAX_FILE_SIZE
            )),
        )?;
        metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
        ctx.streams.insert(stream_id, StreamState::Done);
        return Ok(());
    }
    let file = File::open(&file_path).context("open file for streaming send")?;
    send_message(
        &mut ctx.conn,
        stream_id,
        &Response::FileReady { size: meta.len() },
    )?;
    ctx.streams.insert(
        stream_id,
        StreamState::SendingFileData {
            reader: std::io::BufReader::with_capacity(FILE_CHUNK_SIZE, file),
            total_size: meta.len(),
            sent: 0,
            finished: false,
        },
    );
    Ok(())
}

fn drive_sending_streams(
    ctx: &mut ConnectionContext,
    _socket: &mio::net::UdpSocket,
    metrics: &Arc<Metrics>,
) -> Result<()> {
    let stream_ids: Vec<u64> = ctx
        .streams
        .iter()
        .filter(|(_, s)| matches!(s, StreamState::SendingFileData { .. }))
        .map(|(id, _)| *id)
        .collect();

    let mut chunk = [0u8; FILE_CHUNK_SIZE];
    for stream_id in stream_ids {
        let Some(state) = ctx.streams.get_mut(&stream_id) else {
            continue;
        };
        let StreamState::SendingFileData {
            reader,
            total_size,
            sent,
            finished,
        } = state
        else {
            continue;
        };
        if *finished {
            continue;
        }
        // Push as many chunks as the per-stream flow-control window will
        // accept this iteration. When stream_send returns 0 the stream is
        // blocked; we drop out and try again next iteration after the
        // peer's ACKs have reopened capacity.
        loop {
            if *sent == *total_size {
                *finished = true;
                metrics.downloads_completed.fetch_add(1, Ordering::Relaxed);
                *state = StreamState::Done;
                break;
            }
            let want = ((*total_size - *sent) as usize).min(chunk.len());
            if let Err(e) = reader.read_exact(&mut chunk[..want]) {
                warn!(stream_id, error = %e, "file read failed mid-stream");
                let _ = ctx.conn.stream_send(stream_id, &[], true);
                *state = StreamState::Done;
                break;
            }
            let chunk_is_last = *sent + want as u64 == *total_size;
            match ctx
                .conn
                .stream_send(stream_id, &chunk[..want], chunk_is_last)
            {
                Ok(0) => break, // blocked, retry next iteration
                Ok(n) => {
                    *sent += n as u64;
                    metrics.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    if n < want {
                        // partial: rewind by the bytes quiche didn't accept
                        // so the next iteration re-reads them. seek_relative
                        // is the BufReader-native rewind and avoids
                        // invalidating the in-memory buffer the way Seek
                        // would.
                        if let Err(e) = reader.seek_relative(-((want - n) as i64)) {
                            warn!(stream_id, error = %e, "seek failed during partial send");
                            *state = StreamState::Done;
                            break;
                        }
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    warn!(stream_id, error = ?e, "stream_send failed during Get");
                    *state = StreamState::Done;
                    break;
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn start_put(
    ctx: &mut ConnectionContext,
    stream_id: u64,
    path: &str,
    size: u64,
    mode: u32,
    leftover: Vec<u8>,
    metrics: &Arc<Metrics>,
) -> Result<()> {
    if size > MAX_FILE_SIZE {
        send_message(
            &mut ctx.conn,
            stream_id,
            &Response::Err(format!(
                "Upload too large: {} bytes (max {} bytes)",
                size, MAX_FILE_SIZE
            )),
        )?;
        metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
        ctx.streams.insert(stream_id, StreamState::Done);
        return Ok(());
    }
    let final_path = match handler::resolve_parent(&ctx.cwd, &ctx.user.home, path) {
        Ok(p) => p,
        Err(e) => {
            send_message(&mut ctx.conn, stream_id, &Response::Err(e))?;
            metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
            ctx.streams.insert(stream_id, StreamState::Done);
            return Ok(());
        }
    };
    let temp_path = temp_path_for(&final_path, stream_id);
    let writer = match open_temp_no_follow(&temp_path) {
        Ok(f) => BufWriter::with_capacity(FILE_CHUNK_SIZE, f),
        Err(e) => {
            send_message(
                &mut ctx.conn,
                stream_id,
                &Response::Err(format!("Failed to create upload temp file: {e}")),
            )?;
            metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
            ctx.streams.insert(stream_id, StreamState::Done);
            return Ok(());
        }
    };

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
            writer, remaining, ..
        } = &mut new_state
        {
            if leftover.len() as u64 > *remaining {
                send_message(
                    &mut ctx.conn,
                    stream_id,
                    &Response::Err("Upload exceeded declared size".into()),
                )?;
                metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
                ctx.streams.insert(stream_id, StreamState::Done);
                return Ok(());
            }
            if let Err(e) = writer.write_all(&leftover) {
                send_message(
                    &mut ctx.conn,
                    stream_id,
                    &Response::Err(format!("Failed to write file: {e}")),
                )?;
                metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
                ctx.streams.insert(stream_id, StreamState::Done);
                return Ok(());
            }
            *remaining -= leftover.len() as u64;
            metrics
                .bytes_received
                .fetch_add(leftover.len() as u64, Ordering::Relaxed);
        }
    }
    ctx.streams.insert(stream_id, new_state);

    // Drain anything already buffered for this stream.
    let mut tmp = [0u8; FILE_CHUNK_SIZE];
    if let Some(state) = ctx.streams.get_mut(&stream_id) {
        if let Some(resp) = drive_put(&mut ctx.conn, stream_id, state, &mut tmp, metrics)? {
            if matches!(resp, Response::Err(_)) {
                metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
            }
            send_message(&mut ctx.conn, stream_id, &resp)?;
            *state = StreamState::Done;
        }
    }
    Ok(())
}

fn drive_put(
    conn: &mut quiche::Connection,
    stream_id: u64,
    state: &mut StreamState,
    tmp: &mut [u8],
    metrics: &Arc<Metrics>,
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
            Ok((len, fin)) => {
                let to_take = (len as u64).min(*remaining) as usize;
                if let Err(e) = writer.write_all(&tmp[..to_take]) {
                    return Ok(Some(Response::Err(format!("Failed to write file: {e}"))));
                }
                *remaining -= to_take as u64;
                metrics
                    .bytes_received
                    .fetch_add(to_take as u64, Ordering::Relaxed);
                if to_take < len {
                    return Ok(Some(Response::Err("Upload exceeded declared size".into())));
                }
                if fin && *remaining > 0 {
                    return Ok(Some(Response::Err(format!(
                        "Upload truncated: {} bytes still expected",
                        *remaining
                    ))));
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
        apply_mode(final_path, *mode);
        *completed = true;
        metrics.uploads_completed.fetch_add(1, Ordering::Relaxed);
        return Ok(Some(Response::Ok));
    }

    Ok(None)
}

#[cfg(unix)]
fn apply_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(mode);
    if let Err(e) = fs::set_permissions(path, perms) {
        warn!(path = %path.display(), error = %e, "failed to set permissions");
    }
}

#[cfg(not(unix))]
fn apply_mode(_path: &Path, _mode: u32) {}

fn open_temp_no_follow(path: &Path) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

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
