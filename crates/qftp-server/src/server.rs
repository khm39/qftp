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
use crate::handler::{self, err, io_code};
use crate::limits::{Caps, ConnectionCounter, RateLimiter};
use crate::metrics::Metrics;
use crate::retry::RetryKey;
use crate::user::{self, UserDirectory};

/// Which Request variants are safe to serve while the connection is
/// still in the 0-RTT phase. The rule is "read-only / no
/// side-effects": replays produce identical responses and never
/// mutate persistent state. Anything that writes or renames is
/// refused so a captured 0-RTT flight cannot be replayed to put the
/// server into a different state.
/// Walk `root` and return `(total_bytes, file_count)`. Used for the
/// `Request::Quota` reply and for the `Put` pre-upload quota check.
/// We deliberately skip non-regular files (symlinks, sockets) so the
/// number matches what a `du -b --apparent-size` would report.
fn walk_size(root: &Path) -> (u64, u64) {
    let mut bytes = 0u64;
    let mut count = 0u64;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in read.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                if let Ok(m) = entry.metadata() {
                    bytes = bytes.saturating_add(m.len());
                    count += 1;
                }
            }
        }
    }
    (bytes, count)
}

fn request_is_replay_safe(req: &Request) -> bool {
    matches!(
        req,
        Request::Ls { .. }
            | Request::Cd { .. }
            | Request::Pwd
            | Request::Stat { .. }
            | Request::Get { .. }
            | Request::Quota
            | Request::Quit,
    )
}

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
            process_readable_streams(ctx, &socket, &users, &metrics, &mut rate_limiter, &mut buf)?;
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
/// along that the peer cert is available. Idempotent: returns early if
/// the connection is already on something other than the directory's
/// anonymous record (using Arc pointer equality, so a custom-named
/// anonymous user is still correctly recognised as "not upgraded yet").
fn upgrade_user_from_cert(ctx: &mut ConnectionContext, users: &UserDirectory) {
    let anon = users.anonymous();
    if !Arc::ptr_eq(&ctx.user, &anon) {
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
    // #105: a peer that presents a cert whose CN is not in the user
    // directory must be rejected outright, not silently downgraded to
    // anonymous. Close the QUIC connection with an application-layer
    // error code so the client surfaces an explicit auth failure.
    let Some(resolved) = users.lookup_strict(&cn) else {
        warn!(
            peer = %ctx.peer_addr,
            cn = %cn,
            "rejecting connection: client presented a cert whose CN is not in users.toml"
        );
        // 0x101 is our application-layer "unauthorized" close code.
        // No conflict with the existing 0x00 used for normal shutdown.
        let _ = ctx.conn.close(true, 0x101, b"unknown CN");
        return;
    };
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
        offset: u64,
        length: Option<u64>,
    },
    StartPut {
        stream_id: u64,
        path: String,
        size: u64,
        mode: u32,
        offset: u64,
        expected_checksum: Option<[u8; 32]>,
        leftover: Vec<u8>,
    },
    HandleSimple {
        stream_id: u64,
        req: Request,
    },
    Quit {
        stream_id: u64,
    },
    Quota {
        stream_id: u64,
    },
    AclReject {
        stream_id: u64,
        resp: Response,
    },
}

#[allow(clippy::too_many_arguments)]
fn process_readable_streams(
    ctx: &mut ConnectionContext,
    socket: &mio::net::UdpSocket,
    users: &UserDirectory,
    metrics: &Arc<Metrics>,
    rate_limiter: &mut RateLimiter,
    tmp: &mut [u8],
) -> Result<()> {
    upgrade_user_from_cert(ctx, users);
    let readable: Vec<u64> = ctx.conn.readable().collect();
    let peer_ip = ctx.peer_addr.ip();

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
                // recv_message can fail on a malformed length prefix or
                // an oversized frame from a hostile peer. That's a
                // per-stream problem, not a server-wide one: surface it
                // to the offender and reap the stream rather than
                // letting `?` tear down the whole loop.
                let req: Option<Request> = match recv_message(&mut ctx.conn, stream_id, stream_buf)
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(
                            peer = %ctx.peer_addr,
                            stream_id,
                            error = %e,
                            "malformed request frame; closing stream"
                        );
                        actions.push(PendingAction::AclReject {
                            stream_id,
                            resp: err(ErrorCode::Malformed, "Malformed request"),
                        });
                        *state = StreamState::Done;
                        continue;
                    }
                };
                if let Some(req) = req {
                    metrics.requests_total.fetch_add(1, Ordering::Relaxed);
                    debug!(
                        peer = %ctx.peer_addr,
                        user = %ctx.user.name,
                        stream_id,
                        ?req,
                        "request received"
                    );

                    // Per-request rate limit: token-bucket also gates
                    // protocol requests on established connections so a
                    // single accepted peer can't burn the server with
                    // command floods.
                    if !rate_limiter.try_consume(peer_ip) {
                        metrics
                            .requests_rate_limited
                            .fetch_add(1, Ordering::Relaxed);
                        actions.push(PendingAction::AclReject {
                            stream_id,
                            resp: err(ErrorCode::RateLimited, "Rate limit exceeded"),
                        });
                        *state = StreamState::Done;
                        continue;
                    }

                    // 0-RTT replay protection. Any request decoded
                    // while the QUIC handshake is still in the
                    // early-data phase rode the first flight, which
                    // an attacker can replay byte-for-byte. Read-only
                    // ops are idempotent so we accept them; anything
                    // that mutates server state is refused with
                    // `Unsupported` and the client falls back to a
                    // 1-RTT retry.
                    if ctx.conn.is_in_early_data() {
                        if request_is_replay_safe(&req) {
                            metrics.zero_rtt_accepted.fetch_add(1, Ordering::Relaxed);
                        } else {
                            metrics.zero_rtt_rejected.fetch_add(1, Ordering::Relaxed);
                            actions.push(PendingAction::AclReject {
                                stream_id,
                                resp: err(ErrorCode::Unsupported, "Operation requires 1-RTT data"),
                            });
                            *state = StreamState::Done;
                            continue;
                        }
                    }

                    if let Some(resp) = handler::acl_reject(&ctx.user, &req) {
                        actions.push(PendingAction::AclReject { stream_id, resp });
                        *state = StreamState::Done;
                        continue;
                    }

                    match req {
                        Request::Get {
                            path,
                            offset,
                            length,
                        } => {
                            actions.push(PendingAction::StartGet {
                                stream_id,
                                path,
                                offset,
                                length,
                            });
                            *state = StreamState::Done;
                        }
                        Request::Put {
                            path,
                            size,
                            mode,
                            offset,
                            checksum,
                        } => {
                            let leftover = std::mem::take(stream_buf);
                            actions.push(PendingAction::StartPut {
                                stream_id,
                                path,
                                size,
                                mode,
                                offset,
                                expected_checksum: checksum,
                                leftover,
                            });
                            *state = StreamState::Done;
                        }
                        Request::Quit => {
                            actions.push(PendingAction::Quit { stream_id });
                            *state = StreamState::Done;
                        }
                        Request::Quota => {
                            actions.push(PendingAction::Quota { stream_id });
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
            PendingAction::StartGet {
                stream_id,
                path,
                offset,
                length,
            } => {
                start_get(ctx, stream_id, &path, offset, length, metrics)?;
            }
            PendingAction::StartPut {
                stream_id,
                path,
                size,
                mode,
                offset,
                expected_checksum,
                leftover,
            } => {
                start_put(
                    ctx,
                    stream_id,
                    &path,
                    size,
                    mode,
                    offset,
                    expected_checksum,
                    leftover,
                    metrics,
                )?;
            }
            PendingAction::Quit { stream_id } => {
                send_message(&mut ctx.conn, stream_id, &Response::Ok)?;
                flush_egress(&mut ctx.conn, socket)?;
                ctx.conn.close(true, 0x00, b"bye").ok();
            }
            PendingAction::Quota { stream_id } => {
                let (used_bytes, file_count) = walk_size(&ctx.user.home);
                let resp = Response::QuotaInfo {
                    used_bytes,
                    file_count,
                    limit_bytes: ctx.user.quota_bytes,
                };
                send_message(&mut ctx.conn, stream_id, &resp)?;
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

#[allow(clippy::too_many_arguments)]
fn start_get(
    ctx: &mut ConnectionContext,
    stream_id: u64,
    path: &str,
    offset: u64,
    length: Option<u64>,
    metrics: &Arc<Metrics>,
) -> Result<()> {
    let send_err = |ctx: &mut ConnectionContext, code, msg| -> Result<()> {
        send_message(&mut ctx.conn, stream_id, &err(code, msg))?;
        metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
        ctx.streams.insert(stream_id, StreamState::Done);
        Ok(())
    };

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
            return send_err(ctx, io_code(&e), format!("Failed to stat file: {e}"));
        }
    };
    if !meta.is_file() {
        return send_err(
            ctx,
            ErrorCode::IsADirectory,
            "Not a regular file".to_string(),
        );
    }
    if meta.len() > MAX_FILE_SIZE {
        return send_err(
            ctx,
            ErrorCode::FileTooLarge,
            format!(
                "File too large: {} bytes (max {} bytes)",
                meta.len(),
                MAX_FILE_SIZE
            ),
        );
    }
    if offset > meta.len() {
        return send_err(
            ctx,
            ErrorCode::InvalidRange,
            format!("offset {} past end of file (size {})", offset, meta.len()),
        );
    }
    let remaining = meta.len() - offset;
    let bytes_to_send = match length {
        Some(n) => n.min(remaining),
        None => remaining,
    };
    let mut file = File::open(&file_path).context("open file for streaming send")?;
    if offset > 0 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(offset))
            .with_context(|| format!("seek to offset {offset}"))?;
    }
    send_message(
        &mut ctx.conn,
        stream_id,
        &Response::FileReady {
            size: bytes_to_send,
            total_size: meta.len(),
            checksum_follows: true,
        },
    )?;
    ctx.streams.insert(
        stream_id,
        StreamState::SendingFileData {
            reader: std::io::BufReader::with_capacity(FILE_CHUNK_SIZE, file),
            total_size: bytes_to_send,
            sent: 0,
            hasher: blake3::Hasher::new(),
            trailer: None,
            trailer_offset: 0,
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
        // After this call we either mark the stream Done, or we leave a
        // SendingFileData with updated counters for the next iteration.
        let outcome = drive_one_sender(ctx, stream_id, &mut chunk, metrics);
        if outcome == SendOutcome::Finished {
            if let Some(state) = ctx.streams.get_mut(&stream_id) {
                *state = StreamState::Done;
            }
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum SendOutcome {
    Blocked,
    Finished,
    Failed,
}

fn drive_one_sender(
    ctx: &mut ConnectionContext,
    stream_id: u64,
    chunk: &mut [u8],
    metrics: &Arc<Metrics>,
) -> SendOutcome {
    let Some(state) = ctx.streams.get_mut(&stream_id) else {
        return SendOutcome::Finished;
    };
    let StreamState::SendingFileData {
        reader,
        total_size,
        sent,
        hasher,
        trailer,
        trailer_offset,
        finished,
    } = state
    else {
        return SendOutcome::Finished;
    };
    if *finished {
        return SendOutcome::Finished;
    }

    // Phase A: stream the body. After every chunk that quiche accepts we
    // also feed it into the BLAKE3 hasher so the trailer matches exactly
    // what the peer received.
    while *sent < *total_size && trailer.is_none() {
        let want = ((*total_size - *sent) as usize).min(chunk.len());
        if let Err(e) = reader.read_exact(&mut chunk[..want]) {
            warn!(stream_id, error = %e, "file read failed mid-stream");
            let _ = ctx.conn.stream_send(stream_id, &[], true);
            return SendOutcome::Failed;
        }
        match ctx.conn.stream_send(stream_id, &chunk[..want], false) {
            Ok(0) => {
                if let Err(e) = reader.seek_relative(-(want as i64)) {
                    warn!(stream_id, error = %e, "seek failed when stream blocked");
                    return SendOutcome::Failed;
                }
                return SendOutcome::Blocked;
            }
            Ok(n) => {
                hasher.update(&chunk[..n]);
                *sent += n as u64;
                metrics.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                if n < want {
                    if let Err(e) = reader.seek_relative(-((want - n) as i64)) {
                        warn!(stream_id, error = %e, "seek failed during partial send");
                        return SendOutcome::Failed;
                    }
                    return SendOutcome::Blocked;
                }
            }
            Err(quiche::Error::Done) => {
                if let Err(e) = reader.seek_relative(-(want as i64)) {
                    warn!(stream_id, error = %e, "seek failed on Done");
                    return SendOutcome::Failed;
                }
                return SendOutcome::Blocked;
            }
            Err(e) => {
                warn!(stream_id, error = ?e, "stream_send failed during Get");
                return SendOutcome::Failed;
            }
        }
    }

    // Phase B: body fully sent. Finalize hash once, then push the 32
    // bytes as a trailer with FIN. trailer_offset survives across
    // iterations so a partial-write here resumes cleanly.
    if trailer.is_none() {
        let h = hasher.finalize();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(h.as_bytes());
        *trailer = Some(buf);
        *trailer_offset = 0;
    }
    let bytes = trailer.unwrap();
    // Push the trailer bytes WITHOUT fin first; we only emit the FIN as
    // a separate empty frame once all 32 bytes are accepted. quiche's
    // documented behaviour does keep fin pending across partial writes,
    // but the explicit fin-only step is the same pattern stream_send_all
    // uses elsewhere and makes the "stream closes only when the last
    // byte has been queued" invariant impossible to misread.
    while *trailer_offset < bytes.len() {
        let remaining = &bytes[*trailer_offset..];
        match ctx.conn.stream_send(stream_id, remaining, false) {
            Ok(0) => return SendOutcome::Blocked,
            Ok(n) => {
                *trailer_offset += n;
                metrics.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(quiche::Error::Done) => return SendOutcome::Blocked,
            Err(e) => {
                warn!(stream_id, error = ?e, "stream_send for trailer failed");
                return SendOutcome::Failed;
            }
        }
    }
    // All 32 trailer bytes are queued -- emit the FIN.
    match ctx.conn.stream_send(stream_id, &[], true) {
        Ok(_) | Err(quiche::Error::Done) => {}
        Err(e) => {
            warn!(stream_id, error = ?e, "stream_send for trailer FIN failed");
            return SendOutcome::Failed;
        }
    }

    *finished = true;
    metrics.downloads_completed.fetch_add(1, Ordering::Relaxed);
    SendOutcome::Finished
}

#[allow(clippy::too_many_arguments)]
fn start_put(
    ctx: &mut ConnectionContext,
    stream_id: u64,
    path: &str,
    size: u64,
    mode: u32,
    offset: u64,
    expected_checksum: Option<[u8; 32]>,
    leftover: Vec<u8>,
    metrics: &Arc<Metrics>,
) -> Result<()> {
    let send_err = |ctx: &mut ConnectionContext, code, msg| -> Result<()> {
        send_message(&mut ctx.conn, stream_id, &err(code, msg))?;
        metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
        ctx.streams.insert(stream_id, StreamState::Done);
        Ok(())
    };

    if size > MAX_FILE_SIZE {
        return send_err(
            ctx,
            ErrorCode::FileTooLarge,
            format!(
                "Upload too large: {} bytes (max {} bytes)",
                size, MAX_FILE_SIZE
            ),
        );
    }
    // Quota pre-check. Cheap: walk the user's home once. A naive
    // implementation; a real deployment would cache. Refusing
    // upfront avoids spending the body bytes only to discard them.
    if let Some(limit) = ctx.user.quota_bytes {
        let (used, _) = walk_size(&ctx.user.home);
        // Approximate post-upload size: `used + size - offset` since
        // resume uploads only add the tail.
        let projected = used.saturating_add(size.saturating_sub(offset));
        if projected > limit {
            return send_err(
                ctx,
                ErrorCode::QuotaExceeded,
                format!(
                    "Quota exceeded: would use {projected} bytes (limit {limit}, currently {used})"
                ),
            );
        }
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

    // Resume: if offset > 0 the client is claiming the server already
    // has the first `offset` bytes of this upload in the temp file. We
    // open it for append (not create_new) and validate the existing
    // length matches the offset. Otherwise it's a fresh upload.
    let (writer, mut hasher) = if offset == 0 {
        let f = match open_temp_no_follow(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                return send_err(
                    ctx,
                    io_code(&e),
                    format!("Failed to create upload temp file: {e}"),
                );
            }
        };
        (
            BufWriter::with_capacity(FILE_CHUNK_SIZE, f),
            blake3::Hasher::new(),
        )
    } else {
        // Resume path: open existing temp, validate length, hash its
        // contents so the final checksum still covers the full body.
        let meta = match fs::metadata(&temp_path) {
            Ok(m) => m,
            Err(e) => {
                return send_err(
                    ctx,
                    ErrorCode::InvalidRange,
                    format!("Resume requested at offset {offset} but no temp file exists ({e})"),
                );
            }
        };
        if meta.len() != offset {
            return send_err(
                ctx,
                ErrorCode::InvalidRange,
                format!(
                    "Resume offset {offset} doesn't match server temp length {}",
                    meta.len()
                ),
            );
        }
        let mut hasher = blake3::Hasher::new();
        let mut existing = match open_existing_no_follow(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                return send_err(
                    ctx,
                    io_code(&e),
                    format!("Failed to open temp for resume: {e}"),
                );
            }
        };
        let mut copy_buf = [0u8; FILE_CHUNK_SIZE];
        loop {
            match std::io::Read::read(&mut existing, &mut copy_buf) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&copy_buf[..n]);
                }
                Err(e) => {
                    return send_err(
                        ctx,
                        ErrorCode::Internal,
                        format!("Failed to rehash temp for resume: {e}"),
                    );
                }
            }
        }
        let f = match open_append_no_follow(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                return send_err(
                    ctx,
                    io_code(&e),
                    format!("Failed to reopen temp for append: {e}"),
                );
            }
        };
        (BufWriter::with_capacity(FILE_CHUNK_SIZE, f), hasher)
    };

    let _ = &mut hasher; // borrow as mutable below
    let mut new_state = StreamState::ReadingFileData {
        final_path,
        temp_path,
        writer,
        remaining: size,
        mode,
        completed: false,
        hasher,
        expected_checksum,
    };
    if !leftover.is_empty() {
        if let StreamState::ReadingFileData {
            writer,
            remaining,
            hasher,
            ..
        } = &mut new_state
        {
            if leftover.len() as u64 > *remaining {
                send_message(
                    &mut ctx.conn,
                    stream_id,
                    &err(ErrorCode::UploadOverflow, "Upload exceeded declared size"),
                )?;
                metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
                ctx.streams.insert(stream_id, StreamState::Done);
                return Ok(());
            }
            if let Err(e) = writer.write_all(&leftover) {
                send_message(
                    &mut ctx.conn,
                    stream_id,
                    &err(ErrorCode::Internal, format!("Failed to write file: {e}")),
                )?;
                metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
                ctx.streams.insert(stream_id, StreamState::Done);
                return Ok(());
            }
            hasher.update(&leftover);
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
        hasher,
        expected_checksum,
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
                    return Ok(Some(err(
                        ErrorCode::Internal,
                        format!("Failed to write file: {e}"),
                    )));
                }
                hasher.update(&tmp[..to_take]);
                *remaining -= to_take as u64;
                metrics
                    .bytes_received
                    .fetch_add(to_take as u64, Ordering::Relaxed);
                if to_take < len {
                    return Ok(Some(err(
                        ErrorCode::UploadOverflow,
                        "Upload exceeded declared size",
                    )));
                }
                if fin && *remaining > 0 {
                    return Ok(Some(err(
                        ErrorCode::UploadTruncated,
                        format!("Upload truncated: {} bytes still expected", *remaining),
                    )));
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!(stream_id, error = ?e, "stream_recv error during Put");
                return Ok(Some(err(ErrorCode::Internal, "Stream receive error")));
            }
        }
    }

    if *remaining == 0 {
        if let Err(e) = writer.flush() {
            return Ok(Some(err(
                ErrorCode::Internal,
                format!("Failed to flush file: {e}"),
            )));
        }
        // Verify checksum before rename. If it mismatches we leave the
        // temp in place for the Drop impl to clean up and refuse the
        // upload -- never reveal a corrupted body at `final_path`.
        if let Some(expected) = expected_checksum {
            let got = *hasher.finalize().as_bytes();
            if got != *expected {
                return Ok(Some(err(
                    ErrorCode::ChecksumMismatch,
                    "Upload checksum verification failed",
                )));
            }
        }
        if let Err(e) = fs::rename(temp_path, &final_path) {
            return Ok(Some(err(
                ErrorCode::Internal,
                format!("Failed to finalize file: {e}"),
            )));
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

/// Reopen an existing temp file for read-only rehashing on the Put
/// resume path. O_NOFOLLOW so a swapped-in symlink can't redirect us
/// to read arbitrary files; also assert it's a regular file before
/// accepting it.
fn open_existing_no_follow(path: &Path) -> std::io::Result<File> {
    use std::io::{Error, ErrorKind};
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "resume temp is not a regular file (symlink or directory?)",
        ));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// Reopen an existing temp file for append on the Put resume path.
/// Same O_NOFOLLOW + regular-file requirement as `open_existing_no_follow`.
fn open_append_no_follow(path: &Path) -> std::io::Result<File> {
    use std::io::{Error, ErrorKind};
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "resume temp is not a regular file (symlink or directory?)",
        ));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_safe_allows_readonly_ops() {
        assert!(request_is_replay_safe(&Request::Ls { path: "/".into() }));
        assert!(request_is_replay_safe(&Request::Cd { path: "/".into() }));
        assert!(request_is_replay_safe(&Request::Pwd));
        assert!(request_is_replay_safe(&Request::Stat { path: "x".into() }));
        assert!(request_is_replay_safe(&Request::Get {
            path: "x".into(),
            offset: 0,
            length: None,
        }));
        assert!(request_is_replay_safe(&Request::Quit));
    }

    #[test]
    fn replay_safe_rejects_mutations() {
        assert!(!request_is_replay_safe(&Request::Put {
            path: "x".into(),
            size: 0,
            mode: 0o644,
            offset: 0,
            checksum: Some([0u8; 32]),
        }));
        assert!(!request_is_replay_safe(&Request::Rm { path: "x".into() }));
        assert!(!request_is_replay_safe(&Request::Mkdir {
            path: "x".into()
        }));
        assert!(!request_is_replay_safe(&Request::Rmdir {
            path: "x".into()
        }));
        assert!(!request_is_replay_safe(&Request::Rename {
            from: "a".into(),
            to: "b".into(),
        }));
        assert!(!request_is_replay_safe(&Request::Chmod {
            path: "x".into(),
            mode: 0o644,
        }));
    }
}
