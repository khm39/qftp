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
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use mio::{Events, Interest, Poll, Token, Waker};
use qftp_common::protocol::*;
use qftp_common::transport::*;
use tracing::{debug, info, warn};

use crate::connection::ConnectionContext;
use crate::limits::{Caps, ConnectionCounter, RateLimiter};
use crate::metrics::Metrics;
use crate::retry::RetryKey;
use qftp_protocol::handler::{self, err, io_code};
use qftp_protocol::stream::{
    temp_path_for, ResumeRehash, StreamState, UploadClaim, FILE_CHUNK_SIZE, MAX_FILE_SIZE,
    SEND_CHUNK_SIZE,
};
use qftp_protocol::user::{self, InFlightReservation, User, UserDirectory};

/// Which Request variants are safe to serve while the connection is
/// still in the 0-RTT phase. The rule is "read-only / no
/// side-effects": replays produce identical responses and never
/// mutate persistent state. Anything that writes or renames is
/// refused so a captured 0-RTT flight cannot be replayed to put the
/// server into a different state.
fn request_is_replay_safe(req: &Request) -> bool {
    // Quota is intentionally NOT in this set. Even though the server
    // caches the usage so the reply is cheap, treating it as
    // replay-safe means a captured 0-RTT Quota request can be
    // re-fired indefinitely as a "ping" against the user record —
    // useful primarily as an amplification primitive. The latency
    // cost of forcing 1-RTT for Quota is negligible since it runs
    // once per session.
    //
    // Get is also NOT in this set. Although a Get reply is
    // idempotent and side-effect-free, it can return up to
    // MAX_FILE_SIZE bytes, which turns a replayed 0-RTT flight into
    // a bandwidth amplification primitive — at worst the captured
    // request could be re-fired against a spoofed source IP for
    // reflected-download attacks. The latency cost of forcing 1-RTT
    // for Get is one extra round trip on the first request of a
    // session; subsequent requests within the same session run at
    // normal 1-RTT either way. The list below intentionally keeps
    // only small fixed-size replies (Ls is capped at MAX_DIR_ENTRIES,
    // Stat is a fixed struct, Pwd/Cd/Quit are tiny acks).
    matches!(
        req,
        Request::Ls { .. }
            | Request::Cd { .. }
            | Request::Pwd
            | Request::Stat { .. }
            | Request::Quit,
    )
}

const SERVER_TOKEN: Token = Token(0);
/// Token for the mio `Waker` the handler worker pool uses to wake the
/// event loop as soon as an offloaded request has a response ready.
const WAKER_TOKEN: Token = Token(1);

/// Number of background threads that run blocking filesystem requests
/// (Ls/Stat/Mkdir/Rename/Chmod/Rm/...) off the event-loop thread, so a
/// slow directory walk on one connection can't stall every other
/// connection (H-1).
const HANDLER_WORKERS: usize = 4;

/// Static knobs the loop reads on every iteration.
pub struct ServerConfig {
    pub caps: Caps,
    pub require_retry: bool,
    /// Per-IP request token bucket refill rate (requests per second).
    pub rate_limit_rps: f64,
    /// Per-IP request token bucket burst capacity.
    pub rate_limit_burst: f64,
    /// True when the server was started with `--client-ca` (mTLS).
    /// quiche's `verify_peer(true)` only sets `SSL_VERIFY_PEER`, not
    /// `SSL_VERIFY_FAIL_IF_NO_PEER_CERT`, so a client that presents no
    /// certificate still completes the TLS handshake. When this flag
    /// is set, such connections are closed instead of being served as
    /// the anonymous user.
    pub mtls_required: bool,
}

/// A generic request handed to a handler worker thread for off-loop
/// execution (H-1).
struct HandlerJob {
    conn_key: quiche::ConnectionId<'static>,
    stream_id: u64,
    req: Request,
    cwd: PathBuf,
    user: Arc<User>,
}

/// The result of a `HandlerJob`, routed back to the event loop.
struct HandlerResult {
    conn_key: quiche::ConnectionId<'static>,
    stream_id: u64,
    response: Response,
    /// `cwd` after running the request -- changed only by `Cd`.
    new_cwd: PathBuf,
    /// The user the job ran as. Used to detect a mid-flight auth
    /// upgrade so a stale `cwd` doesn't clobber the upgraded one.
    user: Arc<User>,
}

/// Pool of worker threads that execute blocking filesystem requests
/// off the event-loop thread.
///
/// On drop, the explicit `Drop` impl below replaces `job_tx` with a
/// dummy sender via `mem::replace` so workers blocked in `recv()`
/// wake up with `Err(RecvError)`, then bounded-waits each handle
/// via `is_finished()` and joins them so panic payloads surface in
/// the log. Field declaration order is therefore *not* load-bearing
/// -- the explicit Drop runs before any implicit field drops.
struct HandlerPool {
    job_tx: mpsc::Sender<HandlerJob>,
    result_rx: mpsc::Receiver<HandlerResult>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl Drop for HandlerPool {
    fn drop(&mut self) {
        // Replace `job_tx` with a fresh, detached channel so the only
        // sender feeding workers' `recv()` is dropped *now*; workers
        // wake up with `Err(RecvError)` and exit their loop. The
        // dummy sender drops at end of statement.
        let (dummy_tx, _) = mpsc::channel::<HandlerJob>();
        let _ = std::mem::replace(&mut self.job_tx, dummy_tx);
        // Workers parked inside `recv()` unblock immediately, but a
        // worker mid-syscall (e.g. a slow NFS `readdir`) won't even
        // observe the channel close until that syscall returns.
        // Polling `is_finished()` with a bounded deadline lets server
        // shutdown progress in that case: any thread still running
        // past the deadline is detached (the JoinHandle's normal Drop
        // does not join) and will exit on its own once the syscall
        // completes.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        for handle in std::mem::take(&mut self.workers) {
            while !handle.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if !handle.is_finished() {
                tracing::warn!(
                    thread = handle.thread().name().unwrap_or("<unnamed>"),
                    "qftp handler worker did not exit within shutdown deadline; \
                     detaching (likely stuck in a blocking filesystem syscall)",
                );
                // Dropping the handle without join detaches the thread.
                continue;
            }
            if let Err(payload) = handle.join() {
                let msg = qftp_common::util::panic_payload_message(payload);
                tracing::error!(
                    panic = %msg,
                    "qftp handler worker thread panicked; pool is shutting down anyway",
                );
            }
        }
    }
}

fn spawn_handler_pool(waker: Arc<Waker>) -> HandlerPool {
    let (job_tx, job_rx) = mpsc::channel::<HandlerJob>();
    let (result_tx, result_rx) = mpsc::channel::<HandlerResult>();
    // std mpsc is single-consumer; share the receiver behind a mutex so
    // every worker pulls from the same queue. The lock is held only for
    // the brief `recv`, so jobs still fan out across idle workers.
    let job_rx = Arc::new(Mutex::new(job_rx));
    let mut workers = Vec::with_capacity(HANDLER_WORKERS);
    for i in 0..HANDLER_WORKERS {
        let job_rx = Arc::clone(&job_rx);
        let result_tx = result_tx.clone();
        let waker = Arc::clone(&waker);
        let handle = thread::Builder::new()
            .name(format!("qftp-handler-{i}"))
            .spawn(move || handler_worker(&job_rx, &result_tx, &waker))
            .expect("failed to spawn handler worker");
        workers.push(handle);
    }
    HandlerPool {
        job_tx,
        result_rx,
        workers,
    }
}

fn handler_worker(
    job_rx: &Mutex<mpsc::Receiver<HandlerJob>>,
    result_tx: &mpsc::Sender<HandlerResult>,
    waker: &Waker,
) {
    loop {
        // Hold the lock only across `recv`; release it before running
        // the (potentially slow) filesystem work.
        let job = {
            let rx = job_rx.lock().unwrap_or_else(|e| e.into_inner());
            match rx.recv() {
                Ok(job) => job,
                // job_tx dropped: the server is shutting down.
                Err(_) => return,
            }
        };
        let conn_key = job.conn_key.clone();
        let stream_id = job.stream_id;
        let user = Arc::clone(&job.user);
        let req_dbg = format!("{:?}", job.req);
        // Wrap `run_handler` in catch_unwind so a panic inside a
        // single request handler doesn't permanently shrink the pool
        // (after HANDLER_WORKERS panics nothing would drain
        // `pending_handler_jobs`, and the event loop would queue
        // requests forever). On panic, synthesize an Internal error
        // response and keep the worker alive.
        //
        // Snapshot `cwd` only for `Cd` requests. `Cd` is the only
        // handler arm that mutates `cwd`; other requests (`Ls`,
        // `Stat`, `Mkdir`, ...) take `&mut cwd` but never write to
        // it, so a panic mid-handler can't desync the connection's
        // working directory. Cloning unconditionally would charge
        // every hot-path request a `PathBuf` allocation -- on top of
        // the clone already done by `dispatch_handler_job` to fill
        // `job.cwd` -- for a rollback we'd never use.
        let cwd_snapshot = if matches!(job.req, Request::Cd { .. }) {
            Some(job.cwd.clone())
        } else {
            None
        };
        let mut cwd = job.cwd;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_handler(&job.req, &mut cwd, &job.user)
        }));
        let (response, new_cwd) = match outcome {
            Ok(r) => (r, cwd),
            Err(payload) => {
                let msg = qftp_common::util::panic_payload_message(payload);
                tracing::error!(
                    panic = %msg,
                    request = %req_dbg,
                    user = %user.name,
                    "handler_worker: request handler panicked; replying with Internal \
                     error and restoring cwd to the pre-handler value (if Cd)",
                );
                // For non-Cd requests we did not take a snapshot
                // (cwd is unmodified by the handler), so fall back
                // to `cwd` -- which equals the value Cd hadn't yet
                // overwritten anyway, since the partial-mutation
                // path only exists in Cd's match arm.
                let restored = cwd_snapshot.unwrap_or(cwd);
                (
                    Response::Err(qftp_common::protocol::ErrorResponse::new(
                        qftp_common::protocol::ErrorCode::Internal,
                        "handler crashed",
                    )),
                    restored,
                )
            }
        };
        let result = HandlerResult {
            conn_key,
            stream_id,
            response,
            new_cwd,
            user,
        };
        if result_tx.send(result).is_err() {
            return; // event loop gone
        }
        // Wake the loop so the response goes out without waiting for
        // the next timeout or inbound packet.
        let _ = waker.wake();
    }
}

/// Run a generic (non-Get/Put/Quota/Quit) protocol request to a
/// `Response`. This is the blocking-fs body the worker pool executes
/// off the event-loop thread. `cwd` is updated in place for `Cd`.
fn run_handler(req: &Request, cwd: &mut PathBuf, user: &User) -> Response {
    // Rm also decrements the per-user used-bytes cache, so it
    // can't go through the generic handler (which never sees the
    // deleted file's size). Everything else is plain handle_request.
    if let Request::Rm { path } = req {
        if handler::is_upload_temp(path) {
            return err(
                ErrorCode::PermissionDenied,
                "cannot remove a server-internal upload temp file",
            );
        }
        match handler::resolve(cwd, &user.home, path) {
            Ok(target) => {
                // Parent-dir symlink TOCTOU re-check.
                if let Err(e) = handler::recheck_ancestors_no_symlinks(&target, &user.home) {
                    Response::Err(e)
                } else {
                    let pre_size = std::fs::symlink_metadata(&target)
                        .ok()
                        .filter(|m| m.is_file())
                        .map(|m| m.len())
                        .unwrap_or(0);
                    match std::fs::remove_file(&target) {
                        Ok(()) => {
                            if pre_size > 0 {
                                // Atomic saturating subtract: a plain
                                // load/store loses concurrent Rm
                                // decrements from other worker threads,
                                // drifting `used_bytes` upward until the
                                // user is falsely quota-locked.
                                let _ = user.used_bytes.fetch_update(
                                    Ordering::Relaxed,
                                    Ordering::Relaxed,
                                    |v| Some(v.saturating_sub(pre_size)),
                                );
                            }
                            Response::Ok
                        }
                        Err(e) => err(io_code(&e), format!("rm failed: {e}")),
                    }
                }
            }
            Err(e) => Response::Err(e),
        }
    } else if let Request::Rename { from, to } = req {
        // Rename can overwrite an existing destination file, freeing
        // that file's bytes on disk. `handle_request` never sees
        // `user`, so capture the clobbered size here and refund it from
        // `used_bytes` once the rename succeeds -- otherwise repeated
        // overwrite-renames drift the quota upward until the user is
        // falsely QuotaExceeded.
        let from_path = handler::resolve(cwd, &user.home, from).ok();
        let to_path = handler::resolve_parent(cwd, &user.home, to).ok();
        let clobbered = match (&from_path, &to_path) {
            // A rename onto itself frees nothing; only count a distinct
            // destination that already holds a regular file.
            (Some(f), Some(t)) if f != t => std::fs::symlink_metadata(t)
                .ok()
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .unwrap_or(0),
            _ => 0,
        };
        let resp = handler::handle_request(req, cwd, &user.home);
        if matches!(resp, Response::Ok) && clobbered > 0 {
            user.used_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(clobbered))
                })
                .ok();
        }
        resp
    } else {
        handler::handle_request(req, cwd, &user.home)
    }
}

/// Offload a generic handler request to the worker pool. Falls back to
/// running it inline if the pool channel is somehow closed, so the
/// client always gets a response. On success the connection is marked
/// `handler_in_flight`.
fn dispatch_handler_job(
    pool: &HandlerPool,
    ctx: &mut ConnectionContext,
    metrics: &Metrics,
    stream_id: u64,
    req: Request,
) {
    let job = HandlerJob {
        conn_key: ctx.scid.clone(),
        stream_id,
        req,
        cwd: ctx.cwd.clone(),
        user: Arc::clone(&ctx.user),
    };
    match pool.job_tx.send(job) {
        Ok(()) => ctx.handler_in_flight = true,
        Err(mpsc::SendError(job)) => {
            // Inline fallback: the pool channel is dead (all workers
            // exited, e.g. mid-shutdown). Run the handler here on the
            // event-loop thread, with the same catch_unwind + cwd
            // rollback the worker pool uses, so a handler panic
            // can't take down every other connection.
            let cwd_snapshot = if matches!(job.req, Request::Cd { .. }) {
                Some(job.cwd.clone())
            } else {
                None
            };
            let user = Arc::clone(&job.user);
            let req_dbg = format!("{:?}", job.req);
            let mut cwd = job.cwd;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_handler(&job.req, &mut cwd, &job.user)
            }));
            let (response, new_cwd) = match outcome {
                Ok(r) => (r, cwd),
                Err(payload) => {
                    let msg = qftp_common::util::panic_payload_message(payload);
                    tracing::error!(
                        panic = %msg,
                        request = %req_dbg,
                        user = %user.name,
                        "dispatch_handler_job inline fallback panicked; \
                         replying with Internal error",
                    );
                    let restored = cwd_snapshot.unwrap_or(cwd);
                    (
                        Response::Err(qftp_common::protocol::ErrorResponse::new(
                            qftp_common::protocol::ErrorCode::Internal,
                            "handler crashed",
                        )),
                        restored,
                    )
                }
            };
            ctx.cwd = new_cwd;
            if matches!(response, Response::Err(_)) {
                metrics.inc_requests_failed();
            }
            if let Err(e) = send_message(&mut ctx.conn, stream_id, &response) {
                warn!(stream_id, error = %e, "failed to send handler response");
            }
        }
    }
}

/// Apply a completed handler job: send the response on its stream,
/// commit the `cwd` change, and dispatch the next queued request for
/// that connection (if any).
fn apply_handler_result(
    connections: &mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
    pool: &HandlerPool,
    metrics: &Metrics,
    result: HandlerResult,
) {
    let Some(ctx) = connections.get_mut(&result.conn_key) else {
        // Connection was reaped while the job ran; drop the response.
        return;
    };
    // Commit the cwd only if the connection still belongs to the same
    // user. A handshake completing mid-flight can upgrade the user (and
    // reset cwd to the authenticated home); a stale anonymous cwd must
    // not overwrite that.
    if Arc::ptr_eq(&ctx.user, &result.user) {
        ctx.cwd = result.new_cwd;
    }
    if matches!(result.response, Response::Err(_)) {
        metrics.inc_requests_failed();
    }
    if let Err(e) = send_message(&mut ctx.conn, result.stream_id, &result.response) {
        warn!(
            stream_id = result.stream_id,
            error = %e,
            "failed to send handler response"
        );
    }
    ctx.handler_in_flight = false;
    if let Some((stream_id, req)) = ctx.pending_handler_jobs.pop_front() {
        dispatch_handler_job(pool, ctx, metrics, stream_id, req);
    }
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

    // Handler worker pool, plus the Waker it uses to interrupt poll()
    // as soon as an offloaded request has a response ready (H-1).
    let waker =
        Arc::new(Waker::new(poll.registry(), WAKER_TOKEN).context("failed to create mio Waker")?);
    let handler_pool = spawn_handler_pool(waker);

    let rng = ring::rand::SystemRandom::new();
    let mut rate_limiter =
        RateLimiter::new(server_config.rate_limit_rps, server_config.rate_limit_burst);
    let mut counter = ConnectionCounter::default();
    let retry_key = RetryKey::new().context("seed retry-token signing key")?;

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
    // Reused scratch for the Get send path; allocated once so the
    // larger SEND_CHUNK_SIZE costs nothing per loop iteration.
    let mut send_buf = vec![0u8; SEND_CHUNK_SIZE];
    // Reused scratch for the per-iteration list of streams that are
    // actively sending, so the collect() doesn't allocate each pass.
    let mut sender_ids: Vec<u64> = Vec::new();
    // Same idea for the readable-stream sweep.
    let mut readable_ids: Vec<u64> = Vec::new();
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
        // A resumed Put re-hashing its on-disk prefix has pure local
        // work to do that no network event will wake the loop for; spin
        // at a zero timeout until that re-hash finishes.
        let rehash_pending = connections.values().any(|c| {
            c.streams.values().any(|s| {
                matches!(
                    s,
                    StreamState::ReadingFileData {
                        rehash: Some(_),
                        ..
                    }
                )
            })
        });
        let poll_timeout = match (closing, rehash_pending, shortest_timeout) {
            (true, _, t) => Some(t.unwrap_or(Duration::from_millis(250))),
            (false, true, _) => Some(Duration::ZERO),
            (false, false, Some(t)) => Some(t),
            (false, false, None) => None,
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
            // the peer's DCID is the SCID we issued, so this lookup hits
            // first and is the only one we pay for on the hot path. The
            // borrowed DCID is used as the key directly -- no owned
            // clone -- and the derived alias is only computed on a miss.
            let recv_info = quiche::RecvInfo {
                from,
                to: local_addr,
            };
            if let Some(ctx) = connections.get_mut(&hdr.dcid) {
                if let Err(e) = ctx.conn.recv(&mut buf[..len], recv_info) {
                    warn!(peer = %from, error = ?e, "QUIC recv error");
                }
                continue;
            }
            // Miss: Initial retransmits during the handshake still carry
            // the peer's original DCID, so try its derived alias too.
            let alias = derive_scid(&conn_id_seed, &hdr.dcid);
            if let Some(ctx) = connections.get_mut(&alias) {
                if let Err(e) = ctx.conn.recv(&mut buf[..len], recv_info) {
                    warn!(peer = %from, error = ?e, "QUIC recv error");
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

            let mut ax = AcceptCtx {
                connections: &mut connections,
                counter: &mut counter,
                rate_limiter: &mut rate_limiter,
                quiche_config: &mut quiche_config,
                retry_key: &retry_key,
                conn_id_seed: &conn_id_seed,
                cfg: &server_config,
                users: &users,
                metrics: &metrics,
                rng: &rng,
                socket: &socket,
            };
            // An accept-time failure (a transient UDP send error while
            // issuing a RETRY, a quiche::accept rejection) must stay
            // scoped to this one Initial: propagating it out of `run()`
            // would tear down the whole server and every other client's
            // connection. Log and drop the packet, like the
            // per-connection work below.
            if let Err(e) = try_accept(
                &mut ax,
                from,
                local_addr,
                &hdr,
                &mut buf[..len],
                &mut out_pkt,
            ) {
                warn!(peer = %from, error = %e, "accept failed; dropping Initial");
            }
        }

        // 1.5. Drain completed handler jobs and send their responses.
        while let Ok(result) = handler_pool.result_rx.try_recv() {
            apply_handler_result(&mut connections, &handler_pool, &metrics, result);
        }

        // 2. on_timeout.
        for ctx in connections.values_mut() {
            ctx.conn.on_timeout();
        }

        // 3-5. Per-connection work: streams + sending + egress.
        //
        // An error here is scoped to the one connection it happened on --
        // most commonly a stream-/connection-level QUIC send error after
        // the peer reset a stream or closed the connection mid-request.
        // Such an error must NOT propagate out of `run()`: that would tear
        // down the whole server and every other client's connection. We
        // instead close just the offending connection (the reap sweep
        // below drops it) and keep serving everyone else. Truly fatal
        // socket errors still surface via the ingress `recv_from` path.
        for ctx in connections.values_mut() {
            if let Err(e) = process_readable_streams(
                ctx,
                &socket,
                &users,
                &metrics,
                &mut rate_limiter,
                &mut buf,
                &handler_pool,
                &mut readable_ids,
                server_config.mtls_required,
            ) {
                warn!(peer = %ctx.peer_addr, error = %e, "stream processing failed; closing connection");
                let _ = ctx.conn.close(true, 0x01, b"connection error");
            }
            if let Err(e) = drive_rehash_streams(ctx, &mut buf, &metrics) {
                warn!(peer = %ctx.peer_addr, error = %e, "resume re-hash failed; closing connection");
                let _ = ctx.conn.close(true, 0x01, b"connection error");
            }
            if let Err(e) =
                drive_sending_streams(ctx, &socket, &metrics, &mut send_buf, &mut sender_ids)
            {
                warn!(peer = %ctx.peer_addr, error = %e, "send processing failed; closing connection");
                let _ = ctx.conn.close(true, 0x01, b"connection error");
            }
            if let Err(e) = flush_egress(&mut ctx.conn, &socket) {
                warn!(peer = %ctx.peer_addr, error = %e, "egress flush failed; closing connection");
                let _ = ctx.conn.close(true, 0x01, b"connection error");
            }
        }

        // 6. Reap closed / timed-out connections.
        let before = connections.len();
        connections.retain(|_, ctx| {
            let alive = !ctx.conn.is_closed();
            if !alive {
                let peer_ip = ctx.peer_addr.ip();
                counter.release(peer_ip);
                metrics.dec_connections_open();
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

/// Server-wide state borrowed by [`try_accept`] for one accept attempt.
/// Bundled so the accept path takes a handful of arguments rather than
/// the whole server's worth.
struct AcceptCtx<'a> {
    connections: &'a mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
    counter: &'a mut ConnectionCounter,
    rate_limiter: &'a mut RateLimiter,
    quiche_config: &'a mut quiche::Config,
    retry_key: &'a RetryKey,
    conn_id_seed: &'a [u8; 32],
    cfg: &'a ServerConfig,
    users: &'a UserDirectory,
    metrics: &'a Metrics,
    rng: &'a ring::rand::SystemRandom,
    socket: &'a mio::net::UdpSocket,
}

fn try_accept(
    ax: &mut AcceptCtx,
    from: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    hdr: &quiche::Header,
    pkt: &mut [u8],
    out_pkt: &mut [u8; MAX_DATAGRAM_SIZE],
) -> Result<()> {
    // Validate the DCID range BEFORE consuming a rate-limit token.
    // quiche v0.24 does not enforce RFC 9000 §7.2's >= 8-byte lower
    // bound, so a peer can spray short-DCID Initials cheaply. If we
    // consumed the rate-limit token before this check, the bad peer
    // would pin their per-/32 bucket exhausted (denying legitimate
    // retries from the same prefix) while never completing a
    // handshake.
    if !(8..=20).contains(&hdr.dcid.len()) {
        ax.metrics.inc_initials_dropped_bad_dcid();
        debug!(
            peer = %from,
            dcid_len = hdr.dcid.len(),
            "Initial dropped: DCID outside RFC 9000 §7.2 range",
        );
        return Ok(());
    }

    if !ax.rate_limiter.try_consume(from.ip()) {
        ax.metrics.inc_connections_rejected_rate();
        debug!(peer = %from, "Initial dropped by rate limiter");
        return Ok(());
    }

    // Stateless retry: when required, the very first Initial from a peer
    // has no token. Mint one and send it back as a RETRY; the client will
    // resend the Initial with the token attached.
    if ax.cfg.require_retry {
        let has_token = hdr.token.as_ref().is_some_and(|t| !t.is_empty());
        if !has_token {
            // send_retry returns Ok regardless of whether a RETRY went
            // out, so only credit the retry metric when it actually
            // emitted a packet. The DCID-range check above guarantees
            // mint will succeed today, but keep the conditional so a
            // future relaxation of that check can't silently desync
            // the metric.
            let emitted = send_retry(ax.retry_key, ax.rng, ax.socket, hdr, from, out_pkt)?;
            if emitted {
                ax.metrics.inc_retries_issued();
            }
            return Ok(());
        }
        let token = hdr.token.as_ref().unwrap();
        if ax.retry_key.verify(from, token).is_none() {
            debug!(peer = %from, "Initial with invalid retry token");
            return Ok(());
        }
        // Verified: fall through and accept with odcid set below.
    }

    // RAII slot: every early return below drops the slot, which
    // releases the per-IP and global counters. The success path
    // calls `.commit()` so the slot survives this function and the
    // normal `release(peer_ip)` in the connection-reap loop handles
    // eventual cleanup. This replaces the previous "remember
    // counter.release(from.ip()) on every early-return branch"
    // bookkeeping that was prone to leaks on future refactors.
    let slot = match ax.counter.try_acquire(ax.cfg.caps, from.ip()) {
        Some(s) => s,
        None => {
            ax.metrics.inc_connections_rejected_caps();
            debug!(peer = %from, "Initial dropped by connection cap");
            return Ok(());
        }
    };

    // Derive the server SCID deterministically from the client's DCID +
    // process seed. Retransmitted Initials therefore land on the same
    // connection key instead of accidentally creating duplicates.
    let scid = derive_scid(ax.conn_id_seed, &hdr.dcid);

    // Recover odcid from the retry token if we issued one.
    let odcid_owned: Option<quiche::ConnectionId<'static>> = if ax.cfg.require_retry {
        hdr.token
            .as_ref()
            .and_then(|t| ax.retry_key.verify(from, t))
            .map(|c| quiche::ConnectionId::from_vec(c.as_ref().to_vec()))
    } else {
        None
    };

    let mut conn = match quiche::accept(
        &scid,
        odcid_owned.as_ref(),
        local_addr,
        from,
        ax.quiche_config,
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!(peer = %from, error = ?e, "quiche::accept failed");
            // `slot` drops here -> release happens automatically.
            return Ok(());
        }
    };

    // Feed the original Initial in so the handshake actually starts.
    let recv_info = quiche::RecvInfo {
        from,
        to: local_addr,
    };
    if let Err(e) = conn.recv(pkt, recv_info) {
        warn!(peer = %from, error = ?e, "initial recv failed");
        // `slot` drops here -> release happens automatically.
        return Ok(());
    }

    // mTLS identity isn't ready until the handshake completes; start the
    // connection as the anonymous user and upgrade later if we can.
    let ctx = ConnectionContext::new(conn, from, ax.users.anonymous(), scid.clone());

    // If a previous Initial from this peer already created the slot
    // (the deterministic SCID collapses retransmits onto the same key),
    // just drop the duplicate accept. The slot drops here, releasing
    // the duplicate count so a retransmitted Initial that derives the
    // same SCID doesn't leak a `connections_open` gauge unit for a
    // `ConnectionContext` that is dropped here and never enters the
    // `connections` map.
    if ax.connections.contains_key(&scid) {
        // `slot` drops here -> release happens automatically.
        return Ok(());
    }
    info!(peer = %from, "connection accepted");
    // Order: insert FIRST so the metrics gauge and the cap counter
    // both reflect a live map entry. If `connections.insert` panics
    // (allocator OOM during a HashMap resize), the slot's Drop
    // releases the cap counter; the metric increments below haven't
    // happened yet so the `connections_open` gauge stays in sync.
    // The previous order (inc_connections_open BEFORE insert) leaked
    // the gauge forever on that panic path -- `dec_connections_open`
    // is only called by the reap loop, which iterates the map.
    ax.connections.insert(scid, ctx);
    // From this point on, the connection is live: reap loop is
    // responsible for `release(peer_ip)` and `dec_connections_open`.
    ax.metrics.inc_connections_total();
    ax.metrics.inc_connections_open();
    slot.commit();
    Ok(())
}

/// Deterministically derive a server SCID from the client's DCID using
/// the process-lifetime seed. Truncated to quiche::MAX_CONN_ID_LEN bytes.
fn derive_scid(seed: &[u8; 32], dcid: &quiche::ConnectionId) -> quiche::ConnectionId<'static> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    // `new_from_slice` rejects only when the key length is invalid for
    // the underlying HMAC; SHA-256 accepts any length and `seed` is a
    // fixed 32-byte buffer, so this is provably infallible.
    let mut mac = HmacSha256::new_from_slice(seed)
        .expect("HMAC-SHA256 accepts any key length; 32-byte seed is fine");
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
    out: &mut [u8; MAX_DATAGRAM_SIZE],
) -> Result<bool> {
    let mut new_scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SecureRandom::fill(rng, &mut new_scid_bytes).expect("system RNG failed");
    let new_scid = quiche::ConnectionId::from_ref(&new_scid_bytes);
    // quiche v0.24 does NOT enforce a minimum DCID length on Initial
    // parse. The pre-rate-limit check in `try_accept` filters these
    // before we reach here, but keep the mint defensive in case
    // another caller wires in without that pre-check. Return Ok(false)
    // so the caller knows no retry was actually emitted (and can skip
    // the `retries_issued` metric).
    let token = match retry_key.mint(from, &hdr.dcid) {
        Some(t) => t,
        None => {
            debug!(
                peer = %from,
                dcid_len = hdr.dcid.len(),
                "send_retry: won't mint retry token for out-of-range DCID",
            );
            return Ok(false);
        }
    };
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
    Ok(true)
}

/// Try to look up the authenticated user once the handshake is far enough
/// along that the peer cert is available.
///
/// Returns `false` when the connection was rejected and closed, so the
/// caller skips stream processing for it; `true` to proceed normally.
///
/// Idempotent: returns `true` early if the connection is already on
/// something other than the directory's anonymous record (using Arc
/// pointer equality, so a custom-named anonymous user is still
/// correctly recognised as "not upgraded yet").
fn upgrade_user_from_cert(
    ctx: &mut ConnectionContext,
    users: &UserDirectory,
    mtls_required: bool,
) -> bool {
    let anon = users.anonymous();
    if !Arc::ptr_eq(&ctx.user, &anon) {
        return true;
    }
    if !ctx.conn.is_established() {
        return true;
    }
    let Some(der) = ctx.conn.peer_cert() else {
        // mTLS is configured but the peer presented no certificate.
        // quiche's `verify_peer(true)` only sets `SSL_VERIFY_PEER`,
        // not `SSL_VERIFY_FAIL_IF_NO_PEER_CERT`, so a no-cert client
        // completes the TLS handshake; without this check it would be
        // served as the anonymous user and could read the entire root.
        if mtls_required {
            warn!(
                peer = %ctx.peer_addr,
                "rejecting connection: mTLS is required but the client presented no certificate"
            );
            // 0x101 is our application-layer "unauthorized" close code.
            let _ = ctx.conn.close(true, 0x101, b"client certificate required");
            return false;
        }
        return true;
    };
    // Try SAN dNSName / rfc822Name / URI plus the Subject CN, so a
    // modern PKI (cert-manager, smallstep, SPIFFE) that doesn't
    // populate Subject CN still maps cleanly to users.toml.
    // `resolve_identity` refuses a cert that maps to more than one
    // configured user, closing the SAN/CN identity-confusion gap
    // where an extra SAN entry could select a higher-privileged user.
    let candidates = user::extract_identity_candidates(der);
    match user::resolve_identity(&candidates, users) {
        user::IdentityResolution::Matched { id, user } => {
            info!(
                peer = %ctx.peer_addr,
                user = %user.name,
                matched = %id,
                "upgraded connection to authenticated user"
            );
            ctx.cwd = user.home.clone();
            ctx.user = user;
            true
        }
        // A peer whose cert matches no configured user must be
        // rejected outright, not silently downgraded to anonymous.
        user::IdentityResolution::NoMatch => {
            warn!(
                peer = %ctx.peer_addr,
                ?candidates,
                "rejecting connection: client cert identities are not in users.toml"
            );
            let _ = ctx.conn.close(true, 0x101, b"unknown identity");
            false
        }
        // A cert that resolves to several distinct users is refused
        // rather than guessing which account the peer intended.
        user::IdentityResolution::Ambiguous(matched) => {
            warn!(
                peer = %ctx.peer_addr,
                ?matched,
                "rejecting connection: client cert maps to multiple configured users"
            );
            let _ = ctx.conn.close(true, 0x101, b"ambiguous identity");
            false
        }
    }
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
        no_clobber: bool,
        checksum_trailer: bool,
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
    metrics: &Metrics,
    rate_limiter: &mut RateLimiter,
    tmp: &mut [u8],
    pool: &HandlerPool,
    readable_ids: &mut Vec<u64>,
    mtls_required: bool,
) -> Result<()> {
    if !upgrade_user_from_cert(ctx, users, mtls_required) {
        // Connection was rejected (mTLS / identity failure); its
        // CONNECTION_CLOSE is flushed by the caller and the reap
        // sweep drops it. Don't serve any requests on it.
        return Ok(());
    }
    readable_ids.clear();
    readable_ids.extend(ctx.conn.readable());
    let peer_ip = ctx.peer_addr.ip();

    let mut actions: Vec<PendingAction> = Vec::new();

    for &stream_id in readable_ids.iter() {
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
                    // Enforce per-field length caps on top of
                    // the 16 MiB frame cap. A peer that packed a
                    // multi-MiB path string into a single field
                    // would otherwise allocate that much during
                    // decode; bincode's with_limit bounds the total
                    // frame, not individual fields.
                    if let Err(e) = qftp_common::protocol::validate_request(&req) {
                        warn!(
                            peer = %ctx.peer_addr,
                            stream_id,
                            error = %e,
                            "request failed per-field validation; closing stream"
                        );
                        actions.push(PendingAction::AclReject {
                            stream_id,
                            resp: err(ErrorCode::Malformed, e.to_string()),
                        });
                        *state = StreamState::Done;
                        continue;
                    }
                    metrics.inc_requests_total();
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
                        metrics.inc_requests_rate_limited();
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
                            metrics.inc_zero_rtt_accepted();
                        } else {
                            metrics.inc_zero_rtt_rejected();
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
                            no_clobber,
                            checksum_trailer,
                        } => {
                            let leftover = std::mem::take(stream_buf);
                            actions.push(PendingAction::StartPut {
                                stream_id,
                                path,
                                size,
                                mode,
                                offset,
                                expected_checksum: checksum,
                                no_clobber,
                                checksum_trailer,
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
                        metrics.inc_requests_failed();
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
                metrics.inc_requests_failed();
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
                no_clobber,
                checksum_trailer,
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
                    no_clobber,
                    checksum_trailer,
                    leftover,
                    tmp,
                    metrics,
                )?;
            }
            PendingAction::Quit { stream_id } => {
                send_message(&mut ctx.conn, stream_id, &Response::Ok)?;
                flush_egress(&mut ctx.conn, socket)?;
                ctx.conn.close(true, 0x00, b"bye").ok();
            }
            PendingAction::Quota { stream_id } => {
                // Serve the cached value rather than re-walking
                // the user's home on every Quota request. The cache
                // is initialized once at startup and kept up to date
                // by Put/Rm completion paths. file_count is no longer
                // tracked exactly (it was advisory); report the
                // user's current usage in bytes which is what the
                // quota check actually cares about.
                let used_bytes = ctx.user.current_usage();
                let resp = Response::QuotaInfo {
                    used_bytes,
                    file_count: 0,
                    limit_bytes: ctx.user.quota_bytes,
                };
                send_message(&mut ctx.conn, stream_id, &resp)?;
            }
            PendingAction::HandleSimple { stream_id, req } => {
                // H-1: generic requests run blocking filesystem
                // syscalls, so they're offloaded to the worker pool
                // rather than stalling the event loop. One job at a
                // time per connection keeps `cwd` updates from `Cd`
                // correctly ordered; extra requests queue until the
                // in-flight job completes.
                if ctx.handler_in_flight {
                    ctx.pending_handler_jobs.push_back((stream_id, req));
                } else {
                    dispatch_handler_job(pool, ctx, metrics, stream_id, req);
                }
            }
        }
    }
    Ok(())
}

/// Send a one-shot error response for a stream and mark it Done.
/// Used by both `start_get` and `start_put` to collapse what was the
/// same `send_err` closure repeated in each.
fn fail_stream(
    ctx: &mut ConnectionContext,
    stream_id: u64,
    metrics: &Metrics,
    response: Response,
) -> Result<()> {
    send_message(&mut ctx.conn, stream_id, &response)?;
    metrics.inc_requests_failed();
    ctx.streams.insert(stream_id, StreamState::Done);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn start_get(
    ctx: &mut ConnectionContext,
    stream_id: u64,
    path: &str,
    offset: u64,
    length: Option<u64>,
    metrics: &Metrics,
) -> Result<()> {
    let send_err = |ctx: &mut ConnectionContext, code, msg| -> Result<()> {
        fail_stream(ctx, stream_id, metrics, err(code, msg))
    };

    // Server-internal upload temp files (`*.qftp.partial`) are server
    // bookkeeping: hidden from `Ls`, un-deletable, and swept after they
    // go stale. A client must not be able to read one either.
    if handler::is_upload_temp(path) {
        return fail_stream(
            ctx,
            stream_id,
            metrics,
            err(
                ErrorCode::PermissionDenied,
                "path refers to a server-internal upload temp file",
            ),
        );
    }

    let file_path = match handler::resolve(&ctx.cwd, &ctx.user.home, path) {
        Ok(p) => p,
        Err(e) => return fail_stream(ctx, stream_id, metrics, Response::Err(e)),
    };
    // Parent-dir symlink TOCTOU re-check. O_NOFOLLOW below
    // protects the leaf only; an intermediate parent that was swapped
    // to a symlink between resolve and open would still be traversed
    // by the kernel and let us serve a file outside the user's home.
    if let Err(e) = handler::recheck_ancestors_no_symlinks(&file_path, &ctx.user.home) {
        return send_err(ctx, e.code, e.message);
    }
    // Open with O_NOFOLLOW first, then derive metadata from the
    // resulting fd. This binds the metadata + the bytes we stream to
    // the same inode the path resolved to, eliminating the TOCTOU
    // window between `walk_safe` and `fs::open`.
    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.read(true);
    qftp_common::fs_safe::apply_no_follow(&mut open_opts);
    let file = match open_opts.open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            return send_err(ctx, io_code(&e), format!("Failed to open file: {e}"));
        }
    };
    let meta = match file.metadata() {
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
    send_message(
        &mut ctx.conn,
        stream_id,
        &Response::FileReady {
            size: bytes_to_send,
            total_size: meta.len(),
            checksum_follows: true,
        },
    )?;
    // The reader stays at position 0 even for a resumed Get: the
    // streaming state machine re-hashes the [0..offset) prefix into
    // `hasher` before sending any body bytes, so the trailer is a
    // whole-file BLAKE3 the client can verify its local prefix against.
    ctx.streams.insert(
        stream_id,
        StreamState::SendingFileData {
            reader: std::io::BufReader::with_capacity(SEND_CHUNK_SIZE, file),
            total_size: bytes_to_send,
            sent: 0,
            hasher: blake3::Hasher::new(),
            trailer: None,
            trailer_offset: 0,
            finished: false,
            prefix_remaining: offset,
        },
    );
    Ok(())
}

fn drive_sending_streams(
    ctx: &mut ConnectionContext,
    _socket: &mio::net::UdpSocket,
    metrics: &Metrics,
    send_buf: &mut [u8],
    sender_ids: &mut Vec<u64>,
) -> Result<()> {
    sender_ids.clear();
    sender_ids.extend(
        ctx.streams
            .iter()
            .filter(|(_, s)| matches!(s, StreamState::SendingFileData { .. }))
            .map(|(id, _)| *id),
    );

    for &stream_id in sender_ids.iter() {
        // After this call we either mark the stream Done, or we leave a
        // SendingFileData with updated counters for the next iteration.
        let outcome = drive_one_sender(ctx, stream_id, send_buf, metrics);
        if outcome == SendOutcome::Finished {
            if let Some(state) = ctx.streams.get_mut(&stream_id) {
                *state = StreamState::Done;
            }
        }
    }
    Ok(())
}

/// Advance the prefix re-hash of any resumed Put whose `rehash` is
/// still `Some`. Driven every main-loop iteration (the poll timeout is
/// forced to zero while any exist) so the re-hash makes progress
/// without waiting on network events, since it is pure local I/O.
fn drive_rehash_streams(
    ctx: &mut ConnectionContext,
    scratch: &mut [u8],
    metrics: &Metrics,
) -> Result<()> {
    let ids: Vec<u64> = ctx
        .streams
        .iter()
        .filter(|(_, s)| {
            matches!(
                s,
                StreamState::ReadingFileData {
                    rehash: Some(_),
                    ..
                }
            )
        })
        .map(|(id, _)| *id)
        .collect();
    for stream_id in ids {
        let Some(state) = ctx.streams.get_mut(&stream_id) else {
            continue;
        };
        if let Some(resp) = drive_put(&mut ctx.conn, stream_id, state, scratch, metrics)? {
            if matches!(resp, Response::Err(_)) {
                metrics.inc_requests_failed();
            }
            send_message(&mut ctx.conn, stream_id, &resp)?;
            *state = StreamState::Done;
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
    metrics: &Metrics,
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
        prefix_remaining,
    } = state
    else {
        return SendOutcome::Finished;
    };
    if *finished {
        return SendOutcome::Finished;
    }

    // Phase 0: re-hash the [0..offset) prefix of a resumed Get into
    // `hasher` before streaming any body bytes. Doing this incrementally
    // (one chunk per call) keeps a large resumed Get from stalling the
    // event loop; once `prefix_remaining` reaches 0 the next call falls
    // through to Phase A. The trailer is therefore a whole-file BLAKE3,
    // so the client can verify its local prefix against it (#221).
    if *prefix_remaining > 0 {
        let want = (*prefix_remaining as usize).min(chunk.len());
        if let Err(e) = reader.read_exact(&mut chunk[..want]) {
            warn!(stream_id, error = %e, "file read failed during prefix re-hash");
            let _ = ctx.conn.stream_send(stream_id, &[], true);
            return SendOutcome::Failed;
        }
        hasher.update(&chunk[..want]);
        *prefix_remaining -= want as u64;
        // Yield to the event loop so other streams get a turn; the next
        // iteration continues the prefix walk (or proceeds to Phase A
        // once `prefix_remaining` hits 0).
        return SendOutcome::Blocked;
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
                metrics.add_bytes_sent(n as u64);
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
                metrics.add_bytes_sent(n as u64);
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
    metrics.inc_downloads_completed();
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
    no_clobber: bool,
    checksum_trailer: bool,
    leftover: Vec<u8>,
    scratch: &mut [u8],
    metrics: &Metrics,
) -> Result<()> {
    let send_err = |ctx: &mut ConnectionContext, code, msg| -> Result<()> {
        fail_stream(ctx, stream_id, metrics, err(code, msg))
    };

    // Server-internal upload temp files (`*.qftp.partial`) are server
    // bookkeeping. A client must not `Put` to one: the committed file
    // would be hidden from `Ls`, un-deletable, and swept after 24h.
    if handler::is_upload_temp(path) {
        return send_err(
            ctx,
            ErrorCode::PermissionDenied,
            "path refers to a server-internal upload temp file".to_string(),
        );
    }

    // A resumed upload (`offset > 0`) commits an on-disk `.qftp.partial`
    // prefix that the client never re-sends. The only thing tying that
    // prefix to the client's intent is the BLAKE3 trailer / header
    // checksum. With neither, verification is skipped and a prefix that
    // a co-tenant could have substituted would be committed unverified.
    // Refuse such a resume up front.
    if offset > 0 && !checksum_trailer && expected_checksum.is_none() {
        return send_err(
            ctx,
            ErrorCode::Unsupported,
            "resumed upload requires a checksum".to_string(),
        );
    }

    // The final file is `offset + size` bytes; check the resumed total,
    // not just this round's body, so resume can't append past the cap.
    let final_size = offset.saturating_add(size);
    if final_size > MAX_FILE_SIZE {
        return send_err(
            ctx,
            ErrorCode::FileTooLarge,
            format!("Upload too large: {final_size} bytes (max {MAX_FILE_SIZE} bytes)"),
        );
    }

    let final_path = match handler::resolve_parent(&ctx.cwd, &ctx.user.home, path) {
        Ok(p) => p,
        Err(e) => return fail_stream(ctx, stream_id, metrics, Response::Err(e)),
    };
    // A path whose final component is not a real file name (it ends in
    // `..` or `/`) has no leaf for `temp_path_for` to build a temp name
    // from: `file_name()` is `None`, so the temp would collapse to the
    // bare `.qftp.partial`, shared by every such upload and impossible
    // to address via `Ls`/`Rm`. Refuse the Put up front.
    if final_path.file_name().is_none() {
        return send_err(
            ctx,
            ErrorCode::Malformed,
            "invalid upload path: no file name".to_string(),
        );
    }
    // Parent-dir symlink TOCTOU re-check. The temp file is opened with
    // O_NOFOLLOW, which protects the *leaf* but not the intermediate
    // components -- a parent swapped to a symlink between resolve_parent
    // and open would still be traversed by the kernel.
    if let Err(e) = handler::recheck_ancestors_no_symlinks(&final_path, &ctx.user.home) {
        send_message(&mut ctx.conn, stream_id, &Response::Err(e))?;
        metrics.inc_requests_failed();
        ctx.streams.insert(stream_id, StreamState::Done);
        return Ok(());
    }
    // Enforce client-requested overwrite refusal. lstat (not stat) so a
    // planted symlink at `final_path` counts as "exists" -- otherwise an
    // attacker who could plant a dangling symlink could bypass
    // --no-clobber by aiming it at /nonexistent.
    if no_clobber && std::fs::symlink_metadata(&final_path).is_ok() {
        return send_err(
            ctx,
            ErrorCode::AlreadyExists,
            format!("path already exists (no_clobber): {path}"),
        );
    }
    // Claim the destination so a second concurrent Put to the same path
    // can't share -- and corrupt -- the one deterministically named
    // temp. The claim is a local until it moves into `ReadingFileData`;
    // an early return before then drops it and frees the path.
    let claim = match UploadClaim::try_claim(Arc::clone(&ctx.user), final_path.clone()) {
        Some(c) => c,
        None => {
            return send_err(
                ctx,
                ErrorCode::AlreadyExists,
                format!("an upload to this path is already in progress: {path}"),
            );
        }
    };
    let temp_path = temp_path_for(&final_path);

    // Open the deterministically named resumable temp file *before* the
    // quota check, so a fresh Put can refund a stale partial's bytes
    // first -- otherwise re-uploading a file whose earlier attempt
    // aborted near the quota limit would be rejected for the very bytes
    // it is about to replace.
    //   * Fresh upload (offset == 0): create-or-reuse. A leftover
    //     partial is truncated and reused; its bytes were charged to
    //     `used_bytes` on that abort, so refund them. `prior_bytes` is
    //     0 -- nothing on disk is pre-accounted for this stream.
    //   * Resume (offset > 0): the temp must already exist and hold
    //     exactly `offset` bytes; re-hash that prefix so the BLAKE3
    //     trailer check still covers the whole file. `prior_bytes` is
    //     `offset`: those bytes are already counted in `used_bytes`.
    let (file, hasher, prior_bytes, rehash) = if offset == 0 {
        let f = match open_temp(&temp_path, false) {
            Ok(f) => f,
            Err(e) => {
                return send_err(
                    ctx,
                    io_code(&e),
                    format!("Failed to create upload temp file: {e}"),
                );
            }
        };
        let stale = f.metadata().map(|m| m.len()).unwrap_or(0);
        if stale > 0 {
            ctx.user
                .used_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |u| {
                    Some(u.saturating_sub(stale))
                })
                .ok();
        }
        // Truncate unconditionally: a reused file (a stale partial, or
        // one a local user planted at the predictable path) must not
        // leave trailing bytes past the new body.
        if let Err(e) = f.set_len(0) {
            return send_err(
                ctx,
                io_code(&e),
                format!("Failed to truncate upload temp file: {e}"),
            );
        }
        // Re-assert 0o600: the O_CREAT mode is ignored when the file
        // already existed, so a reused/planted temp could otherwise
        // keep a looser mode and expose the in-progress body.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = f.set_permissions(fs::Permissions::from_mode(0o600)) {
                return send_err(
                    ctx,
                    io_code(&e),
                    format!("Failed to re-assert 0o600 on partial: {e}"),
                );
            }
        }
        (f, blake3::Hasher::new(), 0u64, None)
    } else {
        let mut f = match open_temp(&temp_path, true) {
            Ok(f) => f,
            Err(e) => {
                return send_err(
                    ctx,
                    ErrorCode::InvalidRange,
                    format!("no resumable partial upload to continue: {e}"),
                );
            }
        };
        let have = f.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
        if have != offset {
            return send_err(
                ctx,
                ErrorCode::InvalidRange,
                format!("resume offset {offset} does not match partial length {have}"),
            );
        }
        // Position the write handle to append after the prefix.
        if let Err(e) = std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(offset)) {
            return send_err(
                ctx,
                io_code(&e),
                format!("Failed to seek partial upload: {e}"),
            );
        }
        // Re-hash the [0, offset) prefix incrementally through a second
        // handle, so a large partial doesn't block the event loop with
        // one synchronous pass (driven by `drive_rehash_streams`). The
        // hasher starts empty and is filled before any body byte.
        let rehash_handle = match open_temp(&temp_path, true) {
            Ok(h) => h,
            Err(e) => {
                return send_err(
                    ctx,
                    io_code(&e),
                    format!("Failed to reopen partial for re-hash: {e}"),
                );
            }
        };
        let rehash = ResumeRehash {
            reader: std::io::BufReader::with_capacity(FILE_CHUNK_SIZE, rehash_handle),
            remaining: offset,
            pending_body: Vec::new(),
        };
        (f, blake3::Hasher::new(), offset, Some(rehash))
    };

    // In-flight reservation, then quota check. `used_bytes` now
    // reflects reality: a fresh Put refunded any stale partial above,
    // and a resume's `offset` bytes are legitimately still counted.
    // `size` is the post-offset body the client is about to send.
    //
    // Reserve *before* checking: a check-then-reserve sequence races --
    // two concurrent Puts could both pass the check before either
    // reservation lands and together overshoot the limit. Reserving
    // first means a concurrent Put always sees our bytes in its check.
    let new_bytes = size;
    let mut reservation = InFlightReservation::reserve(Arc::clone(&ctx.user), new_bytes);
    if let Some(limit) = ctx.user.quota_bytes {
        let used = ctx.user.used_bytes.load(Ordering::Relaxed);
        // `in_flight` already includes the reservation just made.
        let in_flight = ctx.user.in_flight_bytes.load(Ordering::Relaxed);
        let projected = used.saturating_add(in_flight);
        if projected > limit {
            // `reservation` is still armed -- it releases `new_bytes`
            // on return. A fresh Put truncated its temp to empty;
            // remove it so a rejected upload leaves no litter. A
            // resume's temp is the user's own partial -- leave it.
            if offset == 0 {
                let _ = fs::remove_file(&temp_path);
            }
            return send_err(
                ctx,
                ErrorCode::QuotaExceeded,
                format!("Quota exceeded: would use {projected} bytes (limit {limit})"),
            );
        }
    }
    let writer = BufWriter::with_capacity(FILE_CHUNK_SIZE, file);

    // The reservation is now owned by `ReadingFileData`'s Drop (via
    // `reserved_bytes`); disarm the guard so the bytes aren't released
    // twice.
    reservation.disarm();
    let mut new_state = StreamState::ReadingFileData {
        final_path,
        temp_path,
        writer,
        remaining: size,
        mode,
        completed: false,
        hasher,
        expected_checksum,
        trailer_buf: if checksum_trailer {
            Some(qftp_protocol::stream::TrailerBuf::new())
        } else {
            None
        },
        reserved_bytes: new_bytes,
        prior_bytes,
        rehash,
        claim,
        owner: Arc::clone(&ctx.user),
    };
    if !leftover.is_empty() {
        if let StreamState::ReadingFileData {
            writer,
            remaining,
            hasher,
            trailer_buf,
            rehash,
            ..
        } = &mut new_state
        {
            // Bytes coalesced into the same recv as the Put request
            // frame can hold the body *and* the 32-byte streaming
            // checksum trailer. Split them exactly as `drive_put`'s
            // Phase A does -- counting the trailer against the body
            // length would spuriously reject the upload with
            // UploadOverflow (and a checksum_trailer Put always sends
            // that trailer in-band right after the body).
            let to_take = (leftover.len() as u64).min(*remaining) as usize;
            let after_body = &leftover[to_take..];
            if !after_body.is_empty() {
                match trailer_buf {
                    Some(buf) => {
                        let consumed = buf.extend(after_body);
                        if consumed < after_body.len() {
                            return fail_stream(
                                ctx,
                                stream_id,
                                metrics,
                                err(
                                    ErrorCode::UploadOverflow,
                                    "Upload exceeded declared size + trailer",
                                ),
                            );
                        }
                    }
                    None => {
                        return fail_stream(
                            ctx,
                            stream_id,
                            metrics,
                            err(ErrorCode::UploadOverflow, "Upload exceeded declared size"),
                        );
                    }
                }
            }
            let body = &leftover[..to_take];
            if let Some(rh) = rehash {
                // Resume: the prefix isn't hashed yet, so these body
                // bytes can't be hashed in order now. Hold them; the
                // re-hash completion path in `drive_put` writes and
                // hashes them once the prefix is done. The trailer (if
                // any) is already buffered above.
                rh.pending_body = body.to_vec();
            } else if !body.is_empty() {
                if let Err(e) = writer.write_all(body) {
                    return fail_stream(
                        ctx,
                        stream_id,
                        metrics,
                        err(ErrorCode::Internal, format!("Failed to write file: {e}")),
                    );
                }
                hasher.update(body);
                *remaining -= to_take as u64;
                metrics.add_bytes_received(to_take as u64);
            }
        }
    }
    ctx.streams.insert(stream_id, new_state);

    // Drain anything already buffered for this stream.
    if let Some(state) = ctx.streams.get_mut(&stream_id) {
        if let Some(resp) = drive_put(&mut ctx.conn, stream_id, state, scratch, metrics)? {
            if matches!(resp, Response::Err(_)) {
                metrics.inc_requests_failed();
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
    metrics: &Metrics,
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
        trailer_buf,
        reserved_bytes,
        prior_bytes,
        rehash,
        owner,
        ..
    } = state
    else {
        return Ok(None);
    };

    // Resume re-hash phase: feed one bounded slice of the existing
    // partial's prefix through BLAKE3 per call. Spreading it over many
    // calls keeps a large partial from stalling the event loop. Body
    // bytes are left buffered in the QUIC stream until this is done.
    if rehash.is_some() {
        // On a resume re-hash read failure the stream is torn down, but
        // `StreamState`'s Drop runs with `completed == false`: it
        // releases `reserved_bytes` yet does NOT refund `prior_bytes`
        // (the `offset` prefix already charged to `used_bytes`) and
        // does NOT delete the temp. A persistent read error would then
        // lock those prefix bytes against the user's quota until the
        // 24h stale sweep. Mirror the checksum-mismatch path: delete
        // the temp, refund `prior_bytes` to the owner's `used_bytes`,
        // and mark the stream `completed` so Drop's abort accounting
        // does not double-count it.
        let mut abort_rehash = |err_resp: Response| -> Response {
            let _ = fs::remove_file(&*temp_path);
            owner
                .in_flight_bytes
                .fetch_sub(*reserved_bytes, Ordering::Relaxed);
            if *prior_bytes > 0 {
                owner
                    .used_bytes
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |u| {
                        Some(u.saturating_sub(*prior_bytes))
                    })
                    .ok();
            }
            *completed = true;
            err_resp
        };
        let rh = rehash.as_mut().unwrap();
        let want = (rh.remaining as usize).min(tmp.len());
        let n = match std::io::Read::read(&mut rh.reader, &mut tmp[..want]) {
            Ok(0) => {
                return Ok(Some(abort_rehash(err(
                    ErrorCode::Internal,
                    "partial upload shrank during resume re-hash",
                ))));
            }
            Ok(n) => n,
            Err(e) => {
                return Ok(Some(abort_rehash(err(
                    io_code(&e),
                    format!("resume re-hash read failed: {e}"),
                ))));
            }
        };
        hasher.update(&tmp[..n]);
        rh.remaining -= n as u64;
        if rh.remaining > 0 {
            return Ok(None);
        }
        // Prefix fully hashed. Hash the body bytes that arrived with the
        // request (held back so they followed the prefix in hash
        // order), write them to disk, then continue into the body
        // phase (Phase A) below.
        let pending = std::mem::take(&mut rh.pending_body);
        *rehash = None;
        if !pending.is_empty() {
            if pending.len() as u64 > *remaining {
                return Ok(Some(err(
                    ErrorCode::UploadOverflow,
                    "Upload exceeded declared size",
                )));
            }
            if let Err(e) = writer.write_all(&pending) {
                return Ok(Some(err(
                    ErrorCode::Internal,
                    format!("Failed to write file: {e}"),
                )));
            }
            hasher.update(&pending);
            *remaining -= pending.len() as u64;
            metrics.add_bytes_received(pending.len() as u64);
        }
        // Deliberately fall through into Phase A rather than returning:
        // if `pending` already held the whole body, the stream has no
        // more readable data and no later `drive_put` call would come,
        // so the upload would never reach Phase B / commit (#180).
    }

    // Phase A: drain body bytes until `remaining == 0`. Anything past
    // the body in the same recv goes into the trailer buffer when
    // streaming-checksum mode is active.
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
                metrics.add_bytes_received(to_take as u64);
                let after_body = len - to_take;
                if after_body > 0 {
                    // Bytes past the body. Legitimate only when the
                    // client opted into the streaming trailer.
                    if let Some(buf) = trailer_buf {
                        let consumed = buf.extend(&tmp[to_take..len]);
                        if consumed < after_body {
                            return Ok(Some(err(
                                ErrorCode::UploadOverflow,
                                "Upload exceeded declared size + trailer",
                            )));
                        }
                    } else {
                        return Ok(Some(err(
                            ErrorCode::UploadOverflow,
                            "Upload exceeded declared size",
                        )));
                    }
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

    // Phase B: body fully received. If streaming-checksum mode is
    // active, keep draining until the 32-byte trailer is complete
    // before verifying.
    if *remaining == 0 {
        if let Some(buf) = trailer_buf.as_mut() {
            while !buf.is_full() {
                match conn.stream_recv(stream_id, tmp) {
                    Ok((len, fin)) => {
                        let consumed = buf.extend(&tmp[..len]);
                        if consumed < len {
                            return Ok(Some(err(
                                ErrorCode::UploadOverflow,
                                "Trailer bytes exceeded 32",
                            )));
                        }
                        if fin && !buf.is_full() {
                            return Ok(Some(err(
                                ErrorCode::UploadTruncated,
                                "Stream closed before BLAKE3 trailer was complete",
                            )));
                        }
                    }
                    Err(quiche::Error::Done) => return Ok(None),
                    Err(quiche::Error::InvalidStreamState(_)) => {
                        // FIN already consumed; stream is gone but
                        // we never finished the trailer.
                        return Ok(Some(err(
                            ErrorCode::UploadTruncated,
                            "Stream closed before BLAKE3 trailer was complete",
                        )));
                    }
                    Err(e) => {
                        warn!(stream_id, error = ?e, "stream_recv error during trailer");
                        return Ok(Some(err(ErrorCode::Internal, "Stream receive error")));
                    }
                }
            }
        }

        if let Err(e) = writer.flush() {
            return Ok(Some(err(
                ErrorCode::Internal,
                format!("Failed to flush file: {e}"),
            )));
        }
        // Verify checksum before rename -- never reveal a corrupted
        // body at `final_path`. Trailer takes precedence over the
        // legacy header checksum when both are present (defensive;
        // client shouldn't set both).
        let expected: Option<[u8; 32]> = trailer_buf
            .as_ref()
            .filter(|b| b.is_full())
            .map(|b| b.as_array())
            .or(*expected_checksum);
        if let Some(expected) = expected {
            let got = *hasher.finalize().as_bytes();
            if got != expected {
                // The bytes on disk are known-corrupt; a resume would
                // re-hash the same temp and fail forever. Remove it so
                // the next upload starts fresh (mirrors `do_get`
                // deleting a corrupt download). Settle the reservation
                // and mark the stream done so the abort path in
                // `StreamState`'s Drop doesn't also account for it.
                let _ = fs::remove_file(temp_path);
                owner
                    .in_flight_bytes
                    .fetch_sub(*reserved_bytes, Ordering::Relaxed);
                // The partial is being deleted. Refund the prefix bytes
                // a prior aborted session charged to `used_bytes`, or
                // they leak permanently against the user's quota.
                if *prior_bytes > 0 {
                    owner
                        .used_bytes
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |u| {
                            Some(u.saturating_sub(*prior_bytes))
                        })
                        .ok();
                }
                *completed = true;
                return Ok(Some(err(
                    ErrorCode::ChecksumMismatch,
                    "Upload checksum verification failed",
                )));
            }
        }
        // Parent-dir symlink TOCTOU re-check, immediately before the
        // commit rename. `start_put` ran this once at entry, but the
        // body transfer can take arbitrarily long; a parent directory
        // swapped to a symlink during the transfer would make this
        // rename land the file outside the user's home. Every other
        // mutating syscall re-checks right before the call -- match
        // that here, and do NOT rename if the re-check fails.
        if let Err(e) = handler::recheck_ancestors_no_symlinks(final_path, &owner.home) {
            return Ok(Some(Response::Err(e)));
        }
        if let Err(e) = fs::rename(temp_path, &final_path) {
            return Ok(Some(err(
                ErrorCode::Internal,
                format!("Failed to finalize file: {e}"),
            )));
        }
        qftp_protocol::stream::apply_mode(final_path, *mode);
        *completed = true;
        // Hand the reservation over to the persistent cache.
        // Once `completed` is true the Drop impl no longer touches
        // in_flight (it only does so on abort), so it's safe to
        // drain the reservation here.
        owner
            .in_flight_bytes
            .fetch_sub(*reserved_bytes, Ordering::Relaxed);
        owner
            .used_bytes
            .fetch_add(*reserved_bytes, Ordering::Relaxed);
        metrics.inc_uploads_completed();
        return Ok(Some(Response::Ok));
    }

    Ok(None)
}

/// Open the resumable Put temp file at `path`.
///
/// `resume == false` (fresh upload): the file is created if absent and
/// opened read+write; the caller truncates it after refunding any stale
/// partial's bytes. `resume == true`: the file must already exist and
/// be a regular file; it is opened read+write without `O_CREAT` so a
/// vanished partial fails cleanly rather than starting a blank upload.
///
/// `O_NOFOLLOW` is set in both cases so a symlink planted at the
/// predictable temp path can never redirect the open. The 0o600 create
/// mode keeps an in-progress partial unreadable by other local users
/// (daemon umask, typically 0o022, would otherwise land it at 0o644).
fn open_temp(path: &Path, resume: bool) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true);
    if resume {
        qftp_common::fs_safe::require_regular_file(path)?;
        qftp_common::fs_safe::apply_no_follow(&mut opts);
    } else {
        opts.create(true);
        qftp_common::fs_safe::apply_owner_only_no_follow(&mut opts);
    }
    opts.open(path)
}

// `temp_path_for` lives in `qftp_protocol::stream` (lifted by review
// cycle 2 #14) and is imported via `use qftp_protocol::stream::...`
// at the top of this file. Single source of truth ensures the native
// server and the WebTransport bridge always agree on the partial
// path so cross-transport resume works.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_safe_allows_readonly_ops() {
        assert!(request_is_replay_safe(&Request::Ls { path: "/".into() }));
        assert!(request_is_replay_safe(&Request::Cd { path: "/".into() }));
        assert!(request_is_replay_safe(&Request::Pwd));
        assert!(request_is_replay_safe(&Request::Stat { path: "x".into() }));
        assert!(request_is_replay_safe(&Request::Quit));
    }

    /// Get must NOT be in the replay-safe set. Even though
    /// its reply is side-effect-free, the body can be up to
    /// MAX_FILE_SIZE -- replaying a captured 0-RTT Get against a
    /// spoofed source IP is a bandwidth amplification primitive.
    #[test]
    fn replay_safe_rejects_get_for_amplification() {
        assert!(!request_is_replay_safe(&Request::Get {
            path: "x".into(),
            offset: 0,
            length: None,
        }));
    }

    #[test]
    fn replay_safe_rejects_mutations() {
        assert!(!request_is_replay_safe(&Request::Put {
            path: "x".into(),
            size: 0,
            mode: 0o644,
            offset: 0,
            checksum: Some([0u8; 32]),
            no_clobber: false,
            checksum_trailer: false,
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

    /// The in-flight partial-upload temp file must be 0o600
    /// regardless of the process umask, so it isn't readable by
    /// other local users while the upload is still in progress.
    #[cfg(unix)]
    #[test]
    fn temp_upload_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        struct UmaskGuard(libc::mode_t);
        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                unsafe { libc::umask(self.0) };
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("victim.partial");
        // Force a permissive umask so the bug would be observable
        // without the explicit mode call.
        let _restore = UmaskGuard(unsafe { libc::umask(0o000) });
        let f = open_temp(&path, false).expect("temp create");
        drop(f);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "temp file mode was {mode:o}, expected 0o600");
    }

    // `temp_path_for` is now defined and tested in
    // `qftp_protocol::stream`; no need to duplicate the deterministic /
    // sibling assertions here.

    #[cfg(unix)]
    #[test]
    fn open_temp_resume_requires_an_existing_partial() {
        // A resume open must fail when there is no partial to continue
        // rather than silently creating a blank one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.partial");
        assert!(open_temp(&path, true).is_err());
        // A fresh open creates it; a following resume open then works.
        drop(open_temp(&path, false).expect("fresh open"));
        assert!(open_temp(&path, true).is_ok());
    }
}
