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
use std::path::PathBuf;
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
use qftp_protocol::stream::{StreamState, SEND_CHUNK_SIZE};
use qftp_protocol::user::{self, User, UserDirectory};

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

/// How long a connection may stay un-established (handshake not
/// complete) before the reap loop force-drops it and releases its cap
/// slot. Much shorter than the QUIC idle timeout (30s) so a flood of
/// spoofed Initials that each commit a connection slot can't pin the
/// global table for the full idle window (#266). Legitimate handshakes
/// complete in well under a second even on lossy links.
const HALF_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Generation of the connection that dispatched this job (L-6).
    generation: u64,
    stream_id: u64,
    req: Request,
    cwd: PathBuf,
    user: Arc<User>,
}

/// The result of a `HandlerJob`, routed back to the event loop.
struct HandlerResult {
    conn_key: quiche::ConnectionId<'static>,
    /// Echoed from the originating `HandlerJob`; compared against the
    /// live connection's generation on apply to drop a response that
    /// would otherwise be misdelivered to a resurrected SCID (L-6).
    generation: u64,
    stream_id: u64,
    response: Response,
    /// `cwd` after running the request -- changed only by `Cd`.
    new_cwd: PathBuf,
    /// The user the job ran as. Used to detect a mid-flight auth
    /// upgrade so a stale `cwd` doesn't clobber the upgraded one.
    user: Arc<User>,
}

/// True when a completed handler result belongs to an older generation
/// than the connection currently occupying its SCID -- i.e. the
/// dispatching connection was reaped and a new one resurrected the
/// (deterministic) SCID before the response came back (L-6).
fn handler_result_is_stale(ctx_generation: u64, result_generation: u64) -> bool {
    ctx_generation != result_generation
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
        let generation = job.generation;
        let stream_id = job.stream_id;
        let user = Arc::clone(&job.user);
        // Wrap `run_handler` in catch_unwind so a panic inside a
        // single request handler doesn't permanently shrink the pool
        // (after HANDLER_WORKERS panics nothing would drain
        // `pending_handler_jobs`, and the event loop would queue
        // requests forever). On panic, synthesize an Internal error
        // response and keep the worker alive.
        let (response, new_cwd) = handle_handler_panic(
            &job.req,
            job.cwd,
            &job.user,
            "handler_worker: request handler panicked; replying with Internal \
             error and restoring cwd to the pre-handler value (if Cd)",
        );
        let result = HandlerResult {
            conn_key,
            generation,
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

/// Run `run_handler` under `catch_unwind`, restoring `cwd` on panic and
/// synthesizing an `Internal` error response. Shared by the worker pool
/// and the inline fallback so a handler panic can't take down the loop.
///
/// Snapshot `cwd` only for `Cd` requests: `Cd` is the only handler arm
/// that mutates `cwd`; other requests take `&mut cwd` but never write to
/// it, so a panic mid-handler can't desync the working directory.
/// `log_msg` is logged verbatim alongside the panic so each caller keeps
/// its own message text.
fn handle_handler_panic(
    req: &Request,
    cwd: PathBuf,
    user: &User,
    log_msg: &str,
) -> (Response, PathBuf) {
    let cwd_snapshot = if matches!(req, Request::Cd { .. }) {
        Some(cwd.clone())
    } else {
        None
    };
    let req_dbg = format!("{:?}", req);
    let mut cwd = cwd;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_handler(req, &mut cwd, user)
    }));
    match outcome {
        Ok(r) => (r, cwd),
        Err(payload) => {
            let msg = qftp_common::util::panic_payload_message(payload);
            tracing::error!(
                panic = %msg,
                request = %req_dbg,
                user = %user.name,
                "{log_msg}",
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
        generation: ctx.generation,
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
            let (response, new_cwd) = handle_handler_panic(
                &job.req,
                job.cwd,
                &job.user,
                "dispatch_handler_job inline fallback panicked; \
                 replying with Internal error",
            );
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
    // The SCID lookup can succeed against a *different* connection that
    // reused the same deterministic SCID after the original was reaped
    // (L-6). Drop the stale response rather than misdeliver it on the
    // resurrected connection's stream.
    if handler_result_is_stale(ctx.generation, result.generation) {
        debug!(
            stream_id = result.stream_id,
            "dropping handler result from a reaped connection generation"
        );
        return;
    }
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
    // Monotonic generation handed to each accepted connection so a
    // delayed handler response can't be misdelivered to a different
    // connection that later reused the same (deterministic) SCID (L-6).
    let mut next_generation: u64 = 0;

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
        phase_shutdown_drain(&shutdown, &mut closing, &mut connections);

        let poll_timeout = compute_poll_timeout(&connections, closing);
        poll.poll(&mut events, poll_timeout)
            .context("poll failed")?;

        // 1. Drain incoming UDP packets.
        let local_addr = socket.local_addr().context("failed to get local addr")?;
        {
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
                next_generation: &mut next_generation,
            };
            phase_ingress(&mut ax, &mut buf, &mut out_pkt, local_addr, closing)?;
        }

        // 1.5. Drain completed handler jobs and send their responses.
        phase_drain_handler_results(&mut connections, &handler_pool, &metrics);

        // 2. on_timeout.
        phase_on_timeout(&mut connections);

        // 3-5. Per-connection work: streams + sending + egress.
        let mut stream_ctx = StreamCtx {
            socket: &socket,
            users: &users,
            metrics: &metrics,
            rate_limiter: &mut rate_limiter,
            pool: &handler_pool,
            tmp: &mut buf,
            readable_ids: &mut readable_ids,
            send_buf: &mut send_buf,
            sender_ids: &mut sender_ids,
            mtls_required: server_config.mtls_required,
        };
        phase_per_connection_work(&mut connections, &mut stream_ctx);

        // 6. Reap closed / timed-out connections.
        phase_reap_connections(&mut connections, &mut counter, &metrics);

        // 7. Sweep Done streams.
        phase_sweep_done_streams(&mut connections);

        if closing && connections.is_empty() {
            break;
        }
    }

    info!("server loop stopped");
    Ok(())
}

/// Phase: on shutdown, flip into draining mode once and close every
/// connection. Idempotent via the `closing` guard.
fn phase_shutdown_drain(
    shutdown: &AtomicBool,
    closing: &mut bool,
    connections: &mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
) {
    if shutdown.load(Ordering::Relaxed) && !*closing {
        info!(
            "shutdown signal received, draining {} connection(s)",
            connections.len()
        );
        *closing = true;
        for c in connections.values_mut() {
            c.conn.close(true, 0x00, b"server shutdown").ok();
        }
    }
}

/// Phase: compute the poll timeout for this iteration.
fn compute_poll_timeout(
    connections: &HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
    closing: bool,
) -> Option<Duration> {
    // The shortest QUIC timeout, but also bounded by the time left
    // until the soonest half-open connection must be reaped (#266):
    // a flood of un-established connections produces no network
    // events, so without this the loop would sleep until the QUIC
    // idle timeout and the half-open reap would be ineffective.
    let shortest_timeout = connections
        .values()
        .filter_map(|c| {
            let quic = c.conn.timeout();
            let half_open = (!c.conn.is_established())
                .then(|| HALF_OPEN_TIMEOUT.saturating_sub(c.created_at.elapsed()));
            match (quic, half_open) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            }
        })
        .min();
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
    match (closing, rehash_pending, shortest_timeout) {
        (true, _, t) => Some(t.unwrap_or(Duration::from_millis(250))),
        (false, true, _) => Some(Duration::ZERO),
        (false, false, Some(t)) => Some(t),
        (false, false, None) => None,
    }
}

/// Phase 1: drain incoming UDP packets and route each to its connection
/// (or to the accept path for Initials). A fatal socket error aborts the
/// loop via `?`; per-packet and accept-time errors stay scoped and logged.
fn phase_ingress(
    ax: &mut AcceptCtx,
    buf: &mut [u8; 65536],
    out_pkt: &mut [u8; 1350],
    local_addr: std::net::SocketAddr,
    closing: bool,
) -> Result<()> {
    loop {
        let (len, from) = match ax.socket.recv_from(buf) {
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
        if let Some(ctx) = ax.connections.get_mut(&hdr.dcid) {
            if let Err(e) = ctx.conn.recv(&mut buf[..len], recv_info) {
                warn!(peer = %from, error = ?e, "QUIC recv error");
            }
            continue;
        }
        // Miss: Initial retransmits during the handshake still carry
        // the peer's original DCID, so try its derived alias too.
        let alias = derive_scid(ax.conn_id_seed, &hdr.dcid);
        if let Some(ctx) = ax.connections.get_mut(&alias) {
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

        // An accept-time failure (a transient UDP send error while
        // issuing a RETRY, a quiche::accept rejection) must stay
        // scoped to this one Initial: propagating it out of `run()`
        // would tear down the whole server and every other client's
        // connection. Log and drop the packet, like the
        // per-connection work below.
        if let Err(e) = try_accept(ax, from, local_addr, &hdr, &mut buf[..len], out_pkt) {
            warn!(peer = %from, error = %e, "accept failed; dropping Initial");
        }
    }
    Ok(())
}

/// Phase 1.5: drain completed handler jobs and send their responses.
fn phase_drain_handler_results(
    connections: &mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
    handler_pool: &HandlerPool,
    metrics: &Metrics,
) {
    while let Ok(result) = handler_pool.result_rx.try_recv() {
        apply_handler_result(connections, handler_pool, metrics, result);
    }
}

/// Phase 2: advance each connection's QUIC timers.
fn phase_on_timeout(connections: &mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>) {
    for ctx in connections.values_mut() {
        ctx.conn.on_timeout();
    }
}

/// Phase 3-5: per-connection work (streams + sending + egress).
///
/// An error here is scoped to the one connection it happened on --
/// most commonly a stream-/connection-level QUIC send error after
/// the peer reset a stream or closed the connection mid-request.
/// Such an error must NOT propagate out of `run()`: that would tear
/// down the whole server and every other client's connection. We
/// instead close just the offending connection (the reap sweep
/// below drops it) and keep serving everyone else. Truly fatal
/// socket errors still surface via the ingress `recv_from` path.
fn phase_per_connection_work(
    connections: &mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
    sx: &mut StreamCtx,
) {
    for ctx in connections.values_mut() {
        if let Err(e) = process_readable_streams(ctx, sx) {
            warn!(peer = %ctx.peer_addr, error = %e, "stream processing failed; closing connection");
            let _ = ctx.conn.close(true, 0x01, b"connection error");
        }
        if let Err(e) = crate::transfer_get::drive_rehash_streams(ctx, sx.tmp, sx.metrics) {
            warn!(peer = %ctx.peer_addr, error = %e, "resume re-hash failed; closing connection");
            let _ = ctx.conn.close(true, 0x01, b"connection error");
        }
        if let Err(e) = crate::transfer_get::drive_sending_streams(
            ctx,
            sx.socket,
            sx.metrics,
            sx.send_buf,
            sx.sender_ids,
        ) {
            warn!(peer = %ctx.peer_addr, error = %e, "send processing failed; closing connection");
            let _ = ctx.conn.close(true, 0x01, b"connection error");
        }
        if let Err(e) = flush_egress(&mut ctx.conn, sx.socket) {
            warn!(peer = %ctx.peer_addr, error = %e, "egress flush failed; closing connection");
            let _ = ctx.conn.close(true, 0x01, b"connection error");
        }
    }
}

/// Phase 6: reap closed / timed-out connections.
fn phase_reap_connections(
    connections: &mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
    counter: &mut ConnectionCounter,
    metrics: &Metrics,
) {
    let before = connections.len();
    connections.retain(|_, ctx| {
        let half_open = half_open_expired(ctx.conn.is_established(), ctx.created_at.elapsed());
        let alive = !ctx.conn.is_closed() && !half_open;
        if !alive {
            if half_open {
                debug!(
                    peer = %ctx.peer_addr,
                    "reaping half-open connection (handshake never completed)"
                );
            }
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
}

/// Phase 7: sweep Done streams from every connection.
fn phase_sweep_done_streams(
    connections: &mut HashMap<quiche::ConnectionId<'static>, ConnectionContext>,
) {
    for ctx in connections.values_mut() {
        ctx.streams.retain(|_, s| !matches!(s, StreamState::Done));
    }
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
    /// Monotonic source for per-connection generations (L-6). Bumped
    /// only when a connection is actually inserted into the table.
    next_generation: &'a mut u64,
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

    // If a previous Initial from this peer already created the slot
    // (the deterministic SCID collapses retransmits onto the same key),
    // just drop the duplicate accept. The slot drops here, releasing
    // the duplicate count so a retransmitted Initial that derives the
    // same SCID doesn't leak a `connections_open` gauge unit for a
    // `ConnectionContext` that is dropped here and never enters the
    // `connections` map. Checked before constructing the context so the
    // duplicate path doesn't burn a generation.
    if ax.connections.contains_key(&scid) {
        // `slot` drops here -> release happens automatically.
        return Ok(());
    }
    // Assign this connection's generation and advance the source (L-6).
    let generation = *ax.next_generation;
    *ax.next_generation = ax.next_generation.wrapping_add(1);
    // mTLS identity isn't ready until the handshake completes; start the
    // connection as the anonymous user and upgrade later if we can.
    let ctx = ConnectionContext::new(conn, from, ax.users.anonymous(), scid.clone(), generation);
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

/// True when a connection has been alive for longer than
/// [`HALF_OPEN_TIMEOUT`] without completing its handshake. Such a
/// connection still occupies a global + per-IP cap slot, so a flood of
/// spoofed Initials that each commit a slot but never finish the
/// handshake could otherwise pin the table for the full QUIC idle
/// timeout (#266). Reaping these early bounds the exposure to
/// `HALF_OPEN_TIMEOUT`.
fn half_open_expired(established: bool, age: Duration) -> bool {
    !established && age >= HALF_OPEN_TIMEOUT
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
    // This runs once per unauthenticated peer's first Initial. A
    // transient system-RNG failure must not panic the whole server on
    // that hostile-controlled path (L-4): drop the packet and report
    // "no retry emitted", mirroring the `mint` None branch below. The
    // peer simply retransmits its Initial and we try again.
    if ring::rand::SecureRandom::fill(rng, &mut new_scid_bytes).is_err() {
        warn!(peer = %from, "send_retry: system RNG failed; dropping Initial without retry");
        return Ok(false);
    }
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
        expected_checksum: Option<Vec<u8>>,
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

/// Per-connection work services shared across every connection in one
/// loop iteration, bundled so the stream-processing path takes a single
/// handle (plus the `&mut ConnectionContext` it operates on) rather than
/// a long positional argument list. Built from disjoint fields of the
/// run loop's state, so it never aliases the `connections` table it is
/// iterated alongside.
struct StreamCtx<'a> {
    socket: &'a mio::net::UdpSocket,
    users: &'a UserDirectory,
    metrics: &'a Metrics,
    rate_limiter: &'a mut RateLimiter,
    pool: &'a HandlerPool,
    tmp: &'a mut [u8],
    readable_ids: &'a mut Vec<u64>,
    send_buf: &'a mut [u8],
    sender_ids: &'a mut Vec<u64>,
    mtls_required: bool,
}

fn process_readable_streams(ctx: &mut ConnectionContext, sx: &mut StreamCtx) -> Result<()> {
    if !upgrade_user_from_cert(ctx, sx.users, sx.mtls_required) {
        // Connection was rejected (mTLS / identity failure); its
        // CONNECTION_CLOSE is flushed by the caller and the reap
        // sweep drops it. Don't serve any requests on it.
        return Ok(());
    }
    sx.readable_ids.clear();
    sx.readable_ids.extend(ctx.conn.readable());

    let actions = plan_actions(ctx, sx.metrics, sx.rate_limiter, sx.tmp, sx.readable_ids)?;

    execute_pending_actions(ctx, sx.socket, sx.metrics, sx.pool, sx.tmp, actions)
}

/// Gate a freshly decoded request through the rate limiter, 0-RTT replay
/// protection, and ACL check, in that order. Returns `Some(resp)` to
/// reject (the caller turns it into an `AclReject` + `Done`), or `None`
/// to proceed with handling the request. The order and short-circuit are
/// load-bearing: rate limit first, then 0-RTT, then ACL.
fn validate_request_prerequisites(
    req: &Request,
    conn: &quiche::Connection,
    user: &User,
    rate_limiter: &mut RateLimiter,
    metrics: &Metrics,
    peer_ip: std::net::IpAddr,
) -> Option<Response> {
    // Per-request rate limit: token-bucket also gates
    // protocol requests on established connections so a
    // single accepted peer can't burn the server with
    // command floods.
    if !rate_limiter.try_consume(peer_ip) {
        metrics.inc_requests_rate_limited();
        return Some(Response::Err(
            qftp_common::protocol::ErrorResponse::with_details(
                ErrorCode::RateLimited,
                "Rate limit exceeded",
                qftp_common::protocol::ErrorDetails::RetryAfter {
                    millis: rate_limiter.retry_after_millis(),
                },
            ),
        ));
    }

    // 0-RTT replay protection. Any request decoded
    // while the QUIC handshake is still in the
    // early-data phase rode the first flight, which
    // an attacker can replay byte-for-byte. Read-only
    // ops are idempotent so we accept them; anything
    // that mutates server state is refused with
    // `Unsupported` and the client falls back to a
    // 1-RTT retry.
    if conn.is_in_early_data() {
        if request_is_replay_safe(req) {
            metrics.inc_zero_rtt_accepted();
        } else {
            metrics.inc_zero_rtt_rejected();
            return Some(err(ErrorCode::Unsupported, "Operation requires 1-RTT data"));
        }
    }

    if let Some(resp) = handler::acl_reject(user, req) {
        return Some(resp);
    }
    None
}

/// Sweep every readable stream once, decode pending requests, run the
/// per-request prerequisite gates, and collect the resulting
/// [`PendingAction`]s. Held a `&mut` into `ctx.streams` throughout, so it
/// cannot act on the requests here; the actions are executed afterward by
/// [`execute_pending_actions`] once that borrow is released.
fn plan_actions(
    ctx: &mut ConnectionContext,
    metrics: &Metrics,
    rate_limiter: &mut RateLimiter,
    tmp: &mut [u8],
    readable_ids: &[u64],
) -> Result<Vec<PendingAction>> {
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

                    if let Some(resp) = validate_request_prerequisites(
                        &req,
                        &ctx.conn,
                        &ctx.user,
                        rate_limiter,
                        metrics,
                        peer_ip,
                    ) {
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
                            hash_algorithm,
                            checksum,
                            no_clobber,
                            checksum_trailer,
                        } => {
                            // qftp/1 negotiates BLAKE3 only; anything else is
                            // refused rather than silently treated as BLAKE3.
                            if hash_algorithm != qftp_common::protocol::HashAlgorithm::Blake3 {
                                actions.push(PendingAction::AclReject {
                                    stream_id,
                                    resp: err(
                                        ErrorCode::Unsupported,
                                        "unsupported hash algorithm (only BLAKE3 is supported)",
                                    ),
                                });
                                *state = StreamState::Done;
                                continue;
                            }
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
                if let Some(resp) =
                    crate::transfer_put::drive_put(&mut ctx.conn, stream_id, state, tmp, metrics)?
                {
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
    Ok(actions)
}

/// Execute the [`PendingAction`]s collected by [`plan_actions`]. By now
/// no borrow into `ctx.streams` is live, so `ctx` can be mutated freely.
fn execute_pending_actions(
    ctx: &mut ConnectionContext,
    socket: &mio::net::UdpSocket,
    metrics: &Metrics,
    pool: &HandlerPool,
    tmp: &mut [u8],
    actions: Vec<PendingAction>,
) -> Result<()> {
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
                crate::transfer_get::start_get(ctx, stream_id, &path, offset, length, metrics)?;
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
                crate::transfer_put::start_put(
                    ctx,
                    stream_id,
                    crate::transfer_put::PutRequest {
                        path,
                        size,
                        mode,
                        offset,
                        expected_checksum,
                        no_clobber,
                        checksum_trailer,
                        leftover,
                    },
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
pub(crate) fn fail_stream(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_result_stale_across_generations() {
        // A result whose generation matches the live connection applies;
        // a mismatch (the SCID was reused by a newer connection) is
        // stale and must be dropped (L-6).
        assert!(!handler_result_is_stale(7, 7));
        assert!(handler_result_is_stale(8, 7));
        assert!(handler_result_is_stale(7, 8));
    }

    #[test]
    fn half_open_expired_reaps_unestablished_after_timeout() {
        // An un-established connection past the half-open window must be
        // reaped so spoofed Initials can't pin cap slots (#266).
        assert!(half_open_expired(false, HALF_OPEN_TIMEOUT));
        assert!(half_open_expired(
            false,
            HALF_OPEN_TIMEOUT + Duration::from_secs(1)
        ));
    }

    #[test]
    fn half_open_does_not_reap_fresh_or_established() {
        // A connection still inside the window survives.
        assert!(!half_open_expired(false, Duration::ZERO));
        assert!(!half_open_expired(
            false,
            HALF_OPEN_TIMEOUT - Duration::from_millis(1)
        ));
        // An established connection is never half-open-reaped, no matter
        // how long it has been alive.
        assert!(!half_open_expired(true, HALF_OPEN_TIMEOUT * 100));
    }

    #[test]
    fn replay_safe_allows_readonly_ops() {
        assert!(request_is_replay_safe(&Request::Ls {
            path: "/".into(),
            cursor: None
        }));
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
            hash_algorithm: qftp_common::protocol::HashAlgorithm::Blake3,
            checksum: Some(vec![0u8; 32]),
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
}
