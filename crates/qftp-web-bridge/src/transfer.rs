//! Per-stream request handling for the WebTransport bridge.
//!
//! Each incoming WebTransport bidirectional stream carries exactly one
//! qftp `Request` in the standard wire framing (4-byte big-endian
//! length prefix + bincode payload). Simple commands are dispatched
//! through `qftp_protocol::handler`; `Get` and `Put` stream a file body
//! plus a 32-byte BLAKE3 trailer in the same on-wire format the native
//! qftp/1 protocol uses, so the integrity guarantees are identical.
//!
//! Streams are independent: every stream starts with its working
//! directory at the user's home, so a web client must address files
//! with absolute paths (the SPA tracks its own location). This lets the
//! session loop run streams concurrently without a shared, mutable cwd.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use qftp_common::protocol::{validate_request, ErrorCode, ErrorResponse, Request, Response};
use qftp_common::transport::{decode_framed_message, MAX_MESSAGE_SIZE};
use qftp_protocol::handler;
use qftp_protocol::stream::{
    apply_mode, classify_put_chunk, resolve_put_checksum, temp_path_for, PutOverflow, TrailerBuf,
    FILE_CHUNK_SIZE, MAX_FILE_SIZE, SEND_CHUNK_SIZE,
};
use qftp_protocol::user::{InFlightReservation, User};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wtransport::{RecvStream, SendStream};

/// Handle one WebTransport bidirectional stream. Errors are logged
/// rather than propagated -- the stream is simply abandoned, which the
/// browser observes as a reset.
pub async fn handle_stream(send: SendStream, recv: RecvStream, user: Arc<User>) {
    if let Err(e) = handle_stream_impl(send, recv, &user).await {
        tracing::warn!(user = %user.name, error = %e, "web bridge stream failed");
    }
}

async fn handle_stream_impl(
    mut send: SendStream,
    mut recv: RecvStream,
    user: &Arc<User>,
) -> Result<()> {
    let (req, leftover) = read_request(&mut recv).await?;

    if let Err(e) = validate_request(&req) {
        return reply_err(
            &mut send,
            ErrorResponse::new(ErrorCode::Malformed, e.to_string()),
        )
        .await;
    }

    if let Some(resp) = handler::acl_reject(user, &req) {
        send_framed(&mut send, &resp).await?;
        return finish(&mut send).await;
    }

    dispatch_request(&mut send, &mut recv, user, req, leftover).await
}

/// Dispatch a validated, ACL-cleared request to its per-kind handler.
/// `Get`/`Put` stream a body; the remaining variants are one-shot
/// replies. Decode/validation/ACL already ran in `handle_stream_impl`.
async fn dispatch_request(
    send: &mut SendStream,
    recv: &mut RecvStream,
    user: &Arc<User>,
    req: Request,
    leftover: Vec<u8>,
) -> Result<()> {
    match req {
        Request::Get {
            path,
            offset,
            length,
        } => do_get(send, user, &path, offset, length).await,

        Request::Put {
            path,
            size,
            mode,
            offset,
            checksum,
            no_clobber,
            checksum_trailer,
        } => {
            do_put(
                send,
                recv,
                user,
                &path,
                size,
                mode,
                offset,
                checksum,
                no_clobber,
                checksum_trailer,
                leftover,
            )
            .await
        }

        Request::Quota => {
            // Serve the cached `used + in_flight` figure rather than
            // re-walking the user's home on every request -- an
            // unauthenticated/anonymous client could otherwise force a
            // full recursive directory scan per WebTransport stream.
            // The cache is initialized once at startup (`from_config`)
            // and kept current by the Put completion path. `file_count`
            // is advisory only and no longer tracked exactly, matching
            // the native server's `Quota` reply.
            send_framed(
                send,
                &Response::QuotaInfo {
                    used_bytes: user.current_usage(),
                    file_count: 0,
                    limit_bytes: user.quota_bytes,
                },
            )
            .await?;
            finish(send).await
        }

        Request::Quit => finish(send).await,

        // The remaining variants (Pwd / Cd / Ls / Mkdir / Rmdir / Rm /
        // Rename / Chmod / Stat) are stateless one-shot operations the
        // shared handler implements directly. They can issue many
        // blocking fs syscalls (an `Ls` of a large directory does one
        // per entry), so they have to run on the blocking-io pool to
        // avoid parking a tokio worker on slow filesystems.
        other => {
            let home = user.home.clone();
            let resp = await_blocking(
                tokio::task::spawn_blocking(move || {
                    let mut cwd = home.clone();
                    handler::handle_request(&other, &mut cwd, &home)
                }),
                "handler request",
            )
            .await?;
            send_framed(send, &resp).await?;
            finish(send).await
        }
    }
}

/// Read one length-prefixed `Request` frame off the stream. Returns the
/// decoded request and any bytes that arrived after the frame (the
/// start of a `Put` body).
async fn read_request(recv: &mut RecvStream) -> Result<(Request, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = vec![0u8; FILE_CHUNK_SIZE];
    loop {
        if let Some(req) = decode_framed_message::<Request>(&mut buf)? {
            return Ok((req, buf));
        }
        match recv.read(&mut tmp).await.context("stream read failed")? {
            // A zero-length read is not end-of-stream: the frame is
            // still incomplete, `buf` grows by nothing, and looping
            // again would spin a CPU with no forward progress. Treat it
            // as anomalous and fail rather than busy-loop.
            Some(0) => {
                anyhow::bail!("stream yielded no data while a request frame was still incomplete")
            }
            Some(n) => buf.extend_from_slice(&tmp[..n]),
            None => anyhow::bail!("stream closed before a complete request frame arrived"),
        }
        anyhow::ensure!(
            buf.len() <= MAX_MESSAGE_SIZE + FILE_CHUNK_SIZE,
            "request frame exceeds maximum size"
        );
    }
}

/// Serialize `msg` into a length-prefixed frame and write it.
async fn send_framed<T: Serialize>(send: &mut SendStream, msg: &T) -> Result<()> {
    let frame = qftp_common::transport::encode_framed_message(msg)?;
    send.write_all(&frame)
        .await
        .context("stream write failed")?;
    Ok(())
}

async fn finish(send: &mut SendStream) -> Result<()> {
    send.finish().await.context("stream finish failed")
}

/// Send a framed error response and close the stream.
async fn reply_err(send: &mut SendStream, e: ErrorResponse) -> Result<()> {
    send_framed(send, &Response::Err(e)).await?;
    finish(send).await
}

async fn do_get(
    send: &mut SendStream,
    user: &User,
    path: &str,
    offset: u64,
    length: Option<u64>,
) -> Result<()> {
    let root = &user.home;

    // Server-internal upload temp files (`*.qftp.partial`) are server
    // bookkeeping: a client must not be able to read one. The native
    // `qftp-server` blocks this in `start_get`; mirror it here so the
    // web bridge has the same security posture.
    if handler::is_upload_temp(path) {
        return reply_err(
            send,
            ErrorResponse::new(
                ErrorCode::PermissionDenied,
                "path refers to a server-internal upload temp file",
            ),
        )
        .await;
    }

    // `resolve` + `recheck_ancestors_no_symlinks` + O_NOFOLLOW `open`
    // each issue blocking syscalls (lstat per ancestor, plus the open
    // itself). Hand the whole bundle to the blocking pool so a slow FS
    // can't park the tokio worker servicing this stream.
    type OpenOutcome = std::result::Result<(std::fs::File, std::fs::Metadata), ErrorResponse>;
    let open_outcome: OpenOutcome = run_blocking_path_op(
        path.to_string(),
        root.clone(),
        "do_get open",
        |path_owned, root_owned| {
            let file_path = handler::resolve(&root_owned, &root_owned, &path_owned)?;
            handler::recheck_ancestors_no_symlinks(&file_path, &root_owned)?;
            let mut open_opts = std::fs::OpenOptions::new();
            open_opts.read(true);
            qftp_common::fs_safe::apply_no_follow(&mut open_opts);
            let std_file = open_opts.open(&file_path).map_err(|e| {
                ErrorResponse::new(handler::io_code(&e), format!("Failed to open file: {e}"))
            })?;
            let meta = std_file.metadata().map_err(|e| {
                ErrorResponse::new(
                    handler::io_code(&e),
                    format!("failed to stat opened file: {e}"),
                )
            })?;
            Ok((std_file, meta))
        },
    )
    .await?;
    let (std_file, meta) = match open_outcome {
        Ok(pair) => pair,
        Err(e) => return reply_err(send, e).await,
    };
    if !meta.is_file() {
        return reply_err(
            send,
            ErrorResponse::new(ErrorCode::IsADirectory, "Not a regular file"),
        )
        .await;
    }
    if meta.len() > MAX_FILE_SIZE {
        return reply_err(
            send,
            ErrorResponse::new(
                ErrorCode::FileTooLarge,
                format!("File too large: {} bytes (max {MAX_FILE_SIZE})", meta.len()),
            ),
        )
        .await;
    }
    if offset > meta.len() {
        return reply_err(
            send,
            ErrorResponse::new(
                ErrorCode::InvalidRange,
                format!("offset {offset} past end of file (size {})", meta.len()),
            ),
        )
        .await;
    }
    let remaining = meta.len() - offset;
    let to_send = length.map_or(remaining, |n| n.min(remaining));

    let mut file = tokio::fs::File::from_std(std_file);

    send_framed(
        send,
        &Response::FileReady {
            size: to_send,
            total_size: meta.len(),
            checksum_follows: true,
        },
    )
    .await?;

    let mut hasher = blake3::Hasher::new();
    let mut chunk = vec![0u8; SEND_CHUNK_SIZE];
    // Re-hash the [0..offset) prefix into the trailer hasher so a resumed
    // Get sends a whole-file BLAKE3, matching the native server and what
    // the native client verifies its local prefix against (#221). The
    // prefix read also leaves the file positioned at `offset`, so the body
    // loop below streams from there without a separate seek.
    let mut prefix_remaining = offset;
    while prefix_remaining > 0 {
        let want = (prefix_remaining as usize).min(chunk.len());
        file.read_exact(&mut chunk[..want])
            .await
            .context("prefix re-hash read failed")?;
        hasher.update(&chunk[..want]);
        prefix_remaining -= want as u64;
    }
    let mut sent = 0u64;
    while sent < to_send {
        let want = ((to_send - sent) as usize).min(chunk.len());
        file.read_exact(&mut chunk[..want])
            .await
            .context("file read failed mid-stream")?;
        send.write_all(&chunk[..want])
            .await
            .context("stream write failed")?;
        hasher.update(&chunk[..want]);
        sent += want as u64;
    }
    send.write_all(hasher.finalize().as_bytes())
        .await
        .context("trailer write failed")?;
    finish(send).await
}

/// Release the in-flight quota reservation and remove the partial temp
/// file unless the upload committed. The in-flight reservation is held
/// in a shared [`InFlightReservation`] (the same guard the native server
/// uses); the partial-file cleanup and `used_bytes` accounting below are
/// web-bridge-specific because, unlike the native server, the bridge has
/// no upload resume and always removes the partial on abort.
struct PutGuard {
    reservation: InFlightReservation,
    temp_path: Option<PathBuf>,
}

impl Drop for PutGuard {
    fn drop(&mut self) {
        // A disarmed reservation means the upload committed: the commit
        // path already settled both counters, and the embedded
        // `InFlightReservation::drop` is a no-op.
        if !self.reservation.is_armed() {
            return;
        }
        // Not committed. The embedded `InFlightReservation::drop` (which
        // runs after this body) releases the in-flight reservation; here
        // we only handle the on-disk partial.
        if let Some(p) = &self.temp_path {
            // Before removing the partial, charge whatever bytes
            // already landed on disk to `used_bytes`. The web-bridge
            // has no resume (every Put truncates the temp at open),
            // so the temp's current size IS the bytes this session
            // produced -- no `prior_bytes` to subtract. If we skip
            // this and the subsequent remove_file fails (EROFS,
            // EACCES on a degraded mount), a "Put -> abort" loop
            // can leak unbounded real disk space while quota
            // accounting stays at zero. Mirrors
            // `StreamState::ReadingFileData::Drop` in the native
            // server (qftp-protocol/src/stream.rs).
            let user = self.reservation.user();
            let written = match std::fs::metadata(p) {
                Ok(m) => m.len(),
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            path = %p.display(),
                            error = %e,
                            "PutGuard::drop: cannot stat partial; \
                             quota accounting will undercount this abort",
                        );
                    }
                    0
                }
            };
            if written > 0 {
                user.used_bytes.fetch_add(written, Ordering::Relaxed);
            }
            if let Err(e) = std::fs::remove_file(p) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %p.display(), error = %e,
                        "failed to clean up partial upload");
                }
            } else if written > 0 {
                // We successfully removed the file we just charged to
                // used_bytes. Refund those bytes so the next quota
                // check sees the correct on-disk state (the partial
                // is gone). If the remove failed above, the bytes
                // stay charged -- which is the safe direction.
                user.used_bytes.fetch_sub(written, Ordering::Relaxed);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn do_put(
    send: &mut SendStream,
    recv: &mut RecvStream,
    user: &Arc<User>,
    path: &str,
    size: u64,
    mode: u32,
    offset: u64,
    expected_checksum: Option<[u8; 32]>,
    no_clobber: bool,
    checksum_trailer: bool,
    leftover: Vec<u8>,
) -> Result<()> {
    let root = &user.home;

    if size > MAX_FILE_SIZE {
        return reply_err(
            send,
            ErrorResponse::new(
                ErrorCode::FileTooLarge,
                format!("Upload too large: {size} bytes (max {MAX_FILE_SIZE})"),
            ),
        )
        .await;
    }
    // Upload resume (continuing a server-side `.partial` from a prior
    // session) is a native-client feature; the web SPA always uploads
    // whole files, so the bridge only accepts fresh uploads.
    if offset != 0 {
        return reply_err(
            send,
            ErrorResponse::new(
                ErrorCode::Unsupported,
                "the web bridge does not support upload resume (offset > 0)",
            ),
        )
        .await;
    }

    // Quota enforcement. Reserve the bytes against `in_flight_bytes`
    // *first*, then check the total. A check-then-reserve sequence
    // races: two concurrent uploads can both pass the check before
    // either reservation lands and together overshoot the limit.
    // From here every early return drops `guard`, which releases the
    // reservation and removes the temp file if one was created.
    let mut guard = PutGuard {
        reservation: InFlightReservation::reserve(Arc::clone(user), size),
        temp_path: None,
    };
    if let Some(limit) = user.quota_bytes {
        let used = user.used_bytes.load(Ordering::Relaxed);
        // `in_flight` already includes the reservation we just made.
        let in_flight = user.in_flight_bytes.load(Ordering::Relaxed);
        let projected = used.saturating_add(in_flight);
        if projected > limit {
            // Dropping `guard` on return releases the reservation.
            return reply_err(
                send,
                ErrorResponse::new(
                    ErrorCode::QuotaExceeded,
                    format!("Quota exceeded: would use {projected} bytes (limit {limit})"),
                ),
            )
            .await;
        }
    }

    // Same shape as `do_get`'s resolve: bundle the path validation
    // syscalls (resolve_parent, ancestor lstats, optional no_clobber
    // lstat) into one blocking task.
    type ResolveOutcome = std::result::Result<(PathBuf, bool), ErrorResponse>;
    let resolve_outcome: ResolveOutcome = run_blocking_path_op(
        path.to_string(),
        root.clone(),
        "do_put resolve",
        |path_owned, root_owned| {
            let final_path = handler::resolve_parent(&root_owned, &root_owned, &path_owned)?;
            handler::recheck_ancestors_no_symlinks(&final_path, &root_owned)?;
            let exists = std::fs::symlink_metadata(&final_path).is_ok();
            Ok((final_path, exists))
        },
    )
    .await?;
    let (final_path, exists) = match resolve_outcome {
        Ok(pair) => pair,
        Err(e) => return reply_err(send, e).await,
    };
    if no_clobber && exists {
        return reply_err(
            send,
            ErrorResponse::new(
                ErrorCode::AlreadyExists,
                format!("path already exists (no_clobber): {path}"),
            ),
        )
        .await;
    }

    // Claim the destination path so a second concurrent upload to the
    // same path can't open and interleave writes into the one
    // deterministically named temp file. `qftp-server`'s `start_put`
    // takes the identical claim; without it each side's BLAKE3 covers
    // only the bytes it sent, so an interleaved corrupt file could
    // still pass verification. Released when this function returns.
    let _claim =
        match qftp_protocol::stream::UploadClaim::try_claim(Arc::clone(user), final_path.clone()) {
            Some(c) => c,
            None => {
                return reply_err(
                    send,
                    ErrorResponse::new(
                        ErrorCode::AlreadyExists,
                        format!("an upload to this path is already in progress: {path}"),
                    ),
                )
                .await;
            }
        };

    let temp_path = temp_path_for(&final_path);
    // Assign the temp_path to the guard *before* the open spawn_blocking
    // so that if the outer future is cancelled (browser disconnect)
    // after the file is created but before this binding lands, the
    // guard's Drop still has the path to clean up. The reverse order
    // would leak a 0o600 partial that nothing reaps.
    guard.temp_path = Some(temp_path.clone());
    // The temp name is now deterministic (`<final>.qftp.partial`), so a
    // stale partial from an earlier aborted upload may already be on
    // disk. `create_new(true)` would fail on it; instead create-or-open
    // and truncate, matching the native server's fresh-Put path -- the
    // web bridge has no resume, so a stale partial is replaced wholesale.
    // `O_NOFOLLOW` (via `apply_owner_only_no_follow`) still rejects a
    // symlink planted at the predictable path. The open + the
    // permission re-assertion are bundled into one blocking task so a
    // slow FS can't park this tokio worker between the two syscalls.
    // A second `recheck_ancestors_no_symlinks` runs inside the same
    // blocking task immediately before the open: the first recheck
    // happened in a separate spawn_blocking, so without re-checking
    // here, two await boundaries + arbitrary tokio scheduling delay
    // open a TOCTOU window where an attacker can swap a parent dir to
    // a symlink between the recheck and the open.
    let temp_path_for_open = temp_path.clone();
    type TempOpenOutcome = std::result::Result<std::fs::File, ErrorResponse>;
    let open_outcome: TempOpenOutcome = run_blocking_path_op(
        final_path.clone(),
        root.clone(),
        "do_put temp-file open",
        move |final_for_open, root_for_open| {
            handler::recheck_ancestors_no_symlinks(&final_for_open, &root_for_open)?;
            let mut open_opts = std::fs::OpenOptions::new();
            open_opts.write(true).create(true).truncate(true);
            qftp_common::fs_safe::apply_owner_only_no_follow(&mut open_opts);
            let std_file = open_opts.open(&temp_path_for_open).map_err(|e| {
                ErrorResponse::new(
                    handler::io_code(&e),
                    format!("Failed to create upload temp file: {e}"),
                )
            })?;
            // The O_CREAT mode is ignored when the file already existed,
            // so a reused stale partial could otherwise keep a looser
            // mode and leak the in-progress body; re-assert owner-only
            // permissions right after open.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std_file
                    .set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| {
                        ErrorResponse::new(
                            handler::io_code(&e),
                            format!("Failed to re-assert 0o600 on partial: {e}"),
                        )
                    })?;
            }
            Ok(std_file)
        },
    )
    .await?;
    let std_file = match open_outcome {
        Ok(f) => f,
        Err(e) => return reply_err(send, e).await,
    };
    let mut file = tokio::fs::File::from_std(std_file);

    let mut hasher = blake3::Hasher::new();
    let mut body_remaining = size;
    let mut trailer_buf = TrailerBuf::new();

    // Route the bytes that arrived alongside the request frame, then
    // keep reading until the body and (when requested) the 32-byte
    // BLAKE3 trailer are complete.
    if let Some(e) = route_put_chunk(
        &leftover,
        &mut file,
        &mut hasher,
        &mut body_remaining,
        &mut trailer_buf,
        checksum_trailer,
    )
    .await?
    {
        return reply_err(send, e).await;
    }
    let mut tmp = vec![0u8; FILE_CHUNK_SIZE];
    while body_remaining > 0 || (checksum_trailer && !trailer_buf.is_full()) {
        let n = match recv.read(&mut tmp).await.context("stream read failed")? {
            Some(0) => {
                // A zero-length read on an open stream is anomalous --
                // the loop would otherwise spin forever without
                // forward progress on `body_remaining` /
                // `trailer_filled`. Treat as the same shape as EOF and
                // fail with UploadTruncated rather than burning a
                // tokio worker until the QUIC idle timeout closes
                // the connection.
                let msg = if body_remaining > 0 {
                    "Upload truncated: stream yielded no data while body bytes remained"
                } else {
                    "Stream yielded no data while the BLAKE3 trailer was incomplete"
                };
                return reply_err(send, ErrorResponse::new(ErrorCode::UploadTruncated, msg)).await;
            }
            Some(n) => n,
            None => {
                let msg = if body_remaining > 0 {
                    "Upload truncated: stream closed before all body bytes arrived"
                } else {
                    "Stream closed before the BLAKE3 trailer was complete"
                };
                return reply_err(send, ErrorResponse::new(ErrorCode::UploadTruncated, msg)).await;
            }
        };
        if let Some(e) = route_put_chunk(
            &tmp[..n],
            &mut file,
            &mut hasher,
            &mut body_remaining,
            &mut trailer_buf,
            checksum_trailer,
        )
        .await?
        {
            return reply_err(send, e).await;
        }
    }

    file.flush().await.context("temp file flush failed")?;
    drop(file);

    // Verify the checksum before the rename: a corrupt body must never
    // become visible at `final_path`. The shared precedence rule (#269):
    // a complete streamed trailer overrides the legacy header checksum
    // when both are present.
    let expected = resolve_put_checksum(checksum_trailer, &trailer_buf, expected_checksum);
    if let Some(expected) = expected {
        if *hasher.finalize().as_bytes() != expected {
            return reply_err(
                send,
                ErrorResponse::new(
                    ErrorCode::ChecksumMismatch,
                    "Upload checksum verification failed",
                ),
            )
            .await;
        }
    }

    // Commit: bundle the symlink TOCTOU recheck + rename + mode
    // application into one blocking task so the tokio scheduler can't
    // interleave another task between them. The recheck must happen
    // here (not just at the start of `do_put`) because the body
    // transfer above can take arbitrarily long, and a parent
    // directory swapped to a symlink during the transfer would make
    // the rename land the file outside the user's home. Splitting
    // rename and apply_mode across two `.await`s would also leave
    // `final_path` at the temp file's 0o600 for any concurrent reader
    // in the gap; bundling them keeps the file invisible at
    // `final_path` until both succeed.
    let temp_for_commit = temp_path.clone();
    type CommitOutcome = std::result::Result<(), ErrorResponse>;
    let commit_outcome: CommitOutcome = run_blocking_path_op(
        final_path.clone(),
        root.clone(),
        "do_put commit",
        move |final_for_commit, root_for_commit| {
            handler::recheck_ancestors_no_symlinks(&final_for_commit, &root_for_commit)?;
            std::fs::rename(&temp_for_commit, &final_for_commit).map_err(|e| {
                ErrorResponse::new(ErrorCode::Internal, format!("Failed to finalize file: {e}"))
            })?;
            // apply_mode logs and continues on failure; never bubbles an
            // error so we can't leave an orphan file at final_path after
            // rename. The suid-stripping policy is shared with the native
            // server (qftp_protocol::stream::apply_mode).
            apply_mode(&final_for_commit, mode);
            Ok(())
        },
    )
    .await?;
    if let Err(e) = commit_outcome {
        return reply_err(send, e).await;
    }

    // The upload committed: disarm the guard so its drop won't undo it,
    // then hand the reservation over to the persistent used-bytes
    // counter.
    guard.reservation.disarm();
    user.in_flight_bytes.fetch_sub(size, Ordering::Relaxed);
    user.used_bytes.fetch_add(size, Ordering::Relaxed);

    send_framed(send, &Response::Ok).await?;
    finish(send).await
}

/// Map the transport-agnostic [`PutOverflow`] from the shared
/// classifier (#269) onto the bridge's `ErrorResponse`.
fn put_overflow_response(o: PutOverflow) -> ErrorResponse {
    match o {
        PutOverflow::BodyExceeded => {
            ErrorResponse::new(ErrorCode::UploadOverflow, "Upload exceeded declared size")
        }
        PutOverflow::TrailerExceeded => ErrorResponse::new(
            ErrorCode::UploadOverflow,
            "Upload exceeded declared size + trailer",
        ),
    }
}

/// Route one received chunk into the upload body and, once the body is
/// full, into the 32-byte BLAKE3 trailer buffer. Returns `Ok(Some(_))`
/// for a protocol error (the caller turns it into an error response),
/// `Ok(None)` on success, and `Err` for an I/O failure.
async fn route_put_chunk(
    chunk: &[u8],
    file: &mut tokio::fs::File,
    hasher: &mut blake3::Hasher,
    body_remaining: &mut u64,
    trailer_buf: &mut TrailerBuf,
    checksum_trailer: bool,
) -> Result<Option<ErrorResponse>> {
    // Shared split policy (#269): the same classifier the native
    // server uses decides body vs. trailer vs. overflow, so the two
    // transports can't drift on the most error-prone part of the Put
    // path. This driver only performs the I/O the split prescribes.
    let split = match classify_put_chunk(
        chunk.len(),
        *body_remaining,
        checksum_trailer,
        trailer_buf.remaining(),
    ) {
        Ok(s) => s,
        Err(o) => return Ok(Some(put_overflow_response(o))),
    };
    if split.to_body > 0 {
        file.write_all(&chunk[..split.to_body])
            .await
            .context("temp file write failed")?;
        hasher.update(&chunk[..split.to_body]);
        *body_remaining -= split.to_body as u64;
    }
    if split.to_trailer > 0 {
        trailer_buf.extend(&chunk[split.to_body..split.to_body + split.to_trailer]);
    }
    Ok(None)
}

/// Await a `tokio::task::JoinHandle` and turn a panic payload into a
/// readable error string. The default `JoinError::Display` produces
/// `"task <id> panicked"` with no panic message; downcasting the
/// payload via the shared `qftp_common::util::panic_payload_message`
/// helper (also used by `HandlerPool::Drop` and `handler_worker` so
/// payload-shape support stays in one place) surfaces the actual
/// panic text so operator logs are diagnosable.
pub async fn await_blocking<T: Send + 'static>(
    handle: tokio::task::JoinHandle<T>,
    desc: &'static str,
) -> Result<T> {
    handle.await.map_err(|je| {
        if je.is_cancelled() {
            return anyhow::anyhow!("{desc} task was cancelled");
        }
        if je.is_panic() {
            let msg = qftp_common::util::panic_payload_message(je.into_panic());
            return anyhow::anyhow!("{desc} panicked: {msg}");
        }
        anyhow::anyhow!("{desc}: {je}")
    })
}

/// Run a path-validating filesystem operation on the blocking pool.
///
/// The `resolve` / `recheck_ancestors_no_symlinks` / open / rename
/// syscalls all block, so each `do_get`/`do_put` step that touches the
/// path bundles them into one `spawn_blocking` and awaits it through
/// `await_blocking`. This helper captures only that owning-then-spawn
/// plumbing: `path_owned` and `root_owned` move into the closure, which
/// runs the whole operation. The closure must keep performing its
/// own `recheck_ancestors_no_symlinks` so that recheck stays atomic
/// with the open/rename inside the single blocking task -- splitting it
/// across the await boundary would reopen the TOCTOU window the bundle
/// closes.
async fn run_blocking_path_op<P, T, F>(
    path_owned: P,
    root_owned: PathBuf,
    desc: &'static str,
    f: F,
) -> Result<T>
where
    P: Send + 'static,
    T: Send + 'static,
    F: FnOnce(P, PathBuf) -> T + Send + 'static,
{
    await_blocking(
        tokio::task::spawn_blocking(move || f(path_owned, root_owned)),
        desc,
    )
    .await
}

// `temp_path_for` lives in `qftp_protocol::stream` and is tested
// there (cycle-2 review #14).

#[cfg(test)]
mod tests {
    use super::*;
    use qftp_protocol::user::Permissions;
    use std::collections::HashSet;
    use std::io::Write;
    use std::sync::atomic::AtomicU64;
    use std::sync::Mutex;

    fn test_user() -> Arc<User> {
        Arc::new(User {
            name: "t".to_string(),
            home: PathBuf::from("/tmp"),
            permissions: Permissions::full(),
            quota_bytes: Some(1_000_000),
            used_bytes: AtomicU64::new(0),
            in_flight_bytes: AtomicU64::new(0),
            active_uploads: Mutex::new(HashSet::new()),
        })
    }

    fn partial_with(dir: &std::path::Path, bytes: usize) -> PathBuf {
        let p = dir.join("upload.qftp.partial");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&vec![0u8; bytes]).unwrap();
        p
    }

    // An aborted upload must release the in-flight reservation and, after
    // removing the partial it cleaned up, leave `used_bytes` unchanged
    // (charged, then refunded once the file is gone).
    #[test]
    fn abort_releases_reservation_and_removes_partial() {
        let dir = tempfile::tempdir().unwrap();
        let user = test_user();
        let temp = partial_with(dir.path(), 600);
        let guard = PutGuard {
            reservation: InFlightReservation::reserve(Arc::clone(&user), 600),
            temp_path: Some(temp.clone()),
        };
        assert_eq!(user.in_flight_bytes.load(Ordering::Relaxed), 600);
        drop(guard);
        assert_eq!(user.in_flight_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(user.used_bytes.load(Ordering::Relaxed), 0);
        assert!(!temp.exists(), "aborted partial should be removed");
    }

    // A committed upload disarms the guard; its drop must touch neither
    // counter (the commit path already settled them) nor the file.
    #[test]
    fn committed_guard_drop_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let user = test_user();
        let temp = partial_with(dir.path(), 600);
        let mut guard = PutGuard {
            reservation: InFlightReservation::reserve(Arc::clone(&user), 600),
            temp_path: Some(temp.clone()),
        };
        // Simulate the commit path: disarm the reservation, then hand the
        // reserved bytes over to the persistent counter.
        guard.reservation.disarm();
        user.in_flight_bytes.fetch_sub(600, Ordering::Relaxed);
        user.used_bytes.fetch_add(600, Ordering::Relaxed);
        drop(guard);
        assert_eq!(user.in_flight_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(user.used_bytes.load(Ordering::Relaxed), 600);
        assert!(temp.exists(), "committed file must not be removed");
    }
}
