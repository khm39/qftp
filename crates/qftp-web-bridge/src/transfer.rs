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

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use qftp_common::protocol::{validate_request, ErrorCode, ErrorResponse, Request, Response};
use qftp_common::transport::{decode_framed_message, MAX_MESSAGE_SIZE};
use qftp_protocol::handler;
use qftp_protocol::stream::{FILE_CHUNK_SIZE, MAX_FILE_SIZE, SEND_CHUNK_SIZE};
use qftp_protocol::user::User;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
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

    match req {
        Request::Get {
            path,
            offset,
            length,
        } => do_get(&mut send, user, &path, offset, length).await,

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
                &mut send,
                &mut recv,
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
                &mut send,
                &Response::QuotaInfo {
                    used_bytes: user.current_usage(),
                    file_count: 0,
                    limit_bytes: user.quota_bytes,
                },
            )
            .await?;
            finish(&mut send).await
        }

        Request::Quit => finish(&mut send).await,

        // The remaining variants (Pwd / Cd / Ls / Mkdir / Rmdir / Rm /
        // Rename / Chmod / Stat) are stateless one-shot operations the
        // shared handler implements directly.
        other => {
            let mut cwd = user.home.clone();
            let resp = handler::handle_request(&other, &mut cwd, &user.home);
            send_framed(&mut send, &resp).await?;
            finish(&mut send).await
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

    let file_path = match handler::resolve(root, root, path) {
        Ok(p) => p,
        Err(e) => return reply_err(send, e).await,
    };
    // Parent-dir symlink TOCTOU re-check: O_NOFOLLOW below guards the
    // leaf only, an intermediate parent swapped to a symlink would
    // still be traversed by the kernel.
    if let Err(e) = handler::recheck_ancestors_no_symlinks(&file_path, root) {
        return reply_err(send, e).await;
    }

    // Open with O_NOFOLLOW first, then derive metadata from the
    // resulting fd so the bytes we stream are bound to the inode the
    // path resolved to.
    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.read(true);
    qftp_common::fs_safe::apply_no_follow(&mut open_opts);
    let std_file = match open_opts.open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            return reply_err(
                send,
                ErrorResponse::new(handler::io_code(&e), format!("Failed to open file: {e}")),
            )
            .await
        }
    };
    let meta = std_file.metadata().context("failed to stat opened file")?;
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
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .with_context(|| format!("seek to offset {offset}"))?;
    }

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
/// file unless the upload committed. Mirrors the `Drop` impl that
/// `qftp_protocol::stream::StreamState` relies on in the native server.
struct PutGuard {
    user: Arc<User>,
    reserved: u64,
    temp_path: Option<PathBuf>,
    completed: bool,
}

impl Drop for PutGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.user
            .in_flight_bytes
            .fetch_sub(self.reserved, Ordering::Relaxed);
        if let Some(p) = &self.temp_path {
            if let Err(e) = std::fs::remove_file(p) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %p.display(), error = %e,
                        "failed to clean up partial upload");
                }
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
    // The native server supports appending to a server-side `.partial`
    // from a prior session; the random temp-file naming makes that
    // unreachable in practice, and the web SPA always uploads whole
    // files, so the bridge only accepts fresh uploads.
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
    user.in_flight_bytes.fetch_add(size, Ordering::Relaxed);
    // From here every early return drops `guard`, which releases the
    // reservation and removes the temp file if one was created.
    let mut guard = PutGuard {
        user: Arc::clone(user),
        reserved: size,
        temp_path: None,
        completed: false,
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

    let final_path = match handler::resolve_parent(root, root, path) {
        Ok(p) => p,
        Err(e) => return reply_err(send, e).await,
    };
    if let Err(e) = handler::recheck_ancestors_no_symlinks(&final_path, root) {
        return reply_err(send, e).await;
    }
    // lstat (not stat) so a planted dangling symlink still counts as
    // "exists" and can't be used to bypass --no-clobber.
    if no_clobber && std::fs::symlink_metadata(&final_path).is_ok() {
        return reply_err(
            send,
            ErrorResponse::new(
                ErrorCode::AlreadyExists,
                format!("path already exists (no_clobber): {path}"),
            ),
        )
        .await;
    }

    let temp_path = temp_path_for(&final_path);
    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true).create_new(true);
    qftp_common::fs_safe::apply_owner_only_no_follow(&mut open_opts);
    let std_file = match open_opts.open(&temp_path) {
        Ok(f) => f,
        Err(e) => {
            return reply_err(
                send,
                ErrorResponse::new(
                    handler::io_code(&e),
                    format!("Failed to create upload temp file: {e}"),
                ),
            )
            .await
        }
    };
    guard.temp_path = Some(temp_path.clone());
    let mut file = tokio::fs::File::from_std(std_file);

    let mut hasher = blake3::Hasher::new();
    let mut body_remaining = size;
    let mut trailer = [0u8; 32];
    let mut trailer_filled = 0usize;

    // Route the bytes that arrived alongside the request frame, then
    // keep reading until the body and (when requested) the 32-byte
    // BLAKE3 trailer are complete.
    if let Some(e) = route_put_chunk(
        &leftover,
        &mut file,
        &mut hasher,
        &mut body_remaining,
        &mut trailer,
        &mut trailer_filled,
        checksum_trailer,
    )
    .await?
    {
        return reply_err(send, e).await;
    }
    let mut tmp = vec![0u8; FILE_CHUNK_SIZE];
    while body_remaining > 0 || (checksum_trailer && trailer_filled < 32) {
        let n = match recv.read(&mut tmp).await.context("stream read failed")? {
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
            &mut trailer,
            &mut trailer_filled,
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
    // become visible at `final_path`. A streamed trailer takes
    // precedence over the legacy header checksum when both are present.
    let expected = if checksum_trailer && trailer_filled == 32 {
        Some(trailer)
    } else {
        expected_checksum
    };
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

    if let Err(e) = std::fs::rename(&temp_path, &final_path) {
        return reply_err(
            send,
            ErrorResponse::new(ErrorCode::Internal, format!("Failed to finalize file: {e}")),
        )
        .await;
    }
    apply_mode(&final_path, mode);

    // The upload committed: stop the guard from undoing it, then hand
    // the reservation over to the persistent used-bytes counter.
    guard.completed = true;
    user.in_flight_bytes.fetch_sub(size, Ordering::Relaxed);
    user.used_bytes.fetch_add(size, Ordering::Relaxed);

    send_framed(send, &Response::Ok).await?;
    finish(send).await
}

/// Route one received chunk into the upload body and, once the body is
/// full, into the 32-byte BLAKE3 trailer buffer. Returns `Ok(Some(_))`
/// for a protocol error (the caller turns it into an error response),
/// `Ok(None)` on success, and `Err` for an I/O failure.
#[allow(clippy::too_many_arguments)]
async fn route_put_chunk(
    chunk: &[u8],
    file: &mut tokio::fs::File,
    hasher: &mut blake3::Hasher,
    body_remaining: &mut u64,
    trailer: &mut [u8; 32],
    trailer_filled: &mut usize,
    checksum_trailer: bool,
) -> Result<Option<ErrorResponse>> {
    let to_body = (chunk.len() as u64).min(*body_remaining) as usize;
    if to_body > 0 {
        file.write_all(&chunk[..to_body])
            .await
            .context("temp file write failed")?;
        hasher.update(&chunk[..to_body]);
        *body_remaining -= to_body as u64;
    }
    let rest = &chunk[to_body..];
    if rest.is_empty() {
        return Ok(None);
    }
    if !checksum_trailer {
        return Ok(Some(ErrorResponse::new(
            ErrorCode::UploadOverflow,
            "Upload exceeded declared size",
        )));
    }
    if rest.len() > 32 - *trailer_filled {
        return Ok(Some(ErrorResponse::new(
            ErrorCode::UploadOverflow,
            "Upload exceeded declared size + trailer",
        )));
    }
    trailer[*trailer_filled..*trailer_filled + rest.len()].copy_from_slice(rest);
    *trailer_filled += rest.len();
    Ok(None)
}

/// Compose a `.qftp.partial.*` temp path next to `final_path`. The
/// random suffix stops a colluding local user from pre-planting a file
/// at a predictable path to block uploads.
fn temp_path_for(final_path: &Path) -> PathBuf {
    let mut rand_bytes = [0u8; 8];
    use ring::rand::SecureRandom as _;
    // A swallowed RNG failure here would leave an all-zero suffix and
    // defeat the anti-planting defense, so fail loudly instead.
    ring::rand::SystemRandom::new()
        .fill(&mut rand_bytes)
        .expect("system RNG failed");
    let suffix = qftp_common::util::to_hex(&rand_bytes);
    let mut name = final_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".qftp.partial.{}.{suffix}", std::process::id()));
    final_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

/// Apply the client-requested mode, stripping suid/sgid/sticky bits so
/// an upload can't plant a setuid primitive inside the served tree.
#[cfg(unix)]
fn apply_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode & 0o0777);
    if let Err(e) = std::fs::set_permissions(path, perms) {
        tracing::warn!(path = %path.display(), error = %e, "failed to set permissions");
    }
}

#[cfg(not(unix))]
fn apply_mode(_path: &Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_path_is_a_sibling_of_the_target() {
        let target = Path::new("/srv/data/report.bin");
        let temp = temp_path_for(target);
        assert_eq!(temp.parent(), target.parent());
        let name = temp.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("report.bin.qftp.partial."), "{name}");
    }

    #[test]
    fn temp_paths_are_unique() {
        let target = Path::new("/srv/data/report.bin");
        assert_ne!(temp_path_for(target), temp_path_for(target));
    }
}
