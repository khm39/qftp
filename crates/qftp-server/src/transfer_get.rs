//! Get (download) transfer driver: opening the requested file, the
//! incremental whole-file BLAKE3 (including a resumed-Get prefix
//! re-read), streaming the body, and the 32-byte checksum trailer.
//! Split out of `server.rs` for cohesion (#271); behavior is unchanged.

use std::io::Read;

use anyhow::Result;
use qftp_common::protocol::*;
use qftp_common::transport::*;
use tracing::warn;

use crate::connection::ConnectionContext;
use crate::metrics::Metrics;
use crate::server::fail_stream;
use qftp_protocol::handler::{self, err, io_code};
use qftp_protocol::stream::{StreamState, MAX_FILE_SIZE, SEND_CHUNK_SIZE};

#[allow(clippy::too_many_arguments)]
pub(crate) fn start_get(
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
        return fail_stream(
            ctx,
            stream_id,
            metrics,
            Response::Err(ErrorResponse::with_details(
                ErrorCode::InvalidRange,
                format!("offset {} past end of file (size {})", offset, meta.len()),
                ErrorDetails::Range {
                    offset,
                    file_size: meta.len(),
                },
            )),
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
            hash_algorithm: HashAlgorithm::Blake3,
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

pub(crate) fn drive_sending_streams(
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
pub(crate) fn drive_rehash_streams(
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
        if let Some(resp) =
            crate::transfer_put::drive_put(&mut ctx.conn, stream_id, state, scratch, metrics)?
        {
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

/// Mutable view of the in-progress `SendingFileData` work-state, bundled
/// so each `send_phase_*` takes this one handle plus the shared transport
/// arguments rather than a long positional list. The fields are borrowed
/// directly out of the `StreamState` so updates persist across calls.
struct BodySend<'a> {
    reader: &'a mut std::io::BufReader<std::fs::File>,
    total_size: &'a mut u64,
    sent: &'a mut u64,
    hasher: &'a mut blake3::Hasher,
    trailer: &'a mut Option<[u8; 32]>,
    trailer_offset: &'a mut usize,
    finished: &'a mut bool,
    prefix_remaining: &'a mut u64,
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
    let mut bs = BodySend {
        reader,
        total_size,
        sent,
        hasher,
        trailer,
        trailer_offset,
        finished,
        prefix_remaining,
    };

    if let Some(outcome) = send_phase_prefix_rehash(&mut ctx.conn, stream_id, chunk, &mut bs) {
        return outcome;
    }

    if let Some(outcome) = send_phase_body(&mut ctx.conn, stream_id, chunk, metrics, &mut bs) {
        return outcome;
    }

    send_phase_trailer(&mut ctx.conn, stream_id, metrics, &mut bs)
}

/// Phase 0: re-hash the [0..offset) prefix of a resumed Get into
/// `hasher` before streaming any body bytes. Doing this incrementally
/// (one chunk per call) keeps a large resumed Get from stalling the
/// event loop; once `prefix_remaining` reaches 0 the next call falls
/// through to Phase A. The trailer is therefore a whole-file BLAKE3,
/// so the client can verify its local prefix against it (#221).
///
/// `Some(outcome)` returns from `drive_one_sender`; `None` falls through
/// to Phase A.
fn send_phase_prefix_rehash(
    conn: &mut quiche::Connection,
    stream_id: u64,
    chunk: &mut [u8],
    bs: &mut BodySend,
) -> Option<SendOutcome> {
    if *bs.prefix_remaining > 0 {
        let want = (*bs.prefix_remaining as usize).min(chunk.len());
        if let Err(e) = bs.reader.read_exact(&mut chunk[..want]) {
            warn!(stream_id, error = %e, "file read failed during prefix re-hash");
            let _ = conn.stream_send(stream_id, &[], true);
            return Some(SendOutcome::Failed);
        }
        bs.hasher.update(&chunk[..want]);
        *bs.prefix_remaining -= want as u64;
        // Yield to the event loop so other streams get a turn; the next
        // iteration continues the prefix walk (or proceeds to Phase A
        // once `prefix_remaining` hits 0).
        return Some(SendOutcome::Blocked);
    }
    None
}

/// Phase A: stream the body. After every chunk that quiche accepts we
/// also feed it into the BLAKE3 hasher so the trailer matches exactly
/// what the peer received.
///
/// `Some(outcome)` returns from `drive_one_sender`; `None` means the
/// body is fully sent and the caller proceeds to Phase B in the same
/// call.
fn send_phase_body(
    conn: &mut quiche::Connection,
    stream_id: u64,
    chunk: &mut [u8],
    metrics: &Metrics,
    bs: &mut BodySend,
) -> Option<SendOutcome> {
    while *bs.sent < *bs.total_size && bs.trailer.is_none() {
        let want = ((*bs.total_size - *bs.sent) as usize).min(chunk.len());
        if let Err(e) = bs.reader.read_exact(&mut chunk[..want]) {
            warn!(stream_id, error = %e, "file read failed mid-stream");
            let _ = conn.stream_send(stream_id, &[], true);
            return Some(SendOutcome::Failed);
        }
        match conn.stream_send(stream_id, &chunk[..want], false) {
            Ok(0) => {
                if let Err(e) = bs.reader.seek_relative(-(want as i64)) {
                    warn!(stream_id, error = %e, "seek failed when stream blocked");
                    return Some(SendOutcome::Failed);
                }
                return Some(SendOutcome::Blocked);
            }
            Ok(n) => {
                bs.hasher.update(&chunk[..n]);
                *bs.sent += n as u64;
                metrics.add_bytes_sent(n as u64);
                if n < want {
                    if let Err(e) = bs.reader.seek_relative(-((want - n) as i64)) {
                        warn!(stream_id, error = %e, "seek failed during partial send");
                        return Some(SendOutcome::Failed);
                    }
                    return Some(SendOutcome::Blocked);
                }
            }
            Err(quiche::Error::Done) => {
                if let Err(e) = bs.reader.seek_relative(-(want as i64)) {
                    warn!(stream_id, error = %e, "seek failed on Done");
                    return Some(SendOutcome::Failed);
                }
                return Some(SendOutcome::Blocked);
            }
            Err(e) => {
                warn!(stream_id, error = ?e, "stream_send failed during Get");
                return Some(SendOutcome::Failed);
            }
        }
    }
    None
}

/// Phase B: body fully sent. Finalize hash once, then push the 32
/// bytes as a trailer with FIN. trailer_offset survives across
/// iterations so a partial-write here resumes cleanly.
fn send_phase_trailer(
    conn: &mut quiche::Connection,
    stream_id: u64,
    metrics: &Metrics,
    bs: &mut BodySend,
) -> SendOutcome {
    if bs.trailer.is_none() {
        let h = bs.hasher.finalize();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(h.as_bytes());
        *bs.trailer = Some(buf);
        *bs.trailer_offset = 0;
    }
    let bytes = bs.trailer.unwrap();
    // Push the trailer bytes WITHOUT fin first; we only emit the FIN as
    // a separate empty frame once all 32 bytes are accepted. quiche's
    // documented behaviour does keep fin pending across partial writes,
    // but the explicit fin-only step is the same pattern stream_send_all
    // uses elsewhere and makes the "stream closes only when the last
    // byte has been queued" invariant impossible to misread.
    while *bs.trailer_offset < bytes.len() {
        let remaining = &bytes[*bs.trailer_offset..];
        match conn.stream_send(stream_id, remaining, false) {
            Ok(0) => return SendOutcome::Blocked,
            Ok(n) => {
                *bs.trailer_offset += n;
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
    match conn.stream_send(stream_id, &[], true) {
        Ok(_) | Err(quiche::Error::Done) => {}
        Err(e) => {
            warn!(stream_id, error = ?e, "stream_send for trailer FIN failed");
            return SendOutcome::Failed;
        }
    }

    *bs.finished = true;
    metrics.inc_downloads_completed();
    SendOutcome::Finished
}
