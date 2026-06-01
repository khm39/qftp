//! Put (upload) transfer driver: accepting a Put request, streaming the
//! body to a `.qftp.partial` temp, verifying the checksum, and the
//! atomic commit rename. Split out of `server.rs` for cohesion (#271);
//! behavior is unchanged.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use qftp_common::protocol::*;
use qftp_common::transport::*;
use tracing::warn;

use crate::connection::ConnectionContext;
use crate::metrics::Metrics;
use crate::server::fail_stream;
use qftp_protocol::compress::{CompressionError, ZstdDecoder};
use qftp_protocol::handler::{self, err, io_code};
use qftp_protocol::stream::{
    temp_path_for, RecvEncoding, ResumeRehash, StreamState, UploadClaim, FILE_CHUNK_SIZE,
    MAX_FILE_SIZE,
};
use qftp_protocol::user::InFlightReservation;

/// Map the transport-agnostic [`PutOverflow`] from the shared
/// classifier (#269) onto the wire `Response::Err` the native server
/// emits.
pub(crate) fn put_overflow_err(o: qftp_protocol::stream::PutOverflow) -> Response {
    use qftp_protocol::stream::PutOverflow;
    match o {
        PutOverflow::BodyExceeded => {
            err(ErrorCode::UploadOverflow, "Upload exceeded declared size")
        }
        PutOverflow::TrailerExceeded => err(
            ErrorCode::UploadOverflow,
            "Upload exceeded declared size + trailer",
        ),
    }
}

fn compressed_decode_err(e: CompressionError) -> Response {
    match e {
        CompressionError::PlaintextLimit { .. } => err(
            ErrorCode::UploadOverflow,
            "decompressed size exceeded declared size",
        ),
        CompressionError::Truncated => err(ErrorCode::DecodeError, "zstd frame is truncated"),
        CompressionError::Codec(e) => {
            err(ErrorCode::DecodeError, format!("zstd decode error: {e}"))
        }
        CompressionError::NoProgress => {
            err(ErrorCode::DecodeError, "zstd decoder made no progress")
        }
    }
}

fn cleanup_rejected_upload(
    temp_path: &Path,
    owner: &Arc<qftp_protocol::user::User>,
    reserved_bytes: u64,
    prior_bytes: u64,
    completed: &mut bool,
) {
    let _ = fs::remove_file(temp_path);
    owner
        .in_flight_bytes
        .fetch_sub(reserved_bytes, Ordering::Relaxed);
    if prior_bytes > 0 {
        owner
            .used_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |u| {
                Some(u.saturating_sub(prior_bytes))
            })
            .ok();
    }
    *completed = true;
}

fn fail_rejected_upload(
    temp_path: &Path,
    owner: &Arc<qftp_protocol::user::User>,
    reserved_bytes: u64,
    prior_bytes: u64,
    completed: &mut bool,
    resp: Response,
) -> Response {
    cleanup_rejected_upload(temp_path, owner, reserved_bytes, prior_bytes, completed);
    resp
}

fn feed_zstd_put_chunk(
    input: &[u8],
    decoder: &mut ZstdDecoder,
    writer: &mut BufWriter<File>,
    hasher: &mut blake3::Hasher,
    remaining: &mut u64,
    trailer_buf: &mut Option<qftp_protocol::stream::TrailerBuf>,
    metrics: &Metrics,
) -> Result<(), Response> {
    if decoder.frame_complete() {
        append_put_trailer(input, trailer_buf)?;
        return Ok(());
    }

    let progress = decoder.push(input).map_err(compressed_decode_err)?;
    while !decoder.pending().is_empty() {
        let n = decoder.pending().len();
        if n as u64 > *remaining {
            return Err(err(
                ErrorCode::UploadOverflow,
                "decompressed size exceeded declared size",
            ));
        }
        writer
            .write_all(decoder.pending())
            .map_err(|e| err(ErrorCode::Internal, format!("Failed to write file: {e}")))?;
        hasher.update(decoder.pending());
        decoder.consume(n);
        *remaining -= n as u64;
        metrics.add_bytes_received(n as u64);
    }

    if progress.frame_complete {
        if *remaining > 0 {
            return Err(err(
                ErrorCode::DecodeError,
                format!("compressed body decoded to fewer bytes than declared: {remaining} bytes missing"),
            ));
        }
        append_put_trailer(&input[progress.consumed..], trailer_buf)?;
    } else if progress.consumed < input.len() {
        return Err(err(
            ErrorCode::DecodeError,
            "zstd decoder stopped before consuming the compressed chunk",
        ));
    }
    Ok(())
}

fn append_put_trailer(
    bytes: &[u8],
    trailer_buf: &mut Option<qftp_protocol::stream::TrailerBuf>,
) -> Result<(), Response> {
    if bytes.is_empty() {
        return Ok(());
    }
    let Some(buf) = trailer_buf else {
        return Err(err(
            ErrorCode::UploadOverflow,
            "Upload exceeded declared size",
        ));
    };
    let consumed = buf.extend(bytes);
    if consumed < bytes.len() {
        return Err(err(ErrorCode::UploadOverflow, "Trailer bytes exceeded 32"));
    }
    Ok(())
}

/// Protocol-level parameters of a `Put` request, grouped so `start_put`
/// takes the transport handles (`ctx`, `stream_id`, scratch, metrics)
/// plus this one bundle rather than a dozen positional arguments.
pub(crate) struct PutRequest {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub offset: u64,
    pub expected_checksum: Option<Vec<u8>>,
    pub no_clobber: bool,
    pub checksum_trailer: bool,
    pub encoding: Encoding,
    pub plaintext_size: u64,
    pub leftover: Vec<u8>,
}

pub(crate) fn start_put(
    ctx: &mut ConnectionContext,
    stream_id: u64,
    req: PutRequest,
    scratch: &mut [u8],
    metrics: &Metrics,
) -> Result<()> {
    let PutRequest {
        path,
        size,
        mode,
        offset,
        expected_checksum,
        no_clobber,
        checksum_trailer,
        encoding,
        plaintext_size,
        leftover,
    } = req;
    let path = path.as_str();
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
    if !encoding.is_supported() {
        return send_err(
            ctx,
            ErrorCode::Unsupported,
            "unsupported upload transfer encoding".to_string(),
        );
    }
    if encoding != Encoding::Identity && !checksum_trailer && expected_checksum.is_none() {
        return send_err(
            ctx,
            ErrorCode::Unsupported,
            "compressed upload requires a checksum".to_string(),
        );
    }
    if encoding != Encoding::Identity && offset != 0 {
        return send_err(
            ctx,
            ErrorCode::Unsupported,
            "compressed resume not supported".to_string(),
        );
    }
    if encoding == Encoding::Zstd && plaintext_size != size {
        return send_err(
            ctx,
            ErrorCode::Malformed,
            format!("compressed upload size {size} != plaintext_size {plaintext_size}"),
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
            return fail_stream(
                ctx,
                stream_id,
                metrics,
                Response::Err(ErrorResponse::with_details(
                    ErrorCode::InvalidRange,
                    format!("resume offset {offset} does not match partial length {have}"),
                    ErrorDetails::Range {
                        offset,
                        file_size: have,
                    },
                )),
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
    let recv_encoding = match encoding {
        Encoding::Identity => RecvEncoding::Identity,
        Encoding::Zstd => match ZstdDecoder::new(size.min(MAX_FILE_SIZE)) {
            Ok(decoder) => RecvEncoding::Zstd { decoder },
            Err(e) => {
                return send_err(
                    ctx,
                    ErrorCode::Internal,
                    format!("failed to initialize zstd decoder: {e}"),
                );
            }
        },
        Encoding::Unknown(_) => unreachable!("unsupported encodings are rejected above"),
    };

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
        no_clobber,
        hasher,
        recv_encoding,
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
            temp_path,
            writer,
            remaining,
            completed,
            hasher,
            recv_encoding,
            trailer_buf,
            reserved_bytes,
            prior_bytes,
            rehash,
            owner,
            ..
        } = &mut new_state
        {
            match recv_encoding {
                RecvEncoding::Identity => {
                    // Bytes coalesced into the same recv as the Put
                    // request frame can hold the body *and* the
                    // 32-byte streaming checksum trailer. Use the
                    // shared classifier so the split policy matches
                    // `drive_put`'s Phase A and the web bridge exactly
                    // (#269).
                    let trailer_remaining =
                        trailer_buf.as_ref().map(|b| b.remaining()).unwrap_or(0);
                    let split = match qftp_protocol::stream::classify_put_chunk(
                        leftover.len(),
                        *remaining,
                        trailer_buf.is_some(),
                        trailer_remaining,
                    ) {
                        Ok(s) => s,
                        Err(o) => return fail_stream(ctx, stream_id, metrics, put_overflow_err(o)),
                    };
                    if split.to_trailer > 0 {
                        if let Some(buf) = trailer_buf {
                            buf.extend(&leftover[split.to_body..split.to_body + split.to_trailer]);
                        }
                    }
                    let body = &leftover[..split.to_body];
                    if let Some(rh) = rehash {
                        // Resume: the prefix isn't hashed yet, so
                        // these body bytes can't be hashed in order
                        // now. Hold them; the re-hash completion path
                        // in `drive_put` writes and hashes them once
                        // the prefix is done. The trailer (if any) is
                        // already buffered above.
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
                        *remaining -= split.to_body as u64;
                        metrics.add_bytes_received(split.to_body as u64);
                    }
                }
                RecvEncoding::Zstd { decoder } => {
                    if let Err(resp) = feed_zstd_put_chunk(
                        &leftover,
                        decoder,
                        writer,
                        hasher,
                        remaining,
                        trailer_buf,
                        metrics,
                    ) {
                        let resp = fail_rejected_upload(
                            temp_path,
                            owner,
                            *reserved_bytes,
                            *prior_bytes,
                            completed,
                            resp,
                        );
                        return fail_stream(ctx, stream_id, metrics, resp);
                    }
                }
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

pub(crate) fn drive_put(
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
        no_clobber,
        hasher,
        recv_encoding,
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
            fail_rejected_upload(
                temp_path,
                owner,
                *reserved_bytes,
                *prior_bytes,
                completed,
                err_resp,
            )
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

    // Phase A: drain body bytes. Identity bodies are length-delimited by
    // `remaining`; zstd bodies are delimited by the self-terminating
    // frame and decrement `remaining` by decoded plaintext bytes.
    loop {
        let body_done = match recv_encoding {
            RecvEncoding::Identity => *remaining == 0,
            RecvEncoding::Zstd { decoder } => decoder.frame_complete(),
        };
        if body_done {
            break;
        }
        match conn.stream_recv(stream_id, tmp) {
            Ok((len, fin)) => {
                match recv_encoding {
                    RecvEncoding::Identity => {
                        // Shared split policy (#269): body bytes
                        // first, the remainder into the streaming
                        // trailer when the client opted in, overflow
                        // otherwise.
                        let trailer_remaining =
                            trailer_buf.as_ref().map(|b| b.remaining()).unwrap_or(0);
                        let split = match qftp_protocol::stream::classify_put_chunk(
                            len,
                            *remaining,
                            trailer_buf.is_some(),
                            trailer_remaining,
                        ) {
                            Ok(s) => s,
                            Err(o) => return Ok(Some(put_overflow_err(o))),
                        };
                        if let Err(e) = writer.write_all(&tmp[..split.to_body]) {
                            return Ok(Some(err(
                                ErrorCode::Internal,
                                format!("Failed to write file: {e}"),
                            )));
                        }
                        hasher.update(&tmp[..split.to_body]);
                        *remaining -= split.to_body as u64;
                        metrics.add_bytes_received(split.to_body as u64);
                        if split.to_trailer > 0 {
                            if let Some(buf) = trailer_buf {
                                buf.extend(&tmp[split.to_body..split.to_body + split.to_trailer]);
                            }
                        }
                        if fin && *remaining > 0 {
                            return Ok(Some(err(
                                ErrorCode::UploadTruncated,
                                format!("Upload truncated: {} bytes still expected", *remaining),
                            )));
                        }
                    }
                    RecvEncoding::Zstd { decoder } => {
                        if let Err(resp) = feed_zstd_put_chunk(
                            &tmp[..len],
                            decoder,
                            writer,
                            hasher,
                            remaining,
                            trailer_buf,
                            metrics,
                        ) {
                            return Ok(Some(fail_rejected_upload(
                                temp_path,
                                owner,
                                *reserved_bytes,
                                *prior_bytes,
                                completed,
                                resp,
                            )));
                        }
                        if fin && !decoder.frame_complete() {
                            return Ok(Some(fail_rejected_upload(
                                temp_path,
                                owner,
                                *reserved_bytes,
                                *prior_bytes,
                                completed,
                                err(
                                    ErrorCode::UploadTruncated,
                                    "Stream closed before zstd frame was complete",
                                ),
                            )));
                        }
                    }
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
    let body_done = match recv_encoding {
        RecvEncoding::Identity => *remaining == 0,
        RecvEncoding::Zstd { decoder } => decoder.frame_complete(),
    };
    if body_done {
        if *remaining > 0 {
            return Ok(Some(fail_rejected_upload(
                temp_path,
                owner,
                *reserved_bytes,
                *prior_bytes,
                completed,
                err(
                    ErrorCode::DecodeError,
                    format!("compressed body decoded to fewer bytes than declared: {remaining} bytes missing"),
                ),
            )));
        }
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
        // body at `final_path`. The shared precedence rule (#269): a
        // complete streaming trailer overrides the legacy header
        // checksum when both are present (defensive; client shouldn't
        // set both).
        let expected: Option<Vec<u8>> = match trailer_buf.as_ref() {
            Some(buf) => {
                qftp_protocol::stream::resolve_put_checksum(true, buf, expected_checksum.clone())
            }
            None => expected_checksum.clone(),
        };
        if let Some(expected) = expected {
            let got = *hasher.finalize().as_bytes();
            if got.as_slice() != expected.as_slice() {
                // The bytes on disk are known-corrupt; a resume would
                // re-hash the same temp and fail forever. Remove it so
                // the next upload starts fresh (mirrors `do_get`
                // deleting a corrupt download). Settle the reservation
                // and mark the stream done so the abort path in
                // `StreamState`'s Drop doesn't also account for it.
                return Ok(Some(fail_rejected_upload(
                    temp_path,
                    owner,
                    *reserved_bytes,
                    *prior_bytes,
                    completed,
                    err(
                        ErrorCode::ChecksumMismatch,
                        "Upload checksum verification failed",
                    ),
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
        // Re-check `no_clobber` immediately before the rename. `start_put`
        // evaluated it once at entry, but a co-tenant (or the client over
        // a second connection) could create `final_path` *during* the
        // transfer; the unconditional rename would then silently overwrite
        // it. On a hit the guard skips the rename and settles accounting.
        if let Some(resp) = no_clobber_commit_guard(
            *no_clobber,
            final_path,
            temp_path,
            owner,
            *reserved_bytes,
            *prior_bytes,
            completed,
        ) {
            return Ok(Some(resp));
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
pub(crate) fn open_temp(path: &Path, resume: bool) -> std::io::Result<File> {
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

/// Commit-time `no_clobber` gate, run immediately before the rename.
///
/// When the upload requested `no_clobber` and a file (or symlink --
/// lstat, not stat, so a planted dangling link still counts) now exists
/// at `final_path`, refuse to overwrite it: the rename is skipped and
/// the partial is cleaned up exactly as the checksum-mismatch path does
/// -- delete the temp, release the in-flight reservation, refund any
/// resume-prefix bytes from `used_bytes`, and mark the stream
/// `completed` so `StreamState`'s Drop does not also account for it.
///
/// Returns `Some(Response::Err(AlreadyExists))` on a refusal (the caller
/// must not rename), `None` when the commit may proceed.
fn no_clobber_commit_guard(
    commit_no_clobber: bool,
    final_path: &Path,
    temp_path: &Path,
    owner: &Arc<qftp_protocol::user::User>,
    reserved_bytes: u64,
    prior_bytes: u64,
    completed: &mut bool,
) -> Option<Response> {
    if !(commit_no_clobber && std::fs::symlink_metadata(final_path).is_ok()) {
        return None;
    }
    cleanup_rejected_upload(temp_path, owner, reserved_bytes, prior_bytes, completed);
    Some(err(
        ErrorCode::AlreadyExists,
        format!("path already exists (no_clobber): {}", final_path.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qftp_protocol::compress::ZstdEncoder;

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

    fn compress_all(plaintext: &[u8]) -> Vec<u8> {
        let mut encoder = ZstdEncoder::new().unwrap();
        for chunk in plaintext.chunks(7777) {
            encoder.push(chunk).unwrap();
        }
        encoder.finish().unwrap();
        let mut out = Vec::new();
        while !encoder.pending().is_empty() {
            out.extend_from_slice(encoder.pending());
            let n = encoder.pending().len();
            encoder.consume(n);
        }
        out
    }

    fn response_code(resp: Response) -> ErrorCode {
        match resp {
            Response::Err(e) => e.code,
            other => panic!("expected error response, got {other:?}"),
        }
    }

    #[test]
    fn zstd_put_feed_writes_plaintext_and_splits_trailer() {
        let plaintext: Vec<u8> = (0..200_000).map(|i| b'a' + (i % 13) as u8).collect();
        let compressed = compress_all(&plaintext);
        let trailer = [0x42u8; 32];
        let mut wire = compressed.clone();
        wire.extend_from_slice(&trailer);

        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("upload.partial")).unwrap();
        let mut writer = BufWriter::new(file);
        let mut hasher = blake3::Hasher::new();
        let mut remaining = plaintext.len() as u64;
        let mut trailer_buf = Some(qftp_protocol::stream::TrailerBuf::new());
        let metrics = Metrics::default();
        let mut decoder = ZstdDecoder::new(remaining).unwrap();

        let splits = [
            0usize,
            1,
            compressed.len() / 2,
            compressed.len().saturating_sub(3),
            compressed.len() + 5,
            wire.len(),
        ];
        for pair in splits.windows(2) {
            feed_zstd_put_chunk(
                &wire[pair[0]..pair[1]],
                &mut decoder,
                &mut writer,
                &mut hasher,
                &mut remaining,
                &mut trailer_buf,
                &metrics,
            )
            .unwrap();
        }
        writer.flush().unwrap();

        assert_eq!(remaining, 0);
        assert!(decoder.frame_complete());
        assert_eq!(trailer_buf.unwrap().as_array(), trailer);
        assert_eq!(
            std::fs::read(dir.path().join("upload.partial")).unwrap(),
            plaintext
        );
        assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 200_000);
    }

    #[test]
    fn zstd_put_feed_rejects_decompression_bomb() {
        let compressed = compress_all(&vec![b'x'; 4096]);
        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("upload.partial")).unwrap();
        let mut writer = BufWriter::new(file);
        let mut hasher = blake3::Hasher::new();
        let mut remaining = 128;
        let mut trailer_buf = Some(qftp_protocol::stream::TrailerBuf::new());
        let metrics = Metrics::default();
        let mut decoder = ZstdDecoder::new(128).unwrap();

        let err = feed_zstd_put_chunk(
            &compressed,
            &mut decoder,
            &mut writer,
            &mut hasher,
            &mut remaining,
            &mut trailer_buf,
            &metrics,
        )
        .unwrap_err();
        assert_eq!(response_code(err), ErrorCode::UploadOverflow);
    }

    #[test]
    fn zstd_put_feed_rejects_malformed_frame() {
        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("upload.partial")).unwrap();
        let mut writer = BufWriter::new(file);
        let mut hasher = blake3::Hasher::new();
        let mut remaining = 1024;
        let mut trailer_buf = Some(qftp_protocol::stream::TrailerBuf::new());
        let metrics = Metrics::default();
        let mut decoder = ZstdDecoder::new(1024).unwrap();

        let err = feed_zstd_put_chunk(
            b"not a zstd frame",
            &mut decoder,
            &mut writer,
            &mut hasher,
            &mut remaining,
            &mut trailer_buf,
            &metrics,
        )
        .unwrap_err();
        assert_eq!(response_code(err), ErrorCode::DecodeError);
    }

    use qftp_protocol::user::{Permissions, User};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::Mutex;

    fn test_user(home: PathBuf) -> Arc<User> {
        Arc::new(User {
            name: "t".to_string(),
            home,
            permissions: Permissions::full(),
            quota_bytes: Some(1_000_000),
            used_bytes: AtomicU64::new(0),
            in_flight_bytes: AtomicU64::new(0),
            active_uploads: Mutex::new(HashSet::new()),
        })
    }

    /// no_clobber + a file that appeared at the destination during the
    /// transfer: the guard refuses, the temp is removed, the stream is
    /// marked completed, and the reservation/prefix accounting is
    /// settled back to zero.
    #[test]
    fn commit_no_clobber_refuses_when_destination_appeared() {
        let dir = tempfile::tempdir().unwrap();
        let user = test_user(dir.path().to_path_buf());
        let temp = dir.path().join("doc.bin.qftp.partial");
        let final_path = dir.path().join("doc.bin");
        fs::write(&temp, b"new-body").unwrap();
        // A racing writer planted the destination after start_put.
        fs::write(&final_path, b"existing").unwrap();

        let reserved = 8u64;
        let prior = 3u64;
        user.in_flight_bytes.fetch_add(reserved, Ordering::Relaxed);
        user.used_bytes.fetch_add(prior, Ordering::Relaxed);
        let mut completed = false;

        let resp = no_clobber_commit_guard(
            true,
            &final_path,
            &temp,
            &user,
            reserved,
            prior,
            &mut completed,
        )
        .expect("guard must refuse");
        match resp {
            Response::Err(e) => assert_eq!(e.code, ErrorCode::AlreadyExists),
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        assert!(completed, "stream must be marked completed");
        assert!(!temp.exists(), "temp must be removed on refusal");
        // The destination the client refused to clobber is untouched.
        assert_eq!(fs::read(&final_path).unwrap(), b"existing");
        assert_eq!(user.in_flight_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(user.used_bytes.load(Ordering::Relaxed), 0);
    }

    /// no_clobber == false: the guard never refuses, even when the
    /// destination exists, so the commit proceeds to overwrite it.
    #[test]
    fn commit_proceeds_without_no_clobber_even_if_destination_exists() {
        let dir = tempfile::tempdir().unwrap();
        let user = test_user(dir.path().to_path_buf());
        let temp = dir.path().join("doc.bin.qftp.partial");
        let final_path = dir.path().join("doc.bin");
        fs::write(&temp, b"new-body").unwrap();
        fs::write(&final_path, b"existing").unwrap();

        let mut completed = false;
        let resp = no_clobber_commit_guard(false, &final_path, &temp, &user, 8, 0, &mut completed);
        assert!(resp.is_none(), "non-no_clobber must not refuse");
        assert!(!completed, "guard must not touch accounting when passing");
        assert!(temp.exists(), "temp must survive for the rename");
    }

    /// no_clobber == true but the destination does not exist at commit:
    /// nothing appeared during the transfer, so the commit proceeds.
    #[test]
    fn commit_proceeds_with_no_clobber_when_destination_absent() {
        let dir = tempfile::tempdir().unwrap();
        let user = test_user(dir.path().to_path_buf());
        let temp = dir.path().join("doc.bin.qftp.partial");
        let final_path = dir.path().join("doc.bin");
        fs::write(&temp, b"new-body").unwrap();

        let mut completed = false;
        let resp = no_clobber_commit_guard(true, &final_path, &temp, &user, 8, 0, &mut completed);
        assert!(resp.is_none(), "absent destination must not refuse");
        assert!(!completed);
        assert!(temp.exists());
    }
}
