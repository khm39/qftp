//! Bulk Get/Put transfer logic for the client.
//!
//! Handles the bits of the protocol that the REPL doesn't model
//! directly:
//!   * Sending an offset for resume.
//!   * Computing BLAKE3 over uploads and verifying the server's
//!     trailer on downloads.
//!   * Driving a progress bar while bytes move.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use qftp_common::protocol::*;
use qftp_common::transport::*;
use qftp_protocol::compress::{is_likely_incompressible, ZstdDecoder, ZstdEncoder};
use qftp_protocol::stream::{FILE_CHUNK_SIZE, MAX_FILE_SIZE};

use crate::proto::Session;

/// Outer-loop buffer for the upload body. Deliberately larger than the
/// protocol's generic `FILE_CHUNK_SIZE` so a 64 MiB put runs the outer
/// event-loop step ~64 times instead of ~1024: each extra trip costs a
/// `read_exact`, stream_send call, ingress drain, and flush_egress, and
/// at small chunk sizes the fixed overhead — not flow-control — was
/// capping loopback put at ~65 MiB/s. quiche handles partial accepts
/// via the inner stream_send loop, so a larger buffer is purely a win
/// when cwnd is open and degrades gracefully when it isn't. This is the
/// one place the client intentionally diverges from `FILE_CHUNK_SIZE`.
const UPLOAD_CHUNK: usize = 1024 * 1024;

/// Process-wide flag set from `--quiet`. When true, `make_bar`
/// returns a hidden ProgressBar so callers don't have to thread the
/// flag through every transfer entry point.
static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_quiet(q: bool) {
    QUIET.store(q, std::sync::atomic::Ordering::Relaxed);
}

/// Bandwidth limit in bytes/second. `0` (default) = unlimited.
/// `--bwlimit` parses K/M/G suffixes and stores the byte rate here.
/// Set once at startup, read from every chunk-loop iteration.
static BW_LIMIT_BPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn set_bw_limit_bps(rate: u64) {
    BW_LIMIT_BPS.store(rate, std::sync::atomic::Ordering::Relaxed);
}

/// `--no-compress` disables client-initiated zstd transfer compression
/// process-wide: uploads are sent as `Identity` and downloads stop
/// advertising `Zstd` in `accept_encoding`. `false` (default) leaves the
/// default-on policy in place. Set once at startup, read per transfer.
static COMPRESSION_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_compression_disabled(disabled: bool) {
    COMPRESSION_DISABLED.store(disabled, std::sync::atomic::Ordering::Relaxed);
}

fn compression_disabled() -> bool {
    COMPRESSION_DISABLED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Token-bucket throttle applied per chunk. Sleeps just long enough
/// to keep the moving average at or below `--bwlimit`. The bucket
/// holds 1s worth of tokens so short bursts don't get over-paced.
pub struct Pacer {
    last: std::time::Instant,
    tokens: f64,
    rate: f64,
    burst: f64,
}

impl Pacer {
    pub fn new() -> Self {
        Self::with_rate(BW_LIMIT_BPS.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Build a `Pacer` for an explicit byte/second `rate`, bypassing the
    /// process-wide `BW_LIMIT_BPS`. `new()` is the production entry point
    /// (reads the `--bwlimit` global); this lets tests construct a pacer
    /// with a known rate without racing on shared static state.
    pub fn with_rate(rate: u64) -> Self {
        let rate = rate as f64;
        Self {
            last: std::time::Instant::now(),
            tokens: rate,
            rate,
            burst: rate.max(64.0 * 1024.0),
        }
    }

    /// Account for `bytes` about to be sent and return how long the
    /// caller must wait before sending them to stay at or below
    /// `--bwlimit`. Returns `Duration::ZERO` (the common case, and
    /// always when the limit is 0 / unlimited) when no wait is needed.
    ///
    /// The wait itself is deliberately *not* performed here: a single
    /// blocking `thread::sleep` of many seconds would starve the QUIC
    /// connection (no ingress/egress/timeout servicing) long enough
    /// for the idle timer to tear it down. The caller performs the
    /// returned wait in small slices while pumping the connection.
    pub fn consume(&mut self, bytes: usize) -> Duration {
        if self.rate <= 0.0 {
            return Duration::ZERO;
        }
        let now = std::time::Instant::now();
        self.refill_tokens(now);

        if self.check_capacity(bytes) {
            self.tokens -= bytes as f64;
            return Duration::ZERO;
        }
        let wait = self.calculate_wait(bytes);
        // Treat the upcoming wait as having drained the deficit; the
        // caller blocks for `wait`, so account for it now and let the
        // next refill (off the updated `last`) credit time elapsed
        // during the wait back into the bucket.
        self.last = now + wait;
        self.tokens = 0.0;
        wait
    }

    /// Credit tokens for the time elapsed since the last refill, capped
    /// at `burst`, and advance `last` to `now`.
    fn refill_tokens(&mut self, now: std::time::Instant) {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
    }

    /// Whether the bucket currently holds enough tokens to send `bytes`
    /// without waiting.
    fn check_capacity(&self, bytes: usize) -> bool {
        (bytes as f64) <= self.tokens
    }

    /// How long the caller must wait to cover the deficit between
    /// `bytes` and the tokens currently in the bucket.
    fn calculate_wait(&self, bytes: usize) -> Duration {
        let need = bytes as f64 - self.tokens;
        Duration::from_secs_f64(need / self.rate)
    }
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a `K`/`M`/`G` / `Ki`/`Mi`/`Gi` suffix into bytes/second.
/// Examples: "5M" = 5_000_000, "1Gi" = 1_073_741_824.
/// Returns 0 for "0" so callers can treat unlimited uniformly.
pub fn parse_bw_limit(input: &str) -> anyhow::Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        anyhow::bail!("bwlimit is empty");
    }
    let bytes = s.as_bytes();
    let (num_end, mult) = qftp_common::util::parse_suffix(bytes)
        .ok_or_else(|| anyhow::anyhow!("bwlimit: unrecognized suffix in '{input}'"))?;
    let num: f64 = std::str::from_utf8(&bytes[..num_end])
        .map_err(|_| anyhow::anyhow!("bwlimit: non-utf8 number"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("bwlimit: bad number '{input}'"))?;
    if num < 0.0 {
        anyhow::bail!("bwlimit: negative rate");
    }
    Ok((num * mult as f64) as u64)
}

fn make_bar(total: u64, label: &str) -> ProgressBar {
    if QUIET.load(std::sync::atomic::Ordering::Relaxed) {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new(total);
    bar.set_message(label.to_string());
    bar.set_style(
        ProgressStyle::with_template(
            "{msg:>10} {wide_bar} {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>12} eta {eta:>4}",
        )
        .unwrap()
        .progress_chars("=> "),
    );
    bar.enable_steady_tick(Duration::from_millis(120));
    bar
}

/// Feed the first `len` bytes read from `r` into `hasher` in
/// `FILE_CHUNK_SIZE`-sized reads. Used by both Get and Put to fold a
/// resumed transfer's `[0..offset)` prefix into the whole-file BLAKE3
/// before the suffix is streamed. `ctx` is the caller's `read_exact`
/// error context so each side keeps its own message verbatim. Reads
/// only; the caller is responsible for any seek positioning around it.
fn hash_prefix<R: Read>(
    r: &mut R,
    len: u64,
    hasher: &mut blake3::Hasher,
    ctx: &'static str,
) -> Result<()> {
    let mut buf = [0u8; FILE_CHUNK_SIZE];
    let mut left = len;
    while left > 0 {
        let want = (left as usize).min(buf.len());
        r.read_exact(&mut buf[..want]).context(ctx)?;
        hasher.update(&buf[..want]);
        left -= want as u64;
    }
    Ok(())
}

enum DownloadBody {
    Identity { received: u64, size: u64 },
    Zstd { decoder: ZstdDecoder },
}

impl DownloadBody {
    fn is_complete(&self) -> bool {
        match self {
            DownloadBody::Identity { received, size } => received >= size,
            DownloadBody::Zstd { decoder } => decoder.frame_complete(),
        }
    }

    fn plaintext_received(&self) -> u64 {
        match self {
            DownloadBody::Identity { received, .. } => *received,
            DownloadBody::Zstd { decoder } => decoder.decoded_len(),
        }
    }
}

fn drain_decoded_plaintext(
    decoder: &mut ZstdDecoder,
    file: &mut File,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    while !decoder.pending().is_empty() {
        let n = decoder.pending().len();
        file.write_all(decoder.pending())
            .context("writing decoded zstd body chunk")?;
        hasher.update(decoder.pending());
        decoder.consume(n);
    }
    Ok(())
}

fn accept_download_bytes(
    body: &mut DownloadBody,
    input: &[u8],
    file: &mut File,
    hasher: &mut blake3::Hasher,
    trailer: &mut Vec<u8>,
    bar: &ProgressBar,
    resume_offset: u64,
) -> Result<()> {
    match body {
        DownloadBody::Identity { received, size } => {
            if *received < *size {
                let body_room = (*size - *received) as usize;
                let body_take = body_room.min(input.len());
                if body_take > 0 {
                    file.write_all(&input[..body_take])
                        .context("writing body chunk")?;
                    hasher.update(&input[..body_take]);
                    *received += body_take as u64;
                    bar.set_position(resume_offset + *received);
                }
                if body_take < input.len() {
                    trailer.extend_from_slice(&input[body_take..]);
                }
            } else {
                trailer.extend_from_slice(input);
            }
        }
        DownloadBody::Zstd { decoder } => {
            if decoder.frame_complete() {
                trailer.extend_from_slice(input);
                return Ok(());
            }
            let progress = decoder.push(input).context("decoding zstd body chunk")?;
            drain_decoded_plaintext(decoder, file, hasher)?;
            bar.set_position(resume_offset + decoder.decoded_len());
            if progress.frame_complete {
                trailer.extend_from_slice(&input[progress.consumed..]);
            } else if progress.consumed < input.len() {
                bail!("zstd decoder stopped before consuming the compressed chunk");
            }
        }
    }
    Ok(())
}

/// Download `remote` to `local`. If `local` already exists, resume from
/// its current length. Verifies the server-supplied BLAKE3 trailer once
/// the body is fully received and refuses to keep the file on mismatch.
pub fn do_get(session: &mut Session, remote: &str, local: &Path) -> Result<()> {
    // Parent span for the whole download so structured logs group the
    // FileReady / chunk / verify events under a single (op=get,
    // path=...) header.
    let _span = tracing::info_span!("transfer", op = "get", path = %remote).entered();
    let stream_id = session.take_stream();
    let mut result = do_get_inner(session, stream_id, remote, local);
    // A resumed download whose local partial is longer than the (now
    // shorter) remote file is refused with InvalidRange; `do_get_inner`
    // deletes the stale local file and signals `StalePartial`. Retry
    // once from scratch on a fresh stream so the transfer isn't stuck
    // failing forever on the leftover partial.
    if result.as_ref().is_err_and(|e| e.is::<StalePartial>()) {
        let stream_id = session.take_stream();
        result = do_get_inner(session, stream_id, remote, local);
    }
    if let Err(e) = &result {
        if !e.is::<StalePartial>() {
            crate::stats::record_failure();
        }
    }
    result
}

fn do_get_inner(session: &mut Session, stream_id: u64, remote: &str, local: &Path) -> Result<()> {
    let resume_offset = match std::fs::metadata(local) {
        Ok(m) if m.is_file() => m.len(),
        _ => 0,
    };

    let req = Request::Get {
        path: remote.to_string(),
        offset: resume_offset,
        length: None,
        // Advertise zstd unless `--no-compress` is set. The server still
        // makes the final choice (and may answer Identity for already-
        // compressed or tiny files); an empty list means identity only.
        accept_encoding: if compression_disabled() {
            Vec::new()
        } else {
            vec![Encoding::Zstd]
        },
    };
    send_message(session.conn, stream_id, &req)?;
    stream_send_all(session.conn, stream_id, &[], true)?;
    flush_egress(session.conn, session.socket)?;

    // The FileReady response and the first chunk of body bytes can be
    // pulled off the stream together; capture whatever recv_message
    // drained past the response frame so the body-read loop below can
    // consume it before going back to stream_recv. For tiny files the
    // entire body + trailer + FIN often arrives in the same ingress.
    let mut carryover: Vec<u8> = Vec::new();
    let resp = session.poll_response_with_buf(stream_id, &mut carryover)?;
    let (size, total_size, checksum_follows, encoding, plaintext_size) = match resp {
        Response::FileReady {
            size,
            total_size,
            checksum_follows,
            encoding,
            plaintext_size,
            ..
        } => (size, total_size, checksum_follows, encoding, plaintext_size),
        Response::Err(e) => {
            // A resumed Get whose offset is past the (now shorter)
            // remote file is refused with InvalidRange: the local
            // partial is stale. Delete it so a retry starts clean, and
            // signal the caller to retry from offset 0.
            if e.code == ErrorCode::InvalidRange && resume_offset > 0 {
                let _ = std::fs::remove_file(local);
                return Err(anyhow::Error::new(StalePartial));
            }
            bail!("server refused Get: {} ({:?})", e.message, e.code);
        }
        other => bail!("unexpected response to Get: {other:?}"),
    };
    let logical_size = match encoding {
        Encoding::Identity => size,
        Encoding::Zstd => {
            if size != plaintext_size {
                bail!(
                    "server returned inconsistent zstd sizes: size ({size}) \
                     != plaintext_size ({plaintext_size})"
                );
            }
            plaintext_size
        }
        Encoding::Unknown(n) => bail!("server selected unsupported transfer encoding {n}"),
    };
    if matches!(encoding, Encoding::Zstd) && plaintext_size > MAX_FILE_SIZE {
        bail!(
            "server announced zstd plaintext size {} above max {}",
            plaintext_size,
            MAX_FILE_SIZE
        );
    }

    // `total_size` is the server's announced full-file size; `size` is
    // the streamed body. `do_get` always sends `length: None`, so the
    // streamed body should be exactly `total_size - resume_offset`. A
    // mismatch means the server is announcing one size and delivering
    // another (e.g. a malicious server returning a valid-looking
    // trailer over a truncated body and banking on `total_size` going
    // unchecked); refuse before we touch the local disk.
    if resume_offset
        .checked_add(logical_size)
        .map(|t| t != total_size)
        .unwrap_or(true)
    {
        bail!(
            "server returned inconsistent sizes: resume_offset ({resume_offset}) \
             + size ({logical_size}) != total_size ({total_size})"
        );
    }

    // Refuse to open through a pre-existing symlink. Combined
    // with the name filter this stops a malicious server from
    // pointing a recursive download at, say, ~/.ssh/authorized_keys
    // via a planted symlink in the destination directory.
    let mut opts = OpenOptions::new();
    opts.read(true)
        .write(true)
        .create(true)
        .truncate(resume_offset == 0);
    qftp_common::fs_safe::apply_no_follow(&mut opts);
    let mut file = opts
        .open(local)
        .with_context(|| format!("opening {} for write", local.display()))?;

    // The server's BLAKE3 trailer is a whole-file hash even for a
    // resumed Get: it re-hashes [0..offset) before streaming the
    // [offset..] suffix. Mirror that here -- feed the local prefix
    // into `hasher` first, then continue with the received suffix.
    // This is what verifies the local prefix: if it doesn't match the
    // remote file's prefix, the whole-file hashes won't match and the
    // download fails at trailer verification (#221).
    let mut hasher = blake3::Hasher::new();
    if resume_offset > 0 {
        file.seek(SeekFrom::Start(0))
            .context("seeking to start of local prefix")?;
        hash_prefix(
            &mut file,
            resume_offset,
            &mut hasher,
            "reading local prefix for hash",
        )?;
        file.seek(SeekFrom::Start(resume_offset))
            .with_context(|| format!("seeking to {resume_offset}"))?;
    }

    let bar = make_bar(total_size, "download");
    bar.set_position(resume_offset);

    let mut body = match encoding {
        Encoding::Identity => DownloadBody::Identity { received: 0, size },
        Encoding::Zstd => DownloadBody::Zstd {
            decoder: ZstdDecoder::new(plaintext_size.min(MAX_FILE_SIZE))
                .context("initializing zstd decoder")?,
        },
        Encoding::Unknown(_) => unreachable!("unsupported encodings are rejected above"),
    };
    let mut trailer = Vec::<u8>::new();
    let mut tmp = [0u8; FILE_CHUNK_SIZE];
    let mut recv_buf = [0u8; 65535];

    let want_trailer = if checksum_follows { 32 } else { 0 };
    let mut stream_finished = false;

    // Drain whatever recv_message already read past the FileReady
    // response frame. For small files the entire body + trailer is
    // sitting in `carryover` before we ever hit stream_recv.
    if !carryover.is_empty() {
        accept_download_bytes(
            &mut body,
            &carryover,
            &mut file,
            &mut hasher,
            &mut trailer,
            &bar,
            resume_offset,
        )?;
        carryover.clear();
    }

    // When the entire body + trailer rode in on `carryover`, the loop
    // below never runs, so it never confirms the stream actually FIN'd.
    // Do one *best-effort, non-blocking* drain here to observe the FIN
    // before trusting the length-complete carryover. This must not
    // block: for a small file the FIN was usually already consumed --
    // and the stream evicted -- by the `recv_message` inside
    // `poll_response_with_buf`, leaving only a flushed ACK and a
    // `conn.timeout()` of the multi-second idle timer, so a `poll.poll`
    // here would stall every tiny download. If the FIN simply hasn't
    // been delivered yet we proceed without erroring: the whole-file
    // BLAKE3 trailer check is the real backstop -- a truncated body that
    // merely happens to match the length targets cannot also match the
    // whole-file hash.
    if body.is_complete() && trailer.len() >= want_trailer && !stream_finished {
        handle_ingress(session.conn, session.socket, &mut recv_buf)?;
        match session.conn.stream_recv(stream_id, &mut tmp) {
            Ok((len, fin)) => {
                // Any bytes past the announced body + trailer are
                // appended just as the main loop does (the trailer check
                // reads only the first 32 bytes); we only care about the
                // FIN here.
                if len > 0 {
                    accept_download_bytes(
                        &mut body,
                        &tmp[..len],
                        &mut file,
                        &mut hasher,
                        &mut trailer,
                        &bar,
                        resume_offset,
                    )?;
                }
                if fin {
                    stream_finished = true;
                }
            }
            Err(quiche::Error::Done) => {}
            Err(quiche::Error::InvalidStreamState(_)) => stream_finished = true,
            Err(e) => bail!("stream_recv: {e}"),
        }
        flush_egress(session.conn, session.socket)?;
        if !stream_finished {
            tracing::debug!(
                "carryover satisfied body + trailer lengths but FIN not yet \
                 observed; relying on trailer hash verification"
            );
        }
    }

    while !body.is_complete() || trailer.len() < want_trailer {
        // Three-step pump: always drain the socket and stream first,
        // and only block in poll.poll when both came up empty. The
        // previous "poll first" arrangement would sleep on the QUIC
        // idle timer when the last few packets had already been
        // delivered to quiche by an earlier ingress call (e.g. the
        // one in `poll_response_with_buf`); the response was sitting
        // on the stream and the kernel UDP buffer was empty, so
        // epoll had no edge event to fire.
        handle_ingress(session.conn, session.socket, &mut recv_buf)?;

        let mut drained_any = false;
        loop {
            match session.conn.stream_recv(stream_id, &mut tmp) {
                Ok((len, fin)) => {
                    drained_any = true;
                    if len > 0 {
                        accept_download_bytes(
                            &mut body,
                            &tmp[..len],
                            &mut file,
                            &mut hasher,
                            &mut trailer,
                            &bar,
                            resume_offset,
                        )?;
                    }
                    if fin {
                        stream_finished = true;
                    }
                }
                Err(quiche::Error::Done) => break,
                // Quiche evicts a stream from its tracker as soon as it
                // marks the stream complete -- which happens the moment
                // we read the FIN byte. Any subsequent stream_recv
                // returns InvalidStreamState instead of Done. Treat
                // that as a graceful end-of-stream: if we have all the
                // expected body + trailer bytes the outer loop will
                // exit normally; if we don't, the post-loop check
                // surfaces "server closed stream early".
                Err(quiche::Error::InvalidStreamState(_)) => {
                    stream_finished = true;
                    break;
                }
                Err(e) => bail!("stream_recv: {e}"),
            }
        }
        flush_egress(session.conn, session.socket)?;

        // If the server FIN'd the stream early without delivering the
        // full body + trailer, don't sit and spin waiting for bytes
        // that will never come.
        if stream_finished && (!body.is_complete() || trailer.len() < want_trailer) {
            let _ = std::fs::remove_file(local);
            bail!(
                "server closed stream early: got {}/{} body bytes and {}/{} trailer bytes",
                body.plaintext_received(),
                logical_size,
                trailer.len(),
                want_trailer
            );
        }

        if session.conn.is_closed() && (!body.is_complete() || trailer.len() < want_trailer) {
            bail!("connection closed during download");
        }

        // If neither the socket nor the stream had anything ready,
        // sleep until the next event or the quiche timer fires.
        if !drained_any {
            session.poll.poll(
                session.events,
                session.conn.timeout().or(Some(Duration::from_millis(100))),
            )?;
            session.conn.on_timeout();
        }
    }

    if let DownloadBody::Zstd { decoder } = &body {
        decoder.finish().context("zstd frame did not complete")?;
        if decoder.decoded_len() != plaintext_size {
            let _ = std::fs::remove_file(local);
            bail!(
                "zstd plaintext size mismatch: decoded {} bytes, expected {}",
                decoder.decoded_len(),
                plaintext_size
            );
        }
    }

    if let Err(e) = file.flush() {
        // Bail rather than report "verified" -- the in-memory BLAKE3
        // covers the bytes we wrote, not the bytes that reached disk.
        // We deliberately do NOT remove the partial here: a resumed
        // download whose final flush failed still has a useful
        // prefix on disk, and the next attempt will either resume
        // (and the existing checksum-mismatch handler below tears
        // down a genuinely corrupt partial) or start fresh from
        // offset 0 anyway. Removing the partial here would force a
        // full re-transfer of a multi-GiB file after a transient
        // flush error.
        bail!("final flush of download file failed: {e}");
    }
    bar.finish_and_clear();

    if checksum_follows {
        let trailer_arr: [u8; 32] = trailer[..32]
            .try_into()
            .context("server trailer was not 32 bytes")?;
        let local_hash = *hasher.finalize().as_bytes();
        if local_hash != trailer_arr {
            // Tear down the corrupted local file rather than leave a
            // confusing half-bad artifact behind.
            let _ = std::fs::remove_file(local);
            bail!(
                "BLAKE3 checksum mismatch after download (expected {} bytes, hash didn't match)",
                logical_size
            );
        }
    }

    println!(
        "Downloaded {} bytes to {} ({}verified)",
        logical_size,
        local.display(),
        if checksum_follows { "" } else { "un" }
    );
    crate::stats::record_download(logical_size);
    Ok(())
}

/// Upload `local` to `remote`. Sends a BLAKE3 checksum the server can
/// verify against the received bytes. Resume from an existing
/// server-side temp at `offset` is supported by passing it through.
/// `no_clobber` asks the server to refuse the Put with
/// `AlreadyExists` rather than overwrite a pre-existing destination.
pub fn do_put(
    session: &mut Session,
    stream_id: u64,
    local: &Path,
    remote: &str,
    offset: u64,
    no_clobber: bool,
) -> Result<()> {
    // Parent span for the whole upload.
    let _span = tracing::info_span!("transfer", op = "put", stream_id, path = %remote).entered();
    let mut result = do_put_inner(session, stream_id, local, remote, offset, no_clobber, true);
    if result
        .as_ref()
        .is_err_and(|e| e.is::<UnsupportedEncoding>())
    {
        let stream_id = session.take_stream();
        result = do_put_inner(session, stream_id, local, remote, offset, no_clobber, false);
    }
    if let Err(e) = &result {
        // A `StalePartial` error is a retry signal for the caller, not
        // an actual transfer failure -- the caller re-uploads from
        // scratch. Skip `record_failure` so a resumed upload with a
        // stale server-side partial doesn't log a spurious failure in
        // the user-facing stats.
        if !e.is::<StalePartial>() {
            crate::stats::record_failure();
        }
    }
    result
}

fn do_put_inner(
    session: &mut Session,
    stream_id: u64,
    local: &Path,
    remote: &str,
    offset: u64,
    no_clobber: bool,
    compression_enabled: bool,
) -> Result<()> {
    let meta =
        std::fs::metadata(local).with_context(|| format!("stat {} for upload", local.display()))?;
    let size = meta.len();

    // The resume offset was probed against an earlier `metadata()`
    // snapshot; if the local file shrank since then, fall back to a
    // fresh upload rather than failing the transfer.
    let offset = if offset > size { 0 } else { offset };

    // Streaming BLAKE3: hash incrementally as we read+send,
    // then ship the 32-byte digest as an in-band trailer after the
    // body. Saves the upfront full-file read+hash pass.
    let mut hasher = blake3::Hasher::new();

    let bytes_to_send = size - offset;
    let mode = unix_mode(&meta);
    // Compress a fresh upload only when: the caller still allows it (the
    // `Unsupported` retry sets this false), the process-wide `--no-compress`
    // is off, the body clears a small floor where compression can't pay,
    // and the local file isn't already a compressed/media format. Resumes
    // (`offset > 0`) stay Identity (compressed resume is not yet wired).
    let encoding = if compression_enabled
        && !compression_disabled()
        && offset == 0
        && bytes_to_send >= 1024
        && !is_likely_incompressible(local)
    {
        Encoding::Zstd
    } else {
        Encoding::Identity
    };

    let req = Request::Put {
        path: remote.to_string(),
        size: bytes_to_send,
        mode,
        offset,
        hash_algorithm: qftp_common::protocol::HashAlgorithm::Blake3,
        // checksum_trailer below carries the verification path; leave
        // the legacy header field empty so the server ignores it.
        checksum: None,
        no_clobber,
        checksum_trailer: true,
        encoding,
        plaintext_size: if encoding == Encoding::Zstd {
            bytes_to_send
        } else {
            0
        },
    };
    send_message(session.conn, stream_id, &req)?;
    flush_egress(session.conn, session.socket)?;

    let mut f = File::open(local).context("opening local for send")?;
    // For resume (offset > 0), the server reconstructed BLAKE3 over the
    // existing prefix already; the client has to hash the prefix too so
    // the trailer covers the same byte range. Read once for hashing
    // only, then seek to `offset` for the actual send.
    if offset > 0 {
        hash_prefix(
            &mut f,
            offset,
            &mut hasher,
            "reading local resume prefix for hash",
        )?;
        // f is now positioned at offset, which is where the send loop
        // wants to start.
    }

    let bar = make_bar(size, "upload");
    bar.set_position(offset);

    let mut sent: u64 = 0;
    let mut buf = vec![0u8; UPLOAD_CHUNK];
    let mut pacer = Pacer::new();
    let mut recv_buf = [0u8; 65535];
    let mut encoder = if encoding == Encoding::Zstd {
        Some(ZstdEncoder::new().context("initializing zstd encoder")?)
    } else {
        None
    };
    while sent < bytes_to_send {
        let want = (bytes_to_send - sent) as usize;
        let want = want.min(buf.len());
        f.read_exact(&mut buf[..want])
            .context("reading local chunk")?;
        // Hash before send -- the buffer is already in cache from
        // read_exact, so this pass is essentially free.
        hasher.update(&buf[..want]);

        // Bandwidth throttle (`--bwlimit`). `consume` returns the
        // delay needed to stay under the limit (ZERO when unlimited or
        // within burst). We must NOT block in one long sleep here: the
        // QUIC connection would go unserviced and its idle timer could
        // expire mid-`put`. Instead spend the delay in short slices,
        // servicing the connection between each so keepalive/ACK
        // traffic keeps flowing.
        let wait = pacer.consume(want);
        if !wait.is_zero() {
            let deadline = std::time::Instant::now() + wait;
            while std::time::Instant::now() < deadline {
                handle_ingress(session.conn, session.socket, &mut recv_buf)?;
                flush_egress(session.conn, session.socket)?;
                session.conn.on_timeout();
                if session.conn.is_closed() {
                    bail!("connection closed during bandwidth-limit wait");
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                // Cap each slice so QUIC is serviced often, but never
                // sleep past the next quiche timer or the deadline.
                let slice = remaining
                    .min(Duration::from_millis(50))
                    .min(session.conn.timeout().unwrap_or(Duration::from_millis(50)));
                if !slice.is_zero() {
                    std::thread::sleep(slice);
                }
            }
        }

        if let Some(encoder) = encoder.as_mut() {
            encoder
                .push(&buf[..want])
                .context("compressing upload chunk")?;
            drain_zstd_encoder_to_wire(session, stream_id, encoder, &mut recv_buf)?;
        } else {
            send_upload_bytes(session, stream_id, &buf[..want], false, &mut recv_buf)?;
        }
        flush_egress(session.conn, session.socket)?;

        sent += want as u64;
        bar.set_position(offset + sent);

        // Non-blocking ingress drain so ACKs keep cwnd opening, but
        // do NOT block in poll.poll here: back-pressure is already
        // handled by the inner `Done -> poll.poll` path, and a
        // mandatory per-chunk poll capped loopback put at ~65 MiB/s
        // by sleeping on `conn.timeout()` between chunks even
        // when send capacity was fine.
        handle_ingress(session.conn, session.socket, &mut recv_buf)?;
        flush_egress(session.conn, session.socket)?;
    }
    if let Some(encoder) = encoder.as_mut() {
        encoder.finish().context("finalizing zstd upload frame")?;
        drain_zstd_encoder_to_wire(session, stream_id, encoder, &mut recv_buf)?;
    }

    // Body fully queued. Push the 32-byte BLAKE3 trailer with FIN.
    let trailer = *hasher.finalize().as_bytes();
    send_upload_bytes(session, stream_id, &trailer, true, &mut recv_buf)?;
    flush_egress(session.conn, session.socket)?;

    bar.finish_and_clear();

    let resp = session.poll_response(stream_id)?;
    match resp {
        Response::Ok => {
            println!("Uploaded {bytes_to_send} bytes to {remote} (verified)");
            crate::stats::record_upload(bytes_to_send);
            Ok(())
        }
        Response::Err(e) => {
            if is_stale_partial(offset, e.code) {
                // The resumed upload was refused because the server-side
                // partial is stale; signal the caller to retry the
                // whole upload from scratch.
                return Err(anyhow::Error::new(StalePartial));
            }
            if encoding == Encoding::Zstd && e.code == ErrorCode::Unsupported {
                return Err(anyhow::Error::new(UnsupportedEncoding));
            }
            bail!("server refused Put: {} ({:?})", e.message, e.code)
        }
        other => bail!("unexpected response to Put: {other:?}"),
    }
}

fn drain_zstd_encoder_to_wire(
    session: &mut Session,
    stream_id: u64,
    encoder: &mut ZstdEncoder,
    recv_buf: &mut [u8; 65535],
) -> Result<()> {
    while !encoder.pending().is_empty() {
        let n = send_upload_bytes(session, stream_id, encoder.pending(), false, recv_buf)?;
        encoder.consume(n);
    }
    Ok(())
}

fn send_upload_bytes(
    session: &mut Session,
    stream_id: u64,
    bytes: &[u8],
    fin: bool,
    recv_buf: &mut [u8; 65535],
) -> Result<usize> {
    let mut sent = 0usize;
    while sent < bytes.len() {
        match session.conn.stream_send(stream_id, &bytes[sent..], fin) {
            Ok(0) | Err(quiche::Error::Done) => {
                flush_egress(session.conn, session.socket)?;
                session.poll.poll(
                    session.events,
                    session.conn.timeout().or(Some(Duration::from_millis(20))),
                )?;
                session.conn.on_timeout();
                handle_ingress(session.conn, session.socket, recv_buf)?;
                if session.conn.is_closed() {
                    bail!("connection closed during upload");
                }
            }
            Ok(n) => sent += n,
            Err(e) => bail!("stream_send failed: {e}"),
        }
    }
    Ok(sent)
}

/// Error returned by [`do_put`] when a *resumed* upload (`offset > 0`)
/// was refused because the server-side partial is stale -- either its
/// bytes no longer match the local file (`ChecksumMismatch`) or it has
/// vanished / changed length (`InvalidRange`). The caller should retry
/// the upload from `offset = 0`.
#[derive(Debug)]
pub struct StalePartial;

impl std::fmt::Display for StalePartial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server-side partial upload is stale; retry from scratch")
    }
}

impl std::error::Error for StalePartial {}

/// Retry signal when a server refuses the zstd upload path.
#[derive(Debug)]
struct UnsupportedEncoding;

impl std::fmt::Display for UnsupportedEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server does not support compressed upload; retrying identity")
    }
}

impl std::error::Error for UnsupportedEncoding {}

/// True when a refused resumed upload should be retried from scratch.
/// The server-side partial is stale: its bytes mismatch the local file
/// (`ChecksumMismatch`), or it vanished / changed length so the resume
/// offset no longer lines up (`InvalidRange`). A non-resume upload
/// (`offset == 0`) is never stale -- there is no partial to retry past.
fn is_stale_partial(offset: u64, code: ErrorCode) -> bool {
    offset > 0 && matches!(code, ErrorCode::ChecksumMismatch | ErrorCode::InvalidRange)
}

/// Probe the server for a resumable partial upload of `remote`.
///
/// An interrupted upload leaves a deterministically named
/// `<remote>.qftp.partial` temp on the server (see the native server's
/// `temp_path_for`). A `Stat` on that path reports how many bytes
/// already landed, which is the offset a resume continues from.
/// Returns `0` — a fresh upload — for any of: no partial, a partial
/// that is empty or larger than the local file, or a probe error. An
/// older server (whose partials carried a random suffix) simply
/// answers `NotFound`, so this degrades cleanly to a fresh upload.
///
/// IMPORTANT: this only checks the partial's *length*, never its
/// *contents*. If the local file's `[0..offset)` prefix was rewritten
/// since the interrupted upload (same or larger total size), the offset
/// returned here points past bytes that no longer match. We deliberately
/// do not re-hash the prefix here -- the partial may be on a remote we
/// can't cheaply read back. The correctness backstop is the trailer
/// check in `do_put`: the client folds its (current) local prefix into
/// the whole-file BLAKE3, the server reconstructs its hash from the
/// stale partial, the two disagree, the server returns
/// `ChecksumMismatch`, and `is_stale_partial` retries the whole upload
/// from `offset == 0`. So a mismatched prefix costs one wasted partial
/// transfer + a full re-send, never silent corruption.
pub fn probe_put_resume_offset(session: &mut Session, remote: &str, local_size: u64) -> u64 {
    // Use the single source of truth `qftp_protocol::stream::temp_path_for`
    // so a future change to the partial naming scheme (suffix, layout)
    // can't drift between the server's commit path and this client probe.
    let partial = qftp_protocol::stream::temp_path_for(std::path::Path::new(remote));
    let req = Request::Stat {
        path: partial.to_string_lossy().into_owned(),
    };
    match session.request_response(&req) {
        Ok(Response::FileStat(s)) if !s.is_dir() => acceptable_resume_offset(s.size, local_size),
        _ => 0,
    }
}

/// Decide the resume offset from a server-reported partial size.
/// A partial is only usable when it is non-empty and no larger than the
/// local file (`0 < partial_size <= local_size`); anything else means a
/// fresh upload (`0`). Length-only, by design -- see
/// [`probe_put_resume_offset`] for why prefix contents aren't checked.
fn acceptable_resume_offset(partial_size: u64, local_size: u64) -> u64 {
    if partial_size > 0 && partial_size <= local_size {
        partial_size
    } else {
        0
    }
}

#[cfg(unix)]
fn unix_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}
#[cfg(not(unix))]
fn unix_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bw_limit_handles_suffixes() {
        assert_eq!(parse_bw_limit("0").unwrap(), 0);
        assert_eq!(parse_bw_limit("100").unwrap(), 100);
        assert_eq!(parse_bw_limit("5K").unwrap(), 5_000);
        assert_eq!(parse_bw_limit("5M").unwrap(), 5_000_000);
        assert_eq!(parse_bw_limit("1G").unwrap(), 1_000_000_000);
        assert_eq!(parse_bw_limit("1Ki").unwrap(), 1024);
        assert_eq!(parse_bw_limit("1Mi").unwrap(), 1024 * 1024);
        assert_eq!(parse_bw_limit("1Gi").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_bw_limit("1.5M").unwrap(), 1_500_000);
    }

    #[test]
    fn parse_bw_limit_rejects_garbage() {
        assert!(parse_bw_limit("").is_err());
        assert!(parse_bw_limit("abc").is_err());
        assert!(parse_bw_limit("-5M").is_err());
    }

    #[test]
    fn pacer_zero_rate_is_noop() {
        // `with_rate` bypasses the shared `BW_LIMIT_BPS` static, so this
        // test can't race a concurrently-running pacer test that sets a
        // throttle on the global.
        let mut p = Pacer::with_rate(0);
        // Unlimited: any size consumes instantly with no required wait.
        assert_eq!(p.consume(1 << 30), Duration::ZERO);
    }

    #[test]
    fn pacer_new_reads_global_rate() {
        // `new()` must keep reading the process-wide `--bwlimit`. This is
        // race-free even under parallel test execution because, now that
        // the throttle tests use `Pacer::with_rate`, this is the only
        // remaining test that touches `BW_LIMIT_BPS` -- nothing else can
        // leak a non-zero rate in between the store and the load.
        BW_LIMIT_BPS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut unlimited = Pacer::new();
        assert_eq!(unlimited.consume(1 << 30), Duration::ZERO);
    }

    #[test]
    fn pacer_throttles_to_rate() {
        // 1 MB/s; the bucket holds 1s of burst. `consume` no longer
        // blocks -- it returns the Duration the caller must wait.
        // `with_rate` keeps this off the shared static entirely.
        let mut p = Pacer::with_rate(1_000_000);
        // 1 MB inside the burst window -> no wait required.
        let first = p.consume(1_000_000);
        // 200 KB more, bucket now empty -> ~200 ms wait required.
        let second = p.consume(200_000);
        assert_eq!(
            first,
            Duration::ZERO,
            "first consume should require no wait, got {first:?}"
        );
        // Some slack for timing jitter (>=150 ms, <=600 ms).
        assert!(
            second >= Duration::from_millis(150),
            "second consume should require a wait >=150ms, got {second:?}"
        );
        assert!(
            second <= Duration::from_millis(600),
            "second consume wait should not exceed 600ms, got {second:?}"
        );
    }

    #[test]
    fn stale_partial_only_for_resumed_uploads() {
        // A resumed upload (offset > 0) refused for a stale-partial
        // reason -- mismatching bytes, or a vanished / wrong-length
        // partial -- should retry the whole upload from scratch.
        assert!(is_stale_partial(100, ErrorCode::ChecksumMismatch));
        assert!(is_stale_partial(100, ErrorCode::InvalidRange));
        // A fresh upload (offset == 0) has no partial to retry past,
        // and an unrelated error is a real failure either way.
        assert!(!is_stale_partial(0, ErrorCode::ChecksumMismatch));
        assert!(!is_stale_partial(0, ErrorCode::InvalidRange));
        assert!(!is_stale_partial(100, ErrorCode::NotFound));
        assert!(!is_stale_partial(100, ErrorCode::PermissionDenied));
    }

    #[test]
    fn resume_offset_accepts_only_in_range_partials() {
        // A non-empty partial no larger than the local file resumes from
        // its length.
        assert_eq!(acceptable_resume_offset(100, 1000), 100);
        // Same-size partial: a full prior upload -- still a valid resume
        // offset by length. (Whether its *contents* still match is not
        // checked here; the do_put trailer verification + StalePartial
        // retry covers a rewritten prefix. See probe_put_resume_offset.)
        assert_eq!(acceptable_resume_offset(1000, 1000), 1000);
        // Empty partial -> nothing to resume past -> fresh upload.
        assert_eq!(acceptable_resume_offset(0, 1000), 0);
        // Partial larger than the local file (local shrank, or a stale
        // partial from a different file) -> fresh upload, never an
        // offset past the end of what we have to send.
        assert_eq!(acceptable_resume_offset(1001, 1000), 0);
        assert_eq!(acceptable_resume_offset(2000, 1000), 0);
        // Zero-length local file accepts no resume.
        assert_eq!(acceptable_resume_offset(0, 0), 0);
        assert_eq!(acceptable_resume_offset(50, 0), 0);
    }
}
