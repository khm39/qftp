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
use mio::{Events, Poll};
use qftp_common::protocol::*;
use qftp_common::transport::*;

use crate::proto::{poll_response, poll_response_with_buf};

const CHUNK: usize = 64 * 1024;

/// Outer-loop buffer for the upload body. Sized much larger than the
/// generic `CHUNK` so a 64 MiB put runs the outer event-loop step ~64
/// times instead of ~1024: each extra trip costs a `read_exact`,
/// stream_send call, ingress drain, and flush_egress, and at small
/// chunk sizes the fixed overhead — not flow-control — was capping
/// loopback put at ~65 MiB/s. quiche handles partial accepts
/// via the inner stream_send loop, so a larger buffer is purely a
/// win when cwnd is open and degrades gracefully when it isn't.
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
        let rate = BW_LIMIT_BPS.load(std::sync::atomic::Ordering::Relaxed) as f64;
        Self {
            last: std::time::Instant::now(),
            tokens: rate,
            rate,
            burst: rate.max(64.0 * 1024.0),
        }
    }

    /// Block until `bytes` tokens are available. No-op when the
    /// limit is 0 (unlimited).
    pub fn consume(&mut self, bytes: usize) {
        if self.rate <= 0.0 {
            return;
        }
        // Refill.
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;

        if (bytes as f64) <= self.tokens {
            self.tokens -= bytes as f64;
            return;
        }
        let need = bytes as f64 - self.tokens;
        let sleep = std::time::Duration::from_secs_f64(need / self.rate);
        std::thread::sleep(sleep);
        // Treat the sleep as having drained the deficit; new
        // `last` accounts for it on the next refill.
        self.last = std::time::Instant::now();
        self.tokens = 0.0;
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
    let (num_end, mult) = parse_suffix(bytes)
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

fn parse_suffix(bytes: &[u8]) -> Option<(usize, u64)> {
    // Walk back from the end to find the digit/suffix boundary.
    let mut end = bytes.len();
    while end > 0 && !bytes[end - 1].is_ascii_digit() && bytes[end - 1] != b'.' {
        end -= 1;
    }
    let suffix = std::str::from_utf8(&bytes[end..]).unwrap_or("");
    let mult: u64 = match suffix {
        "" => 1,
        "K" | "k" => 1_000,
        "M" | "m" => 1_000_000,
        "G" | "g" => 1_000_000_000,
        "Ki" | "ki" => 1024,
        "Mi" | "mi" => 1024 * 1024,
        "Gi" | "gi" => 1024 * 1024 * 1024,
        // An unrecognized suffix is a user typo, not a 1-byte unit.
        _ => return None,
    };
    Some((end, mult))
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

/// Download `remote` to `local`. If `local` already exists, resume from
/// its current length. Verifies the server-supplied BLAKE3 trailer once
/// the body is fully received and refuses to keep the file on mismatch.
pub fn do_get(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
    remote: &str,
    local: &Path,
) -> Result<()> {
    // Parent span for the whole download so structured logs
    // group the FileReady / chunk / verify events under a single
    // (op=get, stream_id=N, path=...) header.
    let _span = tracing::info_span!("transfer", op = "get", stream_id, path = %remote).entered();
    let result = do_get_inner(conn, socket, poll, events, stream_id, remote, local);
    if result.is_err() {
        crate::stats::record_failure();
    }
    result
}

fn do_get_inner(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
    remote: &str,
    local: &Path,
) -> Result<()> {
    let resume_offset = match std::fs::metadata(local) {
        Ok(m) if m.is_file() => m.len(),
        _ => 0,
    };

    let req = Request::Get {
        path: remote.to_string(),
        offset: resume_offset,
        length: None,
    };
    send_message(conn, stream_id, &req)?;
    stream_send_all(conn, stream_id, &[], true)?;
    flush_egress(conn, socket)?;

    // The FileReady response and the first chunk of body bytes can be
    // pulled off the stream together; capture whatever recv_message
    // drained past the response frame so the body-read loop below can
    // consume it before going back to stream_recv. For tiny files the
    // entire body + trailer + FIN often arrives in the same ingress.
    let mut carryover: Vec<u8> = Vec::new();
    let resp = poll_response_with_buf(conn, socket, poll, events, stream_id, &mut carryover)?;
    let (size, total_size, checksum_follows) = match resp {
        Response::FileReady {
            size,
            total_size,
            checksum_follows,
        } => (size, total_size, checksum_follows),
        Response::Err(e) => {
            bail!("server refused Get: {} ({:?})", e.message, e.code);
        }
        other => bail!("unexpected response to Get: {other:?}"),
    };

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

    // When resuming, the server's BLAKE3 trailer is computed
    // over the whole file (server side has no resume concept on its
    // hashing path). Feed the existing on-disk prefix into the hasher
    // before we start consuming network bytes so the trailer check
    // covers prefix tampering as well as new-byte tampering. Without
    // this, an attacker who modified the partial file would land a
    // passing checksum on a corrupt result.
    let mut hasher = blake3::Hasher::new();
    if resume_offset > 0 {
        // Hash the prefix straight from the O_NOFOLLOW handle we'll
        // write through: a second open-by-path would cost an extra
        // syscall and reopen without the symlink guard.
        let mut buf = [0u8; CHUNK];
        let mut left = resume_offset;
        while left > 0 {
            let want = (left as usize).min(buf.len());
            let n = file
                .read(&mut buf[..want])
                .with_context(|| format!("read resume prefix from {}", local.display()))?;
            if n == 0 {
                bail!(
                    "partial file shorter than advertised offset {resume_offset}; \
                     remove it and retry (#116)"
                );
            }
            hasher.update(&buf[..n]);
            left -= n as u64;
        }
        file.seek(SeekFrom::Start(resume_offset))
            .with_context(|| format!("seeking to {resume_offset}"))?;
    }

    let bar = make_bar(total_size, "download");
    bar.set_position(resume_offset);

    let mut received: u64 = 0;
    let mut trailer = Vec::<u8>::new();
    let mut tmp = [0u8; CHUNK];
    let mut recv_buf = [0u8; 65535];

    let want_trailer = if checksum_follows { 32 } else { 0 };
    let mut stream_finished = false;

    // Drain whatever recv_message already read past the FileReady
    // response frame. For small files the entire body + trailer is
    // sitting in `carryover` before we ever hit stream_recv.
    if !carryover.is_empty() {
        let body_room = (size - received) as usize;
        let body_take = body_room.min(carryover.len());
        if body_take > 0 {
            file.write_all(&carryover[..body_take])
                .context("writing body chunk from carryover")?;
            hasher.update(&carryover[..body_take]);
            received += body_take as u64;
            bar.set_position(resume_offset + received);
        }
        if body_take < carryover.len() {
            trailer.extend_from_slice(&carryover[body_take..]);
        }
        carryover.clear();
    }

    while received < size || trailer.len() < want_trailer {
        // Three-step pump: always drain the socket and stream first,
        // and only block in poll.poll when both came up empty. The
        // previous "poll first" arrangement would sleep on the QUIC
        // idle timer when the last few packets had already been
        // delivered to quiche by an earlier ingress call (e.g. the
        // one in `poll_response_with_buf`); the response was sitting
        // on the stream and the kernel UDP buffer was empty, so
        // epoll had no edge event to fire.
        handle_ingress(conn, socket, &mut recv_buf)?;

        let mut drained_any = false;
        loop {
            match conn.stream_recv(stream_id, &mut tmp) {
                Ok((len, fin)) => {
                    drained_any = true;
                    if received < size {
                        let body_room = (size - received) as usize;
                        let body_take = body_room.min(len);
                        file.write_all(&tmp[..body_take])
                            .context("writing body chunk")?;
                        hasher.update(&tmp[..body_take]);
                        received += body_take as u64;
                        bar.set_position(resume_offset + received);
                        if body_take < len {
                            // overflow into trailer bytes
                            trailer.extend_from_slice(&tmp[body_take..len]);
                        }
                    } else {
                        trailer.extend_from_slice(&tmp[..len]);
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
        flush_egress(conn, socket)?;

        // If the server FIN'd the stream early without delivering the
        // full body + trailer, don't sit and spin waiting for bytes
        // that will never come.
        if stream_finished && (received < size || trailer.len() < want_trailer) {
            let _ = std::fs::remove_file(local);
            bail!(
                "server closed stream early: got {}/{} body bytes and {}/{} trailer bytes",
                received,
                size,
                trailer.len(),
                want_trailer
            );
        }

        if conn.is_closed() && (received < size || trailer.len() < want_trailer) {
            bail!("connection closed during download");
        }

        // If neither the socket nor the stream had anything ready,
        // sleep until the next event or the quiche timer fires.
        if !drained_any {
            poll.poll(events, conn.timeout().or(Some(Duration::from_millis(100))))?;
            conn.on_timeout();
        }
    }

    file.flush().ok();
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
                size
            );
        }
    }

    println!(
        "Downloaded {} bytes to {} ({}verified)",
        size,
        local.display(),
        if checksum_follows { "" } else { "un" }
    );
    crate::stats::record_download(size);
    Ok(())
}

/// Upload `local` to `remote`. Sends a BLAKE3 checksum the server can
/// verify against the received bytes. Resume from an existing
/// server-side temp at `offset` is supported by passing it through.
/// `no_clobber` asks the server to refuse the Put with
/// `AlreadyExists` rather than overwrite a pre-existing destination.
#[allow(clippy::too_many_arguments)]
pub fn do_put(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
    local: &Path,
    remote: &str,
    offset: u64,
    no_clobber: bool,
) -> Result<()> {
    // Parent span for the whole upload.
    let _span = tracing::info_span!("transfer", op = "put", stream_id, path = %remote).entered();
    let result = do_put_inner(
        conn, socket, poll, events, stream_id, local, remote, offset, no_clobber,
    );
    if result.is_err() {
        crate::stats::record_failure();
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn do_put_inner(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
    local: &Path,
    remote: &str,
    offset: u64,
    no_clobber: bool,
) -> Result<()> {
    let meta =
        std::fs::metadata(local).with_context(|| format!("stat {} for upload", local.display()))?;
    let size = meta.len();

    if offset > size {
        bail!("resume offset {offset} is past local file size {size}; refusing");
    }

    // Streaming BLAKE3: hash incrementally as we read+send,
    // then ship the 32-byte digest as an in-band trailer after the
    // body. Saves the upfront full-file read+hash pass.
    let mut hasher = blake3::Hasher::new();

    let bytes_to_send = size - offset;
    let mode = unix_mode(&meta);

    let req = Request::Put {
        path: remote.to_string(),
        size: bytes_to_send,
        mode,
        offset,
        // checksum_trailer below carries the verification path; leave
        // the legacy header field empty so the server ignores it.
        checksum: None,
        no_clobber,
        checksum_trailer: true,
    };
    send_message(conn, stream_id, &req)?;
    flush_egress(conn, socket)?;

    let mut f = File::open(local).context("opening local for send")?;
    // For resume (offset > 0), the server reconstructed BLAKE3 over the
    // existing prefix already; the client has to hash the prefix too so
    // the trailer covers the same byte range. Read once for hashing
    // only, then seek to `offset` for the actual send.
    if offset > 0 {
        let mut prefix_buf = [0u8; CHUNK];
        let mut left = offset;
        while left > 0 {
            let want = (left as usize).min(prefix_buf.len());
            f.read_exact(&mut prefix_buf[..want])
                .context("reading local resume prefix for hash")?;
            hasher.update(&prefix_buf[..want]);
            left -= want as u64;
        }
        // f is now positioned at offset, which is where the send loop
        // wants to start.
    }

    let bar = make_bar(size, "upload");
    bar.set_position(offset);

    let mut sent: u64 = 0;
    let mut buf = vec![0u8; UPLOAD_CHUNK];
    let mut pacer = Pacer::new();
    let mut recv_buf = [0u8; 65535];
    while sent < bytes_to_send {
        let want = (bytes_to_send - sent) as usize;
        let want = want.min(buf.len());
        f.read_exact(&mut buf[..want])
            .context("reading local chunk")?;
        // Hash before send -- the buffer is already in cache from
        // read_exact, so this pass is essentially free.
        hasher.update(&buf[..want]);

        // Bandwidth throttle (`--bwlimit`). No-op when unlimited.
        pacer.consume(want);

        // Drive a single chunk to the wire. quiche's stream_send will
        // truncate or refuse the write when the connection's send
        // capacity (flow-control + congestion window) is exhausted —
        // in both cases we have to flush egress and pull ACKs in
        // before the rest of the chunk can be queued. Propagating
        // `Error::Done` here instead would fail any upload that
        // didn't fit in the initial cwnd (~14 KiB).
        //
        // The trailer carries the FIN; never set chunk_fin on
        // body bytes.
        let mut sub = 0usize;
        while sub < want {
            let remaining = &buf[sub..want];
            match conn.stream_send(stream_id, remaining, false) {
                Ok(0) | Err(quiche::Error::Done) => {
                    flush_egress(conn, socket)?;
                    poll.poll(events, conn.timeout().or(Some(Duration::from_millis(20))))?;
                    conn.on_timeout();
                    handle_ingress(conn, socket, &mut recv_buf)?;
                    if conn.is_closed() {
                        bail!("connection closed during upload");
                    }
                }
                Ok(n) => sub += n,
                Err(e) => bail!("stream_send failed: {e}"),
            }
        }
        flush_egress(conn, socket)?;

        sent += want as u64;
        bar.set_position(offset + sent);

        // Non-blocking ingress drain so ACKs keep cwnd opening, but
        // do NOT block in poll.poll here: back-pressure is already
        // handled by the inner `Done -> poll.poll` path, and a
        // mandatory per-chunk poll capped loopback put at ~65 MiB/s
        // by sleeping on `conn.timeout()` between chunks even
        // when send capacity was fine.
        handle_ingress(conn, socket, &mut recv_buf)?;
        flush_egress(conn, socket)?;
    }

    // Body fully queued. Push the 32-byte BLAKE3 trailer with FIN.
    let trailer = *hasher.finalize().as_bytes();
    let mut sub = 0usize;
    while sub < trailer.len() {
        // The trailer is the last data on the stream, so every write
        // carries FIN; quiche keeps it pending across partial writes.
        match conn.stream_send(stream_id, &trailer[sub..], true) {
            Ok(0) | Err(quiche::Error::Done) => {
                flush_egress(conn, socket)?;
                poll.poll(events, conn.timeout().or(Some(Duration::from_millis(20))))?;
                conn.on_timeout();
                handle_ingress(conn, socket, &mut recv_buf)?;
                if conn.is_closed() {
                    bail!("connection closed during trailer send");
                }
            }
            Ok(n) => sub += n,
            Err(e) => bail!("stream_send (trailer) failed: {e}"),
        }
    }
    flush_egress(conn, socket)?;

    bar.finish_and_clear();

    let resp = poll_response(conn, socket, poll, events, stream_id)?;
    match resp {
        Response::Ok => {
            println!("Uploaded {bytes_to_send} bytes to {remote} (verified)");
            crate::stats::record_upload(bytes_to_send);
            Ok(())
        }
        Response::Err(e) => bail!("server refused Put: {} ({:?})", e.message, e.code),
        other => bail!("unexpected response to Put: {other:?}"),
    }
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
pub fn probe_put_resume_offset(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    remote: &str,
    local_size: u64,
) -> u64 {
    let req = Request::Stat {
        path: format!("{remote}.qftp.partial"),
    };
    match crate::proto::request_response(conn, socket, poll, events, next_stream_id, &req) {
        Ok(Response::FileStat(s)) if !s.is_dir && s.size > 0 && s.size <= local_size => s.size,
        _ => 0,
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
        BW_LIMIT_BPS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut p = Pacer::new();
        let t = std::time::Instant::now();
        p.consume(1 << 30);
        assert!(t.elapsed() < std::time::Duration::from_millis(10));
    }

    #[test]
    fn pacer_throttles_to_rate() {
        // 1 MB/s; send 2 MB; expect roughly 2 seconds. We test a
        // smaller window so the suite stays fast.
        BW_LIMIT_BPS.store(1_000_000, std::sync::atomic::Ordering::Relaxed);
        let mut p = Pacer::new();
        let t = std::time::Instant::now();
        // 1 MB inside the burst window -> immediate.
        p.consume(1_000_000);
        let after_first = t.elapsed();
        // 200 KB more -> should require ~200 ms wait.
        p.consume(200_000);
        let after_second = t.elapsed();
        assert!(
            after_first < std::time::Duration::from_millis(50),
            "first consume should be instant, took {after_first:?}"
        );
        // Some slack for CI jitter (>=150 ms, <=600 ms).
        assert!(
            after_second >= std::time::Duration::from_millis(150),
            "second consume should have slept >=150ms, took {after_second:?}"
        );
        assert!(
            after_second <= std::time::Duration::from_millis(600),
            "second consume should not exceed 600ms, took {after_second:?}"
        );
        // Reset for the next test.
        BW_LIMIT_BPS.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}
