//! Per-stream transfer state.
//!
//! The state machine for a single logical transfer (a request, an
//! upload, or a download) is independent of the QUIC implementation
//! carrying the bytes. `qftp-server` keeps one of these per QUIC
//! stream; the transport layer only feeds it bytes and drains bytes
//! from it.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::user::User;

/// Compute the deterministic `.qftp.partial` temp path for a final
/// destination. Both the native server and the WebTransport bridge use
/// this so a resumed upload from the native client always finds the
/// same partial regardless of which transport committed the previous
/// session. Sibling-of-target keeps the temp on the same filesystem so
/// the final `rename` is atomic; the trailing `.qftp.partial` suffix
/// gives the swept-stale-partials code a single grep target.
pub fn temp_path_for(final_path: &Path) -> PathBuf {
    let mut name = final_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".qftp.partial");
    final_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

#[cfg(test)]
mod temp_path_tests {
    use super::temp_path_for;
    use std::path::Path;

    #[test]
    fn sibling_of_target() {
        let target = Path::new("/srv/data/report.bin");
        let temp = temp_path_for(target);
        assert_eq!(temp.parent(), target.parent());
        let name = temp.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "report.bin.qftp.partial");
    }

    #[test]
    fn deterministic() {
        let a = temp_path_for(Path::new("/x/y.dat"));
        let b = temp_path_for(Path::new("/x/y.dat"));
        assert_eq!(a, b);
    }

    #[test]
    fn handles_relative_path_with_no_parent() {
        // `Path::new("loose.bin").parent()` returns Some(""), not None,
        // so the `unwrap_or_else(|| ".")` does not fire and the result
        // is just the filename without a "./" prefix.
        let target = Path::new("loose.bin");
        let temp = temp_path_for(target);
        assert_eq!(temp, Path::new("loose.bin.qftp.partial"));
    }
}

/// Apply a client-requested file mode after a Put commit, stripping the
/// suid/sgid/sticky bits first.
///
/// Letting clients land `04xxx` / `02xxx` / `01xxx` on files inside the
/// served tree supplies a setuid primitive to any downstream process
/// that later copies it (rsync `--preserve-permissions`, nightly
/// backups, indexers running as root, ...). Operators who genuinely need
/// special bits should set them out of band.
///
/// Failures are logged at `warn!` and swallowed: the rename already
/// committed the file, so bubbling an error would either orphan it at
/// `final_path` with the temp's mode or block the upload from being
/// reported complete. Both transports (the native server's poll loop and
/// the WebTransport bridge's commit `spawn_blocking`) call this so the
/// suid-stripping policy lives in one place.
#[cfg(unix)]
pub fn apply_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode & 0o0777);
    if let Err(e) = std::fs::set_permissions(path, perms) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "apply_mode: set_permissions failed; file kept its current mode",
        );
    }
}

#[cfg(not(unix))]
pub fn apply_mode(_path: &Path, _mode: u32) {}

/// Maximum file size accepted by Get/Put.
pub const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Chunk size used for streaming file reads and Put receive buffers.
pub const FILE_CHUNK_SIZE: usize = 64 * 1024;

/// Chunk size used for the Get send path. Larger than `FILE_CHUNK_SIZE`
/// so each main-loop iteration hands the transport a bigger batch and
/// the outer per-stream loop runs fewer times per transfer. The buffer
/// is heap-allocated once in the server's `run()` and reused, so the
/// size does not add stack or per-iteration zeroing cost.
pub const SEND_CHUNK_SIZE: usize = 256 * 1024;

/// Incremental buffer for the streaming BLAKE3 trailer that arrives
/// after a Put body. The trailer is always exactly 32 bytes;
/// this holds whatever subset we've drained off the stream so
/// far so `drive_put` can finalize verification once `filled == 32`.
///
/// Fields are private so the `filled <= 32` invariant `extend` relies on
/// to avoid out-of-bounds indexing can't be violated from outside the
/// crate.
#[derive(Debug)]
pub struct TrailerBuf {
    bytes: [u8; 32],
    filled: u8,
}

impl TrailerBuf {
    pub fn new() -> Self {
        Self {
            bytes: [0u8; 32],
            filled: 0,
        }
    }

    pub fn remaining(&self) -> usize {
        32 - self.filled as usize
    }

    pub fn is_full(&self) -> bool {
        self.filled == 32
    }

    /// The 32-byte trailer payload. Callers should check
    /// [`Self::is_full`] first: when `filled < 32` the suffix of the
    /// returned array is zero (the initial value), not part of the
    /// real trailer.
    pub fn as_array(&self) -> [u8; 32] {
        self.bytes
    }

    /// Append `src` to the buffer, returning the number of bytes
    /// consumed (capped at 32 total).
    pub fn extend(&mut self, src: &[u8]) -> usize {
        let want = self.remaining().min(src.len());
        let start = self.filled as usize;
        self.bytes[start..start + want].copy_from_slice(&src[..want]);
        self.filled += want as u8;
        want
    }
}

impl Default for TrailerBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a Put chunk was rejected. Mirrors the `ErrorCode` the drivers
/// emit, but kept transport-agnostic so the pure classifier in this
/// crate doesn't depend on the wire `ErrorCode` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOverflow {
    /// Bytes past the declared body arrived but the client did not opt
    /// into the streaming checksum trailer.
    BodyExceeded,
    /// Bytes past the declared body + 32-byte trailer arrived.
    TrailerExceeded,
}

/// How a single received Put chunk should be split between the file
/// body and the streaming-checksum trailer. The pure policy is shared
/// by the native server (`start_put`/`drive_put`) and the WebTransport
/// bridge (`route_put_chunk`) so the "what counts as body vs. trailer
/// vs. overflow" rule has a single source of truth (#269). The drivers
/// own the actual I/O (writing `to_body` bytes, extending the trailer
/// buffer); this function only decides the split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutChunkSplit {
    /// Number of leading chunk bytes that belong to the file body.
    pub to_body: usize,
    /// Number of bytes after the body that belong to the trailer.
    /// Always 0 when `overflow` is set.
    pub to_trailer: usize,
}

/// Decide how `chunk_len` received bytes split across the remaining
/// body and (optionally) the streaming checksum trailer.
///
/// * `body_remaining`: declared body bytes not yet received.
/// * `checksum_trailer`: whether the client opted into the 32-byte
///   streaming BLAKE3 trailer after the body.
/// * `trailer_remaining`: trailer bytes the buffer can still accept
///   (`TrailerBuf::remaining()`); ignored when `checksum_trailer` is
///   false.
///
/// Returns `Ok(split)` describing how many bytes go to the body and how
/// many to the trailer, or `Err(PutOverflow)` when the chunk carries
/// more than body (+ trailer) can hold.
pub fn classify_put_chunk(
    chunk_len: usize,
    body_remaining: u64,
    checksum_trailer: bool,
    trailer_remaining: usize,
) -> Result<PutChunkSplit, PutOverflow> {
    let to_body = (chunk_len as u64).min(body_remaining) as usize;
    let after_body = chunk_len - to_body;
    if after_body == 0 {
        return Ok(PutChunkSplit {
            to_body,
            to_trailer: 0,
        });
    }
    if !checksum_trailer {
        return Err(PutOverflow::BodyExceeded);
    }
    if after_body > trailer_remaining {
        return Err(PutOverflow::TrailerExceeded);
    }
    Ok(PutChunkSplit {
        to_body,
        to_trailer: after_body,
    })
}

/// Determine the checksum a completed Put must verify against, applying
/// the precedence rule shared by both transports: a fully-received
/// streaming trailer overrides the legacy header checksum (#269). The
/// `header_checksum` is used only when no complete trailer is present.
pub fn resolve_put_checksum(
    checksum_trailer: bool,
    trailer: &TrailerBuf,
    header_checksum: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    if checksum_trailer && trailer.is_full() {
        Some(trailer.as_array())
    } else {
        header_checksum
    }
}

/// Incremental re-hash of a resumed upload's on-disk prefix.
///
/// A resume continues an existing `.qftp.partial`; the server must feed
/// that prefix through BLAKE3 before the new body bytes so the trailer
/// check still covers the whole file. Doing it in one synchronous pass
/// would block the event loop for the length of the prefix (up to
/// `MAX_FILE_SIZE`), so the prefix is hashed a slice at a time, driven
/// from the main loop. `remaining` counts bytes still to read.
pub struct ResumeRehash {
    pub reader: BufReader<File>,
    pub remaining: u64,
    /// Body bytes that arrived in the same read as the Put request.
    /// They must be hashed *after* the prefix, so they are held here
    /// until the re-hash finishes rather than hashed on arrival.
    pub pending_body: Vec<u8>,
}

/// RAII claim on an upload destination path.
///
/// The `.qftp.partial` temp name is deterministic, so two concurrent
/// Puts to the same destination would otherwise open and interleave
/// their writes into one file -- and since each side's BLAKE3 is
/// computed over the bytes *it* sent (not the file content), the loser
/// could even commit a corrupt file that passed verification.
/// `start_put` takes a claim before accepting a Put; while it is held,
/// a second Put to the same path is refused. The claim lives inside
/// `ReadingFileData`, so it is released whenever the stream ends --
/// commit, abort, or error.
pub struct UploadClaim {
    owner: Arc<User>,
    path: PathBuf,
}

/// Lock a user's `active_uploads`, recovering from a poisoned mutex.
/// The set only tracks in-flight destination paths; a thread that
/// panicked while holding it leaves the set itself consistent, so
/// recovering the guard is correct rather than propagating the panic.
fn lock_uploads(
    user: &User,
) -> std::sync::MutexGuard<'_, std::collections::HashSet<PathBuf>> {
    user.active_uploads
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

impl UploadClaim {
    /// Claim `path` for `user`. Returns `None` when another upload to
    /// the same path is already in progress.
    pub fn try_claim(user: Arc<User>, path: PathBuf) -> Option<UploadClaim> {
        let claimed = lock_uploads(&user).insert(path.clone());
        claimed.then(|| UploadClaim { owner: user, path })
    }
}

impl Drop for UploadClaim {
    fn drop(&mut self) {
        lock_uploads(&self.owner).remove(&self.path);
    }
}

/// Per-stream state on the server side.
///
/// The `Drop` impl on `ReadingFileData` is what guarantees we never leak
/// `.qftp.partial.*` files when an upload aborts mid-flight.
pub enum StreamState {
    /// Reading a protocol request from the stream.
    ReadingRequest { buf: Vec<u8> },
    /// Receiving file bytes (Put) and streaming them straight to disk.
    /// `hasher` accumulates BLAKE3 over the received bytes; on the last
    /// byte we compare it to the client's declared `expected_checksum`,
    /// if any.
    ReadingFileData {
        final_path: PathBuf,
        temp_path: PathBuf,
        writer: BufWriter<File>,
        remaining: u64,
        mode: u32,
        completed: bool,
        hasher: blake3::Hasher,
        expected_checksum: Option<[u8; 32]>,
        /// When set, the client will send a 32-byte BLAKE3 trailer on
        /// the same stream after the body bytes. We accumulate
        /// it here as bytes arrive; once full it overrides
        /// `expected_checksum` in the verification step. `None` means
        /// the request used the legacy header-checksum path.
        trailer_buf: Option<TrailerBuf>,
        /// Bytes reserved against `user.in_flight_bytes` when
        /// the Put was accepted. The Drop impl releases them on
        /// abort; the commit path consumes them and converts the
        /// reservation into `used_bytes`.
        reserved_bytes: u64,
        /// Bytes already on disk and already counted in `used_bytes`
        /// when this stream started -- i.e. the resume `offset` (0 for
        /// a fresh upload). On a checksum mismatch the partial is
        /// deleted, so the mismatch path must refund these from
        /// `used_bytes` or they leak against the user's quota.
        prior_bytes: u64,
        /// `Some` while a resumed upload's existing prefix is still
        /// being re-hashed (see [`ResumeRehash`]); `None` for a fresh
        /// upload or once the prefix is fully hashed. Body bytes are
        /// not consumed until this is `None`.
        rehash: Option<ResumeRehash>,
        /// RAII claim on the destination path; refuses a second
        /// concurrent Put to the same path. Released when this state
        /// drops (commit, abort, or error). Held purely for its
        /// `Drop`, never read.
        #[allow(dead_code)]
        claim: UploadClaim,
        /// Back-reference to the user whose counters we mutate. We
        /// can't share the connection's Arc<User> directly here
        /// because the StreamState is stored inside the connection;
        /// this is a separate clone so Drop has stable access to
        /// the atomics regardless of when the connection itself is
        /// torn down.
        owner: Arc<User>,
    },
    /// Streaming a file to the peer (Get). Driven from the main loop on
    /// every iteration so a single big transfer can't monopolize CPU at
    /// the cost of other connections. `hasher` accumulates BLAKE3 over
    /// the whole file (including the [0..offset) prefix re-read for a
    /// resumed Get); when the body is complete we emit a 32-byte
    /// trailer with the finalized hash + FIN.
    SendingFileData {
        reader: std::io::BufReader<File>,
        total_size: u64,
        sent: u64,
        hasher: blake3::Hasher,
        /// After body is fully sent, the 32-byte checksum trailer is
        /// queued onto the stream. `trailer_offset` advances as bytes
        /// of the trailer are accepted by the transport.
        trailer: Option<[u8; 32]>,
        trailer_offset: usize,
        finished: bool,
        /// Bytes of the [0..offset) prefix still to be re-read into
        /// `hasher` before any body bytes are streamed. For a resumed
        /// Get (`offset > 0`) the server must produce a whole-file
        /// BLAKE3 in its trailer so the client can verify its local
        /// prefix; this counter drives that re-hash incrementally. `0`
        /// for a fresh Get.
        prefix_remaining: u64,
    },
    /// Terminal state. The retain() sweep removes streams in this state.
    Done,
}

impl Drop for StreamState {
    fn drop(&mut self) {
        // An aborted upload leaves its `.qftp.partial` temp on disk on
        // purpose: a later session resumes it by sending an `offset`.
        // To keep that from becoming a quota bypass, the bytes already
        // written this session are moved out of the in-flight
        // reservation and into `used_bytes`, so they keep counting
        // against the user's quota until the partial is either resumed
        // (the resume's commit accounts for the whole file) or
        // truncated by a fresh Put to the same path (which refunds
        // them — see `server::start_put`).
        //
        // This runs on every abort path — explicit StreamState::Done
        // replacement, connection drop, or panic unwind.
        if let StreamState::ReadingFileData {
            completed,
            remaining,
            reserved_bytes,
            writer,
            temp_path,
            owner,
            ..
        } = self
        {
            if !*completed {
                owner
                    .in_flight_bytes
                    .fetch_sub(*reserved_bytes, Ordering::Relaxed);
                // Flush the buffered writer so the bytes we charge below
                // are actually on disk for a later resume. Then charge
                // the *logical* bytes received this session
                // (`reserved_bytes - remaining`) rather than re-`stat`ing
                // the file.
                //
                // Drop runs on the server's single event-loop thread
                // (a connection-reap can drop a `ReadingFileData`), so a
                // synchronous `fs::metadata()` on slow/hung storage would
                // stall every other connection (HOL blocking, #268). On
                // a successful flush the logical count equals the
                // on-disk size minus `prior_bytes` exactly; on a flush
                // failure it can over-charge by at most one BufWriter
                // capacity, which is the safe direction for quota
                // defense. `prior_bytes` (the resume prefix already in
                // `used_bytes`) is excluded by construction since
                // `reserved_bytes`/`remaining` only count this session's
                // body.
                if let Err(e) = writer.flush() {
                    tracing::warn!(
                        path = %temp_path.display(),
                        error = %e,
                        "StreamState::drop: flush of aborted upload buffer failed; \
                         quota will be charged the logical byte count, which may \
                         over-count un-flushed bytes",
                    );
                }
                let written = reserved_bytes.saturating_sub(*remaining);
                if written > 0 {
                    owner.used_bytes.fetch_add(written, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::{Permissions, User};
    use std::sync::atomic::AtomicU64;

    fn test_user() -> Arc<User> {
        Arc::new(User {
            name: "t".to_string(),
            home: PathBuf::from("/tmp"),
            permissions: Permissions::full(),
            quota_bytes: Some(1_000_000),
            used_bytes: AtomicU64::new(0),
            in_flight_bytes: AtomicU64::new(0),
            active_uploads: std::sync::Mutex::new(std::collections::HashSet::new()),
        })
    }

    fn reading_state(
        user: Arc<User>,
        temp: PathBuf,
        reserved: u64,
        remaining: u64,
        completed: bool,
    ) -> StreamState {
        let mut f = File::create(&temp).unwrap();
        // Put `reserved - remaining` bytes on disk so the Drop impl's
        // metadata-based accounting sees what the test simulates as
        // "received this session".
        let received = reserved.saturating_sub(remaining);
        f.write_all(&vec![0u8; received as usize]).unwrap();
        let claim = UploadClaim::try_claim(Arc::clone(&user), temp.clone()).unwrap();
        StreamState::ReadingFileData {
            final_path: temp.with_extension("final"),
            temp_path: temp,
            writer: BufWriter::new(f),
            remaining,
            mode: 0o644,
            completed,
            hasher: blake3::Hasher::new(),
            expected_checksum: None,
            trailer_buf: None,
            reserved_bytes: reserved,
            prior_bytes: 0,
            rehash: None,
            claim,
            owner: user,
        }
    }

    #[test]
    fn abort_moves_written_bytes_into_used() {
        // An interrupted upload must not silently drop the bytes it
        // already wrote: they stay charged against the user's quota
        // (in `used_bytes`) so an abort loop can't bypass the limit.
        let dir = tempfile::tempdir().unwrap();
        let user = test_user();
        user.in_flight_bytes.fetch_add(1000, Ordering::Relaxed);
        // Declared 1000 new bytes, 600 received (remaining 400), abort.
        let state = reading_state(Arc::clone(&user), dir.path().join("f"), 1000, 400, false);
        drop(state);
        assert_eq!(user.in_flight_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(user.used_bytes.load(Ordering::Relaxed), 600);
    }

    #[test]
    fn abort_before_any_bytes_only_releases_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let user = test_user();
        user.in_flight_bytes.fetch_add(1000, Ordering::Relaxed);
        let state = reading_state(Arc::clone(&user), dir.path().join("f"), 1000, 1000, false);
        drop(state);
        assert_eq!(user.in_flight_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(user.used_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn classify_all_body_when_within_remaining() {
        // chunk fully fits in the body; nothing for the trailer.
        let s = classify_put_chunk(10, 100, false, 0).unwrap();
        assert_eq!(s.to_body, 10);
        assert_eq!(s.to_trailer, 0);
    }

    #[test]
    fn classify_overflow_without_trailer() {
        // 5 bytes past the body and no trailer opted in -> overflow.
        let e = classify_put_chunk(10, 5, false, 0).unwrap_err();
        assert_eq!(e, PutOverflow::BodyExceeded);
    }

    #[test]
    fn classify_body_then_trailer_split() {
        // 4 body + 32 trailer in one chunk, trailer mode on.
        let s = classify_put_chunk(36, 4, true, 32).unwrap();
        assert_eq!(s.to_body, 4);
        assert_eq!(s.to_trailer, 32);
    }

    #[test]
    fn classify_trailer_overflow() {
        // body done (0 remaining), 33 trailer bytes but only 32 fit.
        let e = classify_put_chunk(33, 0, true, 32).unwrap_err();
        assert_eq!(e, PutOverflow::TrailerExceeded);
    }

    #[test]
    fn classify_partial_trailer_fits() {
        // 16 trailer bytes when 32 remain: accepted, no overflow.
        let s = classify_put_chunk(16, 0, true, 32).unwrap();
        assert_eq!(s.to_body, 0);
        assert_eq!(s.to_trailer, 16);
    }

    #[test]
    fn resolve_checksum_trailer_overrides_header() {
        let mut tb = TrailerBuf::new();
        tb.extend(&[7u8; 32]);
        assert!(tb.is_full());
        let header = Some([1u8; 32]);
        assert_eq!(
            resolve_put_checksum(true, &tb, header),
            Some([7u8; 32]),
            "a complete trailer must override the header checksum"
        );
    }

    #[test]
    fn resolve_checksum_falls_back_to_header() {
        // Incomplete trailer -> header checksum is used.
        let mut tb = TrailerBuf::new();
        tb.extend(&[7u8; 10]);
        assert!(!tb.is_full());
        let header = Some([1u8; 32]);
        assert_eq!(resolve_put_checksum(true, &tb, header), Some([1u8; 32]));
        // No trailer mode at all -> header checksum.
        assert_eq!(
            resolve_put_checksum(false, &TrailerBuf::new(), header),
            header
        );
        // Neither -> None (verification skipped).
        assert_eq!(resolve_put_checksum(false, &TrailerBuf::new(), None), None);
    }

    #[test]
    fn abort_charges_logical_bytes_without_stat() {
        // #268: Drop must not synchronously `stat` the partial on the
        // event-loop thread. Proven by deleting the temp file *before*
        // Drop runs: a metadata-based accounting would see len 0 (or
        // error) and under-charge, while the logical count
        // (reserved - remaining) still charges the bytes received this
        // session.
        let dir = tempfile::tempdir().unwrap();
        let user = test_user();
        user.in_flight_bytes.fetch_add(1000, Ordering::Relaxed);
        let temp = dir.path().join("f");
        let state = reading_state(Arc::clone(&user), temp.clone(), 1000, 400, false);
        // Remove the on-disk partial so any `fs::metadata` would fail or
        // report 0; the logical path is independent of it.
        std::fs::remove_file(&temp).unwrap();
        drop(state);
        assert_eq!(user.in_flight_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(
            user.used_bytes.load(Ordering::Relaxed),
            600,
            "logical byte count (reserved - remaining) must be charged \
             regardless of the partial's on-disk presence"
        );
    }

    #[test]
    fn completed_upload_drop_is_a_noop() {
        // The commit path already settled the counters; Drop must not
        // touch them again when `completed` is set.
        let dir = tempfile::tempdir().unwrap();
        let user = test_user();
        user.in_flight_bytes.fetch_add(1000, Ordering::Relaxed);
        let state = reading_state(Arc::clone(&user), dir.path().join("f"), 1000, 0, true);
        drop(state);
        assert_eq!(user.in_flight_bytes.load(Ordering::Relaxed), 1000);
        assert_eq!(user.used_bytes.load(Ordering::Relaxed), 0);
    }
}
