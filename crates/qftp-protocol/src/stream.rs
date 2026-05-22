//! Per-stream transfer state.
//!
//! The state machine for a single logical transfer (a request, an
//! upload, or a download) is independent of the QUIC implementation
//! carrying the bytes. `qftp-server` keeps one of these per QUIC
//! stream; the transport layer only feeds it bytes and drains bytes
//! from it.

use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::user::User;

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
#[derive(Debug)]
pub struct TrailerBuf {
    pub bytes: [u8; 32],
    pub filled: u8,
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
    /// the sent bytes; when the body is complete we emit a 32-byte
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
            owner,
            ..
        } = self
        {
            if !*completed {
                let written = reserved_bytes.saturating_sub(*remaining);
                owner
                    .in_flight_bytes
                    .fetch_sub(*reserved_bytes, Ordering::Relaxed);
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
        })
    }

    fn reading_state(
        user: Arc<User>,
        temp: PathBuf,
        reserved: u64,
        remaining: u64,
        completed: bool,
    ) -> StreamState {
        let f = File::create(&temp).unwrap();
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
