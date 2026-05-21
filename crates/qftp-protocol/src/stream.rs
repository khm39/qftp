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
        if let StreamState::ReadingFileData {
            temp_path,
            completed,
            reserved_bytes,
            owner,
            ..
        } = self
        {
            if !*completed {
                // Release the in-flight reservation so the
                // user's quota can recover. This runs on every abort
                // path — explicit StreamState::Done replacement,
                // connection drop, or panic unwind.
                owner
                    .in_flight_bytes
                    .fetch_sub(*reserved_bytes, Ordering::Relaxed);
                if let Err(e) = std::fs::remove_file(&temp_path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            path = %temp_path.display(),
                            error = %e,
                            "failed to clean up partial upload"
                        );
                    }
                }
            }
        }
    }
}
