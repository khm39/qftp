//! Per-connection server state.
//!
//! Each accepted QUIC connection owns a `ConnectionContext`. It holds the
//! quiche connection itself, the user it authenticated as, that user's
//! current working directory, and a per-stream state machine.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use crate::user::User;

/// Maximum file size accepted by Get/Put.
pub const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Chunk size used for streaming file reads and stream sends.
pub const FILE_CHUNK_SIZE: usize = 64 * 1024;

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
        /// #111: bytes reserved against `user.in_flight_bytes` when
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
        /// of the trailer are accepted by quiche.
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
                // #111: release the in-flight reservation so the
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

/// Everything the server tracks per QUIC connection.
pub struct ConnectionContext {
    pub conn: quiche::Connection,
    pub peer_addr: SocketAddr,
    pub user: Arc<User>,
    /// Current working directory. Always inside `user.home`.
    pub cwd: PathBuf,
    pub streams: HashMap<u64, StreamState>,
    /// When the connection was accepted. Used for soak-test diagnostics.
    #[allow(dead_code)]
    pub created_at: Instant,
}

impl ConnectionContext {
    pub fn new(conn: quiche::Connection, peer_addr: SocketAddr, user: Arc<User>) -> Self {
        let cwd = user.home.clone();
        Self {
            conn,
            peer_addr,
            user,
            cwd,
            streams: HashMap::new(),
            created_at: Instant::now(),
        }
    }
}
