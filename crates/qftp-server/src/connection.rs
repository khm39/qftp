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
    ReadingFileData {
        final_path: PathBuf,
        temp_path: PathBuf,
        writer: BufWriter<File>,
        remaining: u64,
        mode: u32,
        completed: bool,
    },
    /// Streaming a file to the peer (Get). Driven from the main loop on
    /// every iteration so a single big transfer can't monopolize CPU at
    /// the cost of other connections.
    SendingFileData {
        reader: std::io::BufReader<File>,
        total_size: u64,
        sent: u64,
        /// True once we've successfully called stream_send with fin=true
        /// for the last byte. We keep the entry around for one more sweep
        /// so the main loop sees completion.
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
            ..
        } = self
        {
            if !*completed {
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
