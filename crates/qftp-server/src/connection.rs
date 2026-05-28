//! Per-connection server state.
//!
//! Each accepted QUIC connection owns a `ConnectionContext`. It holds the
//! quiche connection itself, the user it authenticated as, that user's
//! current working directory, and a per-stream state machine. The
//! per-stream machine (`StreamState`) lives in `qftp-protocol` because
//! it is transport-independent.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use qftp_common::protocol::Request;
use qftp_protocol::stream::StreamState;
use qftp_protocol::user::User;

/// Everything the server tracks per QUIC connection.
pub struct ConnectionContext {
    pub conn: quiche::Connection,
    pub peer_addr: SocketAddr,
    pub user: Arc<User>,
    /// Current working directory. Always inside `user.home`.
    pub cwd: PathBuf,
    pub streams: HashMap<u64, StreamState>,
    /// When the connection was accepted. Used to reap half-open
    /// connections that never complete their handshake (#266) and for
    /// soak-test diagnostics.
    pub created_at: Instant,
    /// The SCID the server issued for this connection -- the key it is
    /// stored under in the connection table. Held here so an offloaded
    /// handler job can be routed back to this connection (H-1).
    pub scid: quiche::ConnectionId<'static>,
    /// Monotonic generation assigned at accept time. `derive_scid` is
    /// deterministic and (with `require_retry=false`) the client
    /// controls its DCID, so a reaped connection's SCID can be re-derived
    /// for a brand-new connection. A `HandlerResult` carries the
    /// generation of the connection that dispatched it; on apply we
    /// discard it if the live connection's generation differs, so a
    /// delayed response can't be misdelivered to the resurrected SCID
    /// (L-6).
    pub generation: u64,
    /// True while a generic handler request for this connection is
    /// running on a worker thread. Generic requests are processed one
    /// at a time per connection so `cwd` updates from `Cd` stay
    /// correctly ordered (H-1).
    pub handler_in_flight: bool,
    /// Generic handler requests received while `handler_in_flight` was
    /// set. Dispatched FIFO as each in-flight job completes.
    pub pending_handler_jobs: VecDeque<(u64, Request)>,
}

impl ConnectionContext {
    pub fn new(
        conn: quiche::Connection,
        peer_addr: SocketAddr,
        user: Arc<User>,
        scid: quiche::ConnectionId<'static>,
        generation: u64,
    ) -> Self {
        let cwd = user.home.clone();
        Self {
            conn,
            peer_addr,
            user,
            cwd,
            streams: HashMap::new(),
            created_at: Instant::now(),
            scid,
            generation,
            handler_in_flight: false,
            pending_handler_jobs: VecDeque::new(),
        }
    }
}
