//! Transport-independent core of the qftp protocol.
//!
//! This crate holds the request-handling logic that does not depend on
//! any particular QUIC implementation: path resolution, per-user ACLs,
//! the user directory, and the per-stream state machine. `qftp-server`
//! drives it over `quiche`; a future WebTransport bridge can drive the
//! same logic over a different transport without forking it.

pub mod handler;
pub mod stream;
pub mod user;
