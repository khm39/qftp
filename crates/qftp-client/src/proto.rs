//! Shared client-side protocol pump.
//!
//! Stream-id allocation and the request/response round-trip used by the
//! REPL, one-shot, and bulk-transfer paths. Centralising it keeps the
//! "drain before you block" behaviour and the `validate_response`
//! defense-in-depth check in a single place.

use std::time::Duration;

use anyhow::Result;
use mio::{Events, Poll};
use qftp_common::protocol::{validate_response, Request, Response};
use qftp_common::transport::{
    flush_egress, handle_ingress, recv_message, send_message, stream_send_all,
};

/// Allocate the next client-initiated bidirectional stream id. QUIC
/// numbers them 0, 4, 8, ... so each call bumps the cursor by 4.
pub fn take_stream(next: &mut u64) -> u64 {
    let cur = *next;
    *next += 4;
    cur
}

/// The QUIC pump handles (`conn`, `socket`, `poll`, `events`) plus the
/// client stream-id cursor, bundled so transfer and orchestration code
/// passes a single `&mut Session` instead of the same five handles. The
/// transfer-specific arguments (`stream_id`, `local`, `remote`, ...)
/// stay as explicit parameters on each call.
pub struct Session<'a> {
    pub conn: &'a mut quiche::Connection,
    pub socket: &'a mio::net::UdpSocket,
    pub poll: &'a mut Poll,
    pub events: &'a mut Events,
    pub next_stream_id: &'a mut u64,
}

impl Session<'_> {
    /// Allocate the next client-initiated bidirectional stream id.
    pub fn take_stream(&mut self) -> u64 {
        take_stream(self.next_stream_id)
    }

    /// Block until a complete `Response` frame arrives on `stream_id`.
    pub fn poll_response(&mut self, stream_id: u64) -> Result<Response> {
        poll_response(self.conn, self.socket, self.poll, self.events, stream_id)
    }

    /// Like [`Session::poll_response`] but the caller owns the
    /// accumulation buffer, so any bytes drained past the response
    /// frame survive in `buf`.
    pub fn poll_response_with_buf(
        &mut self,
        stream_id: u64,
        buf: &mut Vec<u8>,
    ) -> Result<Response> {
        poll_response_with_buf(
            self.conn,
            self.socket,
            self.poll,
            self.events,
            stream_id,
            buf,
        )
    }

    /// Send `req` on a fresh stream and block for its single `Response`.
    pub fn request_response(&mut self, req: &Request) -> Result<Response> {
        request_response(
            self.conn,
            self.socket,
            self.poll,
            self.events,
            self.next_stream_id,
            req,
        )
    }
}

/// Block until a complete `Response` frame arrives on `stream_id`.
pub fn poll_response(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
) -> Result<Response> {
    let mut buf = Vec::new();
    poll_response_with_buf(conn, socket, poll, events, stream_id, &mut buf)
}

/// Same as [`poll_response`] but the caller owns the accumulation
/// buffer, so any bytes `recv_message` drained past the response frame
/// (e.g. the first chunk of a Get body) survive in `buf` for the caller
/// to consume.
pub fn poll_response_with_buf(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
    buf: &mut Vec<u8>,
) -> Result<Response> {
    let mut recv_buf = [0u8; 65535];
    loop {
        // Drain whatever quiche already buffered before blocking in
        // poll.poll: the response often lands during an earlier ingress
        // pump, leaving epoll with no edge event left to fire.
        if let Some(resp) = recv_message::<Response>(conn, stream_id, buf)? {
            // Per-field cap defense in depth against a malicious server
            // packing oversized strings / listings into a single field.
            validate_response(&resp)
                .map_err(|e| anyhow::anyhow!("server sent invalid response: {e}"))?;
            flush_egress(conn, socket)?;
            return Ok(resp);
        }
        if conn.is_closed() {
            anyhow::bail!("connection closed");
        }
        poll.poll(events, conn.timeout().or(Some(Duration::from_millis(100))))?;
        conn.on_timeout();
        handle_ingress(conn, socket, &mut recv_buf)?;
        flush_egress(conn, socket)?;
    }
}

/// Send `req` on a fresh stream and block for its single `Response`.
pub fn request_response(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    req: &Request,
) -> Result<Response> {
    let stream_id = take_stream(next_stream_id);
    send_message(conn, stream_id, req)?;
    stream_send_all(conn, stream_id, &[], true)?;
    flush_egress(conn, socket)?;
    poll_response(conn, socket, poll, events, stream_id)
}

/// Join a remote directory prefix with a relative path. Backslashes in
/// `rel` are normalized to `/` so Windows clients still produce POSIX
/// remote paths; a `prefix` of `/` or empty roots the result at `/`.
pub fn join_remote(prefix: &str, rel: &std::path::Path) -> String {
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    if prefix.is_empty() || prefix == "/" {
        format!("/{rel_str}")
    } else if prefix.ends_with('/') {
        format!("{prefix}{rel_str}")
    } else {
        format!("{prefix}/{rel_str}")
    }
}

#[cfg(test)]
mod tests {
    use super::join_remote;
    use std::path::Path;

    #[test]
    fn join_remote_root() {
        assert_eq!(join_remote("/", Path::new("a/b.txt")), "/a/b.txt");
        assert_eq!(join_remote("", Path::new("a/b.txt")), "/a/b.txt");
    }

    #[test]
    fn join_remote_prefix() {
        assert_eq!(join_remote("/dst", Path::new("a/b.txt")), "/dst/a/b.txt");
        assert_eq!(join_remote("/dst/", Path::new("a/b.txt")), "/dst/a/b.txt");
    }
}
