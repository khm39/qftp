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
