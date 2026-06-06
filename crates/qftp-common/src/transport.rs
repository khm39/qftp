use serde::{de::DeserializeOwned, Serialize};

use crate::error::TransportError;

/// Result alias for the structured `qftp-common::transport` API.
type Result<T, E = TransportError> = std::result::Result<T, E>;

pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const STREAM_BUF_SIZE: usize = 65536;
/// Maximum allowed control message size (16 MB). Prevents a malicious peer from
/// sending an enormous length prefix that causes unbounded memory allocation.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// QUIC flow-control window advertised for a single bidirectional
/// stream. Sized to comfortably cover BDP on a gigabit link with
/// ~100ms RTT (~12.5 MB), with headroom so `send_file_streaming`
/// doesn't have to spin-wait on the peer's ACK. The actual user-space
/// buffer is `FILE_CHUNK_SIZE` (64 KiB); this window only bounds
/// quiche's internal bookkeeping and kernel UDP buffers.
pub const INITIAL_MAX_STREAM_DATA: u64 = 16 * 1024 * 1024;

/// Per-connection flow-control window. `initial_max_streams_bidi` is
/// 4, so this is sized as `4 * INITIAL_MAX_STREAM_DATA` -- enough for
/// every concurrent stream to be at its individual cap with no extra
/// slack.
pub const INITIAL_MAX_CONNECTION_DATA: u64 = 4 * INITIAL_MAX_STREAM_DATA;

/// Target size for SO_RCVBUF / SO_SNDBUF on the QUIC sockets, in bytes.
/// Linux's default UDP recv buffer (`net.core.rmem_default`, usually
/// 208 KiB) overflows almost immediately when one side bursts a full
/// file's worth of packets faster than the other side can drain its
/// kernel queue: the result is silent UDP drops, runaway QUIC PTO
/// backoff, and 30s+ stalls in the middle of a transfer. 4 MiB is
/// the standard `net.core.rmem_max` cap on most distros — request
/// it explicitly, accept whatever the kernel grants (the syscall
/// returns success even when the value is clamped), and rely on
/// QUIC's own flow control to keep memory bounded.
const SOCKET_BUF_HINT_BYTES: usize = 4 * 1024 * 1024;

/// Bump the kernel send/receive buffers on a UDP socket. Failures are
/// logged at debug level and otherwise ignored: the OS may cap the
/// value below what we asked for, and on unsupported platforms (e.g.
/// Windows) the helper is a no-op.
#[cfg(unix)]
pub fn tune_udp_buffers(socket: &std::net::UdpSocket) {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let want = SOCKET_BUF_HINT_BYTES as libc::c_int;
    for opt in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &want as *const _ as *const libc::c_void,
                std::mem::size_of_val(&want) as libc::socklen_t,
            )
        };
        if ret != 0 {
            tracing::debug!(
                opt,
                error = ?std::io::Error::last_os_error(),
                "setsockopt failed (will use kernel default)"
            );
        }
    }
}

#[cfg(not(unix))]
pub fn tune_udp_buffers(_socket: &std::net::UdpSocket) {}

/// Maximum number of QUIC datagrams to coalesce into a single
/// `sendmsg(UDP_SEGMENT)` burst. The underlying GSO skb must
/// fit within Linux's per-device `gso_max_size`, which is 65 536
/// bytes on every NIC we've seen (including loopback). At our
/// `MAX_DATAGRAM_SIZE = 1350` that gives a hard ceiling of 48
/// segments before the kernel returns `EMSGSIZE` and our fallback
/// path kicks in; 32 leaves comfortable headroom for slightly
/// larger MTUs (DPLPMTUD pushing us toward 1500) without flipping
/// the GSO-disabled flag.
#[cfg(target_os = "linux")]
const GSO_BURST_PACKETS: usize = 32;

/// Tracks whether UDP_SEGMENT (GSO) is usable on this socket. Starts
/// in "try" state, flips to "off" the first time the kernel rejects a
/// GSO send (older kernels, some virtual NICs). After that we stay on
/// the per-packet fallback for the lifetime of the process.
#[cfg(target_os = "linux")]
static GSO_USABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

// Reusable per-thread scratch for the GSO coalescing path. `flush_egress`
// runs once per connection per event-loop iteration, so allocating this
// buffer per call shows up on the hot path; a thread-local keeps one
// buffer alive for the lifetime of each thread that flushes (the server
// loop, each client, each fanout worker).
#[cfg(target_os = "linux")]
thread_local! {
    static GSO_BUF: std::cell::RefCell<Vec<u8>> =
        std::cell::RefCell::new(vec![0u8; MAX_DATAGRAM_SIZE * GSO_BURST_PACKETS]);
}

/// Static call-site labels for [`TransportError::io_ctx`]. Centralized
/// here so the per-`send_to`/`recv_from` breadcrumbs operators grep for
/// stay in one place. The Linux-only labels are cfg-gated to match the
/// `flush_egress` GSO paths that reference them; the unconditional ones
/// are used on every platform.
mod contexts {
    pub const SEND_PER_PACKET_FALLBACK: &str = "UDP send_to (per-packet fallback)";
    pub const RECV_FROM: &str = "UDP recv_from";

    #[cfg(target_os = "linux")]
    pub const SEND_PATH_SWAP: &str = "UDP send_to (path swap)";
    #[cfg(target_os = "linux")]
    pub const SEND_OVERSIZE: &str = "UDP send_to (oversize)";
    #[cfg(target_os = "linux")]
    pub const SEND_SINGLE: &str = "UDP send_to (single)";
    #[cfg(target_os = "linux")]
    pub const SEND_FALLBACK: &str = "UDP send_to (fallback)";
}

/// Flush pending outgoing packets from the QUIC connection to the UDP
/// socket. On Linux this coalesces up to `GSO_BURST_PACKETS` datagrams
/// into a single `sendmsg(UDP_SEGMENT)`; on other platforms,
/// and after a runtime fallback, it falls back to one `send_to` per
/// datagram. The latter is what quiche's own examples used originally
/// and what every earlier version of `flush_egress` did, so the
/// fallback path is the safe equivalent of the old behavior.
pub fn flush_egress(conn: &mut quiche::Connection, socket: &mio::net::UdpSocket) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        flush_egress_linux(conn, socket)
    }
    #[cfg(not(target_os = "linux"))]
    {
        flush_egress_per_packet(conn, socket)
    }
}

/// Per-packet fallback: one `sendmsg` per QUIC datagram. Used on
/// non-Linux platforms and on Linux when UDP_SEGMENT has been
/// disabled at runtime (`GSO_USABLE = false`).
fn flush_egress_per_packet(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
) -> Result<()> {
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    loop {
        let (write, send_info) = match conn.send(&mut out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => break,
            Err(e) => {
                return Err(TransportError::quic_ctx(
                    "conn.send (per-packet fallback)",
                    e,
                ))
            }
        };

        socket
            .send_to(&out[..write], send_info.to)
            .map_err(|e| TransportError::io_ctx(contexts::SEND_PER_PACKET_FALLBACK, e))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn flush_egress_linux(conn: &mut quiche::Connection, socket: &mio::net::UdpSocket) -> Result<()> {
    use std::sync::atomic::Ordering;

    if !GSO_USABLE.load(Ordering::Relaxed) {
        return flush_egress_per_packet(conn, socket);
    }

    GSO_BUF.with(|cell| flush_egress_gso(conn, socket, cell.borrow_mut().as_mut_slice()))
}

/// Outcome of feeding one freshly-written datagram into an in-progress
/// GSO batch. This is the I/O-independent half of the `flush_egress_gso`
/// state machine, factored out so the batching boundaries — which decide
/// what lands on the wire and where packet boundaries fall — are
/// unit-testable without a `quiche::Connection` or a real socket. The
/// actual `sendmsg`/`send_to` syscalls (and the `GSO_USABLE` fallback)
/// live in [`send_batch`] / [`sendmsg_udp_segment`] and are exercised
/// only on Linux/CI; they are not reachable from a host unit test.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GsoStep {
    /// Append this packet to the open batch; the batch stays open.
    Append,
    /// Append this packet as the final (short-tail) segment, then flush
    /// the batch. A UDP_SEGMENT burst may only have a shorter segment as
    /// its last one.
    AppendThenFlush,
    /// This packet cannot extend the open batch (different destination,
    /// or larger than the committed `seg_size`). Flush the open batch
    /// first (if any), then send this packet on its own.
    FlushThenSendAlone,
}

/// Pure per-packet decision for the GSO coalescing loop. `seg_size` is
/// the segment size committed by the first packet of the open batch
/// (`0` when the batch is empty), `same_dst` is whether the new packet's
/// destination matches the batch's, and `write` is the new packet's
/// length. Mirrors exactly the branch order in [`flush_egress_gso`]:
/// path-swap is checked before the oversize comparison, so a different
/// destination always sends the packet alone regardless of its size.
#[cfg(target_os = "linux")]
fn gso_step(seg_size: usize, same_dst: bool, write: usize) -> GsoStep {
    if seg_size == 0 {
        // First packet of a batch: it establishes `seg_size`, so it is
        // never a path swap or oversize relative to itself.
        return GsoStep::Append;
    }
    if !same_dst || write > seg_size {
        return GsoStep::FlushThenSendAlone;
    }
    if write < seg_size {
        return GsoStep::AppendThenFlush;
    }
    GsoStep::Append
}

/// GSO-coalescing flush loop. `buf` is caller-provided reusable scratch
/// (`GSO_BUF`), at least `MAX_DATAGRAM_SIZE * GSO_BURST_PACKETS` bytes.
#[cfg(target_os = "linux")]
fn flush_egress_gso(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    buf: &mut [u8],
) -> Result<()> {
    'outer: loop {
        let mut total = 0usize;
        let mut seg_size = 0usize;
        let mut dst: Option<std::net::SocketAddr> = None;
        let mut packets = 0usize;

        // Coalesce up to GSO_BURST_PACKETS datagrams. All but the last
        // segment in a UDP_SEGMENT burst must be exactly `seg_size`
        // bytes; the last one may be shorter and ends the batch.
        // Different destinations or a packet that exceeds the
        // established segment size also end the batch.
        for _ in 0..GSO_BURST_PACKETS {
            let cap = MAX_DATAGRAM_SIZE.min(buf.len() - total);
            if cap == 0 {
                break;
            }
            let (write, send_info) = match conn.send(&mut buf[total..total + cap]) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(TransportError::quic_ctx("conn.send (gso)", e)),
            };

            // From here on we only need disjoint subslices of `buf`;
            // no named borrow of `buf` outlives the match arms.

            let same_dst = dst.map(|prev| prev == send_info.to).unwrap_or(true);
            match gso_step(seg_size, same_dst, write) {
                GsoStep::FlushThenSendAlone => {
                    // Path swap or oversize mid-burst: commit what we
                    // have, send the just-written packet on its own,
                    // then restart. `dst` is `Some` here because an
                    // empty batch (`seg_size == 0`) always yields
                    // `Append`.
                    if total > 0 {
                        send_batch(socket, &buf[..total], dst.unwrap(), seg_size, packets)?;
                    }
                    let ctx = if same_dst {
                        contexts::SEND_OVERSIZE
                    } else {
                        contexts::SEND_PATH_SWAP
                    };
                    socket
                        .send_to(&buf[total..total + write], send_info.to)
                        .map_err(|e| TransportError::io_ctx(ctx, e))?;
                    continue 'outer;
                }
                GsoStep::Append => {
                    if seg_size == 0 {
                        dst = Some(send_info.to);
                        seg_size = write;
                    }
                    total += write;
                    packets += 1;
                }
                GsoStep::AppendThenFlush => {
                    total += write;
                    packets += 1;
                    // Short tail: must be the last segment in this burst.
                    break;
                }
            }
        }

        if total == 0 {
            break;
        }

        send_batch(socket, &buf[..total], dst.unwrap(), seg_size, packets)?;
    }

    Ok(())
}

/// Split a coalesced GSO batch of `total` bytes back into the
/// `(offset, len)` ranges of its constituent datagrams, each `seg_size`
/// bytes except a possibly-shorter final segment. This is the inverse
/// of what `sendmsg(UDP_SEGMENT)` does in the kernel and is used to
/// replay a batch per-packet after GSO is disabled mid-flight. Pulled
/// out as a pure function so the offset arithmetic — where an off-by-one
/// would corrupt packet boundaries on the wire — is unit-testable
/// without a socket.
#[cfg(target_os = "linux")]
fn gso_replay_ranges(total: usize, seg_size: usize) -> impl Iterator<Item = (usize, usize)> {
    debug_assert!(seg_size > 0, "seg_size must be non-zero to avoid a stall");
    let mut off = 0usize;
    std::iter::from_fn(move || {
        if off >= total {
            return None;
        }
        let n = seg_size.min(total - off);
        let start = off;
        off += n;
        Some((start, n))
    })
}

/// Send a single batch. Uses `sendmsg(UDP_SEGMENT)` when the batch
/// contains more than one packet; otherwise falls back to `send_to`.
/// Disables GSO for the rest of the process on the first kernel
/// rejection so we don't spam EIO / EINVAL on each subsequent flush.
#[cfg(target_os = "linux")]
fn send_batch(
    socket: &mio::net::UdpSocket,
    buf: &[u8],
    dst: std::net::SocketAddr,
    seg_size: usize,
    packets: usize,
) -> Result<()> {
    if packets <= 1 {
        socket
            .send_to(buf, dst)
            .map_err(|e| TransportError::io_ctx(contexts::SEND_SINGLE, e))?;
        return Ok(());
    }

    match sendmsg_udp_segment(socket, buf, dst, seg_size as u16) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!(
                ?e,
                packets,
                seg_size,
                "UDP_SEGMENT send failed; disabling GSO and falling back to per-packet"
            );
            use std::sync::atomic::Ordering;
            GSO_USABLE.store(false, Ordering::Relaxed);
            // Replay the batch one packet at a time so we don't drop
            // this flight on the floor.
            for (off, n) in gso_replay_ranges(buf.len(), seg_size) {
                socket
                    .send_to(&buf[off..off + n], dst)
                    .map_err(|e| TransportError::io_ctx(contexts::SEND_FALLBACK, e))?;
            }
            Ok(())
        }
    }
}

/// Linux `sendmsg(UDP_SEGMENT)` wrapper. The kernel splits `buf`
/// into back-to-back datagrams of exactly `seg_size` bytes (the last
/// may be shorter). Returns the raw OS error on rejection so the
/// caller can fall back without losing the cause in `tracing`.
#[cfg(target_os = "linux")]
fn sendmsg_udp_segment(
    socket: &mio::net::UdpSocket,
    buf: &[u8],
    dst: std::net::SocketAddr,
    seg_size: u16,
) -> std::io::Result<()> {
    use std::mem::{size_of, MaybeUninit};
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();

    // Stage dst as sockaddr_storage so we can hand a stable pointer to
    // sendmsg without caring about v4/v6 at this layer.
    let mut sa_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let sa_len = match dst {
        std::net::SocketAddr::V4(v4) => {
            let sa = unsafe { &mut *(&mut sa_storage as *mut _ as *mut libc::sockaddr_in) };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            };
            size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        std::net::SocketAddr::V6(v6) => {
            let sa = unsafe { &mut *(&mut sa_storage as *mut _ as *mut libc::sockaddr_in6) };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_flowinfo = v6.flowinfo();
            sa.sin6_scope_id = v6.scope_id();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };

    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Control buffer big enough for one UDP_SEGMENT cmsg.
    let cmsg_space = unsafe { libc::CMSG_SPACE(size_of::<u16>() as u32) } as usize;
    let mut cmsg_buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::zeroed(); cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut sa_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = sa_len;
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<u16>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut u16;
        std::ptr::write_unaligned(data, seg_size);
    }

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read incoming UDP packets from the socket and feed them into the QUIC connection.
pub fn handle_ingress(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    buf: &mut [u8],
) -> Result<()> {
    let local_addr = socket.local_addr()?;

    loop {
        let (len, from) = match socket.recv_from(buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(TransportError::io_ctx(contexts::RECV_FROM, e)),
        };

        let recv_info = quiche::RecvInfo {
            from,
            to: local_addr,
        };

        match conn.recv(&mut buf[..len], recv_info) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = ?e, "QUIC recv error");
            }
        }
    }

    Ok(())
}

/// Serialize a message into a single buffer with a 4-byte BE length
/// prefix. The inverse of [`decode_framed_message`]; transports that
/// don't speak `quiche::Connection` (the WebTransport bridge) frame
/// through this so the wire format stays in one place.
pub fn encode_framed_message<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    // Serialize straight into one length-prefixed buffer: the 4-byte
    // BE prefix up front, then bincode appends the payload after it.
    // Avoids the separate payload Vec + copy the two-step form needs.
    let payload_len = bincode::serialized_size(msg)? as usize;
    if payload_len > MAX_MESSAGE_SIZE {
        return Err(TransportError::FrameTooLarge {
            actual: payload_len,
            max: MAX_MESSAGE_SIZE,
        });
    }
    let mut data = Vec::with_capacity(4 + payload_len);
    data.extend_from_slice(&(payload_len as u32).to_be_bytes());
    bincode::serialize_into(&mut data, msg)?;
    Ok(data)
}

/// Serialize a message and send it on a QUIC stream with a 4-byte BE length prefix.
pub fn send_message<T: Serialize>(
    conn: &mut quiche::Connection,
    stream_id: u64,
    msg: &T,
) -> Result<()> {
    let data = encode_framed_message(msg)?;
    stream_send_all(conn, stream_id, &data, false)?;
    Ok(())
}

/// Send all bytes on a QUIC stream, handling partial writes by retrying.
pub fn stream_send_all(
    conn: &mut quiche::Connection,
    stream_id: u64,
    data: &[u8],
    fin: bool,
) -> Result<()> {
    // Send the body without `fin`. quiche can accept far more than
    // STREAM_BUF_SIZE in a single `stream_send` (bounded only by the
    // flow-control window), so the accepted length is only known after
    // the call -- there is no reliable way to know in advance which
    // write carries the last byte. Always defer the FIN to an explicit
    // empty-fin frame after the loop.
    let mut offset = 0;
    while offset < data.len() {
        let written = conn
            .stream_send(stream_id, &data[offset..], false)
            .map_err(|e| TransportError::quic_ctx("stream_send", e))?;
        offset += written;
        if written == 0 {
            return Err(TransportError::StreamBlocked);
        }
    }
    // Deliver the FIN as a dedicated empty-fin frame once the whole
    // body has been queued. This covers both the empty-`data` case and
    // a non-empty body, and guarantees `fin=true` is never passed to a
    // mid-data `stream_send`.
    if fin {
        conn.stream_send(stream_id, &[], true)
            .map_err(|e| TransportError::quic_ctx("stream_send (fin)", e))?;
    }
    Ok(())
}

/// Try to receive a length-prefixed message from a QUIC stream.
///
/// Data is accumulated in `stream_buf` across calls. Returns `Ok(None)` if
/// not enough data is available yet to decode a complete message.
pub fn recv_message<T: DeserializeOwned>(
    conn: &mut quiche::Connection,
    stream_id: u64,
    stream_buf: &mut Vec<u8>,
) -> Result<Option<T>> {
    // Read any available data from the stream into stream_buf.
    let mut tmp = [0u8; STREAM_BUF_SIZE];
    loop {
        match conn.stream_recv(stream_id, &mut tmp) {
            Ok((len, _fin)) => {
                stream_buf.extend_from_slice(&tmp[..len]);
            }
            Err(quiche::Error::Done) => break,
            // Quiche removes a stream from its tracker the instant
            // the peer's FIN byte is delivered; subsequent reads on
            // the same id return InvalidStreamState instead of Done.
            // Both mean "no more bytes will arrive", so handle them
            // the same way here.
            Err(quiche::Error::InvalidStreamState(_)) => break,
            Err(e) => return Err(TransportError::quic_ctx("stream_recv", e)),
        }
    }

    decode_framed_message(stream_buf)
}

/// Bincode options for the framed control-message decode path. The
/// `with_limit(MAX_MESSAGE_SIZE)` cap is the *total* decode-byte budget
/// for the whole frame (a second line of defense alongside the 4-byte
/// length-prefix cap), **not** a per-field cap: bincode will still
/// allocate a single 16 MiB `String`/`Vec` field within that budget.
/// Per-field upper bounds live in `protocol::validate_request` /
/// `validate_response`, applied after decode. `with_fixint_encoding` +
/// `allow_trailing_bytes` reproduce the historical wire settings. Only
/// the decode path uses these -- `encode_framed_message` deliberately
/// uses bincode's free functions (no decode-side limit at encode time).
fn make_bincode_options() -> impl bincode::Options {
    use bincode::Options as _;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_MESSAGE_SIZE as u64)
}

/// Decode one length-prefixed bincode message from `stream_buf` using
/// the exact same length cap and bincode options the production
/// `recv_message` path applies. On success the consumed prefix +
/// payload bytes are drained from `stream_buf`. Returns `Ok(None)`
/// when the buffer doesn't yet contain a complete frame.
///
/// This is split out from `recv_message` so the fuzz targets
/// in `fuzz/` can drive the same decode path that runs in production.
/// Decoding bincode bytes directly (without the 4-byte prefix and
/// `with_limit(MAX_MESSAGE_SIZE)`) leaves the actual code path
/// uncovered.
pub fn decode_framed_message<T: DeserializeOwned>(stream_buf: &mut Vec<u8>) -> Result<Option<T>> {
    if stream_buf.len() < 4 {
        return Ok(None);
    }

    let msg_len =
        u32::from_be_bytes([stream_buf[0], stream_buf[1], stream_buf[2], stream_buf[3]]) as usize;

    if msg_len > MAX_MESSAGE_SIZE {
        return Err(TransportError::FrameTooLarge {
            actual: msg_len,
            max: MAX_MESSAGE_SIZE,
        });
    }

    if stream_buf.len() < 4 + msg_len {
        return Ok(None);
    }

    // Cap the cumulative read-byte budget at MAX_MESSAGE_SIZE. This
    // is in addition to the 4-byte length-prefix check above; combined
    // with the post-decode `validate_request` / `validate_response`
    // pass (`qftp_common::protocol`), it bounds both wire-size and
    // individual-field sizes against a malicious peer. Note: bincode's
    // `with_limit` is the TOTAL decode-byte budget, not a per-field
    // cap -- bincode will still allocate a single 16 MiB `String`/`Vec`
    // field within that budget, so the per-field defense lives in
    // `validate_*`.
    use bincode::Options as _;
    let msg: T = make_bincode_options().deserialize(&stream_buf[4..4 + msg_len])?;

    // Drain the consumed bytes.
    stream_buf.drain(..4 + msg_len);

    Ok(Some(msg))
}

/// Apply common QUIC transport parameters shared by client and server.
fn apply_common_config(config: &mut quiche::Config, allow_early_data: bool) -> Result<()> {
    config
        .set_application_protos(&[crate::protocol::ALPN])
        .map_err(|e| TransportError::TlsConfig(format!("failed to set ALPN: {e}")))?;

    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    // Phase 1 sends and receives files in chunks (qftp-server's
    // send_file_streaming and drive_put), so peak memory no longer scales
    // with the flow-control window. The per-stream RAM upper bound is the
    // BufReader/BufWriter capacity (64 KiB) -- this window only bounds
    // quiche's internal bookkeeping and kernel UDP buffers. initial_max_streams_bidi
    // stays low because the current client only opens one bidi stream at
    // a time. Previous values were 2 GiB total / 1 GiB per stream,
    // vastly over-sized for the gigabit BDP this protocol actually sees;
    // shrunk so quiche state + UDP buffers don't bloat per peer.
    config.set_initial_max_data(INITIAL_MAX_CONNECTION_DATA);
    config.set_initial_max_stream_data_bidi_local(INITIAL_MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(INITIAL_MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(4);
    config.set_disable_active_migration(true);

    // Pacing is on by default in quiche, which makes `conn.send` return
    // `Done` after one BBR-calculated burst even when many packets are
    // queued. That defeats our `sendmsg(UDP_SEGMENT)` coalescing in
    // `flush_egress` -- we'd land 1-3 packets per batch instead
    // of the 64-packet GSO cap. The protocol does its own back-pressure
    // via QUIC's flow-control window, and the existing congestion
    // controller still gates total in-flight bytes, so disabling the
    // explicit pacer just lets us drain queued packets in one syscall.
    config.enable_pacing(false);

    // 0-RTT resumption. Server-side replay protection is enforced in
    // the per-Request decode path (write ops refused while
    // `is_in_early_data()`). The client side gates this on whether
    // the TLS stack itself verifies the peer cert:
    //   * verify_peer = true: BoringSSL validates the certificate
    //     chain, and the client additionally binds the leaf to the
    //     requested hostname after the handshake (see
    //     qftp-client `connect::cert_matches_hostname`). A MitM lacking
    //     a cert that both chains to a trusted CA *and* names this host
    //     cannot complete the resumed handshake, so 0-RTT bytes stay
    //     confidential.
    //   * verify_peer = false (--insecure or TOFU before pin-binding
    //     lands): an attacker who terminates the connection could
    //     receive the first Request bytes. Skip enable_early_data
    //     to force a 1-RTT handshake; the application-layer TOFU
    //     check then runs before any request bytes leave the host.
    if allow_early_data {
        config.enable_early_data();
    }

    Ok(())
}

/// Server TLS configuration.
pub struct ServerTlsConfig {
    /// PEM-encoded server certificate chain.
    pub cert_pem: String,
    /// PEM-encoded server private key.
    pub key_pem: String,
    /// When set, the server requires clients to present a certificate
    /// chained to this PEM CA bundle (mTLS).
    pub client_ca_pem: Option<String>,
}

/// Client TLS configuration.
pub struct ClientTlsConfig {
    /// Verify the server's certificate. Should be true outside of dev.
    pub verify_peer: bool,
    /// Path to a PEM CA bundle to verify the server cert against. When
    /// `None` the system trust store is used.
    pub ca_path: Option<String>,
    /// Client certificate to present (for mTLS-enabled servers).
    pub client_cert: Option<ClientCert>,
}

/// Client certificate material for mTLS.
pub struct ClientCert {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Create a QUIC server configuration.
pub fn create_server_config(tls: &ServerTlsConfig) -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| TransportError::TlsConfig(format!("failed to create QUIC config: {e}")))?;

    config
        .load_cert_chain_from_pem_file(&tls.cert_pem)
        .map_err(|e| TransportError::TlsConfig(format!("failed to load cert chain: {e}")))?;
    config
        .load_priv_key_from_pem_file(&tls.key_pem)
        .map_err(|e| TransportError::TlsConfig(format!("failed to load private key: {e}")))?;

    if let Some(ca_path) = &tls.client_ca_pem {
        config
            .load_verify_locations_from_file(ca_path)
            .map_err(|e| {
                TransportError::TlsConfig(format!("failed to load client CA bundle: {e}"))
            })?;
        // NOTE: quiche's `verify_peer(true)` sets `SSL_VERIFY_PEER`
        // only, not `SSL_VERIFY_FAIL_IF_NO_PEER_CERT`. A client that
        // presents no certificate still completes the TLS handshake,
        // so mTLS *presence* is enforced at the application layer:
        // `upgrade_user_from_cert` closes any established connection
        // that has no peer cert when the server was started with
        // `--client-ca`.
        config.verify_peer(true);
    }

    apply_common_config(&mut config, true)?;

    Ok(config)
}

/// Create a QUIC client configuration.
pub fn create_client_config(tls: ClientTlsConfig) -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| TransportError::TlsConfig(format!("failed to create QUIC config: {e}")))?;

    config.verify_peer(tls.verify_peer);

    if let Some(ca_path) = &tls.ca_path {
        config
            .load_verify_locations_from_file(ca_path)
            .map_err(|e| TransportError::TlsConfig(format!("failed to load CA bundle: {e}")))?;
    } else if tls.verify_peer {
        // Fall back to the platform trust store. quiche delegates to
        // BoringSSL; without an explicit bundle the OS roots are used.
        // Log on failure so an operator on a minimal image
        // (Alpine without ca-certificates, scratch container) gets a
        // concrete diagnostic instead of "TLS broken with no
        // explanation" later in the handshake.
        if let Err(e) = config.load_verify_locations_from_directory("/etc/ssl/certs") {
            tracing::warn!(
                error = ?e,
                "no system trust store at /etc/ssl/certs; \
                 pass --ca, --insecure, or --trust-on-first-use"
            );
        }
    }

    if let Some(cc) = &tls.client_cert {
        config
            .load_cert_chain_from_pem_file(&cc.cert_pem)
            .map_err(|e| TransportError::TlsConfig(format!("failed to load client cert: {e}")))?;
        config
            .load_priv_key_from_pem_file(&cc.key_pem)
            .map_err(|e| TransportError::TlsConfig(format!("failed to load client key: {e}")))?;
    }

    // Gate 0-RTT on whether the TLS stack will actually
    // authenticate the peer.
    apply_common_config(&mut config, tls.verify_peer)?;

    Ok(config)
}

#[cfg(all(test, target_os = "linux"))]
mod gso_tests {
    use super::*;

    fn ranges(total: usize, seg: usize) -> Vec<(usize, usize)> {
        gso_replay_ranges(total, seg).collect()
    }

    #[test]
    fn replay_exact_multiple_of_seg_size() {
        // 3 full segments, no short tail.
        assert_eq!(
            ranges(3000, 1000),
            vec![(0, 1000), (1000, 1000), (2000, 1000)]
        );
    }

    #[test]
    fn replay_short_tail_not_a_multiple() {
        // 2 full segments + a 250-byte tail; the tail must not overrun
        // `total` nor be padded up to seg_size.
        assert_eq!(
            ranges(2250, 1000),
            vec![(0, 1000), (1000, 1000), (2000, 250)]
        );
    }

    #[test]
    fn replay_single_packet_smaller_than_seg() {
        // A lone short packet (the path that `send_batch` only reaches
        // for packets > 1, but the arithmetic must still be correct).
        assert_eq!(ranges(250, 1000), vec![(0, 250)]);
    }

    #[test]
    fn replay_single_full_segment() {
        assert_eq!(ranges(1000, 1000), vec![(0, 1000)]);
    }

    #[test]
    fn replay_empty_batch_yields_nothing() {
        assert_eq!(ranges(0, 1000), Vec::<(usize, usize)>::new());
    }

    #[test]
    fn replay_covers_every_byte_without_overlap() {
        // Property: ranges tile [0, total) contiguously with no gap or
        // overlap, so the per-packet replay reproduces the batch exactly.
        let total = 7 * MAX_DATAGRAM_SIZE - 17;
        let seg = MAX_DATAGRAM_SIZE;
        let mut expected = 0usize;
        for (off, n) in gso_replay_ranges(total, seg) {
            assert_eq!(off, expected, "non-contiguous range");
            assert!(n <= seg, "segment exceeds seg_size");
            assert!(n > 0, "empty segment");
            expected += n;
        }
        assert_eq!(expected, total, "ranges did not cover the whole batch");
    }

    // --- gso_step / batch-planning coverage (C4) ---
    //
    // These exercise the I/O-independent half of `flush_egress_gso`: the
    // four batching boundaries called out in the review — (1) the first
    // write fixing `seg_size`, (2) a short-tail write ending the batch,
    // (3) an oversize write falling back to a single send, (4) the
    // GSO_BURST_PACKETS cap. The `sendmsg(UDP_SEGMENT)` syscall and the
    // `GSO_USABLE` runtime fallback are NOT covered here (they need a
    // real socket / kernel) and run only under Linux/CI.

    #[test]
    fn step_first_packet_always_appends() {
        // seg_size == 0 means an empty batch: the first packet fixes the
        // segment size and can never be a path swap or oversize.
        assert_eq!(gso_step(0, true, 1350), GsoStep::Append);
        assert_eq!(gso_step(0, false, 1), GsoStep::Append);
        assert_eq!(gso_step(0, true, 0), GsoStep::Append);
    }

    #[test]
    fn step_equal_size_same_dst_appends() {
        assert_eq!(gso_step(1350, true, 1350), GsoStep::Append);
    }

    #[test]
    fn step_short_tail_appends_then_flushes() {
        assert_eq!(gso_step(1350, true, 1349), GsoStep::AppendThenFlush);
        assert_eq!(gso_step(1350, true, 1), GsoStep::AppendThenFlush);
    }

    #[test]
    fn step_oversize_same_dst_sends_alone() {
        assert_eq!(gso_step(1200, true, 1350), GsoStep::FlushThenSendAlone);
    }

    #[test]
    fn step_path_swap_sends_alone_regardless_of_size() {
        // Branch order matters: a different destination short-circuits
        // before the oversize comparison, so even an equal- or
        // smaller-sized packet to a new dst is sent on its own.
        assert_eq!(gso_step(1350, false, 1350), GsoStep::FlushThenSendAlone);
        assert_eq!(gso_step(1350, false, 800), GsoStep::FlushThenSendAlone);
        assert_eq!(gso_step(1350, false, 1500), GsoStep::FlushThenSendAlone);
    }

    /// One emitted unit of the GSO plan. `Batch` carries the segment size
    /// and how many packets coalesce into the `sendmsg(UDP_SEGMENT)` (or
    /// a lone `send_to` when `packets == 1`); `Single` is a packet sent
    /// on its own off the path-swap / oversize fallback.
    #[derive(Debug, PartialEq, Eq)]
    enum PlanItem {
        Batch { seg_size: usize, packets: usize },
        Single { size: usize },
    }

    /// Test-only re-implementation of the `flush_egress_gso` batching
    /// state machine over a fixed sequence of writes, sharing the exact
    /// `gso_step` decision the production loop uses. Each input is
    /// `(write, same_dst)` where `same_dst` is whether this write's
    /// destination matches the open batch's. `burst` is the per-batch
    /// packet cap (the production constant is `GSO_BURST_PACKETS`).
    ///
    /// This drives the same arithmetic that decides what coalesces vs.
    /// what falls out as a single send, without a `quiche::Connection`
    /// or a socket. It does NOT model the kernel `sendmsg` / `GSO_USABLE`
    /// fallback (Linux/CI only).
    fn plan(writes: &[(usize, bool)], burst: usize) -> Vec<PlanItem> {
        fn flush_open(out: &mut Vec<PlanItem>, seg: &mut usize, pk: &mut usize) {
            if *pk > 0 {
                out.push(PlanItem::Batch {
                    seg_size: *seg,
                    packets: *pk,
                });
            }
            *seg = 0;
            *pk = 0;
        }

        let mut out = Vec::new();
        let mut i = 0;
        while i < writes.len() {
            // Restart of the `'outer` loop: a fresh batch fills until the
            // burst cap, a short tail, or a fallback breaks it.
            let mut seg_size = 0usize;
            let mut packets = 0usize;
            while i < writes.len() && packets < burst {
                let (write, same_dst) = writes[i];
                match gso_step(seg_size, same_dst, write) {
                    GsoStep::FlushThenSendAlone => {
                        flush_open(&mut out, &mut seg_size, &mut packets);
                        out.push(PlanItem::Single { size: write });
                        i += 1;
                        break;
                    }
                    GsoStep::Append => {
                        if seg_size == 0 {
                            seg_size = write;
                        }
                        packets += 1;
                        i += 1;
                    }
                    GsoStep::AppendThenFlush => {
                        packets += 1;
                        i += 1;
                        flush_open(&mut out, &mut seg_size, &mut packets);
                        break;
                    }
                }
            }
            // Burst cap or input exhausted with an open batch: commit it.
            flush_open(&mut out, &mut seg_size, &mut packets);
        }
        out
    }

    #[test]
    fn plan_uniform_equal_writes_coalesce_into_one_batch() {
        let writes = vec![(1350, true); 5];
        assert_eq!(
            plan(&writes, GSO_BURST_PACKETS),
            vec![PlanItem::Batch {
                seg_size: 1350,
                packets: 5
            }]
        );
    }

    #[test]
    fn plan_short_tail_closes_the_batch() {
        // 3 full segments then a short tail ends the burst; anything
        // after the tail (here nothing) would begin a new batch.
        let writes = vec![(1350, true), (1350, true), (1350, true), (900, true)];
        assert_eq!(
            plan(&writes, GSO_BURST_PACKETS),
            vec![PlanItem::Batch {
                seg_size: 1350,
                packets: 4
            }]
        );
    }

    #[test]
    fn plan_short_tail_then_more_starts_new_batch() {
        let writes = vec![(1350, true), (900, true), (1350, true), (1350, true)];
        assert_eq!(
            plan(&writes, GSO_BURST_PACKETS),
            vec![
                PlanItem::Batch {
                    seg_size: 1350,
                    packets: 2,
                },
                PlanItem::Batch {
                    seg_size: 1350,
                    packets: 2,
                },
            ]
        );
    }

    #[test]
    fn plan_oversize_falls_out_as_single_then_resumes() {
        // First write fixes seg_size = 1200. The 1350 cannot extend it,
        // so the 2-packet batch is committed and the 1350 is sent alone;
        // the trailing 1200 opens a fresh batch.
        let writes = vec![(1200, true), (1200, true), (1350, true), (1200, true)];
        assert_eq!(
            plan(&writes, GSO_BURST_PACKETS),
            vec![
                PlanItem::Batch {
                    seg_size: 1200,
                    packets: 2,
                },
                PlanItem::Single { size: 1350 },
                PlanItem::Batch {
                    seg_size: 1200,
                    packets: 1,
                },
            ]
        );
    }

    #[test]
    fn plan_path_swap_commits_then_sends_alone() {
        // Two packets to dst A coalesce; the third is to a different dst
        // and is sent on its own even though it is the same size.
        let writes = vec![(1350, true), (1350, true), (1350, false)];
        assert_eq!(
            plan(&writes, GSO_BURST_PACKETS),
            vec![
                PlanItem::Batch {
                    seg_size: 1350,
                    packets: 2,
                },
                PlanItem::Single { size: 1350 },
            ]
        );
    }

    #[test]
    fn plan_oversize_as_first_write_after_swap_is_just_a_single_open() {
        // A standalone oversize write that begins an empty batch is not
        // "oversize relative to itself": it opens a new batch as the
        // first packet (seg_size == 0 path), then closing flushes it as
        // a 1-packet batch.
        let writes = vec![(1500, true)];
        assert_eq!(
            plan(&writes, GSO_BURST_PACKETS),
            vec![PlanItem::Batch {
                seg_size: 1500,
                packets: 1,
            }]
        );
    }

    #[test]
    fn plan_exactly_burst_packets_is_one_batch() {
        let writes = vec![(1350, true); GSO_BURST_PACKETS];
        assert_eq!(
            plan(&writes, GSO_BURST_PACKETS),
            vec![PlanItem::Batch {
                seg_size: 1350,
                packets: GSO_BURST_PACKETS,
            }]
        );
    }

    #[test]
    fn plan_burst_plus_one_splits_into_two_batches() {
        let writes = vec![(1350, true); GSO_BURST_PACKETS + 1];
        assert_eq!(
            plan(&writes, GSO_BURST_PACKETS),
            vec![
                PlanItem::Batch {
                    seg_size: 1350,
                    packets: GSO_BURST_PACKETS,
                },
                PlanItem::Batch {
                    seg_size: 1350,
                    packets: 1,
                },
            ]
        );
    }

    #[test]
    fn plan_small_burst_cap_boundary() {
        // Burst cap of 2: 5 equal writes split 2 + 2 + 1.
        let writes = vec![(1000, true); 5];
        assert_eq!(
            plan(&writes, 2),
            vec![
                PlanItem::Batch {
                    seg_size: 1000,
                    packets: 2,
                },
                PlanItem::Batch {
                    seg_size: 1000,
                    packets: 2,
                },
                PlanItem::Batch {
                    seg_size: 1000,
                    packets: 1,
                },
            ]
        );
    }

    #[test]
    fn plan_total_packet_count_is_conserved() {
        // Property: every input write lands on the wire exactly once,
        // whether coalesced into a batch or sent on its own.
        let writes = vec![
            (1350, true),
            (1350, true),
            (1350, false),
            (1200, true),
            (900, true),
            (1500, true),
            (1350, true),
        ];
        let items = plan(&writes, GSO_BURST_PACKETS);
        let counted: usize = items
            .iter()
            .map(|it| match it {
                PlanItem::Batch { packets, .. } => *packets,
                PlanItem::Single { .. } => 1,
            })
            .sum();
        assert_eq!(counted, writes.len());
    }
}
