use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};

pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const STREAM_BUF_SIZE: usize = 65536;
/// Maximum allowed control message size (16 MB). Prevents a malicious peer from
/// sending an enormous length prefix that causes unbounded memory allocation.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Flush pending outgoing packets from the QUIC connection to the UDP socket.
pub fn flush_egress(conn: &mut quiche::Connection, socket: &mio::net::UdpSocket) -> Result<()> {
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    loop {
        let (write, send_info) = match conn.send(&mut out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(e).context("QUIC send failed"),
        };

        socket
            .send_to(&out[..write], send_info.to)
            .context("UDP send_to failed")?;
    }

    Ok(())
}

/// Read incoming UDP packets from the socket and feed them into the QUIC connection.
pub fn handle_ingress(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    buf: &mut [u8],
) -> Result<()> {
    let local_addr = socket.local_addr().context("failed to get local addr")?;

    loop {
        let (len, from) = match socket.recv_from(buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("UDP recv_from failed"),
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

/// Serialize a message and send it on a QUIC stream with a 4-byte BE length prefix.
pub fn send_message<T: Serialize>(
    conn: &mut quiche::Connection,
    stream_id: u64,
    msg: &T,
) -> Result<()> {
    let payload = bincode::serialize(msg).context("failed to serialize message")?;
    anyhow::ensure!(
        payload.len() <= MAX_MESSAGE_SIZE,
        "message too large: {} bytes (max {})",
        payload.len(),
        MAX_MESSAGE_SIZE
    );
    let len = payload.len() as u32;
    let mut data = Vec::with_capacity(4 + payload.len());
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(&payload);

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
    let mut offset = 0;
    while offset < data.len() {
        let is_last = offset + STREAM_BUF_SIZE >= data.len();
        let written = conn
            .stream_send(stream_id, &data[offset..], fin && is_last)
            .context("stream_send failed")?;
        offset += written;
        if written == 0 {
            anyhow::bail!("stream_send wrote 0 bytes, stream may be blocked");
        }
    }
    // If data is empty and fin is requested, send a fin-only frame.
    if data.is_empty() && fin {
        conn.stream_send(stream_id, &[], true)
            .context("stream_send fin failed")?;
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
            Err(e) => return Err(e).context("stream_recv failed"),
        }
    }

    // Check if we have enough data to parse a complete message.
    if stream_buf.len() < 4 {
        return Ok(None);
    }

    let msg_len =
        u32::from_be_bytes([stream_buf[0], stream_buf[1], stream_buf[2], stream_buf[3]]) as usize;

    anyhow::ensure!(
        msg_len <= MAX_MESSAGE_SIZE,
        "peer sent oversized message: {} bytes (max {})",
        msg_len,
        MAX_MESSAGE_SIZE
    );

    if stream_buf.len() < 4 + msg_len {
        return Ok(None);
    }

    // #117: bound per-field allocations during deserialization. The
    // 4-byte frame length is already bounded by MAX_MESSAGE_SIZE, but
    // bincode's defaults will happily allocate a 16 MiB `String` for
    // a single field within that frame. with_limit caps individual
    // String/Vec allocations during decode at the same MAX_MESSAGE_SIZE.
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_MESSAGE_SIZE as u64);
    use bincode::Options as _;
    let msg: T = opts
        .deserialize(&stream_buf[4..4 + msg_len])
        .context("failed to deserialize message")?;

    // Drain the consumed bytes.
    stream_buf.drain(..4 + msg_len);

    Ok(Some(msg))
}

/// Apply common QUIC transport parameters shared by client and server.
fn apply_common_config(config: &mut quiche::Config, allow_early_data: bool) -> Result<()> {
    config
        .set_application_protos(&[crate::protocol::ALPN])
        .context("failed to set ALPN")?;

    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    // Phase 1 sends and receives files in chunks (qftp-server's
    // send_file_streaming and drive_put), so peak memory no longer scales
    // with the flow-control window. We still keep the windows generous to
    // minimize how often send_file_streaming has to spin-wait for a peer
    // ACK; the per-stream RAM upper bound is now the BufReader/BufWriter
    // capacity (64 KiB) rather than the window itself. initial_max_streams_bidi
    // stays low because the server is still single-connection (Phase 2,
    // issue #36): the current client only opens one bidi stream at a time.
    // Phase 2's multi-connection rewrite is the right place to revisit
    // both dimensions in concert with a real egress-driven sender.
    config.set_initial_max_data(2 * 1024 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(1024 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(1024 * 1024 * 1024);
    config.set_initial_max_streams_bidi(4);
    config.set_disable_active_migration(true);

    // 0-RTT resumption. Server-side replay protection is enforced in
    // the per-Request decode path (write ops refused while
    // `is_in_early_data()`). The client side gates this on whether
    // the TLS stack itself verifies the peer cert:
    //   * verify_peer = true: a MitM cannot complete the resumed
    //     handshake without the real server's private key, so 0-RTT
    //     bytes stay confidential.
    //   * verify_peer = false (--insecure or TOFU before pin-binding
    //     lands): an attacker who terminates the connection could
    //     receive the first Request bytes (#110). Skip enable_early_data
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
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).context("failed to create QUIC config")?;

    config
        .load_cert_chain_from_pem_file(&tls.cert_pem)
        .context("failed to load cert chain")?;
    config
        .load_priv_key_from_pem_file(&tls.key_pem)
        .context("failed to load private key")?;

    if let Some(ca_path) = &tls.client_ca_pem {
        config
            .load_verify_locations_from_file(ca_path)
            .context("failed to load client CA bundle")?;
        config.verify_peer(true);
    }

    apply_common_config(&mut config, true)?;

    Ok(config)
}

/// Create a QUIC client configuration.
pub fn create_client_config(tls: ClientTlsConfig) -> Result<quiche::Config> {
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).context("failed to create QUIC config")?;

    config.verify_peer(tls.verify_peer);

    if let Some(ca_path) = &tls.ca_path {
        config
            .load_verify_locations_from_file(ca_path)
            .context("failed to load CA bundle")?;
    } else if tls.verify_peer {
        // Fall back to the platform trust store. quiche delegates to
        // BoringSSL; without an explicit bundle the OS roots are used.
        // #124: log on failure so an operator on a minimal image
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
            .context("failed to load client cert")?;
        config
            .load_priv_key_from_pem_file(&cc.key_pem)
            .context("failed to load client key")?;
    }

    // #110: gate 0-RTT on whether the TLS stack will actually
    // authenticate the peer.
    apply_common_config(&mut config, tls.verify_peer)?;

    Ok(config)
}
