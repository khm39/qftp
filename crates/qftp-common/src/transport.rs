use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};

pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const STREAM_BUF_SIZE: usize = 65536;

/// Flush pending outgoing packets from the QUIC connection to the UDP socket.
pub fn flush_egress(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
) -> Result<()> {
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
                log::warn!("QUIC recv error: {:?}", e);
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

    if stream_buf.len() < 4 + msg_len {
        return Ok(None);
    }

    let msg: T = bincode::deserialize(&stream_buf[4..4 + msg_len])
        .context("failed to deserialize message")?;

    // Drain the consumed bytes.
    stream_buf.drain(..4 + msg_len);

    Ok(Some(msg))
}

/// Create a QUIC server configuration with the given certificate and key PEM data.
pub fn create_server_config(cert_pem: &str, key_pem: &str) -> Result<quiche::Config> {
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).context("failed to create QUIC config")?;

    config
        .load_cert_chain_from_pem_file(cert_pem)
        .context("failed to load cert chain")?;
    config
        .load_priv_key_from_pem_file(key_pem)
        .context("failed to load private key")?;

    config
        .set_application_protos(&[b"qftp"])
        .context("failed to set ALPN")?;

    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_disable_active_migration(true);

    Ok(config)
}

/// Create a QUIC client configuration (peer verification disabled).
pub fn create_client_config() -> Result<quiche::Config> {
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).context("failed to create QUIC config")?;

    config.verify_peer(false);

    config
        .set_application_protos(&[b"qftp"])
        .context("failed to set ALPN")?;

    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_disable_active_migration(true);

    Ok(config)
}
