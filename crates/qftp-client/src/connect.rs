//! Shared client-side QUIC connection setup.
//!
//! The one-shot path, the sync uploader, the watch uploader, and the
//! fanout helper all need the same sequence: build a `quiche::Config`
//! from a `ConnectionSpec`, bind a UDP socket, mint a SCID, call
//! `quiche::connect`, optionally hand it a 0-RTT session ticket, then
//! pump the handshake until established or closed. This module
//! collapses those five copies into one helper.
//!
//! The REPL path in `main.rs` does extra work (TOFU pinning, explicit
//! `--no-zero-rtt`, custom ticket directory, banner) so it doesn't go
//! through here; it uses `client_cert_from_spec` for the one piece
//! it does share.
use std::net::UdpSocket;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use mio::{Events, Interest, Poll, Token};
use qftp_common::transport::{
    create_client_config, flush_egress, handle_ingress, ClientCert, ClientTlsConfig,
};

use crate::config::ConnectionSpec;
use crate::session_store;

const CLIENT: Token = Token(0);

/// Convert a `ConnectionSpec`'s `client_cert` / `client_key` pair into
/// the `ClientCert` struct expected by `create_client_config`. Returns
/// `None` if either half is missing.
pub fn client_cert_from_spec(spec: &ConnectionSpec) -> Option<ClientCert> {
    match (&spec.client_cert, &spec.client_key) {
        (Some(c), Some(k)) => Some(ClientCert {
            cert_pem: c.clone(),
            key_pem: k.clone(),
        }),
        _ => None,
    }
}

/// Open a connection to `spec.host` and drive the handshake to
/// completion. The optional `context_label` is woven into error
/// messages so a failure from sync / watch / fanout still points at
/// the right caller.
pub fn establish(
    spec: &ConnectionSpec,
    context_label: &str,
) -> Result<(quiche::Connection, mio::net::UdpSocket, Poll, Events)> {
    let mut config = create_client_config(ClientTlsConfig {
        verify_peer: !spec.insecure,
        ca_path: spec.ca.clone(),
        client_cert: client_cert_from_spec(spec),
    })?;

    let peer_addr = spec
        .host
        .parse()
        .with_context(|| format!("{context_label}: bad host {}", spec.host))?;
    let std_socket =
        UdpSocket::bind("0.0.0.0:0").with_context(|| format!("{context_label}: UDP bind"))?;
    std_socket.set_nonblocking(true)?;
    std_socket.connect(peer_addr)?;
    let local_addr = std_socket.local_addr()?;
    let mut socket = mio::net::UdpSocket::from_std(std_socket);

    let rng = ring::rand::SystemRandom::new();
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    use ring::rand::SecureRandom;
    rng.fill(&mut scid_bytes).unwrap();
    let scid = quiche::ConnectionId::from_vec(scid_bytes.to_vec());
    let mut conn = quiche::connect(
        Some(&spec.server_name),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )?;

    // 0-RTT resume if we have a ticket. A rejected ticket is a silent
    // fallback to 1-RTT; the caller path-specific REPL flow has a
    // richer policy (forget the ticket, emit a tracing line) but the
    // automated paths just want the speedup when it works.
    if let Some(dir) = session_store::default_dir() {
        if let Some(ticket) = session_store::load(&dir, &spec.host, None) {
            let _ = conn.set_session(&ticket);
        }
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    poll.registry()
        .register(&mut socket, CLIENT, Interest::READABLE)?;

    flush_egress(&mut conn, &socket)?;
    let mut buf = [0u8; 65535];
    loop {
        poll.poll(
            &mut events,
            conn.timeout().or(Some(Duration::from_millis(100))),
        )?;
        conn.on_timeout();
        handle_ingress(&mut conn, &socket, &mut buf)?;
        flush_egress(&mut conn, &socket)?;
        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            return Err(anyhow!(
                "{context_label}: connection closed during handshake"
            ));
        }
    }

    Ok((conn, socket, poll, events))
}
