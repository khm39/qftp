//! Shared client-side QUIC connection setup.
//!
//! Every client path — the REPL, the one-shot subcommands, the sync
//! and watch uploaders, and the fanout helper — needs the same
//! sequence: build a `quiche::Config` from a `ConnectionSpec`, bind a
//! UDP socket, mint a SCID, call `quiche::connect`, optionally hand it
//! a 0-RTT session ticket, then pump the handshake until established
//! or closed. This module is the single implementation.
//!
//! [`EstablishOpts`] carries the few knobs that differ between paths:
//! the non-interactive callers use [`EstablishOpts::for_spec`], while
//! the REPL builds it explicitly so it can route `--no-zero-rtt`, a
//! custom ticket directory, and TOFU's verify-peer override through.
//! TOFU pinning itself runs in `main.rs` on the returned connection.

use std::net::UdpSocket;
use std::path::PathBuf;
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

/// Knobs for [`establish`] that vary between client paths.
pub struct EstablishOpts {
    /// Verify the server cert in the TLS stack. False for `--insecure`
    /// or while TOFU runs its own pin check after the handshake.
    pub verify_peer: bool,
    /// Attempt 0-RTT resumption from a stored session ticket.
    pub zero_rtt: bool,
    /// Session-ticket directory override. `None` uses the default.
    pub ticket_dir: Option<PathBuf>,
    /// Server-cert fingerprint a stored 0-RTT ticket must be bound to.
    /// In TOFU mode this is the pinned known_hosts value, so a ticket
    /// is only resumed against the same server identity it was saved
    /// for (defends against DNS-repoint / cert-rotation replay). `None`
    /// in CA mode, where the TLS layer's chain validation covers it.
    pub expected_cert_fingerprint: Option<[u8; 32]>,
}

impl EstablishOpts {
    /// Defaults for the non-interactive paths: TLS verification follows
    /// `spec.insecure`, 0-RTT on, and the default ticket directory.
    /// These paths use CA-mode verification (no TOFU), so the ticket
    /// fingerprint binding is left to the TLS layer.
    pub fn for_spec(spec: &ConnectionSpec) -> Self {
        Self {
            verify_peer: !spec.insecure,
            zero_rtt: true,
            ticket_dir: None,
            expected_cert_fingerprint: None,
        }
    }
}

/// A connection driven through its handshake, ready for requests.
pub struct Established {
    pub conn: quiche::Connection,
    pub socket: mio::net::UdpSocket,
    pub poll: Poll,
    pub events: Events,
    /// True when quiche accepted a 0-RTT session ticket.
    pub resumed: bool,
}

/// Open a connection to `spec.host` and drive the handshake to
/// completion. `context_label` is woven into error messages so a
/// failure still points at the calling path.
pub fn establish(
    spec: &ConnectionSpec,
    context_label: &str,
    opts: EstablishOpts,
) -> Result<Established> {
    let mut config = create_client_config(ClientTlsConfig {
        verify_peer: opts.verify_peer,
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
    qftp_common::transport::tune_udp_buffers(&std_socket);
    let local_addr = std_socket.local_addr()?;
    let mut socket = mio::net::UdpSocket::from_std(std_socket);

    let rng = ring::rand::SystemRandom::new();
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    use ring::rand::SecureRandom;
    rng.fill(&mut scid_bytes).expect("system RNG failed");
    let scid = quiche::ConnectionId::from_vec(scid_bytes.to_vec());
    let mut conn = quiche::connect(
        Some(&spec.server_name),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )?;

    // 0-RTT resume: hand quiche a stored ticket before any I/O so the
    // first Initial can carry early data. A rejected ticket falls back
    // to 1-RTT; the stale blob is forgotten so it isn't replayed.
    let mut resumed = false;
    if opts.zero_rtt {
        let dir = opts.ticket_dir.clone().or_else(session_store::default_dir);
        if let Some(dir) = &dir {
            if let Some(ticket) =
                session_store::load(dir, &spec.host, opts.expected_cert_fingerprint.as_ref())
            {
                match conn.set_session(&ticket) {
                    Ok(()) => {
                        resumed = true;
                        tracing::info!(host = %spec.host, "0-RTT: resuming session");
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "stale session ticket; falling back to 1-RTT"
                        );
                        let _ = session_store::forget(dir, &spec.host);
                    }
                }
            }
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

    Ok(Established {
        conn,
        socket,
        poll,
        events,
        resumed,
    })
}
