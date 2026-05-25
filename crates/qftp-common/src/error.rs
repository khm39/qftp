//! Structured errors for the `qftp-common` transport layer.
//!
//! Public surface returns these instead of `anyhow::Error` so
//! consumers (`qftp-server`, `qftp-client`, `qftp-web-bridge`) can
//! pattern-match on the failure category — e.g. retry on transient
//! `Io`/`Quic`, drop the connection on `Bincode`/`FrameTooLarge`,
//! refuse startup on `TlsConfig`. `?`-using callers whose function
//! signature is `anyhow::Result<_>` continue to compile unchanged
//! because `anyhow::Error: From<TransportError>` via the blanket
//! `Error + Send + Sync + 'static` impl.

/// Errors surfaced by the `qftp-common::transport` public functions.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Socket / underlying I/O error without per-call-site context.
    /// Use [`TransportError::IoCtx`] when the call site can name the
    /// subsystem ("UDP send_to (path swap)" vs "UDP recv_from", etc.)
    /// so operator log greps stay meaningful.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// I/O error with a static call-site label. The label disambiguates
    /// `flush_egress`'s 5 distinct `send_to` paths (per-packet single,
    /// GSO path-swap, GSO oversize-fallback, sendmsg-fallback) and
    /// `handle_ingress`'s `recv_from`, preserving the breadcrumbs that
    /// existed before the structured-error refactor (cycle-2 #13).
    #[error("{context}: {source}")]
    IoCtx {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// quiche transport / handshake failure without call-site context.
    #[error("QUIC: {0}")]
    Quic(#[from] quiche::Error),

    /// quiche error with a static call-site label (`stream_send` vs
    /// `stream_recv` vs `stream_send (fin)`), restoring the
    /// breadcrumbs that the structured-error refactor dropped.
    #[error("QUIC {context}: {source}")]
    QuicCtx {
        context: &'static str,
        #[source]
        source: quiche::Error,
    },

    /// bincode encode/decode error.
    #[error("bincode codec: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),

    /// A frame would exceed `MAX_MESSAGE_SIZE` if encoded, or the
    /// declared length on the wire is over the cap.
    #[error("frame size {actual} bytes exceeds MAX_MESSAGE_SIZE ({max})")]
    FrameTooLarge { actual: usize, max: usize },

    /// `stream_send` returned `Ok(0)` despite the stream still having
    /// flow-control credit; this is the "stuck stream" sentinel and is
    /// surfaced as its own variant so a caller can choose to retry
    /// after a transport flush instead of tearing down the whole
    /// connection. Today every caller treats it as fatal (matching the
    /// pre-refactor `anyhow::bail!` behaviour); the variant exists so
    /// retry support can be added in one place when needed.
    #[error("stream_send wrote 0 bytes; the stream is blocked")]
    StreamBlocked,

    /// TLS / quiche-config construction failure (PEM load, cipher
    /// configuration, ALPN setup). Carries the underlying message
    /// for diagnostics; not intended to be matched on.
    #[error("TLS config: {0}")]
    TlsConfig(String),
}

impl TransportError {
    /// Wrap an `io::Error` with a static `'static` call-site label.
    /// Convenience constructor for the `IoCtx` variant.
    pub fn io_ctx(context: &'static str, source: std::io::Error) -> Self {
        Self::IoCtx { context, source }
    }

    /// Wrap a `quiche::Error` with a static `'static` call-site label.
    pub fn quic_ctx(context: &'static str, source: quiche::Error) -> Self {
        Self::QuicCtx { context, source }
    }
}
