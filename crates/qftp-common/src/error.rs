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
    /// Socket / underlying I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// quiche transport / handshake failure.
    #[error("QUIC: {0}")]
    Quic(#[from] quiche::Error),

    /// bincode encode/decode error.
    #[error("bincode codec: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),

    /// A frame would exceed `MAX_MESSAGE_SIZE` if encoded, or the
    /// declared length on the wire is over the cap.
    #[error("frame size {actual} bytes exceeds MAX_MESSAGE_SIZE ({max})")]
    FrameTooLarge { actual: usize, max: usize },

    /// Peer or our own stream_send made no forward progress; treated
    /// as a fatal stream error rather than spinning.
    #[error("stream_send wrote 0 bytes; the stream is blocked")]
    StreamBlocked,

    /// TLS / quiche-config construction failure (PEM load, cipher
    /// configuration, ALPN setup). Carries the underlying message
    /// for diagnostics; not intended to be matched on.
    #[error("TLS config: {0}")]
    TlsConfig(String),
}
