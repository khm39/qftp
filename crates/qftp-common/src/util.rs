//! Small shared helpers used across the qftp crates.

use std::fmt::Write as _;

/// Lowercase-hex encode a byte slice.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Best-effort extraction of a panic payload's message for logging.
/// Mirrors what the default panic hook prints to stderr: a
/// `panic!("lit")` produces a `&'static str` payload; a
/// `panic!("fmt: {}", x)` produces a `String`. Anything else falls
/// through to a sentinel string so the caller's `tracing` log line
/// always carries SOMETHING.
///
/// Centralized here so the native server's `HandlerPool::Drop`, the
/// web-bridge's `await_blocking`, the `handler_worker` catch_unwind
/// path, and the `fanout.rs` worker-panic path stay in sync as Rust
/// gains support for additional payload shapes.
pub fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "<non-string panic payload>".to_string()
}

/// Length-checked byte comparison that runs in time independent of the
/// contents (the early `false` only reveals the length, which for a
/// high-entropy secret is not the secret-bearing part). Used for
/// secret comparisons — bearer tokens, retry-token HMAC tags — so a
/// timing side channel can't recover the secret byte by byte.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_encodes_lowercase() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        assert!(constant_time_eq(b"s3cret-token", b"s3cret-token"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"s3cret-token", b"s3cret-tokeN"));
        assert!(!constant_time_eq(b"s3cret-token", b"s3cret-token-"));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
