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

/// `12 B` / `1.2 KB` / `3.4 MB` / `5.6 GB`. Matches the REPL `ls`
/// rendering style.
pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// `45s` / `1m15s` / `1h01m01s`. Human-readable elapsed duration.
pub fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m{:02}s", secs / 3600, (secs / 60) % 60, secs % 60)
    }
}

/// Split a byte string into (digit/`.`-prefix end index, unit multiplier).
/// Recognizes `K`/`M`/`G` (decimal) and `Ki`/`Mi`/`Gi` (binary) suffixes,
/// case-insensitively; an empty suffix is `1`. Returns `None` for an
/// unrecognized suffix (a user typo, not a 1-byte unit).
pub fn parse_suffix(bytes: &[u8]) -> Option<(usize, u64)> {
    // Walk back from the end to find the digit/suffix boundary.
    let mut end = bytes.len();
    while end > 0 && !bytes[end - 1].is_ascii_digit() && bytes[end - 1] != b'.' {
        end -= 1;
    }
    let suffix = std::str::from_utf8(&bytes[end..]).unwrap_or("");
    let mult: u64 = match suffix {
        "" => 1,
        "K" | "k" => 1_000,
        "M" | "m" => 1_000_000,
        "G" | "g" => 1_000_000_000,
        "Ki" | "ki" => 1024,
        "Mi" | "mi" => 1024 * 1024,
        "Gi" | "gi" => 1024 * 1024 * 1024,
        // An unrecognized suffix is a user typo, not a 1-byte unit.
        _ => return None,
    };
    Some((end, mult))
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

    #[test]
    fn format_size_thresholds() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn format_duration_rolls_over() {
        use std::time::Duration;
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(75)), "1m15s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h01m01s");
    }

    #[test]
    fn parse_suffix_units() {
        assert_eq!(parse_suffix(b"5"), Some((1, 1)));
        assert_eq!(parse_suffix(b"5M"), Some((1, 1_000_000)));
        assert_eq!(parse_suffix(b"1Gi"), Some((1, 1024 * 1024 * 1024)));
        assert_eq!(parse_suffix(b"2k"), Some((1, 1_000)));
        assert_eq!(parse_suffix(b"1.5Mi"), Some((3, 1024 * 1024)));
        assert_eq!(parse_suffix(b"3x"), None);
    }
}
