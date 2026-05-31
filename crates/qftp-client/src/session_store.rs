//! Persistent QUIC session ticket store for 0-RTT resumption.
//!
//! On disconnect the client serialises `quiche::Connection::session()`
//! (an opaque BoringSSL session blob plus the peer's transport
//! parameters) to `~/.qftp/session-tickets/<host>:<port>.ticket`. On
//! the next connect, the file is loaded and passed back via
//! `Connection::set_session()` before any I/O, which lets the client
//! send 0-RTT data on its first flight.
//!
//! The ticket file is stored with mode 0600 on Unix: like any other
//! resumption material it is roughly equivalent to a password.
//!
//! ## TTL
//!
//! BoringSSL's ticket lifetime is generally 7 days, but tickets can
//! be invalidated by the server (rotated key, restart with a fresh
//! cert) at any time. We keep a self-imposed 24h TTL: older tickets
//! are dropped at load time so a long-lived stale ticket can never
//! send 0-RTT into the void. A rejected resumption silently falls
//! back to 1-RTT.
//!
//! The save timestamp is embedded in the file header (8-byte big-endian
//! unix seconds) so the TTL is computed from an authenticated value the
//! attacker cannot extend by `touch`-ing the file. The filesystem mtime
//! is kept only as a cheap fast-path: a file already older than the TTL
//! by mtime is dropped without a read, but a fresh-looking mtime never
//! resurrects a ticket whose embedded timestamp is past the TTL. Files
//! written by older versions carry no embedded timestamp and fall back
//! to the (unauthenticated) mtime, matching their historical behaviour.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};

/// Magic + version header prepended to every ticket file.
///
/// `V1` (`QFT1\0FP\n`): magic(8) + fingerprint(32) + ticket. Written by
/// older versions that bound the ticket to a server-cert fingerprint
/// but had no embedded timestamp; the TTL fell back to the file mtime.
///
/// `V2` (`QFT2\0FP\n`): magic(8) + timestamp_be(8) + fingerprint(32) +
/// ticket. The timestamp is unix seconds at save time, used as the
/// authenticated age source so the TTL can't be extended by `touch`.
///
/// Files matching neither magic are legacy headerless tickets: "no
/// binding, load unconditionally (subject to mtime TTL)".
const TICKET_FILE_MAGIC_V1: &[u8; 8] = b"QFT1\0FP\n";
const TICKET_FILE_MAGIC_V2: &[u8; 8] = b"QFT2\0FP\n";
const MAGIC_LEN: usize = 8;
const TIMESTAMP_LEN: usize = 8;
const FINGERPRINT_LEN: usize = 32;
const HEADER_LEN_V1: usize = MAGIC_LEN + FINGERPRINT_LEN;
const HEADER_LEN_V2: usize = MAGIC_LEN + TIMESTAMP_LEN + FINGERPRINT_LEN;

/// 24h TTL. Long enough for "qftp put a; qftp put b" workflows to
/// resume the second connection, short enough that a rotated server
/// cert is naturally re-discovered within a day.
pub const TICKET_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default directory: `~/.qftp/session-tickets/`. Returns `None`
/// when `$HOME` is unset.
pub fn default_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".qftp/session-tickets"))
}

/// Build the ticket file path for a given `host:port`.
pub fn ticket_path(dir: &Path, host_port: &str) -> PathBuf {
    // Sanitize: colons and slashes in the host string would create
    // path separators on Windows or interpret oddly. Map them to '_'.
    let safe: String = host_port
        .chars()
        .map(|c| {
            if matches!(c, ':' | '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .collect();
    // Defense in depth: even though slashes are already mapped (so a
    // bare `..` can't introduce a separator), neutralise a component
    // that is exactly `.` or `..` so a future caller feeding an
    // attacker-influenced host can't end up addressing the parent dir.
    // The `.ticket` suffix keeps `..` from being a real traversal
    // component, but map it explicitly so intent is unambiguous.
    let safe = match safe.as_str() {
        "." | ".." => "_",
        _ => safe.as_str(),
    };
    dir.join(format!("{safe}.ticket"))
}

/// Load a ticket for `host_port` from `dir` if it exists and is
/// fresh. Returns `None` for missing / expired / unreadable
/// tickets so the caller can fall through to a 1-RTT handshake.
///
/// `expected_fingerprint` lets a TOFU caller bind the saved
/// ticket to the pinned server identity. When `Some(fp)`, the
/// stored fingerprint must match exactly or the file is dropped and
/// `None` returned — defends against DNS-repoint / cert-rotation
/// replay scenarios. When `None`, the binding is not enforced
/// (callers in CA mode rely on the TLS layer's cert validation
/// instead). Files written by older versions have no header and are
/// loaded unconditionally for backward compatibility.
pub fn load(
    dir: &Path,
    host_port: &str,
    expected_fingerprint: Option<&[u8; 32]>,
) -> Option<Vec<u8>> {
    let path = ticket_path(dir, host_port);
    let meta = std::fs::metadata(&path).ok()?;

    // Fast-path: if the (unauthenticated) mtime already puts the file
    // past the TTL, it cannot be fresh under any reading -- drop it
    // without a read. A *fresh-looking* mtime is not trusted on its own;
    // the authoritative age check below uses the embedded timestamp.
    if let Ok(modified) = meta.modified() {
        if let Ok(age) = SystemTime::now().duration_since(modified) {
            if age > TICKET_TTL {
                let _ = std::fs::remove_file(&path);
                return None;
            }
        }
    }

    let raw = std::fs::read(&path).ok()?;
    let parsed = match parse_ticket_file(&raw) {
        Some(p) => p,
        None => {
            // Legacy (no header) file. No binding to verify and no
            // embedded timestamp, so the mtime fast-path above is the
            // only freshness gate -- matches historical behaviour.
            return if expected_fingerprint.is_some() {
                // TOFU caller insists on a binding; we don't have
                // one. Treat as a miss and purge so the next save
                // writes the new format.
                let _ = std::fs::remove_file(&path);
                None
            } else {
                Some(raw)
            };
        }
    };

    // V2 carries an authenticated save timestamp. Compute age from it so
    // a `touch`-refreshed mtime can't extend the TTL. The age is computed
    // in raw unix seconds (not via `SystemTime`/`Duration` arithmetic) so
    // a far-future or overflowing timestamp can't slip past the gate by
    // making subtraction error out -- any V2 timestamp that doesn't map
    // to an age within `[0, TTL]` (allowing a small clock-skew grace for
    // the future direction) drops the ticket. A V2 file is *always*
    // governed by its embedded timestamp; it never falls back to the
    // (unauthenticated) mtime. V1 has no embedded timestamp and relies on
    // the mtime fast-path already applied above.
    if let Some(saved_secs) = parsed.saved_secs {
        if !v2_timestamp_fresh(saved_secs) {
            let _ = std::fs::remove_file(&path);
            return None;
        }
    }

    if let Some(want) = expected_fingerprint {
        if parsed.fingerprint != want {
            // Wrong server: purge so we don't keep offering a stale
            // ticket against a rotated / repointed host.
            tracing::warn!(
                host_port,
                "session ticket fingerprint mismatch (server cert changed or DNS repoint?); discarding"
            );
            let _ = std::fs::remove_file(&path);
            return None;
        }
    }
    Some(parsed.ticket.to_vec())
}

struct ParsedTicket<'a> {
    fingerprint: &'a [u8; 32],
    /// Authenticated save time, unix seconds. `Some` for V2 files,
    /// `None` for V1 (no embedded timestamp -> caller falls back to
    /// mtime). A V2 file always keeps `Some` here even for a degenerate
    /// timestamp, so it can never silently demote to the mtime path.
    saved_secs: Option<u64>,
    ticket: &'a [u8],
}

fn parse_ticket_file(buf: &[u8]) -> Option<ParsedTicket<'_>> {
    if buf.len() < MAGIC_LEN {
        return None;
    }
    let magic: &[u8; 8] = buf[..MAGIC_LEN].try_into().ok()?;
    if magic == TICKET_FILE_MAGIC_V2 {
        if buf.len() < HEADER_LEN_V2 {
            return None;
        }
        let ts_bytes: [u8; 8] = buf[MAGIC_LEN..MAGIC_LEN + TIMESTAMP_LEN].try_into().ok()?;
        let secs = u64::from_be_bytes(ts_bytes);
        let fp: &[u8; 32] = buf[MAGIC_LEN + TIMESTAMP_LEN..HEADER_LEN_V2]
            .try_into()
            .ok()?;
        Some(ParsedTicket {
            fingerprint: fp,
            saved_secs: Some(secs),
            ticket: &buf[HEADER_LEN_V2..],
        })
    } else if magic == TICKET_FILE_MAGIC_V1 {
        if buf.len() < HEADER_LEN_V1 {
            return None;
        }
        let fp: &[u8; 32] = buf[MAGIC_LEN..HEADER_LEN_V1].try_into().ok()?;
        Some(ParsedTicket {
            fingerprint: fp,
            saved_secs: None,
            ticket: &buf[HEADER_LEN_V1..],
        })
    } else {
        None
    }
}

/// Allowed clock-skew when a V2 ticket's embedded save time is in the
/// future. Robustness only (an NTP step between `put a; put b` on the
/// same box), not a security boundary: a far-future timestamp beyond
/// this grace is rejected so it can't be accepted indefinitely.
const FUTURE_SKEW_GRACE: u64 = 5 * 60;

/// Whether a V2 ticket's embedded `saved_secs` puts its age within the
/// TTL. Computed in raw unix seconds so neither a far-future timestamp
/// nor a `u64::MAX` overflow can bypass the gate via `SystemTime` /
/// `Duration` errors.
fn v2_timestamp_fresh(saved_secs: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if saved_secs > now {
        // Future-dated: tolerate a small skew, reject anything beyond it.
        saved_secs - now <= FUTURE_SKEW_GRACE
    } else {
        now - saved_secs <= TICKET_TTL.as_secs()
    }
}

/// Persist a ticket for `host_port` into `dir`. Creates the
/// directory if needed; mode 0600 on Unix. A `None` ticket means
/// "the connection didn't produce a session", which is a no-op.
///
/// `fingerprint` is the SHA-256 of the server's leaf cert; it is
/// stored alongside the ticket so a subsequent `load` against a
/// rotated / hijacked host can detect the change.
pub fn save(
    dir: &Path,
    host_port: &str,
    ticket: Option<&[u8]>,
    fingerprint: &[u8; 32],
) -> Result<()> {
    let Some(ticket) = ticket else { return Ok(()) };
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = ticket_path(dir, host_port);
    // Embed the save time so the TTL is computed from an authenticated
    // value rather than the externally-mutable mtime. A clock before
    // the epoch is clamped to 0 (the resulting age is then "ancient",
    // which only makes the ticket expire sooner -- the safe direction).
    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut body = Vec::with_capacity(HEADER_LEN_V2 + ticket.len());
    body.extend_from_slice(TICKET_FILE_MAGIC_V2);
    body.extend_from_slice(&now_secs.to_be_bytes());
    body.extend_from_slice(fingerprint);
    body.extend_from_slice(ticket);
    write_owner_only(&path, &body)
}

#[cfg(unix)]
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // Write into a sibling temp + atomic rename so a concurrent
    // reader never sees a half-written ticket. The rename also
    // refreshes mtime, which our TTL check relies on.
    //
    // The temp filename carries a pid + monotonic counter suffix:
    // two concurrent saves for the same host:port (e.g. a `put-multi
    // --to host,host` fanout) would otherwise share one deterministic
    // temp path, interleave their `write_all`s, and rename a
    // mixed-content blob into place. Each writer here gets its own
    // temp; whichever rename runs last publishes a well-formed (if
    // not necessarily newest) ticket.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "ticket.tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("failed to open {}", tmp.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    f.sync_all().ok();
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    // See the unix branch for why the temp path carries a random-ish
    // pid + counter suffix.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "ticket.tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .with_context(|| format!("failed to open {}", tmp.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Persist a ticket extracted from a live quiche connection,
/// computing the fingerprint binding automatically from the
/// peer cert. Returns `Ok(())` and saves nothing if the connection
/// did not produce a session or did not present a leaf cert.
pub fn save_from_conn(dir: &Path, host_port: &str, conn: &quiche::Connection) -> Result<()> {
    let Some(ticket) = conn.session() else {
        return Ok(());
    };
    let Some(der) = conn.peer_cert() else {
        return Ok(());
    };
    let fp = crate::known_hosts::fingerprint_sha256(der);
    save(dir, host_port, Some(ticket), &fp)
}

/// Delete a stored ticket. Used when the server explicitly rejects
/// resumption so we don't keep replaying a bad ticket.
pub fn forget(dir: &Path, host_port: &str) -> Result<()> {
    let path = ticket_path(dir, host_port);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!(e).context(format!("failed to remove {}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const ZERO_FP: [u8; 32] = [0u8; 32];

    #[test]
    fn save_then_load_roundtrips() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let ticket = b"opaque-bytes".to_vec();
        save(dir, "host:4433", Some(&ticket), &ZERO_FP).unwrap();
        assert_eq!(load(dir, "host:4433", None).as_deref(), Some(&ticket[..]));
    }

    #[test]
    fn load_with_matching_fingerprint_returns_ticket() {
        // TOFU caller passes the pinned fingerprint and gets
        // the ticket back when it matches.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let mut fp = [0u8; 32];
        fp[0] = 0xab;
        save(dir, "host:4433", Some(b"opaque"), &fp).unwrap();
        assert_eq!(
            load(dir, "host:4433", Some(&fp)).as_deref(),
            Some(&b"opaque"[..])
        );
    }

    #[test]
    fn load_with_mismatched_fingerprint_purges_ticket() {
        // A fingerprint that doesn't match the stored binding
        // means the host is now a different physical server (DNS
        // repoint or cert rotation). Drop the ticket.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let mut fp = [0u8; 32];
        fp[0] = 0xab;
        save(dir, "host:4433", Some(b"opaque"), &fp).unwrap();
        let mut wrong = [0u8; 32];
        wrong[0] = 0xcd;
        assert!(load(dir, "host:4433", Some(&wrong)).is_none());
        // The bad ticket was purged.
        let path = ticket_path(dir, "host:4433");
        assert!(!path.exists());
    }

    #[test]
    fn load_missing_is_none() {
        let tmp = TempDir::new().unwrap();
        assert!(load(tmp.path(), "host:4433", None).is_none());
    }

    #[test]
    fn save_none_is_noop() {
        let tmp = TempDir::new().unwrap();
        save(tmp.path(), "host:4433", None, &ZERO_FP).unwrap();
        assert!(load(tmp.path(), "host:4433", None).is_none());
    }

    #[test]
    fn ticket_path_sanitises_separators() {
        let p = ticket_path(Path::new("/tmp"), "[::1]:4433");
        // No raw colons in the filename.
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(!name.contains(':'));
        assert!(name.ends_with(".ticket"));
    }

    #[test]
    fn forget_removes_existing_and_tolerates_missing() {
        let tmp = TempDir::new().unwrap();
        save(tmp.path(), "host:4433", Some(b"data"), &ZERO_FP).unwrap();
        forget(tmp.path(), "host:4433").unwrap();
        assert!(load(tmp.path(), "host:4433", None).is_none());
        // Second call is a noop, not an error.
        forget(tmp.path(), "host:4433").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_0600_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        save(tmp.path(), "host:4433", Some(b"data"), &ZERO_FP).unwrap();
        let meta = std::fs::metadata(ticket_path(tmp.path(), "host:4433")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn expired_ticket_is_dropped() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        save(dir, "host:4433", Some(b"data"), &ZERO_FP).unwrap();
        let path = ticket_path(dir, "host:4433");
        // Backdate mtime past the TTL with libc::utimes.
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let stale = now_secs - TICKET_TTL.as_secs() as i64 - 60;
        let times = [
            libc::timeval {
                tv_sec: stale,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: stale,
                tv_usec: 0,
            },
        ];
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
        assert_eq!(rc, 0, "utimes failed");
        assert!(load(dir, "host:4433", None).is_none());
        // load() drops the stale file as a side effect.
        assert!(!path.exists());
    }

    // Compose a raw V2 ticket file with an explicit embedded timestamp.
    fn v2_bytes(saved_at_secs: u64, fp: &[u8; 32], ticket: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(TICKET_FILE_MAGIC_V2);
        body.extend_from_slice(&saved_at_secs.to_be_bytes());
        body.extend_from_slice(fp);
        body.extend_from_slice(ticket);
        body
    }

    // Compose a raw V1 (no embedded timestamp) ticket file.
    fn v1_bytes(fp: &[u8; 32], ticket: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(TICKET_FILE_MAGIC_V1);
        body.extend_from_slice(fp);
        body.extend_from_slice(ticket);
        body
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn save_writes_v2_with_embedded_timestamp() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        save(dir, "host:4433", Some(b"opaque"), &ZERO_FP).unwrap();
        let raw = std::fs::read(ticket_path(dir, "host:4433")).unwrap();
        assert_eq!(&raw[..MAGIC_LEN], TICKET_FILE_MAGIC_V2);
        let ts_bytes: [u8; 8] = raw[MAGIC_LEN..MAGIC_LEN + TIMESTAMP_LEN]
            .try_into()
            .unwrap();
        let saved = u64::from_be_bytes(ts_bytes);
        // Timestamp is within a minute of "now".
        assert!(now_secs().abs_diff(saved) < 60, "embedded ts must be ~now");
        assert_eq!(&raw[HEADER_LEN_V2..], b"opaque");
    }

    #[test]
    fn stale_embedded_timestamp_dropped_even_with_fresh_mtime() {
        // The core fix: a fresh mtime must NOT resurrect a ticket whose
        // authenticated embedded timestamp is past the TTL. Simulates a
        // local attacker `touch`-ing a stolen/old ticket.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let stale = now_secs() - TICKET_TTL.as_secs() - 60;
        let path = ticket_path(dir, "host:4433");
        std::fs::write(&path, v2_bytes(stale, &ZERO_FP, b"opaque")).unwrap();
        // The file was just written, so its mtime is "now" (fresh). The
        // embedded timestamp is what must gate freshness here.
        assert!(load(dir, "host:4433", None).is_none());
        assert!(!path.exists(), "stale-by-embedded-ts ticket must be purged");
    }

    #[test]
    fn fresh_embedded_timestamp_loads() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let path = ticket_path(dir, "host:4433");
        std::fs::write(&path, v2_bytes(now_secs(), &ZERO_FP, b"opaque")).unwrap();
        assert_eq!(
            load(dir, "host:4433", None).as_deref(),
            Some(&b"opaque"[..])
        );
    }

    #[test]
    fn far_future_embedded_timestamp_dropped() {
        // An attacker-set far-future timestamp must NOT be accepted
        // indefinitely. Computing age in raw seconds (rather than
        // letting duration_since error out and clamping to zero age)
        // means a timestamp beyond the small skew grace is dropped.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let path = ticket_path(dir, "host:4433");
        let future = now_secs() + TICKET_TTL.as_secs() * 10;
        std::fs::write(&path, v2_bytes(future, &ZERO_FP, b"opaque")).unwrap();
        assert!(load(dir, "host:4433", None).is_none());
        assert!(!path.exists(), "far-future ticket must be purged");
    }

    #[test]
    fn within_grace_future_timestamp_loads() {
        // A small forward skew (NTP step between two puts on the same
        // box) is tolerated so resumption still works.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let path = ticket_path(dir, "host:4433");
        let slightly_future = now_secs() + FUTURE_SKEW_GRACE / 2;
        std::fs::write(&path, v2_bytes(slightly_future, &ZERO_FP, b"opaque")).unwrap();
        assert_eq!(
            load(dir, "host:4433", None).as_deref(),
            Some(&b"opaque"[..])
        );
    }

    #[test]
    fn overflow_embedded_timestamp_dropped_not_demoted_to_mtime() {
        // A u64::MAX timestamp must be dropped, not silently demoted to
        // the mtime path (which a fresh mtime would then pass). This is
        // the second indefinite-acceptance door the raw-seconds age
        // computation closes.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let path = ticket_path(dir, "host:4433");
        std::fs::write(&path, v2_bytes(u64::MAX, &ZERO_FP, b"opaque")).unwrap();
        // Fresh mtime (just written), but the overflowing embedded ts
        // governs and rejects it.
        assert!(load(dir, "host:4433", None).is_none());
        assert!(!path.exists(), "overflow ticket must be purged");
    }

    #[cfg(unix)]
    #[test]
    fn v1_ticket_loads_via_mtime_fallback() {
        // Backward compat: a V1 file has no embedded timestamp, so the
        // mtime is the only freshness source. A fresh mtime loads it.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let mut fp = [0u8; 32];
        fp[0] = 0xab;
        let path = ticket_path(dir, "host:4433");
        std::fs::write(&path, v1_bytes(&fp, b"legacy-opaque")).unwrap();
        assert_eq!(
            load(dir, "host:4433", Some(&fp)).as_deref(),
            Some(&b"legacy-opaque"[..])
        );
    }

    #[cfg(unix)]
    #[test]
    fn v1_ticket_dropped_when_mtime_stale() {
        // Backward compat: a V1 file past the TTL by mtime is still
        // dropped (its only freshness gate), no panic / misparse.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let path = ticket_path(dir, "host:4433");
        std::fs::write(&path, v1_bytes(&ZERO_FP, b"legacy")).unwrap();
        let stale = now_secs() as i64 - TICKET_TTL.as_secs() as i64 - 60;
        let times = [
            libc::timeval {
                tv_sec: stale,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: stale,
                tv_usec: 0,
            },
        ];
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
        assert_eq!(rc, 0, "utimes failed");
        assert!(load(dir, "host:4433", None).is_none());
        assert!(!path.exists());
    }

    #[test]
    fn legacy_headerless_ticket_still_loads() {
        // A pre-binding file with no recognised magic loads
        // unconditionally (subject only to the mtime fast-path) when no
        // fingerprint is required, preserving the original behaviour.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let path = ticket_path(dir, "host:4433");
        std::fs::write(&path, b"no-header-just-bytes").unwrap();
        assert_eq!(
            load(dir, "host:4433", None).as_deref(),
            Some(&b"no-header-just-bytes"[..])
        );
    }

    #[test]
    fn ticket_path_dotdot_host_stays_within_dir() {
        // A '..' host must not address the parent of `dir`.
        let dir = Path::new("/tmp/qftp-tickets");
        let p = ticket_path(dir, "..");
        assert_eq!(p.parent().unwrap(), dir, "must stay inside dir");
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(
            !name.starts_with(".."),
            "component must not be '..'; got {name}"
        );
        assert_eq!(name, "_.ticket");

        // A '.' host likewise.
        let p_dot = ticket_path(dir, ".");
        assert_eq!(p_dot.parent().unwrap(), dir);
        assert_eq!(p_dot.file_name().unwrap().to_string_lossy(), "_.ticket");

        // A host that merely embeds dots is left intact (already safe
        // since slashes are mapped, so it stays one filename component).
        let p_embed = ticket_path(dir, "..foo");
        assert_eq!(p_embed.parent().unwrap(), dir);
        assert_eq!(
            p_embed.file_name().unwrap().to_string_lossy(),
            "..foo.ticket"
        );
    }
}
