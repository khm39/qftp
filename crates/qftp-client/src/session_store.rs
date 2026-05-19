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

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};

/// Magic + version header prepended to every ticket file written by
/// versions that bind the ticket to a server-cert fingerprint (#122).
/// Files without this header are treated as "no binding, load
/// unconditionally" for backward compatibility.
const TICKET_FILE_MAGIC: &[u8; 8] = b"QFT1\0FP\n";
const FINGERPRINT_LEN: usize = 32;
const HEADER_LEN: usize = TICKET_FILE_MAGIC.len() + FINGERPRINT_LEN;

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
    dir.join(format!("{safe}.ticket"))
}

/// Load a ticket for `host_port` from `dir` if it exists and is
/// fresh. Returns `None` for missing / expired / unreadable
/// tickets so the caller can fall through to a 1-RTT handshake.
///
/// `expected_fingerprint` (#122) lets a TOFU caller bind the saved
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
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age > TICKET_TTL {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    let raw = std::fs::read(&path).ok()?;
    let (stored_fp, ticket_bytes) = match parse_ticket_file(&raw) {
        Some(parts) => parts,
        None => {
            // Legacy (no header) file. No binding to verify.
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
    if let Some(want) = expected_fingerprint {
        if stored_fp != want {
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
    Some(ticket_bytes.to_vec())
}

fn parse_ticket_file(buf: &[u8]) -> Option<(&[u8; 32], &[u8])> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    if &buf[..TICKET_FILE_MAGIC.len()] != TICKET_FILE_MAGIC {
        return None;
    }
    let fp: &[u8; 32] = buf[TICKET_FILE_MAGIC.len()..HEADER_LEN].try_into().ok()?;
    Some((fp, &buf[HEADER_LEN..]))
}

/// Persist a ticket for `host_port` into `dir`. Creates the
/// directory if needed; mode 0600 on Unix. A `None` ticket means
/// "the connection didn't produce a session", which is a no-op.
///
/// `fingerprint` is the SHA-256 of the server's leaf cert; it is
/// stored alongside the ticket so a subsequent `load` against a
/// rotated / hijacked host can detect the change (#122).
pub fn save(
    dir: &Path,
    host_port: &str,
    ticket: Option<&[u8]>,
    fingerprint: &[u8; 32],
) -> Result<()> {
    let Some(ticket) = ticket else { return Ok(()) };
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = ticket_path(dir, host_port);
    let mut body = Vec::with_capacity(HEADER_LEN + ticket.len());
    body.extend_from_slice(TICKET_FILE_MAGIC);
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
    let tmp = path.with_extension("ticket.tmp");
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
    let tmp = path.with_extension("ticket.tmp");
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
/// computing the fingerprint binding (#122) automatically from the
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
        // #122: TOFU caller passes the pinned fingerprint and gets
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
        // #122: a fingerprint that doesn't match the stored binding
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
}
