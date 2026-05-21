//! TOFU (Trust On First Use) server-cert pinning, modelled on SSH's
//! `known_hosts`.
//!
//! ## File format
//!
//! One entry per line. Comments (`#`) and blank lines are ignored.
//! Each entry pairs a `host:port` with the SHA-256 fingerprint of the
//! server's leaf certificate (DER-encoded):
//!
//! ```text
//! # ~/.qftp/known_hosts -- managed by qftp-client --trust-on-first-use
//! files.example:4433 sha256:9c8f5d...
//! 127.0.0.1:4433 sha256:0123ab...
//! ```
//!
//! ## Security model
//!
//! TOFU shifts trust to the **first** connection: whoever is on the
//! wire when you first connect becomes your trusted server. Subsequent
//! connections are pinned. This is exactly the SSH `known_hosts`
//! model, with the same limitation.
//!
//! Because quiche does not (yet) expose a custom-verifier hook for
//! TLS 1.3, we run TOFU *after* the handshake completes: we ask quiche
//! to skip its own peer verification (`verify_peer(false)`) and then
//! compare the leaf cert fingerprint to the pinned value. On mismatch
//! we close the connection immediately. The MitM window is the same
//! as SSH's: the attacker can complete the handshake but cannot
//! retain trust once the fingerprint check runs.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

/// A single pinned `(host:port, sha256-fingerprint)` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub host_port: String,
    /// Lowercase hex SHA-256 of the leaf cert's DER bytes, 64 chars.
    pub fingerprint_hex: String,
}

/// In-memory view of the known_hosts file.
#[derive(Debug, Default)]
pub struct KnownHosts {
    entries: Vec<Entry>,
}

/// Outcome of looking up a `(host:port, fingerprint)` pair.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No prior entry for this host. Caller should pin it.
    New,
    /// Prior entry matches. Connect silently.
    Match,
    /// Prior entry exists but the fingerprint differs. Caller MUST
    /// abort the connection. The pinned value is returned for the
    /// diagnostic.
    Mismatch { pinned: String },
}

impl KnownHosts {
    /// Read `path`. A missing file is not an error — we return an
    /// empty file the caller can append to.
    pub fn load(path: &Path) -> Result<Self> {
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(e).with_context(|| format!("failed to open {}", path.display()));
            }
        };
        Self::from_reader(BufReader::new(f))
    }

    pub fn from_reader<R: BufRead>(reader: R) -> Result<Self> {
        let mut entries = Vec::new();
        for (lineno, line) in reader.lines().enumerate() {
            let line = line.context("read known_hosts line")?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Lenient parse: malformed lines are skipped with a
            // warning rather than aborting the whole load. A typo'd
            // entry should not lock the user out of every host.
            let mut it = trimmed.split_whitespace();
            let host_port = match it.next() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let fp = match it.next() {
                Some(s) => s,
                None => {
                    tracing::warn!(line = lineno + 1, "known_hosts: skipping malformed entry");
                    continue;
                }
            };
            let Some(hex) = fp.strip_prefix("sha256:") else {
                tracing::warn!(
                    line = lineno + 1,
                    "known_hosts: skipping entry with unsupported algorithm"
                );
                continue;
            };
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                tracing::warn!(
                    line = lineno + 1,
                    "known_hosts: skipping entry with malformed fingerprint"
                );
                continue;
            }
            entries.push(Entry {
                host_port,
                fingerprint_hex: hex.to_ascii_lowercase(),
            });
        }
        Ok(KnownHosts { entries })
    }

    /// Raw 32-byte fingerprint pinned for `host_port`, if an entry
    /// exists. Used to bind a stored 0-RTT session ticket to the pinned
    /// server identity before the handshake runs. Returns `None` for an
    /// unknown host (nothing to bind to yet) or an entry whose hex is
    /// not exactly 32 bytes.
    pub fn pinned_fingerprint(&self, host_port: &str) -> Option<[u8; 32]> {
        let entry = self.entries.iter().find(|e| e.host_port == host_port)?;
        decode_fingerprint_hex(&entry.fingerprint_hex)
    }

    pub fn lookup(&self, host_port: &str, fingerprint_hex: &str) -> Verdict {
        let want = fingerprint_hex.to_ascii_lowercase();
        for e in &self.entries {
            if e.host_port == host_port {
                return if e.fingerprint_hex == want {
                    Verdict::Match
                } else {
                    Verdict::Mismatch {
                        pinned: e.fingerprint_hex.clone(),
                    }
                };
            }
        }
        Verdict::New
    }

    /// Append a new entry to `path`. Creates the file (and parent
    /// directory) if needed. Mode is set to 0600 on Unix so a
    /// fingerprint database isn't world-readable.
    pub fn append_to_file(path: &Path, host_port: &str, fingerprint_hex: &str) -> Result<()> {
        // Refuse to write host strings that could inject extra
        // (attacker-pinned) entries on adjacent lines. The host_port
        // value originates from a CLI argument / config / URL and
        // could carry embedded newlines or framing-sensitive
        // whitespace.
        if !is_valid_host_port(host_port) {
            anyhow::bail!("refusing to pin host with disallowed characters: {host_port:?} (#114)");
        }
        if !is_valid_fingerprint_hex(fingerprint_hex) {
            anyhow::bail!("refusing to pin malformed fingerprint: {fingerprint_hex:?} (#114)");
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .with_context(|| format!("failed to open {} for append", path.display()))?;
        // Serialize concurrent `qftp-client -T` invocations so
        // we don't get duplicate or interleaved entries. flock is
        // released automatically when the File drops.
        let _guard = ExclusiveLock::acquire(&f)
            .with_context(|| format!("failed to flock {}", path.display()))?;
        writeln!(f, "{host_port} sha256:{fingerprint_hex}")
            .with_context(|| format!("failed to write {}", path.display()))?;
        f.sync_all().ok();
        Ok(())
    }
}

/// RAII guard that wraps `flock(LOCK_EX)`. Lock is dropped when the
/// guard goes out of scope. The caller must keep the underlying
/// `File` alive at least as long as the guard.
#[cfg(unix)]
struct ExclusiveLock(std::os::unix::io::RawFd);

#[cfg(not(unix))]
struct ExclusiveLock;

#[cfg(unix)]
impl ExclusiveLock {
    fn acquire(f: &File) -> std::io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let fd = f.as_raw_fd();
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(fd))
    }
}

#[cfg(not(unix))]
impl ExclusiveLock {
    fn acquire(_f: &File) -> std::io::Result<Self> {
        Ok(Self)
    }
}

#[cfg(unix)]
impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0, libc::LOCK_UN) };
    }
}

/// Lexical validation for a `host:port` string before we trust it
/// enough to write into `known_hosts`. Allows ASCII letters, digits,
/// `.`, `_`, `-`, plus `:` `[` `]` for bracketed IPv6 forms. Rejects
/// anything else (notably whitespace, including newlines).
fn is_valid_host_port(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '[' | ']'))
}

/// 64 lowercase or uppercase hex chars.
fn is_valid_fingerprint_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Decode a 64-char hex fingerprint into its 32 raw bytes. Returns
/// `None` for any string that is not exactly 64 hex digits.
fn decode_fingerprint_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *byte = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Compute the lowercase-hex SHA-256 of a DER-encoded leaf cert.
pub fn fingerprint_hex(der: &[u8]) -> String {
    let mut s = String::with_capacity(64);
    for b in fingerprint_sha256(der).iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Raw 32-byte SHA-256 of a DER-encoded leaf cert. Used for binary
/// binding fields like the session-ticket file header.
pub fn fingerprint_sha256(der: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Default path for the known_hosts file: `~/.qftp/known_hosts`.
/// Returns `None` if `$HOME` is unset (CI matrices, daemons).
pub fn default_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".qftp/known_hosts"))
}

/// Error builder for the "server cert changed" case. SSH-style banner
/// so the operator immediately knows what happened.
pub fn mismatch_error(host_port: &str, pinned: &str, seen: &str) -> anyhow::Error {
    anyhow!(
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
         @    WARNING: SERVER CERTIFICATE HAS CHANGED!             @\n\
         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
         IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n\
         Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n\
         It is also possible that the server certificate has just been changed.\n\
         The SHA-256 fingerprint for the certificate sent by the remote host is\n\
           sha256:{seen}\n\
         Please contact your administrator. To get rid of this message, remove\n\
         the {host_port} entry from ~/.qftp/known_hosts.\n\
         Pinned fingerprint was sha256:{pinned}",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    #[test]
    fn parse_comments_and_blank_lines() {
        let src = b"# header comment\n\n  \nfoo:1 sha256:aa\n";
        // Last line malformed (fingerprint too short) -- skipped.
        let kh = KnownHosts::from_reader(Cursor::new(&src[..])).unwrap();
        assert!(kh.entries.is_empty());
    }

    #[test]
    fn parse_valid_entry() {
        let fp = "0".repeat(64);
        let src = format!("host:4433 sha256:{fp}\n");
        let kh = KnownHosts::from_reader(Cursor::new(src.as_bytes())).unwrap();
        assert_eq!(kh.entries.len(), 1);
        assert_eq!(kh.entries[0].host_port, "host:4433");
        assert_eq!(kh.entries[0].fingerprint_hex, fp);
    }

    #[test]
    fn lookup_match_mismatch_new() {
        let fp = "a".repeat(64);
        let other = "b".repeat(64);
        let src = format!("host:4433 sha256:{fp}\n");
        let kh = KnownHosts::from_reader(Cursor::new(src.as_bytes())).unwrap();
        assert_eq!(kh.lookup("host:4433", &fp), Verdict::Match);
        assert_eq!(
            kh.lookup("host:4433", &other),
            Verdict::Mismatch { pinned: fp.clone() }
        );
        assert_eq!(kh.lookup("unknown:4433", &fp), Verdict::New);
    }

    #[test]
    fn case_insensitive_fingerprint() {
        let fp_low = "abcdef".repeat(10) + "abcd";
        let fp_up = fp_low.to_ascii_uppercase();
        let src = format!("host:4433 sha256:{fp_up}\n");
        let kh = KnownHosts::from_reader(Cursor::new(src.as_bytes())).unwrap();
        assert_eq!(kh.lookup("host:4433", &fp_low), Verdict::Match);
    }

    #[test]
    fn skip_unsupported_algorithm() {
        let fp = "0".repeat(40);
        let src = format!("host:4433 sha1:{fp}\n");
        let kh = KnownHosts::from_reader(Cursor::new(src.as_bytes())).unwrap();
        assert!(kh.entries.is_empty());
    }

    #[test]
    fn append_creates_file_and_directory() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested/known_hosts");
        let fp = "f".repeat(64);
        KnownHosts::append_to_file(&path, "h:4433", &fp).unwrap();
        let kh = KnownHosts::load(&path).unwrap();
        assert_eq!(kh.entries.len(), 1);
        assert_eq!(kh.lookup("h:4433", &fp), Verdict::Match);
    }

    #[test]
    fn fingerprint_hex_is_deterministic_lowercase() {
        let fp = fingerprint_hex(b"abc");
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            fp,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn append_rejects_host_string_with_newline() {
        // A newline in host_port would inject an attacker-pinned
        // entry on the next line. Refuse to write.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_hosts");
        let fp = "0".repeat(64);
        let err = KnownHosts::append_to_file(&path, "evil:4433\nvictim:4433 sha256:bad", &fp)
            .expect_err("expected append to refuse newline-laced host");
        assert!(err.to_string().contains("#114"), "unexpected error: {err}");
    }

    #[test]
    fn append_rejects_whitespace_in_host() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_hosts");
        let fp = "0".repeat(64);
        let err = KnownHosts::append_to_file(&path, "host with space:4433", &fp)
            .expect_err("expected append to refuse whitespace in host");
        assert!(err.to_string().contains("#114"));
    }

    #[test]
    fn append_rejects_malformed_fingerprint() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_hosts");
        let err = KnownHosts::append_to_file(&path, "h:4433", "not-hex")
            .expect_err("expected append to refuse non-hex fingerprint");
        assert!(err.to_string().contains("#114"));
    }

    #[test]
    fn append_accepts_bracketed_ipv6() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_hosts");
        let fp = "0".repeat(64);
        KnownHosts::append_to_file(&path, "[::1]:4433", &fp)
            .expect("bracketed IPv6 host should be accepted");
    }

    #[test]
    fn pinned_fingerprint_decodes_entry_and_misses_unknown_host() {
        let fp_hex = format!("ab{}", "00".repeat(31));
        let src = format!("host:4433 sha256:{fp_hex}\n");
        let kh = KnownHosts::from_reader(Cursor::new(src.as_bytes())).unwrap();
        let raw = kh
            .pinned_fingerprint("host:4433")
            .expect("known host should yield a fingerprint");
        assert_eq!(raw[0], 0xab);
        assert!(raw[1..].iter().all(|&b| b == 0));
        assert!(kh.pinned_fingerprint("unknown:4433").is_none());
    }

    #[test]
    fn pinned_fingerprint_round_trips_with_fingerprint_sha256() {
        let der = b"server-leaf-cert-der";
        let fp_hex = fingerprint_hex(der);
        let src = format!("srv:4433 sha256:{fp_hex}\n");
        let kh = KnownHosts::from_reader(Cursor::new(src.as_bytes())).unwrap();
        assert_eq!(
            kh.pinned_fingerprint("srv:4433"),
            Some(fingerprint_sha256(der))
        );
    }

    #[test]
    fn append_then_match_in_same_session() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_hosts");
        let fp = fingerprint_hex(b"server-cert-der");
        KnownHosts::append_to_file(&path, "srv:4433", &fp).unwrap();
        let kh = KnownHosts::load(&path).unwrap();
        assert_eq!(kh.lookup("srv:4433", &fp), Verdict::Match);
    }
}
