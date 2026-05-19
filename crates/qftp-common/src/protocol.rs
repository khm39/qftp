//! Wire protocol shared by qftp-server and qftp-client.
//!
//! ## Versioning
//!
//! The ALPN identifier is `qftp/<major>` (currently `qftp/1`). Each
//! ALPN value implies a single wire-compatible major version; QUIC
//! refuses to establish a connection when neither side offers a
//! compatible value, which is the same effect as a Hello/Welcome
//! negotiation but with zero protocol round-trips. Minor extensions
//! within the major version are accommodated by `#[non_exhaustive]`
//! enums and `#[serde(default)]` fields, so older binaries silently
//! ignore newer fields they don't understand.
//!
//! ## Wire format
//!
//! Each protocol message is bincode-serialized into a length-prefixed
//! frame (4-byte big-endian length, then the payload). File body bytes
//! follow the framed `FileReady` response on the same stream and are
//! sized exactly by `FileReady::size`. When `checksum_follows` is set,
//! 32 raw bytes (BLAKE3 of the streamed body) follow immediately after
//! the body, with the QUIC stream FIN flag set on the last byte.

use serde::{Deserialize, Serialize};

/// Reject `name` as a directory-entry component if it can be used to
/// escape its parent on either side of the protocol. The check is
/// purely lexical and runs on values arriving from the network — i.e.
/// every `DirEntry.name` the client receives from a server, and every
/// path fragment the server hands back in a listing. Rules:
///
///   - empty string
///   - "." or ".."
///   - any '/' (POSIX separator)
///   - any '\\' (Windows separator; rejected unconditionally so the
///     same listing is safe on both platforms)
///   - any NUL byte
///   - leading whitespace or control characters are not blocked here;
///     `Path::join` handles those harmlessly. Path-traversal is the
///     concern (#108 / SECURITY.md).
pub fn safe_entry_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    !name.contains(['/', '\\', '\0'])
}

/// ALPN value advertised over QUIC. The trailing major version lets us
/// retire wire-incompatible revisions cleanly.
pub const ALPN: &[u8] = b"qftp/1";

/// Major protocol version, embedded in ALPN. Bumping this breaks wire
/// compatibility with older clients.
pub const PROTOCOL_MAJOR: u16 = 1;

/// Machine-readable error category. Scripts and recursive transfers
/// check this rather than parsing the human-readable message.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Path resolution found no such file or directory.
    NotFound,
    /// ACL or filesystem permission check refused the operation.
    PermissionDenied,
    /// Destination exists when the operation requires it not to.
    AlreadyExists,
    /// Operation expected a directory and got a regular file (or vice versa).
    NotADirectory,
    IsADirectory,
    /// Payload exceeds the server's configured maximum.
    FileTooLarge,
    /// Peer sent more body bytes than its Put declared.
    UploadOverflow,
    /// Peer sent FIN before delivering its declared body bytes.
    UploadTruncated,
    /// BLAKE3 checksum verification failed.
    ChecksumMismatch,
    /// In-connection rate limit kicked in.
    RateLimited,
    /// Malformed protocol frame.
    Malformed,
    /// Server-side I/O or unexpected internal error.
    Internal,
    /// Authentication failed or the user is not configured.
    Unauthorized,
    /// Range / resume offset isn't valid for this file.
    InvalidRange,
    /// Feature isn't supported by this version of the protocol.
    Unsupported,
    /// The operation would push the user past their configured quota.
    QuotaExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorResponse {
    pub fn new(code: ErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code,
            message: msg.into(),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Ls {
        path: String,
    },
    Cd {
        path: String,
    },
    Pwd,
    /// Download. `offset` lets clients resume an interrupted transfer;
    /// `length: Some(n)` requests exactly `n` bytes (capped at file end),
    /// `None` means "to EOF".
    Get {
        path: String,
        #[serde(default)]
        offset: u64,
        #[serde(default)]
        length: Option<u64>,
    },
    /// Upload. `offset` lets clients append to a server-side `.partial`
    /// from where they left off; the server validates that the existing
    /// temp matches that offset before accepting more bytes. `checksum`
    /// (BLAKE3) is verified after the last byte is written.
    Put {
        path: String,
        size: u64,
        mode: u32,
        #[serde(default)]
        offset: u64,
        #[serde(default)]
        checksum: Option<[u8; 32]>,
    },
    Mkdir {
        path: String,
    },
    Rmdir {
        path: String,
    },
    Rm {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Chmod {
        path: String,
        mode: u32,
    },
    Stat {
        path: String,
    },
    /// Report on the user's storage usage and quota. The server walks
    /// the requesting user's home and aggregates total bytes + file
    /// count. Has no path argument; the home is implicit in the
    /// authenticated user.
    Quota,
    Quit,
}

/// #140: per-field length caps applied on top of the frame-wide
/// `MAX_MESSAGE_SIZE` (16 MiB) limit in `recv_message`. The frame cap
/// alone lets a single `path` String be up to 16 MiB, which is two
/// orders of magnitude beyond POSIX `PATH_MAX`. Refusing absurdly long
/// fields up front is defense in depth — it shrinks worst-case memory
/// per accepted request and avoids surprising downstream paths that
/// were never designed for multi-MiB strings.
pub const MAX_PATH_FIELD_LEN: usize = 4096;
pub const MAX_ERROR_MESSAGE_LEN: usize = 1024;
pub const MAX_DIR_LISTING_ENTRIES: usize = 100_000;

impl Request {
    /// Reject Requests whose String fields exceed per-field caps.
    /// Returns an error code suitable for sending back to the peer.
    pub fn validate_field_lengths(&self) -> Result<(), &'static str> {
        let check_path = |s: &str| -> Result<(), &'static str> {
            if s.len() > MAX_PATH_FIELD_LEN {
                Err("path field exceeds MAX_PATH_FIELD_LEN")
            } else {
                Ok(())
            }
        };
        match self {
            Request::Ls { path }
            | Request::Cd { path }
            | Request::Get { path, .. }
            | Request::Put { path, .. }
            | Request::Mkdir { path }
            | Request::Rmdir { path }
            | Request::Rm { path }
            | Request::Chmod { path, .. }
            | Request::Stat { path } => check_path(path),
            Request::Rename { from, to } => {
                check_path(from)?;
                check_path(to)
            }
            Request::Pwd | Request::Quota | Request::Quit => Ok(()),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Err(ErrorResponse),
    DirListing(Vec<DirEntry>),
    Path(String),
    FileStat(FileStat),
    /// Sent immediately before the body bytes for Get. `size` is the
    /// number of bytes the server is about to stream (post-offset and
    /// post-length clamping). `total_size` is the file's full size on
    /// disk so the client can detect truncation across resume sessions.
    /// When `checksum_follows` is true, the 32 bytes immediately after
    /// the body are the BLAKE3 hash of the streamed body; the client
    /// verifies them. Computing the hash inline avoids a second file
    /// read on the server side.
    FileReady {
        size: u64,
        #[serde(default)]
        total_size: u64,
        #[serde(default)]
        checksum_follows: bool,
    },
    /// Reply to `Request::Quota`. `limit_bytes = None` means "no
    /// quota configured" (unlimited).
    QuotaInfo {
        used_bytes: u64,
        file_count: u64,
        #[serde(default)]
        limit_bytes: Option<u64>,
    },
}

impl Response {
    /// Reject Responses whose variable-size fields exceed per-field
    /// caps. Mirrors `Request::validate_field_lengths` on the client
    /// side: a hostile server could otherwise hand the client a
    /// multi-MiB ErrorResponse.message or a DirListing with millions
    /// of entries. See #140.
    pub fn validate_field_lengths(&self) -> Result<(), &'static str> {
        match self {
            Response::Err(e) => {
                if e.message.len() > MAX_ERROR_MESSAGE_LEN {
                    Err("ErrorResponse message exceeds MAX_ERROR_MESSAGE_LEN")
                } else {
                    Ok(())
                }
            }
            Response::DirListing(entries) => {
                if entries.len() > MAX_DIR_LISTING_ENTRIES {
                    Err("DirListing exceeds MAX_DIR_LISTING_ENTRIES")
                } else {
                    Ok(())
                }
            }
            Response::Path(p) => {
                if p.len() > MAX_PATH_FIELD_LEN {
                    Err("Path response exceeds MAX_PATH_FIELD_LEN")
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: u64,
    pub mode: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileStat {
    pub size: u64,
    pub is_dir: bool,
    pub modified: u64,
    pub mode: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request(req: &Request) -> Request {
        let bytes = bincode::serialize(req).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    fn round_trip_response(resp: &Response) -> Response {
        let bytes = bincode::serialize(resp).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    #[test]
    fn put_request_round_trip() {
        let req = Request::Put {
            path: "dir/file.bin".into(),
            size: 12345,
            mode: 0o644,
            offset: 4096,
            checksum: Some([7u8; 32]),
        };
        match round_trip_request(&req) {
            Request::Put {
                path,
                size,
                mode,
                offset,
                checksum,
            } => {
                assert_eq!(path, "dir/file.bin");
                assert_eq!(size, 12345);
                assert_eq!(mode, 0o644);
                assert_eq!(offset, 4096);
                assert_eq!(checksum, Some([7u8; 32]));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn get_request_with_range_round_trip() {
        let req = Request::Get {
            path: "big.iso".into(),
            offset: 1024 * 1024,
            length: Some(8 * 1024 * 1024),
        };
        match round_trip_request(&req) {
            Request::Get {
                path,
                offset,
                length,
            } => {
                assert_eq!(path, "big.iso");
                assert_eq!(offset, 1024 * 1024);
                assert_eq!(length, Some(8 * 1024 * 1024));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn dir_listing_round_trip() {
        let resp = Response::DirListing(vec![DirEntry {
            name: "a".into(),
            is_dir: false,
            size: 1,
            modified: 2,
            mode: 0o600,
        }]);
        match round_trip_response(&resp) {
            Response::DirListing(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "a");
                assert_eq!(entries[0].mode, 0o600);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn file_ready_response_round_trip() {
        let resp = Response::FileReady {
            size: 99,
            total_size: 200,
            checksum_follows: true,
        };
        match round_trip_response(&resp) {
            Response::FileReady {
                size,
                total_size,
                checksum_follows,
            } => {
                assert_eq!(size, 99);
                assert_eq!(total_size, 200);
                assert!(checksum_follows);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn safe_entry_name_rejects_traversal() {
        assert!(!safe_entry_name(""));
        assert!(!safe_entry_name("."));
        assert!(!safe_entry_name(".."));
        assert!(!safe_entry_name("a/b"));
        assert!(!safe_entry_name("..\\foo"));
        assert!(!safe_entry_name("foo\0bar"));
        assert!(!safe_entry_name("/etc/passwd"));
        assert!(safe_entry_name("normal.txt"));
        assert!(safe_entry_name("file with spaces"));
        assert!(safe_entry_name("ünicode-ok"));
        assert!(safe_entry_name("..hidden"));
    }

    #[test]
    fn err_response_round_trip() {
        let resp = Response::Err(ErrorResponse::new(ErrorCode::NotFound, "missing"));
        match round_trip_response(&resp) {
            Response::Err(e) => {
                assert_eq!(e.code, ErrorCode::NotFound);
                assert_eq!(e.message, "missing");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn alpn_carries_major() {
        assert_eq!(ALPN, b"qftp/1");
        assert_eq!(PROTOCOL_MAJOR, 1);
    }

    #[test]
    fn request_field_caps_accept_reasonable_paths() {
        let r = Request::Ls {
            path: "a".repeat(MAX_PATH_FIELD_LEN),
        };
        assert!(r.validate_field_lengths().is_ok());
    }

    #[test]
    fn request_field_caps_reject_oversized_path() {
        let r = Request::Ls {
            path: "a".repeat(MAX_PATH_FIELD_LEN + 1),
        };
        assert!(r.validate_field_lengths().is_err());
    }

    #[test]
    fn request_field_caps_reject_oversized_rename_to() {
        let r = Request::Rename {
            from: "ok".into(),
            to: "z".repeat(MAX_PATH_FIELD_LEN + 1),
        };
        assert!(r.validate_field_lengths().is_err());
    }

    #[test]
    fn response_field_caps_reject_oversized_err_message() {
        let r = Response::Err(ErrorResponse::new(
            ErrorCode::Internal,
            "x".repeat(MAX_ERROR_MESSAGE_LEN + 1),
        ));
        assert!(r.validate_field_lengths().is_err());
    }
}
