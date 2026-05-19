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

/// #140: per-field upper bounds enforced after `recv_message` returns
/// a decoded message but before any further processing. The frame as
/// a whole is already capped at `MAX_MESSAGE_SIZE` (16 MiB) by
/// `decode_framed_message`, but bincode's `with_limit` does not cap
/// any single `String`/`Vec` field below the frame size: a peer can
/// pack the entire 16 MiB into one `path` and the decoder will
/// happily allocate it. Defense in depth against that.
///
/// Limits chosen to be comfortably above any realistic legitimate
/// input but well below the frame cap:
///   * paths: 4 KiB (POSIX PATH_MAX is 4096; longer values would
///     never resolve on a real filesystem anyway)
///   * error messages: 1 KiB (human-readable diagnostics)
///   * directory listings: 100 000 entries (a single Ls response
///     larger than this is itself an abuse vector and should be
///     refused at the source).
pub const MAX_PATH_LEN: usize = 4 * 1024;
pub const MAX_ERROR_MESSAGE_LEN: usize = 1024;
pub const MAX_DIR_ENTRIES: usize = 100_000;

/// Errors surfaced by [`validate_request`] / [`validate_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError(pub String);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ValidationError {}

fn check_path(field: &str, value: &str) -> Result<(), ValidationError> {
    if value.len() > MAX_PATH_LEN {
        return Err(ValidationError(format!(
            "{field} field is {} bytes, exceeds MAX_PATH_LEN ({MAX_PATH_LEN}) (#140)",
            value.len()
        )));
    }
    Ok(())
}

/// Apply [`MAX_PATH_LEN`] / [`MAX_ERROR_MESSAGE_LEN`] sanity caps to
/// a decoded [`Request`]. Call this immediately after `recv_message`
/// on the server before dispatching. Variants without bounded string
/// fields are no-ops.
pub fn validate_request(req: &Request) -> Result<(), ValidationError> {
    match req {
        Request::Ls { path }
        | Request::Cd { path }
        | Request::Get { path, .. }
        | Request::Put { path, .. }
        | Request::Mkdir { path }
        | Request::Rmdir { path }
        | Request::Rm { path }
        | Request::Chmod { path, .. }
        | Request::Stat { path } => check_path("path", path),
        Request::Rename { from, to } => {
            check_path("from", from)?;
            check_path("to", to)
        }
        Request::Pwd | Request::Quit | Request::Quota => Ok(()),
    }
}

/// Apply [`MAX_PATH_LEN`] / [`MAX_ERROR_MESSAGE_LEN`] / [`MAX_DIR_ENTRIES`]
/// caps to a decoded [`Response`]. Call this immediately after
/// `recv_message` on the client before dispatching.
pub fn validate_response(resp: &Response) -> Result<(), ValidationError> {
    match resp {
        Response::Err(e) => {
            if e.message.len() > MAX_ERROR_MESSAGE_LEN {
                return Err(ValidationError(format!(
                    "ErrorResponse.message is {} bytes, exceeds MAX_ERROR_MESSAGE_LEN ({MAX_ERROR_MESSAGE_LEN}) (#140)",
                    e.message.len()
                )));
            }
            Ok(())
        }
        Response::DirListing(entries) => {
            if entries.len() > MAX_DIR_ENTRIES {
                return Err(ValidationError(format!(
                    "DirListing has {} entries, exceeds MAX_DIR_ENTRIES ({MAX_DIR_ENTRIES}) (#140)",
                    entries.len()
                )));
            }
            for entry in entries {
                if entry.name.len() > MAX_PATH_LEN {
                    return Err(ValidationError(format!(
                        "DirEntry.name is {} bytes, exceeds MAX_PATH_LEN ({MAX_PATH_LEN}) (#140)",
                        entry.name.len()
                    )));
                }
            }
            Ok(())
        }
        Response::Path(p) => check_path("Path", p),
        Response::Ok
        | Response::FileStat(_)
        | Response::FileReady { .. }
        | Response::QuotaInfo { .. } => Ok(()),
    }
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
    /// `no_clobber` (#70): when true, the server refuses the upload
    /// with `AlreadyExists` if `path` already exists. Pre-existing
    /// behavior (silent overwrite) is preserved by the `#[serde(default)]`
    /// `false`.
    Put {
        path: String,
        size: u64,
        mode: u32,
        #[serde(default)]
        offset: u64,
        #[serde(default)]
        checksum: Option<[u8; 32]>,
        #[serde(default)]
        no_clobber: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            no_clobber: true,
        };
        match round_trip_request(&req) {
            Request::Put {
                path,
                size,
                mode,
                offset,
                checksum,
                no_clobber,
            } => {
                assert_eq!(path, "dir/file.bin");
                assert_eq!(size, 12345);
                assert_eq!(mode, 0o644);
                assert_eq!(offset, 4096);
                assert_eq!(checksum, Some([7u8; 32]));
                assert!(no_clobber);
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

    // #140 ------------------------------------------------------------

    #[test]
    fn validate_request_rejects_oversized_path() {
        let req = Request::Ls {
            path: "a".repeat(MAX_PATH_LEN + 1),
        };
        let e = validate_request(&req).unwrap_err();
        assert!(e.0.contains("#140"), "unexpected error: {e}");
    }

    #[test]
    fn validate_request_accepts_borderline_path() {
        let req = Request::Get {
            path: "a".repeat(MAX_PATH_LEN),
            offset: 0,
            length: None,
        };
        validate_request(&req).expect("MAX_PATH_LEN exactly should pass");
    }

    #[test]
    fn validate_request_checks_both_rename_fields() {
        let req = Request::Rename {
            from: "a".into(),
            to: "z".repeat(MAX_PATH_LEN + 1),
        };
        let e = validate_request(&req).unwrap_err();
        assert!(e.0.contains("to"), "expected `to` field cited, got: {e}");
    }

    #[test]
    fn validate_response_rejects_oversized_error_message() {
        let resp = Response::Err(ErrorResponse::new(
            ErrorCode::Internal,
            "x".repeat(MAX_ERROR_MESSAGE_LEN + 1),
        ));
        let e = validate_response(&resp).unwrap_err();
        assert!(e.0.contains("#140"), "unexpected error: {e}");
    }

    #[test]
    fn validate_response_rejects_huge_listing() {
        let entry = DirEntry {
            name: "x".into(),
            is_dir: false,
            size: 0,
            modified: 0,
            mode: 0o644,
        };
        // Build a listing one entry over the cap. Using zero-cost
        // clones because DirEntry's String is tiny.
        let entries = (0..MAX_DIR_ENTRIES + 1)
            .map(|_| DirEntry { ..entry.clone() })
            .collect();
        let resp = Response::DirListing(entries);
        let e = validate_response(&resp).unwrap_err();
        assert!(e.0.contains("MAX_DIR_ENTRIES"), "unexpected error: {e}");
    }
}
