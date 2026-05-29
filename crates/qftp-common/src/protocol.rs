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
//! Each protocol message is bincode-serialized (fixint, little-endian;
//! enum tags are `u32`) into a length-prefixed frame (4-byte big-endian
//! length, then the payload). File body bytes follow the framed
//! `FileReady` response on the same stream and are sized exactly by
//! `FileReady::size`. When `checksum_follows` is set, the digest of the
//! streamed body follows immediately after the body (length = the
//! negotiated [`HashAlgorithm`]'s [`HashAlgorithm::digest_len`], BLAKE3
//! → 32 bytes), with the QUIC stream FIN flag set on the last byte.
//!
//! ## Numeric on-wire enums
//!
//! [`FileType`], [`HashAlgorithm`] and [`ErrorCode`] are encoded as a
//! single `u32` value (not a positional bincode index) via hand-written
//! [`Serialize`]/[`Deserialize`] impls, so unknown values decode to an
//! `Unknown(n)` variant instead of failing. [`Request`]/[`Response`]/
//! [`ErrorDetails`] keep derived serde; bincode already writes their
//! variant tag as a `u32`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
///     concern (SECURITY.md).
pub fn safe_entry_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    !name.contains(['/', '\\', '\0'])
}

/// Per-field upper bounds enforced after `recv_message` returns
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
mod limits {
    pub const MAX_PATH_LEN: usize = 4 * 1024;
    pub const MAX_ERROR_MESSAGE_LEN: usize = 1024;
    pub const MAX_DIR_ENTRIES: usize = 100_000;
}
pub use limits::*;

/// Errors surfaced by [`validate_request`] / [`validate_response`].
///
/// The variants are structured so callers can pattern-match on the
/// specific cap that was exceeded (path length vs. error-message length
/// vs. directory-entry count) instead of grepping `Display` text.
/// The `(#140)` tag in each `#[error(...)]` message refers to the
/// issue that introduced these caps and is preserved for grep
/// continuity with operator runbooks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    #[error("{field} field is {len} bytes, exceeds MAX_PATH_LEN ({max}) (#140)")]
    PathTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    #[error("ErrorResponse.message is {len} bytes, exceeds MAX_ERROR_MESSAGE_LEN ({max}) (#140)")]
    ErrorMessageTooLong { len: usize, max: usize },
    #[error("DirListing has {len} entries, exceeds MAX_DIR_ENTRIES ({max}) (#140)")]
    DirEntriesTooMany { len: usize, max: usize },
}

fn check_path(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.len() > MAX_PATH_LEN {
        return Err(ValidationError::PathTooLong {
            field,
            len: value.len(),
            max: MAX_PATH_LEN,
        });
    }
    Ok(())
}

/// Apply [`MAX_PATH_LEN`] / [`MAX_ERROR_MESSAGE_LEN`] sanity caps to
/// a decoded [`Request`]. Call this immediately after `recv_message`
/// on the server before dispatching. Variants without bounded string
/// fields are no-ops.
pub fn validate_request(req: &Request) -> Result<(), ValidationError> {
    match req {
        Request::Ls { path, .. }
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
                return Err(ValidationError::ErrorMessageTooLong {
                    len: e.message.len(),
                    max: MAX_ERROR_MESSAGE_LEN,
                });
            }
            Ok(())
        }
        Response::DirListing { entries, .. } => {
            if entries.len() > MAX_DIR_ENTRIES {
                return Err(ValidationError::DirEntriesTooMany {
                    len: entries.len(),
                    max: MAX_DIR_ENTRIES,
                });
            }
            for entry in entries {
                check_path("DirEntry.name", &entry.name)?;
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

/// File classification carried in [`DirEntry`] / [`FileStat`], encoded
/// on the wire as a `u32`. Unknown values decode to `Unknown(n)` so a
/// future server can add classifications without breaking old clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileType {
    #[default]
    Regular,
    Directory,
    Symlink,
    Other,
    Unknown(u32),
}

impl FileType {
    pub fn to_u32(self) -> u32 {
        match self {
            FileType::Regular => 0,
            FileType::Directory => 1,
            FileType::Symlink => 2,
            FileType::Other => 3,
            FileType::Unknown(n) => n,
        }
    }

    pub fn from_u32(n: u32) -> Self {
        match n {
            0 => FileType::Regular,
            1 => FileType::Directory,
            2 => FileType::Symlink,
            3 => FileType::Other,
            other => FileType::Unknown(other),
        }
    }
}

impl Serialize for FileType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.to_u32())
    }
}

impl<'de> Deserialize<'de> for FileType {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(FileType::from_u32(u32::deserialize(d)?))
    }
}

/// Content-hash algorithm negotiated for a transfer, encoded on the
/// wire as a `u32`. BLAKE3 is the only algorithm in qftp/1; the field
/// exists so a future algorithm can be added without a wire-major bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    #[default]
    Blake3,
    Unknown(u32),
}

impl HashAlgorithm {
    pub fn to_u32(self) -> u32 {
        match self {
            HashAlgorithm::Blake3 => 0,
            HashAlgorithm::Unknown(n) => n,
        }
    }

    pub fn from_u32(n: u32) -> Self {
        match n {
            0 => HashAlgorithm::Blake3,
            other => HashAlgorithm::Unknown(other),
        }
    }

    /// Length in bytes of this algorithm's digest, or `None` for an
    /// algorithm this build doesn't know how to compute. This is the
    /// size of the header `checksum` and the streamed trailer.
    pub fn digest_len(self) -> Option<usize> {
        match self {
            HashAlgorithm::Blake3 => Some(32),
            _ => None,
        }
    }
}

impl Serialize for HashAlgorithm {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.to_u32())
    }
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(HashAlgorithm::from_u32(u32::deserialize(d)?))
    }
}

/// Machine-readable error category, encoded on the wire as a numeric
/// `u32` status (class structure mirrors HTTP: `4xx` caller-caused,
/// `5xx` server-caused). Scripts and recursive transfers check this
/// rather than parsing the human-readable message. Unknown codes decode
/// to `Unknown(n)` and are classified by their leading digit.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// A numeric status this build doesn't have a named variant for.
    Unknown(u32),
}

/// Coarse classification of an [`ErrorCode`] by who caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Client,
    Server,
}

impl ErrorCode {
    pub fn to_u32(self) -> u32 {
        match self {
            ErrorCode::Malformed => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::PermissionDenied => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::Unsupported => 405,
            ErrorCode::AlreadyExists => 409,
            ErrorCode::FileTooLarge => 413,
            ErrorCode::InvalidRange => 416,
            ErrorCode::NotADirectory => 420,
            ErrorCode::IsADirectory => 421,
            ErrorCode::ChecksumMismatch => 422,
            ErrorCode::UploadOverflow => 423,
            ErrorCode::UploadTruncated => 424,
            ErrorCode::RateLimited => 429,
            ErrorCode::QuotaExceeded => 430,
            ErrorCode::Internal => 500,
            ErrorCode::Unknown(n) => n,
        }
    }

    pub fn from_u32(n: u32) -> Self {
        match n {
            400 => ErrorCode::Malformed,
            401 => ErrorCode::Unauthorized,
            403 => ErrorCode::PermissionDenied,
            404 => ErrorCode::NotFound,
            405 => ErrorCode::Unsupported,
            409 => ErrorCode::AlreadyExists,
            413 => ErrorCode::FileTooLarge,
            416 => ErrorCode::InvalidRange,
            420 => ErrorCode::NotADirectory,
            421 => ErrorCode::IsADirectory,
            422 => ErrorCode::ChecksumMismatch,
            423 => ErrorCode::UploadOverflow,
            424 => ErrorCode::UploadTruncated,
            429 => ErrorCode::RateLimited,
            430 => ErrorCode::QuotaExceeded,
            500 => ErrorCode::Internal,
            other => ErrorCode::Unknown(other),
        }
    }

    /// Who caused this error, by leading digit: `4xx` → client,
    /// `5xx` → server. Anything else defaults to server.
    pub fn class(self) -> ErrorClass {
        match self.to_u32() / 100 {
            4 => ErrorClass::Client,
            5 => ErrorClass::Server,
            _ => ErrorClass::Server,
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.to_u32())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(ErrorCode::from_u32(u32::deserialize(d)?))
    }
}

/// Structured, machine-readable supplement to an [`ErrorResponse`].
/// `u32`-tagged and `#[non_exhaustive]` so new detail kinds can be
/// added without a wire-major bump.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorDetails {
    /// Carried with [`ErrorCode::InvalidRange`].
    Range { offset: u64, file_size: u64 },
    /// Carried with [`ErrorCode::UploadOverflow`] / [`ErrorCode::UploadTruncated`].
    Upload { received: u64, declared: u64 },
    /// Carried with [`ErrorCode::RateLimited`].
    RetryAfter { millis: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub details: Option<ErrorDetails>,
}

impl ErrorResponse {
    pub fn new(code: ErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code,
            message: msg.into(),
            details: None,
        }
    }

    pub fn with_details(code: ErrorCode, msg: impl Into<String>, details: ErrorDetails) -> Self {
        Self {
            code,
            message: msg.into(),
            details: Some(details),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Ls {
        path: String,
        /// Opaque, server-defined pagination cursor echoed back from a
        /// prior `DirListing.next_cursor`. `None` requests the first
        /// page.
        #[serde(default)]
        cursor: Option<String>,
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
    /// (digest bytes for `hash_algorithm`) is verified after the last
    /// byte is written. `no_clobber`: when true, the server refuses the
    /// upload with `AlreadyExists` if `path` already exists. Pre-existing
    /// behavior (silent overwrite) is preserved by the `#[serde(default)]`
    /// `false`.
    Put {
        path: String,
        size: u64,
        mode: u32,
        #[serde(default)]
        offset: u64,
        /// Negotiated content-hash algorithm. Defaults to BLAKE3; the
        /// server refuses anything else with `Unsupported`.
        #[serde(default)]
        hash_algorithm: HashAlgorithm,
        /// Digest bytes (length = `hash_algorithm.digest_len()`).
        #[serde(default)]
        checksum: Option<Vec<u8>>,
        #[serde(default)]
        no_clobber: bool,
        /// When true, the client appends a digest trailer (length =
        /// `hash_algorithm.digest_len()`) on the same stream after the
        /// `size` body bytes. This lets the client hash as it sends
        /// instead of doing a full pre-send pass to populate the header
        /// `checksum` field. When false, `checksum` is authoritative
        /// (legacy path); `None` here with `checksum_trailer = false`
        /// means no verification at all (pre-existing behavior
        /// preserved).
        #[serde(default)]
        checksum_trailer: bool,
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
    /// Directory listing page. `next_cursor = Some(..)` signals more
    /// pages follow (echo it back in `Request::Ls.cursor`); `None`
    /// means this is the last page.
    DirListing {
        entries: Vec<DirEntry>,
        #[serde(default)]
        next_cursor: Option<String>,
    },
    Path(String),
    FileStat(FileStat),
    /// Sent immediately before the body bytes for Get. `size` is the
    /// number of bytes the server is about to stream (post-offset and
    /// post-length clamping). `total_size` is the file's full size on
    /// disk so the client can detect truncation across resume sessions.
    /// When `checksum_follows` is true, the digest bytes (length =
    /// `hash_algorithm.digest_len()`) immediately after the body are the
    /// hash of the streamed body; the client verifies them. Computing
    /// the hash inline avoids a second file read on the server side.
    FileReady {
        size: u64,
        #[serde(default)]
        total_size: u64,
        #[serde(default)]
        checksum_follows: bool,
        #[serde(default)]
        hash_algorithm: HashAlgorithm,
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
    pub file_type: FileType,
    pub size: u64,
    pub modified: u64,
    /// Nanosecond part of `modified` (`0..1_000_000_000`).
    pub mtime_nanos: u32,
    /// Owner uid; `0` where unavailable (e.g. Windows).
    pub uid: u32,
    /// Owner gid; `0` where unavailable (e.g. Windows).
    pub gid: u32,
    pub mode: u32,
}

impl DirEntry {
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: u64,
    pub modified: u64,
    /// Nanosecond part of `modified` (`0..1_000_000_000`).
    pub mtime_nanos: u32,
    /// Owner uid; `0` where unavailable (e.g. Windows).
    pub uid: u32,
    /// Owner gid; `0` where unavailable (e.g. Windows).
    pub gid: u32,
    pub mode: u32,
}

impl FileStat {
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }
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
            hash_algorithm: HashAlgorithm::Blake3,
            checksum: Some(vec![7u8; 32]),
            no_clobber: true,
            checksum_trailer: false,
        };
        match round_trip_request(&req) {
            Request::Put {
                path,
                size,
                mode,
                offset,
                hash_algorithm,
                checksum,
                no_clobber,
                checksum_trailer,
            } => {
                assert_eq!(path, "dir/file.bin");
                assert_eq!(size, 12345);
                assert_eq!(mode, 0o644);
                assert_eq!(offset, 4096);
                assert_eq!(hash_algorithm, HashAlgorithm::Blake3);
                assert_eq!(checksum, Some(vec![7u8; 32]));
                assert!(no_clobber);
                assert!(!checksum_trailer);
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
        let resp = Response::DirListing {
            entries: vec![DirEntry {
                name: "a".into(),
                file_type: FileType::Regular,
                size: 1,
                modified: 2,
                mtime_nanos: 3,
                uid: 1000,
                gid: 1000,
                mode: 0o600,
            }],
            next_cursor: None,
        };
        match round_trip_response(&resp) {
            Response::DirListing {
                entries,
                next_cursor,
            } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "a");
                assert_eq!(entries[0].mode, 0o600);
                assert_eq!(entries[0].file_type, FileType::Regular);
                assert!(!entries[0].is_dir());
                assert_eq!(next_cursor, None);
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
            hash_algorithm: HashAlgorithm::Blake3,
        };
        match round_trip_response(&resp) {
            Response::FileReady {
                size,
                total_size,
                checksum_follows,
                hash_algorithm,
            } => {
                assert_eq!(size, 99);
                assert_eq!(total_size, 200);
                assert!(checksum_follows);
                assert_eq!(hash_algorithm, HashAlgorithm::Blake3);
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
                assert_eq!(e.details, None);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn err_response_with_details_round_trip() {
        let resp = Response::Err(ErrorResponse::with_details(
            ErrorCode::InvalidRange,
            "bad range",
            ErrorDetails::Range {
                offset: 10,
                file_size: 5,
            },
        ));
        match round_trip_response(&resp) {
            Response::Err(e) => {
                assert_eq!(e.code, ErrorCode::InvalidRange);
                assert_eq!(
                    e.details,
                    Some(ErrorDetails::Range {
                        offset: 10,
                        file_size: 5,
                    })
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn error_code_numeric_mapping() {
        assert_eq!(ErrorCode::Malformed.to_u32(), 400);
        assert_eq!(ErrorCode::NotFound.to_u32(), 404);
        assert_eq!(ErrorCode::QuotaExceeded.to_u32(), 430);
        assert_eq!(ErrorCode::Internal.to_u32(), 500);
        assert_eq!(ErrorCode::from_u32(404), ErrorCode::NotFound);
        assert_eq!(ErrorCode::from_u32(999), ErrorCode::Unknown(999));
        assert_eq!(ErrorCode::NotFound.class(), ErrorClass::Client);
        assert_eq!(ErrorCode::Internal.class(), ErrorClass::Server);
        assert_eq!(ErrorCode::Unknown(999).class(), ErrorClass::Server);
        assert_eq!(ErrorCode::Unknown(450).class(), ErrorClass::Client);
    }

    #[test]
    fn error_code_serializes_as_u32() {
        let bytes = bincode::serialize(&ErrorCode::NotFound).unwrap();
        assert_eq!(bytes, 404u32.to_le_bytes());
        let back: ErrorCode = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, ErrorCode::NotFound);
        // An unknown code on the wire decodes rather than failing.
        let unknown = bincode::serialize(&777u32).unwrap();
        let back: ErrorCode = bincode::deserialize(&unknown).unwrap();
        assert_eq!(back, ErrorCode::Unknown(777));
    }

    #[test]
    fn file_type_serializes_as_u32() {
        let bytes = bincode::serialize(&FileType::Symlink).unwrap();
        assert_eq!(bytes, 2u32.to_le_bytes());
        let back: FileType = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, FileType::Symlink);
        let unknown = bincode::serialize(&9u32).unwrap();
        let back: FileType = bincode::deserialize(&unknown).unwrap();
        assert_eq!(back, FileType::Unknown(9));
    }

    #[test]
    fn hash_algorithm_digest_len() {
        assert_eq!(HashAlgorithm::Blake3.digest_len(), Some(32));
        assert_eq!(HashAlgorithm::Unknown(1).digest_len(), None);
        assert_eq!(HashAlgorithm::default(), HashAlgorithm::Blake3);
        let bytes = bincode::serialize(&HashAlgorithm::Blake3).unwrap();
        assert_eq!(bytes, 0u32.to_le_bytes());
    }

    #[test]
    fn alpn_carries_major() {
        assert_eq!(ALPN, b"qftp/1");
        assert_eq!(PROTOCOL_MAJOR, 1);
    }

    // ------------------------------------------------------------

    #[test]
    fn validate_request_rejects_oversized_path() {
        let req = Request::Ls {
            path: "a".repeat(MAX_PATH_LEN + 1),
            cursor: None,
        };
        let e = validate_request(&req).unwrap_err();
        assert!(e.to_string().contains("#140"), "unexpected error: {e}");
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
        assert!(
            matches!(e, ValidationError::PathTooLong { field: "to", .. }),
            "expected `to` field cited, got: {e:?}"
        );
    }

    #[test]
    fn validate_response_rejects_oversized_error_message() {
        let resp = Response::Err(ErrorResponse::new(
            ErrorCode::Internal,
            "x".repeat(MAX_ERROR_MESSAGE_LEN + 1),
        ));
        let e = validate_response(&resp).unwrap_err();
        assert!(e.to_string().contains("#140"), "unexpected error: {e}");
    }

    #[test]
    fn validate_response_rejects_huge_listing() {
        let entry = DirEntry {
            name: "x".into(),
            file_type: FileType::Regular,
            size: 0,
            modified: 0,
            mtime_nanos: 0,
            uid: 0,
            gid: 0,
            mode: 0o644,
        };
        // Build a listing one entry over the cap.
        let entries = (0..MAX_DIR_ENTRIES + 1).map(|_| entry.clone()).collect();
        let resp = Response::DirListing {
            entries,
            next_cursor: None,
        };
        let e = validate_response(&resp).unwrap_err();
        assert!(
            matches!(e, ValidationError::DirEntriesTooMany { .. }),
            "unexpected error: {e:?}"
        );
    }
}
