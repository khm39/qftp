//! Language-independent conformance vectors for the qftp wire protocol.
//!
//! The Rust reference implementation is the *producer* of the golden
//! byte strings under `test-vectors/`; any second implementation
//! validates its encoder/decoder against the same JSON without
//! depending on Rust or bincode. The sample set lives here so the
//! generator (`gen-vectors`) and the regression test
//! (`tests/conformance.rs`) share a single definition — the test
//! re-derives the bytes the generator wrote, so a wire change that
//! isn't reflected in `test-vectors/` fails CI.

use qftp_common::protocol::{
    DirEntry, ErrorCode, ErrorDetails, ErrorResponse, FileStat, FileType, HashAlgorithm, Request,
    Response,
};
use serde::{Deserialize, Serialize};

/// One golden vector: a protocol value, its serde-JSON form, and the
/// exact bytes on the wire (framed and payload-only).
#[derive(Debug, Serialize, Deserialize)]
pub struct Vector {
    pub name: String,
    pub description: String,
    /// serde JSON form of the value. Enums are externally tagged
    /// (`{"Variant": {..}}`); see `test-vectors/README.md`.
    pub value: serde_json::Value,
    /// bincode payload only, no frame prefix (lowercase hex).
    pub payload_hex: String,
    /// Full wire frame: 4-byte big-endian length prefix + payload (hex).
    pub wire_hex: String,
}

/// A `test-vectors/*.json` file: a set of vectors for one message type.
#[derive(Debug, Serialize, Deserialize)]
pub struct VectorFile {
    pub protocol: String,
    pub kind: String,
    pub note: String,
    pub vectors: Vec<Vector>,
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length {}", s.len()));
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).ok_or("invalid hex digit")?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or("invalid hex digit")?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// Every `Request` variant (13) plus a few field-presence variations
/// that exercise the `#[serde(default)]` optional fields. Names are
/// stable identifiers referenced from the spec.
pub fn request_samples() -> Vec<(&'static str, &'static str, Request)> {
    vec![
        (
            "ls",
            "List a directory.",
            Request::Ls {
                path: "docs".into(),
                cursor: None,
            },
        ),
        (
            "cd",
            "Change the working directory.",
            Request::Cd {
                path: "/srv/pub".into(),
            },
        ),
        (
            "pwd",
            "Query the current directory (no fields).",
            Request::Pwd,
        ),
        (
            "get_full",
            "Download from the start to EOF (offset=0, length=None defaults).",
            Request::Get {
                path: "report.pdf".into(),
                offset: 0,
                length: None,
            },
        ),
        (
            "get_range",
            "Ranged/resumed download with an explicit offset and length.",
            Request::Get {
                path: "big.iso".into(),
                offset: 1_048_576,
                length: Some(8_388_608),
            },
        ),
        (
            "put_minimal",
            "Upload with required fields only; optional fields at their defaults.",
            Request::Put {
                path: "up/data.bin".into(),
                size: 4096,
                mode: 0o644,
                offset: 0,
                hash_algorithm: HashAlgorithm::Blake3,
                checksum: None,
                no_clobber: false,
                checksum_trailer: false,
            },
        ),
        (
            "put_full",
            "Upload with a resume offset, a header checksum, and no-clobber set.",
            Request::Put {
                path: "up/data.bin".into(),
                size: 12345,
                mode: 0o600,
                offset: 4096,
                hash_algorithm: HashAlgorithm::Blake3,
                checksum: Some(vec![0x11; 32]),
                no_clobber: true,
                checksum_trailer: false,
            },
        ),
        (
            "put_trailer",
            "Upload that streams a 32-byte BLAKE3 trailer after the body.",
            Request::Put {
                path: "up/stream.bin".into(),
                size: 65536,
                mode: 0o644,
                offset: 0,
                hash_algorithm: HashAlgorithm::Blake3,
                checksum: None,
                no_clobber: false,
                checksum_trailer: true,
            },
        ),
        (
            "mkdir",
            "Create a directory.",
            Request::Mkdir {
                path: "newdir".into(),
            },
        ),
        (
            "rmdir",
            "Remove an empty directory.",
            Request::Rmdir {
                path: "olddir".into(),
            },
        ),
        (
            "rm",
            "Remove a file.",
            Request::Rm {
                path: "tmp/old.log".into(),
            },
        ),
        (
            "rename",
            "Rename/move within the user root.",
            Request::Rename {
                from: "a.txt".into(),
                to: "b.txt".into(),
            },
        ),
        (
            "chmod",
            "Change a file's mode.",
            Request::Chmod {
                path: "script.sh".into(),
                mode: 0o755,
            },
        ),
        (
            "stat",
            "Stat a path.",
            Request::Stat {
                path: "report.pdf".into(),
            },
        ),
        (
            "quota",
            "Query storage usage and quota (no fields).",
            Request::Quota,
        ),
        ("quit", "End the session (no fields).", Request::Quit),
    ]
}

/// Every `Response` variant (7) plus default/empty edge cases.
pub fn response_samples() -> Vec<(&'static str, &'static str, Response)> {
    vec![
        ("ok", "Generic success.", Response::Ok),
        (
            "err",
            "Structured error reply.",
            Response::Err(ErrorResponse::new(ErrorCode::NotFound, "no such file")),
        ),
        (
            "err_details",
            "Structured error reply carrying ErrorDetails::Range.",
            Response::Err(ErrorResponse::with_details(
                ErrorCode::InvalidRange,
                "offset past end of file",
                ErrorDetails::Range {
                    offset: 4096,
                    file_size: 1024,
                },
            )),
        ),
        (
            "dir_listing",
            "Directory listing with a file and a subdirectory.",
            Response::DirListing {
                entries: vec![
                    DirEntry {
                        name: "file.txt".into(),
                        file_type: FileType::Regular,
                        size: 1024,
                        modified: 1_700_000_000,
                        mtime_nanos: 0,
                        uid: 1000,
                        gid: 1000,
                        mode: 0o644,
                    },
                    DirEntry {
                        name: "subdir".into(),
                        file_type: FileType::Directory,
                        size: 0,
                        modified: 1_700_000_500,
                        mtime_nanos: 0,
                        uid: 1000,
                        gid: 1000,
                        mode: 0o755,
                    },
                ],
                next_cursor: None,
            },
        ),
        (
            "dir_listing_empty",
            "Empty directory listing.",
            Response::DirListing {
                entries: vec![],
                next_cursor: None,
            },
        ),
        (
            "path",
            "A path reply (e.g. to Pwd).",
            Response::Path("/srv/pub/docs".into()),
        ),
        (
            "file_stat",
            "Stat result for a regular file.",
            Response::FileStat(FileStat {
                file_type: FileType::Regular,
                size: 4096,
                modified: 1_700_000_000,
                mtime_nanos: 0,
                uid: 1000,
                gid: 1000,
                mode: 0o644,
            }),
        ),
        (
            "file_ready",
            "Get header sent before the body, with a trailing checksum.",
            Response::FileReady {
                size: 8_388_608,
                total_size: 10_000_000,
                checksum_follows: true,
                hash_algorithm: HashAlgorithm::Blake3,
            },
        ),
        (
            "file_ready_minimal",
            "Get header with defaulted optional fields.",
            Response::FileReady {
                size: 1024,
                total_size: 0,
                checksum_follows: false,
                hash_algorithm: HashAlgorithm::Blake3,
            },
        ),
        (
            "quota_info",
            "Quota reply with a configured limit.",
            Response::QuotaInfo {
                used_bytes: 1_073_741_824,
                file_count: 42,
                limit_bytes: Some(5_368_709_120),
            },
        ),
        (
            "quota_info_unlimited",
            "Quota reply, no limit configured.",
            Response::QuotaInfo {
                used_bytes: 100,
                file_count: 3,
                limit_bytes: None,
            },
        ),
    ]
}

/// All `ErrorCode` variants in declaration order. The generator emits
/// one `Response::Err` per code so the registry in `spec/error-codes.md`
/// is backed by measured bytes. The on-wire value of each code is its
/// numeric status (`ErrorCode::to_u32`, e.g. 404/500), not this list
/// index.
pub fn error_code_samples() -> Vec<(&'static str, ErrorCode)> {
    use ErrorCode::*;
    vec![
        ("NotFound", NotFound),
        ("PermissionDenied", PermissionDenied),
        ("AlreadyExists", AlreadyExists),
        ("NotADirectory", NotADirectory),
        ("IsADirectory", IsADirectory),
        ("FileTooLarge", FileTooLarge),
        ("UploadOverflow", UploadOverflow),
        ("UploadTruncated", UploadTruncated),
        ("ChecksumMismatch", ChecksumMismatch),
        ("RateLimited", RateLimited),
        ("Malformed", Malformed),
        ("Internal", Internal),
        ("Unauthorized", Unauthorized),
        ("InvalidRange", InvalidRange),
        ("Unsupported", Unsupported),
        ("QuotaExceeded", QuotaExceeded),
    ]
}
