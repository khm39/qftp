//! The Rust reference implementation must round-trip every golden
//! vector both ways:
//!   1. decode `wire_hex` and confirm the JSON `value` matches, and
//!   2. re-encode that `value` and confirm the bytes are identical.
//!
//! A second implementation in any language runs the same two checks
//! against `test-vectors/*.json` without this crate.

use qftp_common::protocol::{Request, Response};
use qftp_common::transport::{decode_framed_message, encode_framed_message};
use qftp_conformance::{hex_decode, hex_encode, VectorFile};
use serde::{de::DeserializeOwned, Serialize};
use std::path::PathBuf;

fn load(file: &str) -> VectorFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors")
        .join(file);
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}\nRun `cargo run -p qftp-conformance --bin gen-vectors` to (re)generate.",
            path.display()
        )
    });
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn check<T: DeserializeOwned + Serialize>(vf: &VectorFile) {
    assert!(!vf.vectors.is_empty(), "vector file has no vectors");
    for v in &vf.vectors {
        let framed =
            hex_decode(&v.wire_hex).unwrap_or_else(|e| panic!("{}: bad wire_hex: {e}", v.name));

        // payload_hex must be wire_hex minus the 4-byte length prefix.
        assert!(framed.len() >= 4, "{}: frame shorter than prefix", v.name);
        assert_eq!(
            hex_encode(&framed[4..]),
            v.payload_hex,
            "{}: payload_hex mismatch",
            v.name
        );

        // The 4-byte big-endian prefix must equal the payload length.
        let declared = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(
            declared,
            framed.len() - 4,
            "{}: length prefix mismatch",
            v.name
        );

        // 1. Decode the frame; its JSON form must equal `value`.
        let mut buf = framed.clone();
        let msg: T = decode_framed_message(&mut buf)
            .unwrap_or_else(|e| panic!("{}: decode failed: {e}", v.name))
            .unwrap_or_else(|| panic!("{}: frame decoded as incomplete", v.name));
        assert!(buf.is_empty(), "{}: bytes left over after decode", v.name);
        assert_eq!(
            serde_json::to_value(&msg).unwrap(),
            v.value,
            "{}: decoded value mismatch",
            v.name
        );

        // 2. Re-encode from `value`; the bytes must be identical.
        let from_value: T = serde_json::from_value(v.value.clone())
            .unwrap_or_else(|e| panic!("{}: from_value failed: {e}", v.name));
        let re = encode_framed_message(&from_value)
            .unwrap_or_else(|e| panic!("{}: encode failed: {e}", v.name));
        assert_eq!(
            hex_encode(&re),
            v.wire_hex,
            "{}: re-encoded bytes differ",
            v.name
        );
    }
}

#[test]
fn requests_round_trip() {
    check::<Request>(&load("requests.json"));
}

#[test]
fn responses_round_trip() {
    check::<Response>(&load("responses.json"));
}

#[test]
fn error_codes_round_trip() {
    check::<Response>(&load("error-codes.json"));
}
