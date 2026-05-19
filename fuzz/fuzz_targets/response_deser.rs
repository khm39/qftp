#![no_main]
//! Same guarantee as request_deser, on the client side: a misbehaving
//! server can send arbitrary bytes back and the client must not panic.
//! Drives the production decode path (length prefix + bincode
//! with_limit). See #141.
use libfuzzer_sys::fuzz_target;
use qftp_common::protocol::Response;
use qftp_common::transport::decode_framed_for_fuzz;

fuzz_target!(|data: &[u8]| {
    let _ = decode_framed_for_fuzz::<Response>(data);
});
