#![no_main]
//! Same guarantee as request_deser, on the client side: a misbehaving
//! server can send arbitrary bytes back and the client must not panic.
use libfuzzer_sys::fuzz_target;
use qftp_common::protocol::Response;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<Response>(data);
});
