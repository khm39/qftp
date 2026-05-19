#![no_main]
//! Same guarantee as request_deser, on the client side: a misbehaving
//! server can send arbitrary bytes back and the client must not panic.
//!
//! #141: see request_deser.rs -- routed through the production
//! `decode_framed_message` helper so the fuzz corpus exercises the
//! same length-prefix + bincode-with-limit decode that recv_message
//! uses in the client.
use libfuzzer_sys::fuzz_target;
use qftp_common::protocol::Response;
use qftp_common::transport::decode_framed_message;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let _ = decode_framed_message::<Response>(&mut buf);
});
