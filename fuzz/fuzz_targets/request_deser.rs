#![no_main]
//! Make sure decoding arbitrary bytes into `Request` never panics. A
//! peer can send anything on the wire, so this drives the same code
//! path `recv_message` uses in production: 4-byte BE length prefix +
//! bincode `with_limit(MAX_MESSAGE_SIZE)`. See #141 — the prior version
//! called `bincode::deserialize` directly and missed the production
//! length-prefix and per-field limit handling.
use libfuzzer_sys::fuzz_target;
use qftp_common::protocol::Request;
use qftp_common::transport::decode_framed_for_fuzz;

fuzz_target!(|data: &[u8]| {
    let _ = decode_framed_for_fuzz::<Request>(data);
});
