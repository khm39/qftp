#![no_main]
//! Make sure decoding arbitrary bytes into `Request` via the *production*
//! decode path (the same length-prefix + bincode-with-limit config that
//! `recv_message` uses) never panics. A peer can send anything on the wire
//! and the server hands that buffer to `decode_framed_message`; any panic
//! here would crash the server.
//!
//! Previously this called `bincode::deserialize::<Request>(data)`
//! with the default (unbounded) bincode options, which is *not* what
//! production runs. The fuzzer was therefore exercising a decode path
//! that didn't match the binary. Use `decode_framed_message` so the
//! corpus exercises the real recv_message logic, including the 4-byte
//! BE length prefix and `with_limit(MAX_MESSAGE_SIZE)`.
use libfuzzer_sys::fuzz_target;
use qftp_common::protocol::Request;
use qftp_common::transport::decode_framed_message;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let _ = decode_framed_message::<Request>(&mut buf);
});
