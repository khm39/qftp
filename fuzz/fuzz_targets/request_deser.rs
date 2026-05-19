#![no_main]
//! Make sure bincode-deserializing arbitrary bytes into `Request` never
//! panics. A peer can send anything on the wire, and recv_message hands
//! the slice straight to bincode::deserialize -- any panic here would
//! crash the server.
use libfuzzer_sys::fuzz_target;
use qftp_common::protocol::Request;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<Request>(data);
});
