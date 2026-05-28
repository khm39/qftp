//! Native put/get edge-case coverage flagged in #274.
//!
//! Drives the real `qftp-client` against a real `qftp-server` through
//! the shared [`ServerFixture`]. Covers the zero-byte round trip, which
//! exercises the body/trailer paths with `size == 0` — the case most
//! likely to trip an off-by-one in the chunk loop or a "no bytes ever
//! arrived" assumption.

use std::fs;

use qftp_bench::ServerFixture;

/// A zero-byte file must put and get cleanly: the client should send an
/// empty body plus its trailer, the server should commit an empty file,
/// and the download must verify and land a zero-byte file (not delete
/// the dest as a failed transfer).
#[test]
fn empty_file_round_trips() {
    let fx = ServerFixture::start().expect("start server");
    let home = fx.client_env_home();
    fs::create_dir_all(&home).expect("client home");

    let local = home.join("empty.bin");
    fs::write(&local, b"").expect("stage empty local file");

    fx.run_repl(&format!("put {} /empty.bin", local.display()))
        .expect("put of empty file should succeed");

    // The anonymous user's home is `<root>/anonymous`, so `/empty.bin`
    // resolves there.
    let server_file = fx.root.path().join("anonymous").join("empty.bin");
    let committed = fs::read(&server_file).expect("read committed empty upload");
    assert!(committed.is_empty(), "uploaded file should be empty");

    let dest = home.join("roundtrip.bin");
    fx.run_repl(&format!("get /empty.bin {}", dest.display()))
        .expect("get of empty file should succeed");

    let got = fs::read(&dest).expect("read downloaded empty file");
    assert!(got.is_empty(), "downloaded file should be empty");
}
