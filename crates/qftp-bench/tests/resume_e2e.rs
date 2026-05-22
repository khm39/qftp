//! End-to-end regression tests for the P1 resume / connectivity fixes.
//!
//! Each test spins up a real `qftp-server` and drives the real
//! `qftp-client` binary through the shared [`ServerFixture`]:
//!
//!   * #179 -- the client can connect to a hostname, not just an IP.
//!   * #178 -- a resumed download verifies and is not deleted.
//!   * #180 -- a resumed upload runs through to commit.
//!
//! #181 (a stale-partial `InvalidRange` triggers a retry) is covered by
//! the `is_stale_partial` unit test in `qftp-client`'s `transfer` module.

use std::fs;
use std::process::Command;

use qftp_bench::{read_prefix, write_random_file, ServerFixture};

/// #179: connection setup must resolve a DNS name. Before the fix
/// `host:port` was handed to `str::parse::<SocketAddr>()`, which only
/// accepts numeric IP literals, so every hostname URL was rejected.
#[test]
fn connects_via_hostname() {
    let fx = ServerFixture::start().expect("start server");
    let home = fx.client_env_home();
    fs::create_dir_all(&home).expect("client home");

    // `localhost` is a DNS name (the fixture's own helpers use the
    // numeric `127.0.0.1`); resolving it is exactly what #179 fixed.
    let url = format!("qftp://localhost:{}/", fx.addr.port());
    let out = Command::new(&fx.client_bin)
        .env("HOME", &home)
        .env("RUST_LOG", "error")
        .args([
            "--insecure",
            "--server-name",
            "localhost",
            "--no-zero-rtt",
            "-e",
            "ls /",
            &url,
        ])
        .output()
        .expect("run qftp-client");

    assert!(
        out.status.success(),
        "client could not connect to hostname URL {url}:\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// #178: a resumed download must verify successfully. The client hashes
/// only the streamed `[offset..]` bytes, matching the server's suffix
/// trailer; before the fix it hashed the whole local file, so every
/// resume failed the BLAKE3 check and the partial file was deleted.
#[test]
fn resumes_an_interrupted_download() {
    const SIZE: usize = 300_000;
    const ALREADY_HAVE: usize = 120_000;

    let fx = ServerFixture::start().expect("start server");
    // The anonymous user's home is `<root>/anonymous`, so a remote path
    // of `/download.bin` resolves there -- not at the server root.
    let server_home = fx.root.path().join("anonymous");
    fs::create_dir_all(&server_home).expect("server home");
    let server_file = server_home.join("download.bin");
    write_random_file(&server_file, SIZE).expect("stage server file");

    // Simulate an interrupted download: the local destination already
    // holds the first `ALREADY_HAVE` bytes of the server's file.
    let home = fx.client_env_home();
    fs::create_dir_all(&home).expect("client home");
    let dest = home.join("download.bin");
    let prefix = read_prefix(&server_file, ALREADY_HAVE).expect("read prefix");
    fs::write(&dest, &prefix).expect("stage partial download");

    fx.run_repl(&format!("get /download.bin {}", dest.display()))
        .expect("resumed get should succeed");

    let got = fs::read(&dest).expect("read resumed download");
    let want = fs::read(&server_file).expect("read server file");
    assert_eq!(got.len(), want.len(), "resumed download has wrong length");
    assert!(got == want, "resumed download content does not match");
}

/// #180: a resumed upload must run through to commit. Before the fix
/// the server's re-hash completion path returned early instead of
/// continuing into the body / commit phase.
#[test]
fn resumes_an_interrupted_upload() {
    const SIZE: usize = 400_000;
    const ALREADY_SENT: usize = 100_000;

    let fx = ServerFixture::start().expect("start server");
    let home = fx.client_env_home();
    fs::create_dir_all(&home).expect("client home");

    let local_file = home.join("upload.bin");
    write_random_file(&local_file, SIZE).expect("stage local file");

    // Simulate an interrupted upload: the server already holds the
    // first `ALREADY_SENT` bytes as `<dest>.qftp.partial`, so the
    // client's next `put` probes it and resumes. The anonymous user's
    // home is `<root>/anonymous`, where `/upload.bin` resolves.
    let server_home = fx.root.path().join("anonymous");
    fs::create_dir_all(&server_home).expect("server home");
    let partial = server_home.join("upload.bin.qftp.partial");
    let prefix = read_prefix(&local_file, ALREADY_SENT).expect("read prefix");
    fs::write(&partial, &prefix).expect("stage partial upload");

    fx.run_repl(&format!("put {} /upload.bin", local_file.display()))
        .expect("resumed put should succeed");

    let got = fs::read(server_home.join("upload.bin")).expect("read committed upload");
    let want = fs::read(&local_file).expect("read local file");
    assert_eq!(got.len(), want.len(), "resumed upload has wrong length");
    assert!(got == want, "resumed upload content does not match");
}
