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
///
/// Verifying only the final content can't tell a working resume apart
/// from a silent full re-download: both leave the right bytes on disk.
/// To pin the resume path observationally, the staged partial here has
/// the *correct length* but *wrong content* for `[0..ALREADY_HAVE)`.
/// When `get` resumes it folds that bad local prefix into the
/// whole-file BLAKE3 (which is exactly the #221 prefix-verification
/// behaviour), so the trailer check fails and the corrupt partial is
/// deleted -- the first `get` is *expected to fail*. A second `get`
/// then finds no local file, starts fresh from offset 0, and lands the
/// correct content. A client that ignored the local prefix (e.g.
/// hashed only the suffix, or full-downloaded without folding the
/// prefix) would have "succeeded" on the first call with corrupt bytes
/// on disk, so the required first-call failure is what distinguishes a
/// real resume.
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

    // Simulate an interrupted download whose on-disk prefix has the
    // right length but the wrong bytes: same length as the server's
    // real `[0..ALREADY_HAVE)`, but every byte flipped so it cannot
    // match. A correct resume must reject this prefix at trailer
    // verification rather than silently keep it.
    let home = fx.client_env_home();
    fs::create_dir_all(&home).expect("client home");
    let dest = home.join("download.bin");
    let mut bad_prefix = read_prefix(&server_file, ALREADY_HAVE).expect("read prefix");
    for b in bad_prefix.iter_mut() {
        *b = !*b;
    }
    fs::write(&dest, &bad_prefix).expect("stage corrupt partial download");

    // The resume folds the corrupt prefix into the whole-file BLAKE3,
    // the trailer disagrees, and `do_get` tears the partial down. This
    // first attempt must fail -- a success here would mean the local
    // prefix was never verified.
    let first = fx.run_repl(&format!("get /download.bin {}", dest.display()));
    assert!(
        first.is_err(),
        "get over a corrupt same-length partial must fail trailer \
         verification, not silently keep the bad prefix"
    );
    assert!(
        !dest.exists(),
        "a failed resume must delete the corrupt partial so a retry \
         starts clean"
    );

    // With the corrupt partial gone, a second `get` starts from offset
    // 0 and downloads the whole file correctly.
    fx.run_repl(&format!("get /download.bin {}", dest.display()))
        .expect("fresh get after corrupt partial removal should succeed");

    let got = fs::read(&dest).expect("read resumed download");
    let want = fs::read(&server_file).expect("read server file");
    assert_eq!(got.len(), want.len(), "resumed download has wrong length");
    assert!(got == want, "resumed download content does not match");
}

/// #180: a resumed upload must run through to commit. Before the fix
/// the server's re-hash completion path returned early instead of
/// continuing into the body / commit phase.
///
/// As with the download test, the committed content alone can't tell a
/// real resume apart from a silent full upload. To pin the resume path
/// the staged partial holds a *valid* prefix (the local file's real
/// first `ALREADY_SENT` bytes), so the server reconstructs its BLAKE3
/// over `[partial] + [streamed suffix]` and the commit only verifies if
/// those staged bytes were actually reused. The post-conditions then
/// observe that the resume was taken: the deterministic
/// `<dest>.qftp.partial` was consumed (renamed into place), not left
/// behind, and the committed file matches byte-for-byte.
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
    // A committed upload renames the partial into place; a leftover
    // `.qftp.partial` would mean the resume never reached commit.
    assert!(
        !partial.exists(),
        "the resumed upload must consume <dest>.qftp.partial on commit"
    );
}

/// A resumed upload whose server-side partial is the *right length but
/// wrong content* must still end with the correct file on disk. This is
/// the put-side counterpart to the download corruption test, and the
/// regression backstop for `probe_put_resume_offset`: that probe checks
/// only the partial's length, never its bytes, so a same-size corrupt
/// partial passes the probe and the client resumes from `offset =
/// ALREADY_SENT`. The client folds its (good) local prefix into the
/// whole-file BLAKE3 while the server reconstructs its hash from the
/// (bad) staged partial, the two disagree, the server returns
/// `ChecksumMismatch`, `is_stale_partial` fires, and the REPL re-uploads
/// the whole file from scratch -- landing the correct content. A client
/// that trusted the probed offset without the trailer backstop would
/// commit a corrupt file here.
#[test]
fn put_resume_recovers_from_corrupt_same_size_partial() {
    const SIZE: usize = 400_000;
    const ALREADY_SENT: usize = 100_000;

    let fx = ServerFixture::start().expect("start server");
    let home = fx.client_env_home();
    fs::create_dir_all(&home).expect("client home");

    let local_file = home.join("upload.bin");
    write_random_file(&local_file, SIZE).expect("stage local file");

    // Stage a partial of the same length as the local file's real
    // prefix but with every byte flipped, so the length-only resume
    // probe accepts it yet its contents cannot match.
    let server_home = fx.root.path().join("anonymous");
    fs::create_dir_all(&server_home).expect("server home");
    let partial = server_home.join("upload.bin.qftp.partial");
    let mut bad_prefix = read_prefix(&local_file, ALREADY_SENT).expect("read prefix");
    for b in bad_prefix.iter_mut() {
        *b = !*b;
    }
    fs::write(&partial, &bad_prefix).expect("stage corrupt partial upload");

    // The first resume attempt is refused with ChecksumMismatch; the
    // REPL re-uploads from scratch and the call still returns Ok because
    // the from-scratch upload commits. `run_repl` only fails on a
    // `failed:` line, which the successful re-upload never prints.
    fx.run_repl(&format!("put {} /upload.bin", local_file.display()))
        .expect("put over a corrupt same-size partial should recover from scratch");

    let got = fs::read(server_home.join("upload.bin")).expect("read committed upload");
    let want = fs::read(&local_file).expect("read local file");
    assert_eq!(got.len(), want.len(), "recovered upload has wrong length");
    assert!(got == want, "recovered upload content does not match");
    assert!(
        !partial.exists(),
        "the from-scratch re-upload must consume <dest>.qftp.partial on commit"
    );
}
