//! Shared helpers for the qftp E2E benchmarks.
//!
//! The benches in `benches/` spin up the real `qftp-server` and
//! `qftp-client` binaries on loopback and time the resulting transfers.
//! The helpers live here so multiple bench files (if added later) can
//! share the fixture instead of duplicating subprocess plumbing.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

/// Workspace root, derived from this crate's manifest dir.
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("CARGO_MANIFEST_DIR has no two-level parent")
}

/// Build `qftp-server` + `qftp-client` in release mode and return their
/// paths. Idempotent and cheap once they're built.
pub fn build_binaries() -> Result<(PathBuf, PathBuf)> {
    let root = workspace_root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let status = Command::new(&cargo)
        .args([
            "build",
            "--release",
            "--bin",
            "qftp-server",
            "--bin",
            "qftp-client",
        ])
        .current_dir(&root)
        .status()
        .context("failed to invoke cargo build for qftp-server / qftp-client")?;
    if !status.success() {
        return Err(anyhow!("cargo build failed with status {status}"));
    }

    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let server = target_dir.join("release/qftp-server");
    let client = target_dir.join("release/qftp-client");
    if !server.exists() {
        return Err(anyhow!(
            "qftp-server binary missing at {}",
            server.display()
        ));
    }
    if !client.exists() {
        return Err(anyhow!(
            "qftp-client binary missing at {}",
            client.display()
        ));
    }
    Ok((server, client))
}

/// Bind an ephemeral UDP port, read it back, and drop the socket. The
/// returned port is *probably* free for the next ~ms. There is an
/// inherent race; callers should retry on bind failure.
fn pick_free_port() -> Result<u16> {
    let s = UdpSocket::bind("127.0.0.1:0").context("bind ephemeral UDP")?;
    Ok(s.local_addr()?.port())
}

/// A live qftp-server child process bound to a known address. Dropping
/// the fixture kills the server. The server root is a tempdir owned by
/// the fixture so the bench can stage files for `get` and inspect what
/// `put` left behind.
pub struct ServerFixture {
    child: Child,
    pub addr: SocketAddr,
    pub root: tempfile::TempDir,
    pub client_bin: PathBuf,
}

impl ServerFixture {
    pub fn start() -> Result<Self> {
        let (server_bin, client_bin) = build_binaries()?;
        // Retry the bind-port handshake a few times; the picked port is
        // racy but usually fine on a quiet bench box.
        let mut last_err: Option<anyhow::Error> = None;
        for _ in 0..5 {
            let port = pick_free_port()?;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let root = tempfile::tempdir().context("server tempdir")?;

            // The default anonymous user is read-only. The
            // bench needs to upload, so write a users.toml that grants
            // the anonymous user full permissions on this throwaway
            // root.
            let users_path = root.path().join("users.toml");
            fs::write(
                &users_path,
                "[anonymous]\nname = \"anonymous\"\n\
                 permissions = { read = true, write = true, mkdir = true, \
                 rmdir = true, rename = true, delete = true, chmod = true }\n",
            )
            .context("write users.toml")?;

            let mut cmd = Command::new(&server_bin);
            cmd.args([
                "--self-signed",
                "--bind",
                &addr.to_string(),
                "--root",
                root.path().to_str().unwrap(),
                "--users",
                users_path.to_str().unwrap(),
                "--max-connections",
                "256",
                "--max-connections-per-ip",
                "256",
                // criterion's warm-up + sampling fires hundreds of
                // back-to-back transfers from the same loopback IP.
                // Push the per-IP request rate limiter well past
                // what the harness can drive so it doesn't become
                // the dominant measurement.
                "--rate-limit-rps",
                "100000",
                "--rate-limit-burst",
                "100000",
            ])
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

            // On Linux ask the kernel to SIGKILL the child when the bench
            // harness exits, so a panicking bench never leaks a server.
            #[cfg(target_os = "linux")]
            unsafe {
                use std::os::unix::process::CommandExt;
                cmd.pre_exec(|| {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                    Ok(())
                });
            }

            let mut child = cmd.spawn().context("spawn qftp-server")?;
            let stderr = child.stderr.take().expect("piped stderr");

            // Forward every server-stderr line to the bench harness's
            // stderr so a failing run surfaces the cause. The readiness
            // check itself is a client probe; we don't parse logs.
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    eprintln!("[qftp-server] {line}");
                }
            });

            // Probe-loop until the server accepts a connection. We run
            // a real REPL command (`ls /` via -e) so we know QUIC +
            // TLS + protocol are all up. The one-shot subcommands
            // can't be combined with --insecure, so we drive the REPL.
            // 10s is generous for self-signed startup on any bench box.
            let home = root.path().join("client-home");
            let _ = fs::create_dir_all(&home);
            let probe_url = format!("qftp://127.0.0.1:{port}/");
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut ready = false;
            while Instant::now() < deadline {
                if child.try_wait().ok().flatten().is_some() {
                    break; // server died; outer loop will retry
                }
                let status = Command::new(&client_bin)
                    .env("HOME", &home)
                    .env("RUST_LOG", "error")
                    .args([
                        "--insecure",
                        "--server-name",
                        "localhost",
                        "--no-zero-rtt",
                        "-e",
                        "ls /",
                        &probe_url,
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                if matches!(status, Ok(s) if s.success()) {
                    ready = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            if ready {
                return Ok(Self {
                    child,
                    addr,
                    root,
                    client_bin,
                });
            }

            last_err = Some(anyhow!(
                "qftp-server on {addr} did not accept a probe within 10s"
            ));
            let _ = child.kill();
            let _ = child.wait();
        }
        Err(last_err.unwrap_or_else(|| anyhow!("qftp-server failed to start")))
    }

    /// Per-client HOME so the bench doesn't pollute the developer's
    /// real `~/.qftp/`.
    pub fn client_env_home(&self) -> PathBuf {
        self.root.path().join("client-home")
    }

    /// Loopback URL for the running server. REPL `-e` commands are
    /// evaluated relative to the path part of this URL (we use `/`).
    pub fn endpoint_url(&self) -> String {
        format!("qftp://127.0.0.1:{}/", self.addr.port())
    }

    /// Run a single REPL command via `-e` and return the client's
    /// stderr/stdout on failure. The REPL path is the only way to
    /// combine `--insecure` with a one-shot operation — qftp-client's
    /// subcommands declare `args_conflicts_with_subcommands`, so the
    /// global TLS flags are forbidden once `put`/`get`/`ls` is on the
    /// command line.
    ///
    /// If the client doesn't return within
    /// `QFTP_BENCH_CLIENT_TIMEOUT_SECS` (default 60s — enough for a
    /// 1 GiB transfer at low loopback throughput), it is killed and
    /// the call returns an error. This stops a single stalled
    /// connection from wedging the entire bench harness on the 30s
    /// QUIC idle timeout.
    pub fn run_repl(&self, script: &str) -> Result<()> {
        let home = self.client_env_home();
        let _ = fs::create_dir_all(&home);
        let mut child = Command::new(&self.client_bin)
            .env("HOME", &home)
            .env("RUST_LOG", "error")
            .args([
                "--insecure",
                "--server-name",
                "localhost",
                "--no-zero-rtt",
                "-e",
                script,
                &self.endpoint_url(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn qftp-client")?;

        let timeout = std::env::var("QFTP_BENCH_CLIENT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(60));
        let deadline = Instant::now() + timeout;
        let out = loop {
            match child.try_wait().context("wait qftp-client")? {
                Some(_) => {
                    break child
                        .wait_with_output()
                        .context("collect qftp-client output")?;
                }
                None => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(anyhow!(
                            "qftp-client -e {script:?} timed out after {:?}",
                            timeout
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        if !out.status.success() {
            return Err(anyhow!(
                "qftp-client -e {script:?} failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            ));
        }
        // The REPL exits 0 even when an individual command fails (it
        // prints "put X failed: …" and moves on). Treat any line
        // containing `failed:` as a transfer error so the bench doesn't
        // silently measure error paths. The REPL splits its diagnostics
        // across both streams -- `ls`/`mget`/`stat` failures land on
        // stdout, but `put`/`get` failures are emitted via `eprintln!`
        // on stderr -- so scan both. Only the client's own output is on
        // this stderr; the server's is forwarded by a separate thread,
        // so a server-side `failed:` line can't be misattributed here.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        for line in stdout.lines().chain(stderr.lines()) {
            if line.contains(" failed:") {
                return Err(anyhow!(
                    "qftp-client -e {script:?} reported error: {line}\n\
                     --- full stdout ---\n{stdout}\n\
                     --- full stderr ---\n{stderr}"
                ));
            }
        }
        Ok(())
    }
}

impl Drop for ServerFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Write `size` bytes of pseudo-random content to `path`. The content
/// is deterministic but cheap to generate, which keeps each iteration's
/// pre-work out of the measurement.
pub fn write_random_file(path: &Path, size: usize) -> Result<()> {
    let mut f = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    // Simple xorshift to fill a buffer once, then write it in chunks.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let chunk = 64 * 1024;
    let mut buf = vec![0u8; chunk];
    for slot in buf.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        slot.copy_from_slice(&state.to_le_bytes());
    }

    let mut written = 0usize;
    while written < size {
        let n = (size - written).min(chunk);
        f.write_all(&buf[..n])
            .with_context(|| format!("write {}", path.display()))?;
        written += n;
    }
    f.flush()?;
    Ok(())
}

/// Sanity helper: read the first `n` bytes of a file. Used in
/// integration assertions, not in the timed bench body itself.
#[allow(dead_code)]
pub fn read_prefix(path: &Path, n: usize) -> Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)?;
    Ok(buf)
}
