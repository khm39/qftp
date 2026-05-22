//! Regression test for #177.
//!
//! A peer that resets a stream (sends STOP_SENDING) right after sending
//! a request used to crash the *whole* server: the resulting per-stream
//! QUIC send error propagated out of `process_readable_streams` through
//! `run()`, the process exited, and every other client's connection was
//! dropped with it.
//!
//! This test drives that exact sequence against a real `qftp-server`
//! over a real QUIC connection and asserts that the server (a) keeps
//! running and (b) still serves brand-new connections afterwards.

use std::io::BufRead;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use qftp_common::protocol::Request;
use qftp_common::transport::{create_client_config, encode_framed_message, ClientTlsConfig};

/// Bind an ephemeral UDP port and hand it back. Racy, but fine for a test.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral udp")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// A live `qftp-server` child process. Dropping it kills the server.
struct TestServer {
    child: Child,
    addr: SocketAddr,
    _root: tempfile::TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_server() -> TestServer {
    let root = tempfile::tempdir().expect("server tempdir");
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_qftp-server"))
        .args([
            "--self-signed",
            "--bind",
            &addr.to_string(),
            "--root",
            root.path().to_str().unwrap(),
            "--max-connections-per-ip",
            "64",
        ])
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qftp-server");

    // Forward the server's stderr so a CI failure shows the cause.
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                eprintln!("[qftp-server] {line}");
            }
        });
    }

    TestServer {
        child,
        addr,
        _root: root,
    }
}

/// One QUIC client: a connected UDP socket plus its quiche connection.
struct Client {
    socket: UdpSocket,
    conn: quiche::Connection,
}

/// A distinct source connection ID for every connection in the test.
fn unique_scid() -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut scid = [0u8; 16];
    scid[..8].copy_from_slice(&n.to_le_bytes());
    scid[8..].copy_from_slice(&nanos.to_le_bytes());
    scid
}

/// Drain everything quiche wants to send out onto the socket.
fn flush(socket: &UdpSocket, conn: &mut quiche::Connection, out: &mut [u8]) -> Result<(), String> {
    loop {
        match conn.send(out) {
            Ok((n, _)) => {
                socket.send(&out[..n]).map_err(|e| e.to_string())?;
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(format!("conn.send: {e}")),
        }
    }
}

/// Open a QUIC connection to `addr` and drive the handshake to
/// completion. Returns `Err` if the handshake does not finish in time --
/// which is exactly what happens once the server process is gone.
fn connect(addr: SocketAddr) -> Result<Client, String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    socket.connect(addr).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|e| e.to_string())?;
    let local = socket.local_addr().map_err(|e| e.to_string())?;

    let mut config = create_client_config(ClientTlsConfig {
        verify_peer: false,
        ca_path: None,
        client_cert: None,
    })
    .map_err(|e| e.to_string())?;

    let scid_bytes = unique_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some("localhost"), &scid, local, addr, &mut config)
        .map_err(|e| e.to_string())?;

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut out = [0u8; 1500];
    let mut buf = [0u8; 2048];
    while !conn.is_established() {
        if Instant::now() > deadline {
            return Err("handshake did not complete in time".into());
        }
        flush(&socket, &mut conn, &mut out)?;
        match socket.recv(&mut buf) {
            Ok(n) => {
                let info = quiche::RecvInfo {
                    from: addr,
                    to: local,
                };
                let _ = conn.recv(&mut buf[..n], info);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(format!("socket.recv: {e}")),
        }
        if conn.is_closed() {
            return Err("connection closed during handshake".into());
        }
    }
    Ok(Client { socket, conn })
}

/// Service the connection for `dur`, draining sends and feeding recvs,
/// so the server has time to process whatever we just sent it.
fn pump(client: &mut Client, dur: Duration) {
    let local = client.socket.local_addr().unwrap();
    let peer = client.socket.peer_addr().unwrap();
    let mut out = [0u8; 1500];
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        let _ = flush(&client.socket, &mut client.conn, &mut out);
        match client.socket.recv(&mut buf) {
            Ok(n) => {
                let info = quiche::RecvInfo {
                    from: peer,
                    to: local,
                };
                let _ = client.conn.recv(&mut buf[..n], info);
            }
            Err(_) => client.conn.on_timeout(),
        }
    }
}

/// Block until the server accepts a connection, or panic after `within`.
fn wait_until_serving(addr: SocketAddr, within: Duration, ctx: &str) {
    let deadline = Instant::now() + within;
    loop {
        if connect(addr).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "{ctx}");
        std::thread::sleep(Duration::from_millis(150));
    }
}

#[test]
fn stream_reset_after_request_does_not_crash_server() {
    let mut server = spawn_server();

    wait_until_serving(
        server.addr,
        Duration::from_secs(15),
        "server never became ready",
    );

    // The attack: open a bidirectional stream, send a real request, then
    // immediately STOP_SENDING that same stream. The server decodes the
    // request and tries to write its reply -- which now fails, because
    // the peer has stopped the stream. Pre-#177-fix that error tore down
    // the whole event loop.
    let mut attacker = connect(server.addr).expect("attacker handshake");
    let framed = encode_framed_message(&Request::Quota).expect("encode request");
    attacker
        .conn
        .stream_send(0, &framed, false)
        .expect("stream_send request");
    attacker
        .conn
        .stream_shutdown(0, quiche::Shutdown::Read, 0x1010)
        .expect("stream_shutdown (STOP_SENDING)");
    let mut out = [0u8; 1500];
    flush(&attacker.socket, &mut attacker.conn, &mut out).expect("flush attack flight");
    // Give the server ample time to process the request + STOP_SENDING.
    pump(&mut attacker, Duration::from_millis(800));
    drop(attacker);

    // (a) The server process must still be alive.
    let exited = server.child.try_wait().expect("try_wait on server child");
    assert!(
        exited.is_none(),
        "qftp-server process exited ({exited:?}) after a client reset a stream \
         mid-request -- regression of #177"
    );

    // (b) ...and it must still serve brand-new connections.
    wait_until_serving(
        server.addr,
        Duration::from_secs(8),
        "server stopped accepting connections after the stream-reset attack",
    );
}
