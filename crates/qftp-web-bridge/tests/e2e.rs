//! End-to-end test for `qftp-web-bridge`.
//!
//! Spawns the real bridge binary, connects to it over a real
//! WebTransport connection, and exercises the full request path:
//! mkdir / put / ls / get (with the BLAKE3 trailer) / rename / rm /
//! rmdir, plus header-checksum verification, ACL enforcement, and
//! bearer-token rejection. The SPA HTTP listener is checked too.
//!
//! This is the coverage the per-crate unit tests cannot give: the
//! WebTransport data path in `transfer.rs` only runs against a live
//! quinn connection.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use qftp_common::protocol::{Encoding, ErrorCode, Request, Response};
use qftp_common::transport::{decode_framed_message, encode_framed_message};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wtransport::endpoint::endpoint_side::Client;
use wtransport::{ClientConfig, Connection, Endpoint, Identity, RecvStream, SendStream};

/// Kills the spawned bridge when the test ends (including on panic).
struct Bridge(Child);
impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Decode the first length-prefixed `Response` frame out of `data`,
/// draining the consumed prefix + payload so the bytes that follow the
/// frame (a `Get` body + BLAKE3 trailer) stay in `data`. The inner
/// `expect` reproduces the old `split_frame` assert that the buffer
/// holds a complete frame.
fn decode_response(data: &mut Vec<u8>) -> Response {
    decode_framed_message::<Response>(data)
        .expect("decode response")
        .expect("response frame is incomplete")
}

async fn read_to_end(recv: &mut RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    // Heap, not a stack `[u8; 65536]`: `#[tokio::test]` polls the whole
    // test future on the harness thread's 2 MiB stack, where each awaited
    // call bakes in its own copy of this buffer and overflows it.
    let mut buf = vec![0u8; 65536];
    while let Some(n) = recv.read(&mut buf).await.expect("recv read") {
        out.extend_from_slice(&buf[..n]);
    }
    out
}

async fn open_bi(conn: &Connection) -> (SendStream, RecvStream) {
    conn.open_bi()
        .await
        .expect("open_bi request")
        .await
        .expect("open_bi accept")
}

/// Run a one-shot request whose reply is a single framed `Response`.
async fn op(conn: &Connection, req: &Request) -> Response {
    let (mut send, mut recv) = open_bi(conn).await;
    send.write_all(&encode_framed_message(req).unwrap())
        .await
        .expect("write request");
    send.finish().await.expect("finish request");
    let mut data = read_to_end(&mut recv).await;
    decode_response(&mut data)
}

/// Upload `body`, optionally with a header BLAKE3 checksum.
async fn put(conn: &Connection, path: &str, body: &[u8], checksum: Option<[u8; 32]>) -> Response {
    let (mut send, mut recv) = open_bi(conn).await;
    let req = Request::Put {
        path: path.to_string(),
        size: body.len() as u64,
        mode: 0o644,
        offset: 0,
        hash_algorithm: qftp_common::protocol::HashAlgorithm::Blake3,
        checksum: checksum.map(|c| c.to_vec()),
        no_clobber: false,
        checksum_trailer: false,
        encoding: Encoding::Identity,
        plaintext_size: 0,
    };
    send.write_all(&encode_framed_message(&req).unwrap())
        .await
        .expect("write put header");
    send.write_all(body).await.expect("write put body");
    send.finish().await.expect("finish put");
    let mut data = read_to_end(&mut recv).await;
    decode_response(&mut data)
}

/// Upload `body` the way the browser SPA does: declare
/// `checksum_trailer = true` and append a 32-byte BLAKE3 trailer after
/// the body on the same stream.
async fn put_with_trailer(
    conn: &Connection,
    path: &str,
    body: &[u8],
    trailer: [u8; 32],
) -> Response {
    let (mut send, mut recv) = open_bi(conn).await;
    let req = Request::Put {
        path: path.to_string(),
        size: body.len() as u64,
        mode: 0o644,
        offset: 0,
        hash_algorithm: qftp_common::protocol::HashAlgorithm::Blake3,
        checksum: None,
        no_clobber: false,
        checksum_trailer: true,
        encoding: Encoding::Identity,
        plaintext_size: 0,
    };
    send.write_all(&encode_framed_message(&req).unwrap())
        .await
        .expect("write put header");
    send.write_all(body).await.expect("write put body");
    send.write_all(&trailer).await.expect("write put trailer");
    send.finish().await.expect("finish put");
    let mut data = read_to_end(&mut recv).await;
    decode_response(&mut data)
}

/// Download `path`; returns the framed response plus the trailing
/// bytes (body + 32-byte BLAKE3 trailer).
async fn get(conn: &Connection, path: &str) -> (Response, Vec<u8>) {
    let (mut send, mut recv) = open_bi(conn).await;
    let req = Request::Get {
        path: path.to_string(),
        offset: 0,
        length: None,
        accept_encoding: Vec::new(),
    };
    send.write_all(&encode_framed_message(&req).unwrap())
        .await
        .expect("write get");
    send.finish().await.expect("finish get");
    let mut data = read_to_end(&mut recv).await;
    let resp = decode_response(&mut data);
    (resp, data)
}

/// Like [`get`] but resumes from `offset`, exercising the whole-file
/// BLAKE3 trailer path for a partial download.
async fn get_at(conn: &Connection, path: &str, offset: u64) -> (Response, Vec<u8>) {
    let (mut send, mut recv) = open_bi(conn).await;
    let req = Request::Get {
        path: path.to_string(),
        offset,
        length: None,
        accept_encoding: Vec::new(),
    };
    send.write_all(&encode_framed_message(&req).unwrap())
        .await
        .expect("write get");
    send.finish().await.expect("finish get");
    let mut data = read_to_end(&mut recv).await;
    let resp = decode_response(&mut data);
    (resp, data)
}

fn expect_ok(resp: Response, ctx: &str) {
    match resp {
        Response::Ok => {}
        other => panic!("{ctx}: expected Ok, got {other:?}"),
    }
}

fn expect_err(resp: Response, ctx: &str) -> ErrorCode {
    match resp {
        Response::Err(e) => e.code,
        other => panic!("{ctx}: expected Err, got {other:?}"),
    }
}

async fn dial(
    endpoint: &Endpoint<Client>,
    port: u16,
    token: &str,
) -> Result<Connection, wtransport::error::ConnectingError> {
    endpoint
        .connect(format!("https://127.0.0.1:{port}/?token={token}").as_str())
        .await
}

fn write_file(path: &Path, contents: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

/// Issue one HTTP/1.1 GET against the SPA listener and return the
/// whole response (head + body).
async fn http_get(port: u16, path: &str) -> String {
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect SPA http port");
    sock.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_webtransport() {
    let dir = tempfile::tempdir().unwrap();
    let base: PathBuf = dir.path().canonicalize().unwrap();
    let root = base.join("root");
    std::fs::create_dir(&root).unwrap();

    // A short-lived ECDSA P-256 cert: the shape `serverCertificateHashes`
    // pinning requires, so the test client can trust it by hash.
    let identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    let cert_hash = identity.certificate_chain().as_slice()[0].hash();
    let cert_path = base.join("cert.pem");
    let key_path = base.join("key.pem");
    identity
        .certificate_chain()
        .store_pemfile(&cert_path)
        .await
        .unwrap();
    identity
        .private_key()
        .store_secret_pemfile(&key_path)
        .await
        .unwrap();

    let users_path = base.join("users.toml");
    write_file(
        &users_path,
        "[[users]]\n\
         name = \"alice\"\n\
         permissions = { read = true, write = true, delete = true, \
         mkdir = true, rmdir = true, rename = true, chmod = true }\n\
         \n\
         [[users]]\n\
         name = \"bob\"\n\
         permissions = { read = true }\n",
    );
    let tokens_path = base.join("tokens.toml");
    write_file(
        &tokens_path,
        "[[tokens]]\ntoken = \"tok-alice\"\nuser = \"alice\"\n\
         \n\
         [[tokens]]\ntoken = \"tok-bob\"\nuser = \"bob\"\n",
    );

    let wt_port = free_udp_port();
    let http_port = free_tcp_port();

    let child = Command::new(env!("CARGO_BIN_EXE_qftp-web-bridge"))
        .args([
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--bind",
            &format!("127.0.0.1:{wt_port}"),
            "--http-bind",
            &format!("127.0.0.1:{http_port}"),
            "--root",
            root.to_str().unwrap(),
            "--users",
            users_path.to_str().unwrap(),
            "--users-tokens",
            tokens_path.to_str().unwrap(),
        ])
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn qftp-web-bridge");
    let mut bridge = Bridge(child);

    let client_config = ClientConfig::builder()
        .with_bind_address("127.0.0.1:0".parse().unwrap())
        .with_server_certificate_hashes([cert_hash.clone()])
        .build();
    let endpoint = Endpoint::client(client_config).expect("client endpoint");

    // The bridge needs a moment to load the cert and bind. Retry the
    // first connection until it comes up.
    let mut alice = None;
    for _ in 0..50 {
        if let Some(status) = bridge.0.try_wait().expect("try_wait") {
            panic!("bridge exited early with {status}");
        }
        match dial(&endpoint, wt_port, "tok-alice").await {
            Ok(conn) => {
                alice = Some(conn);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(150)).await,
        }
    }
    let alice = alice.expect("bridge never became reachable");

    // mkdir
    expect_ok(
        op(
            &alice,
            &Request::Mkdir {
                path: "/sub".into(),
            },
        )
        .await,
        "mkdir",
    );

    // put -- 300 KB exercises the multi-chunk streaming loops.
    let body: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let digest = *blake3::hash(&body).as_bytes();
    expect_ok(
        put(&alice, "/sub/big.bin", &body, Some(digest)).await,
        "put with valid checksum",
    );
    assert_eq!(
        std::fs::read(root.join("alice/sub/big.bin")).unwrap(),
        body,
        "uploaded bytes must land in the user's home"
    );

    // ls
    match op(
        &alice,
        &Request::Ls {
            path: "/sub".into(),
            cursor: None,
        },
    )
    .await
    {
        Response::DirListing { entries, .. } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name, "big.bin");
            assert_eq!(entries[0].size, body.len() as u64);
            assert!(!entries[0].is_dir());
        }
        other => panic!("ls: expected DirListing, got {other:?}"),
    }

    // get -- verify the body and the 32-byte BLAKE3 trailer.
    let (resp, rest) = get(&alice, "/sub/big.bin").await;
    match resp {
        Response::FileReady { size, .. } => {
            let size = size as usize;
            assert_eq!(rest.len(), size + 32, "body + trailer length");
            assert_eq!(&rest[..size], &body[..], "downloaded body mismatch");
            assert_eq!(
                &rest[size..size + 32],
                blake3::hash(&body).as_bytes(),
                "BLAKE3 trailer mismatch"
            );
        }
        other => panic!("get: expected FileReady, got {other:?}"),
    }

    // Resumed get (offset > 0) -- the body is the [offset..] suffix but the
    // trailer must be the WHOLE-file BLAKE3 (the prefix re-hashed), so the
    // native client can verify its local [0..offset) prefix against it
    // (#265). The old code hashed only the suffix, which always mismatched.
    {
        let offset = (body.len() / 3) as u64;
        let (resp, rest) = get_at(&alice, "/sub/big.bin", offset).await;
        match resp {
            Response::FileReady {
                size, total_size, ..
            } => {
                let size = size as usize;
                assert_eq!(total_size, body.len() as u64, "resumed get total_size");
                assert_eq!(size, body.len() - offset as usize, "resumed get size");
                assert_eq!(rest.len(), size + 32, "resumed body + trailer length");
                assert_eq!(
                    &rest[..size],
                    &body[offset as usize..],
                    "resumed body must be the [offset..] suffix"
                );
                assert_eq!(
                    &rest[size..size + 32],
                    blake3::hash(&body).as_bytes(),
                    "resumed get must send whole-file BLAKE3, not suffix-only"
                );
            }
            other => panic!("resumed get: expected FileReady, got {other:?}"),
        }
    }

    // A resumed get whose offset exceeds SEND_CHUNK_SIZE (256 KiB): the
    // prefix re-hash loop must iterate more than once, crossing a chunk
    // boundary (prefix_remaining -= want, read_exact) before the body
    // streams. A 600 KB upload with a 300 KB offset makes the loop run
    // twice (256 KiB + ~44 KiB), guarding the boundary arithmetic (#277).
    {
        let big_body: Vec<u8> = (0..600_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let big_digest = *blake3::hash(&big_body).as_bytes();
        expect_ok(
            put(&alice, "/sub/multi.bin", &big_body, Some(big_digest)).await,
            "put multi-chunk-prefix body",
        );

        let offset = 300_000u64;
        assert!(
            offset > 256 * 1024,
            "offset must exceed SEND_CHUNK_SIZE to span the prefix loop"
        );
        let (resp, rest) = get_at(&alice, "/sub/multi.bin", offset).await;
        match resp {
            Response::FileReady {
                size, total_size, ..
            } => {
                let size = size as usize;
                assert_eq!(total_size, big_body.len() as u64, "multi-prefix total_size");
                assert_eq!(size, big_body.len() - offset as usize, "multi-prefix size");
                assert_eq!(rest.len(), size + 32, "multi-prefix body + trailer length");
                assert_eq!(
                    &rest[..size],
                    &big_body[offset as usize..],
                    "multi-prefix body must be the [offset..] suffix"
                );
                assert_eq!(
                    &rest[size..size + 32],
                    blake3::hash(&big_body).as_bytes(),
                    "multi-prefix resumed get must re-hash the whole file across chunks"
                );
            }
            other => panic!("multi-prefix resumed get: expected FileReady, got {other:?}"),
        }

        // offset == total_size: zero body, the trailer is the whole-file
        // BLAKE3 (the prefix is the entire file). Exercises the edge where
        // the body loop never runs but the prefix re-hash covers everything.
        let (resp, rest) = get_at(&alice, "/sub/multi.bin", big_body.len() as u64).await;
        match resp {
            Response::FileReady {
                size, total_size, ..
            } => {
                assert_eq!(size, 0, "offset==total must yield a zero-length body");
                assert_eq!(
                    total_size,
                    big_body.len() as u64,
                    "offset==total total_size"
                );
                assert_eq!(rest.len(), 32, "offset==total must send only the trailer");
                assert_eq!(
                    &rest[..32],
                    blake3::hash(&big_body).as_bytes(),
                    "offset==total trailer must be the whole-file BLAKE3"
                );
            }
            other => panic!("offset==total get: expected FileReady, got {other:?}"),
        }

        expect_ok(
            op(
                &alice,
                &Request::Rm {
                    path: "/sub/multi.bin".into(),
                },
            )
            .await,
            "rm multi.bin",
        );
    }

    // A wrong header checksum must be refused and must not appear on disk.
    let code = expect_err(
        put(&alice, "/sub/bad.bin", &body, Some([0u8; 32])).await,
        "put with wrong checksum",
    );
    assert_eq!(code, ErrorCode::ChecksumMismatch);
    assert!(
        !root.join("alice/sub/bad.bin").exists(),
        "a checksum-failed upload must not be committed"
    );

    // A streamed BLAKE3 trailer -- the path the browser SPA uses for
    // every upload -- must verify and commit.
    expect_ok(
        put_with_trailer(&alice, "/sub/trailer.bin", &body, digest).await,
        "put with valid streamed trailer",
    );
    assert_eq!(
        std::fs::read(root.join("alice/sub/trailer.bin")).unwrap(),
        body,
        "trailer-verified upload must land on disk"
    );
    // A wrong streamed trailer must be refused like a wrong header
    // checksum, and must not leave a file behind.
    let code = expect_err(
        put_with_trailer(&alice, "/sub/bad-trailer.bin", &body, [0u8; 32]).await,
        "put with wrong streamed trailer",
    );
    assert_eq!(code, ErrorCode::ChecksumMismatch);
    assert!(
        !root.join("alice/sub/bad-trailer.bin").exists(),
        "a trailer-checksum-failed upload must not be committed"
    );
    expect_ok(
        op(
            &alice,
            &Request::Rm {
                path: "/sub/trailer.bin".into(),
            },
        )
        .await,
        "rm trailer.bin",
    );

    // rename / rm / rmdir
    expect_ok(
        op(
            &alice,
            &Request::Rename {
                from: "/sub/big.bin".into(),
                to: "/sub/renamed.bin".into(),
            },
        )
        .await,
        "rename",
    );
    expect_ok(
        op(
            &alice,
            &Request::Rm {
                path: "/sub/renamed.bin".into(),
            },
        )
        .await,
        "rm",
    );
    expect_ok(
        op(
            &alice,
            &Request::Rmdir {
                path: "/sub".into(),
            },
        )
        .await,
        "rmdir",
    );

    // ACL: bob is read-only, so mkdir must be refused.
    let bob = dial(&endpoint, wt_port, "tok-bob")
        .await
        .expect("bob connects");
    let code = expect_err(
        op(
            &bob,
            &Request::Mkdir {
                path: "/nope".into(),
            },
        )
        .await,
        "bob mkdir",
    );
    assert_eq!(code, ErrorCode::PermissionDenied);

    // An unknown token must be refused at the session layer.
    assert!(
        dial(&endpoint, wt_port, "not-a-real-token").await.is_err(),
        "an unknown bearer token must not establish a session"
    );

    // The SPA HTTP listener serves the bundled page.
    let page = http_get(http_port, "/").await;
    assert!(page.starts_with("HTTP/1.1 200 OK"), "SPA http status");
    assert!(page.contains("<!doctype html>"), "SPA http body");

    // /config.json advertises the WebTransport port and the leaf
    // certificate hash the SPA pins for self-signed deployments.
    let cfg = http_get(http_port, "/config.json").await;
    assert!(cfg.starts_with("HTTP/1.1 200 OK"), "config.json status");
    assert!(cfg.contains("application/json"), "config.json content type");
    let expected_hash: String = cert_hash
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        cfg.contains(&format!("\"certHash\":\"{expected_hash}\"")),
        "config.json must advertise the leaf cert hash, got: {cfg}"
    );
    assert!(
        cfg.contains(&format!("\"webtransportPort\":{wt_port}")),
        "config.json must advertise the WebTransport port"
    );

    drop(alice);
    drop(bob);
    let _ = bridge.0.kill();
}
