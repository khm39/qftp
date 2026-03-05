use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use mio::{Events, Interest, Poll, Token};
use qftp_common::protocol::*;
use qftp_common::transport::*;

mod handler;

const SERVER: Token = Token(0);

#[derive(Parser)]
#[command(name = "qftp-server", about = "QUIC File Transfer Protocol Server")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    bind: String,
    #[arg(long, default_value = ".")]
    root: String,
}

enum StreamState {
    ReadingRequest { buf: Vec<u8> },
    ReadingFileData { path: PathBuf, remaining: u64, data: Vec<u8>, mode: u32 },
    Done,
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let root = fs::canonicalize(&args.root).context("failed to canonicalize root directory")?;

    // Generate self-signed certificate.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("failed to generate self-signed certificate")?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    // Write cert and key to temp files for quiche.
    let cert_path = std::env::temp_dir().join("qftp-server-cert.pem");
    let key_path = std::env::temp_dir().join("qftp-server-key.pem");
    fs::write(&cert_path, &cert_pem).context("failed to write cert PEM")?;
    fs::write(&key_path, &key_pem).context("failed to write key PEM")?;

    let mut config = create_server_config(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
    )?;

    // Create UDP socket.
    let addr: std::net::SocketAddr = args.bind.parse().context("invalid bind address")?;
    let std_socket = std::net::UdpSocket::bind(addr).context("failed to bind UDP socket")?;
    std_socket.set_nonblocking(true).context("failed to set nonblocking")?;
    let mut socket = mio::net::UdpSocket::from_std(std_socket);

    log::info!("QFTP server listening on {}", addr);

    // Register with mio.
    let mut poll = Poll::new().context("failed to create mio Poll")?;
    poll.registry()
        .register(&mut socket, SERVER, Interest::READABLE)
        .context("failed to register socket with poll")?;

    let mut events = Events::with_capacity(1024);

    // Connection state.
    let mut conn: Option<quiche::Connection> = None;
    let mut cwd: PathBuf = root.clone();
    let mut streams: HashMap<u64, StreamState> = HashMap::new();

    let mut buf = [0u8; 65536];

    let rng = ring::rand::SystemRandom::new();

    loop {
        // Calculate poll timeout from QUIC connection timeout.
        let timeout = conn.as_ref().and_then(|c| c.timeout());

        poll.poll(&mut events, timeout).context("poll failed")?;

        // Handle timeout.
        if let Some(ref mut c) = conn {
            if c.is_timed_out() {
                log::info!("Connection timed out, resetting state");
                conn = None;
                cwd = root.clone();
                streams.clear();
                continue;
            }
            c.on_timeout();
        }

        // Read incoming UDP packets.
        let local_addr = socket.local_addr().context("failed to get local addr")?;
        loop {
            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("UDP recv_from failed"),
            };

            if conn.is_none() {
                // Parse QUIC header to check for Initial packet.
                let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                    Ok(hdr) => hdr,
                    Err(e) => {
                        log::warn!("Failed to parse QUIC header: {:?}", e);
                        continue;
                    }
                };

                if hdr.ty != quiche::Type::Initial {
                    log::warn!("Non-Initial packet without connection, ignoring");
                    continue;
                }

                // Generate server connection ID.
                let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
                ring::rand::SecureRandom::fill(&rng, &mut scid_bytes).unwrap();
                let scid = quiche::ConnectionId::from_vec(scid_bytes.to_vec());

                let new_conn = quiche::accept(&scid, None, local_addr, from, &mut config)
                    .context("failed to accept QUIC connection")?;

                log::info!("New QUIC connection from {}", from);
                conn = Some(new_conn);
            }

            // Feed the packet into the connection.
            if let Some(ref mut c) = conn {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                match c.recv(&mut buf[..len], recv_info) {
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("QUIC recv error: {:?}", e);
                    }
                }
            }
        }

        // Process readable streams.
        if let Some(ref mut c) = conn {
            let readable: Vec<u64> = c.readable().collect();

            for stream_id in readable {
                // Ensure there is a stream state entry.
                if !streams.contains_key(&stream_id) {
                    streams.insert(stream_id, StreamState::ReadingRequest { buf: Vec::new() });
                }

                let state = streams.get_mut(&stream_id).unwrap();

                match state {
                    StreamState::ReadingRequest { buf: ref mut stream_buf } => {
                        let req: Option<Request> = recv_message(c, stream_id, stream_buf)?;

                        if let Some(req) = req {
                            log::info!("Stream {} request: {:?}", stream_id, req);

                            match req {
                                Request::Get { ref path } => {
                                    match handler::resolve(&cwd, &root, path) {
                                        Ok(file_path) => {
                                            match fs::read(&file_path) {
                                                Ok(data) => {
                                                    let size = data.len() as u64;
                                                    send_message(c, stream_id, &Response::FileReady { size })?;
                                                    c.stream_send(stream_id, &data, true)
                                                        .context("failed to send file data")?;
                                                }
                                                Err(e) => {
                                                    send_message(
                                                        c,
                                                        stream_id,
                                                        &Response::Err(format!("Failed to read file: {e}")),
                                                    )?;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            send_message(c, stream_id, &Response::Err(e))?;
                                        }
                                    }
                                    *state = StreamState::Done;
                                }

                                Request::Put { ref path, size, mode } => {
                                    let file_path = match handler::resolve_parent(&cwd, &root, path) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            send_message(c, stream_id, &Response::Err(e))?;
                                            *state = StreamState::Done;
                                            continue;
                                        }
                                    };

                                    // Any leftover data in stream_buf is the start of file data.
                                    let leftover = std::mem::take(stream_buf);

                                    *state = StreamState::ReadingFileData {
                                        path: file_path,
                                        remaining: size,
                                        data: leftover,
                                        mode,
                                    };

                                    // Check if we already have all the data.
                                    if let StreamState::ReadingFileData {
                                        ref path,
                                        remaining,
                                        ref data,
                                        mode,
                                    } = state
                                    {
                                        if data.len() as u64 >= *remaining {
                                            let file_data = &data[..*remaining as usize];
                                            match fs::write(path, file_data) {
                                                Ok(()) => {
                                                    let perms = fs::Permissions::from_mode(*mode);
                                                    if let Err(e) = fs::set_permissions(path, perms) {
                                                        log::warn!("Failed to set permissions on {}: {}", path.display(), e);
                                                    }
                                                    send_message(c, stream_id, &Response::Ok)?;
                                                }
                                                Err(e) => {
                                                    send_message(
                                                        c,
                                                        stream_id,
                                                        &Response::Err(format!(
                                                            "Failed to write file: {e}"
                                                        )),
                                                    )?;
                                                }
                                            }
                                            *state = StreamState::Done;
                                        }
                                    }
                                }

                                Request::Quit => {
                                    send_message(c, stream_id, &Response::Ok)?;
                                    flush_egress(c, &socket)?;
                                    c.close(true, 0x00, b"bye")
                                        .ok(); // may already be closing
                                    *state = StreamState::Done;
                                }

                                other => {
                                    let response = handler::handle_request(&other, &mut cwd, &root);
                                    send_message(c, stream_id, &response)?;
                                    *state = StreamState::Done;
                                }
                            }
                        }
                    }

                    StreamState::ReadingFileData {
                        ref path,
                        remaining,
                        ref mut data,
                        mode,
                    } => {
                        let mut tmp = [0u8; STREAM_BUF_SIZE];
                        loop {
                            match c.stream_recv(stream_id, &mut tmp) {
                                Ok((len, _fin)) => {
                                    data.extend_from_slice(&tmp[..len]);
                                }
                                Err(quiche::Error::Done) => break,
                                Err(e) => {
                                    log::warn!("stream_recv error on stream {}: {:?}", stream_id, e);
                                    break;
                                }
                            }
                        }

                        if data.len() as u64 >= *remaining {
                            let file_data = &data[..*remaining as usize];
                            match fs::write(path, file_data) {
                                Ok(()) => {
                                    let perms = fs::Permissions::from_mode(*mode);
                                    let _ = fs::set_permissions(path, perms);
                                    send_message(c, stream_id, &Response::Ok)?;
                                }
                                Err(e) => {
                                    send_message(
                                        c,
                                        stream_id,
                                        &Response::Err(format!("Failed to write file: {e}")),
                                    )?;
                                }
                            }
                            *state = StreamState::Done;
                        }
                    }

                    StreamState::Done => {}
                }
            }

            // Flush outgoing data.
            flush_egress(c, &socket)?;

            // Check if connection is closed.
            if c.is_closed() {
                log::info!("Connection closed, resetting state");
                conn = None;
                cwd = root.clone();
                streams.clear();
                continue;
            }
        }

        // Clean up completed streams.
        streams.retain(|_, state| !matches!(state, StreamState::Done));
    }
}
