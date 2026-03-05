use std::fs;
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use mio::{Events, Interest, Poll, Token};
use qftp_common::protocol::*;
use qftp_common::transport::*;

mod repl;

const CLIENT: Token = Token(0);

#[derive(Parser)]
#[command(name = "qftp-client", about = "QUIC File Transfer Protocol Client")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    host: String,
}

fn poll_response(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
) -> Result<Response> {
    let mut buf = Vec::new();
    loop {
        poll.poll(events, conn.timeout().or(Some(Duration::from_millis(100))))?;
        conn.on_timeout();
        handle_ingress(conn, socket, &mut [0u8; 65535])?;

        match recv_message::<Response>(conn, stream_id, &mut buf)? {
            Some(resp) => {
                flush_egress(conn, socket)?;
                return Ok(resp);
            }
            None => {
                flush_egress(conn, socket)?;
            }
        }

        if conn.is_closed() {
            anyhow::bail!("Connection closed");
        }
    }
}

fn poll_file_data(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
    size: u64,
) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        poll.poll(events, conn.timeout().or(Some(Duration::from_millis(100))))?;
        conn.on_timeout();
        handle_ingress(conn, socket, &mut [0u8; 65535])?;

        let mut tmp = [0u8; STREAM_BUF_SIZE];
        loop {
            match conn.stream_recv(stream_id, &mut tmp) {
                Ok((len, _fin)) => data.extend_from_slice(&tmp[..len]),
                Err(quiche::Error::Done) => break,
                Err(e) => anyhow::bail!("Stream recv error: {}", e),
            }
        }

        flush_egress(conn, socket)?;

        if data.len() as u64 >= size {
            data.truncate(size as usize);
            return Ok(data);
        }
        if conn.is_closed() {
            anyhow::bail!("Connection closed during file transfer");
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let mut config = create_client_config()?;

    let peer_addr = args.host.parse().context("failed to parse host address")?;

    let std_socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
    std_socket.set_nonblocking(true)?;
    std_socket.connect(peer_addr)?;

    let local_addr = std_socket.local_addr()?;

    let mut socket =
        mio::net::UdpSocket::from_std(std_socket);

    // Generate connection ID
    let rng = ring::rand::SystemRandom::new();
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    use ring::rand::SecureRandom;
    rng.fill(&mut scid_bytes).unwrap();
    let scid = quiche::ConnectionId::from_vec(scid_bytes.to_vec());

    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, peer_addr, &mut config)?;

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);

    poll.registry()
        .register(&mut socket, CLIENT, Interest::READABLE)?;

    // Perform handshake
    flush_egress(&mut conn, &socket)?;
    loop {
        poll.poll(&mut events, conn.timeout().or(Some(Duration::from_millis(100))))?;
        conn.on_timeout();
        handle_ingress(&mut conn, &socket, &mut [0u8; 65535])?;
        flush_egress(&mut conn, &socket)?;

        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            anyhow::bail!("Connection closed during handshake");
        }
    }

    println!("Connected to {}", args.host);

    let mut rl = rustyline::DefaultEditor::new()?;
    let mut next_stream_id: u64 = 0;

    loop {
        let line = match rl.readline("qftp> ") {
            Ok(l) => l,
            Err(rustyline::error::ReadlineError::Interrupted | rustyline::error::ReadlineError::Eof) => break,
            Err(e) => {
                println!("Error: {}", e);
                break;
            }
        };
        let _ = rl.add_history_entry(&line);

        let cmd = match repl::parse_command(&line) {
            Some(c) => c,
            None => continue,
        };

        let stream_id = next_stream_id;
        next_stream_id += 4;

        match cmd {
            repl::Command::Remote(ref req) => {
                let is_quit = matches!(req, Request::Quit);
                send_message(&mut conn, stream_id, req)?;
                conn.stream_send(stream_id, &[], true)?;
                flush_egress(&mut conn, &socket)?;
                let resp = poll_response(&mut conn, &socket, &mut poll, &mut events, stream_id)?;
                repl::display_response(&resp);
                if is_quit {
                    break;
                }
            }
            repl::Command::Get { remote, local } => {
                let req = Request::Get {
                    path: remote.clone(),
                };
                send_message(&mut conn, stream_id, &req)?;
                conn.stream_send(stream_id, &[], true)?;
                flush_egress(&mut conn, &socket)?;

                let resp = poll_response(&mut conn, &socket, &mut poll, &mut events, stream_id)?;
                match resp {
                    Response::FileReady { size } => {
                        let local_path = local.unwrap_or_else(|| {
                            Path::new(&remote)
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string()
                        });
                        println!("Downloading {} ({} bytes)...", local_path, size);
                        let data = poll_file_data(
                            &mut conn, &socket, &mut poll, &mut events, stream_id, size,
                        )?;
                        fs::write(&local_path, &data)?;
                        println!("Downloaded {} bytes to {}", data.len(), local_path);
                    }
                    Response::Err(e) => println!("Error: {}", e),
                    other => println!("Unexpected response: {:?}", other),
                }
            }
            repl::Command::Put { local, remote } => {
                let file_data = match fs::read(&local) {
                    Ok(d) => d,
                    Err(e) => {
                        println!("Error reading {}: {}", local, e);
                        continue;
                    }
                };
                let meta = fs::metadata(&local)?;
                let mode = meta.permissions().mode();
                let remote_path = remote.unwrap_or_else(|| {
                    Path::new(&local)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                });
                let req = Request::Put {
                    path: remote_path.clone(),
                    size: file_data.len() as u64,
                    mode,
                };
                send_message(&mut conn, stream_id, &req)?;
                conn.stream_send(stream_id, &file_data, true)?;
                flush_egress(&mut conn, &socket)?;
                println!("Uploading {} ({} bytes)...", remote_path, file_data.len());
                let resp =
                    poll_response(&mut conn, &socket, &mut poll, &mut events, stream_id)?;
                repl::display_response(&resp);
            }
        }
    }

    println!("Goodbye.");
    Ok(())
}
