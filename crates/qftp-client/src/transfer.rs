//! Bulk Get/Put transfer logic for the client.
//!
//! Handles the bits of the protocol that the REPL doesn't model
//! directly:
//!   * Sending an offset for resume.
//!   * Computing BLAKE3 over uploads and verifying the server's
//!     trailer on downloads.
//!   * Driving a progress bar while bytes move.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use mio::{Events, Poll};
use qftp_common::protocol::*;
use qftp_common::transport::*;

const CHUNK: usize = 64 * 1024;

fn make_bar(total: u64, label: &str) -> ProgressBar {
    let bar = ProgressBar::new(total);
    bar.set_message(label.to_string());
    bar.set_style(
        ProgressStyle::with_template(
            "{msg:>10} {wide_bar} {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>12} eta {eta:>4}",
        )
        .unwrap()
        .progress_chars("=> "),
    );
    bar.enable_steady_tick(Duration::from_millis(120));
    bar
}

/// Download `remote` to `local`. If `local` already exists, resume from
/// its current length. Verifies the server-supplied BLAKE3 trailer once
/// the body is fully received and refuses to keep the file on mismatch.
pub fn do_get(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
    remote: &str,
    local: &Path,
) -> Result<()> {
    let resume_offset = match std::fs::metadata(local) {
        Ok(m) if m.is_file() => m.len(),
        _ => 0,
    };

    let req = Request::Get {
        path: remote.to_string(),
        offset: resume_offset,
        length: None,
    };
    send_message(conn, stream_id, &req)?;
    stream_send_all(conn, stream_id, &[], true)?;
    flush_egress(conn, socket)?;

    let resp = poll_response(conn, socket, poll, events, stream_id)?;
    let (size, total_size, checksum_follows) = match resp {
        Response::FileReady {
            size,
            total_size,
            checksum_follows,
        } => (size, total_size, checksum_follows),
        Response::Err(e) => {
            bail!("server refused Get: {} ({:?})", e.message, e.code);
        }
        other => bail!("unexpected response to Get: {other:?}"),
    };

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(resume_offset == 0)
        .open(local)
        .with_context(|| format!("opening {} for write", local.display()))?;
    if resume_offset > 0 {
        file.seek(SeekFrom::Start(resume_offset))
            .with_context(|| format!("seeking to {resume_offset}"))?;
    }

    let bar = make_bar(total_size, "download");
    bar.set_position(resume_offset);

    let mut received: u64 = 0;
    let mut hasher = blake3::Hasher::new();
    let mut trailer = Vec::<u8>::new();
    let mut tmp = [0u8; CHUNK];

    let want_trailer = if checksum_follows { 32 } else { 0 };
    let mut stream_finished = false;

    while received < size || trailer.len() < want_trailer {
        poll.poll(events, conn.timeout().or(Some(Duration::from_millis(100))))?;
        conn.on_timeout();
        handle_ingress(conn, socket, &mut [0u8; 65535])?;

        loop {
            match conn.stream_recv(stream_id, &mut tmp) {
                Ok((len, fin)) => {
                    if received < size {
                        let body_room = (size - received) as usize;
                        let body_take = body_room.min(len);
                        file.write_all(&tmp[..body_take])
                            .context("writing body chunk")?;
                        hasher.update(&tmp[..body_take]);
                        received += body_take as u64;
                        bar.set_position(resume_offset + received);
                        if body_take < len {
                            // overflow into trailer bytes
                            trailer.extend_from_slice(&tmp[body_take..len]);
                        }
                    } else {
                        trailer.extend_from_slice(&tmp[..len]);
                    }
                    if fin {
                        stream_finished = true;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => bail!("stream_recv: {e}"),
            }
        }
        flush_egress(conn, socket)?;

        // If the server FIN'd the stream early without delivering the
        // full body + trailer, don't sit and spin waiting for bytes
        // that will never come.
        if stream_finished && (received < size || trailer.len() < want_trailer) {
            let _ = std::fs::remove_file(local);
            bail!(
                "server closed stream early: got {}/{} body bytes and {}/{} trailer bytes",
                received,
                size,
                trailer.len(),
                want_trailer
            );
        }

        if conn.is_closed() && (received < size || trailer.len() < want_trailer) {
            bail!("connection closed during download");
        }
    }

    file.flush().ok();
    bar.finish_and_clear();

    if checksum_follows {
        let trailer_arr: [u8; 32] = trailer[..32]
            .try_into()
            .context("server trailer was not 32 bytes")?;
        let local_hash = *hasher.finalize().as_bytes();
        if local_hash != trailer_arr {
            // Tear down the corrupted local file rather than leave a
            // confusing half-bad artifact behind.
            let _ = std::fs::remove_file(local);
            bail!(
                "BLAKE3 checksum mismatch after download (expected {} bytes, hash didn't match)",
                size
            );
        }
    }

    println!(
        "Downloaded {} bytes to {} ({}verified)",
        size,
        local.display(),
        if checksum_follows { "" } else { "un" }
    );
    Ok(())
}

/// Upload `local` to `remote`. Sends a BLAKE3 checksum the server can
/// verify against the received bytes. Resume from an existing
/// server-side temp at `offset` is supported by passing it through.
#[allow(clippy::too_many_arguments)]
pub fn do_put(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    stream_id: u64,
    local: &Path,
    remote: &str,
    offset: u64,
) -> Result<()> {
    let meta =
        std::fs::metadata(local).with_context(|| format!("stat {} for upload", local.display()))?;
    let size = meta.len();

    if offset > size {
        bail!("resume offset {offset} is past local file size {size}; refusing");
    }

    // Hash whole local file first so we have a checksum to commit to.
    let mut hasher = blake3::Hasher::new();
    {
        let mut f = File::open(local).context("opening local for hashing")?;
        let mut buf = [0u8; CHUNK];
        loop {
            let n = f.read(&mut buf).context("reading local for hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }
    let checksum = *hasher.finalize().as_bytes();

    let bytes_to_send = size - offset;
    let mode = unix_mode(&meta);

    let req = Request::Put {
        path: remote.to_string(),
        size: bytes_to_send,
        mode,
        offset,
        checksum: Some(checksum),
    };
    send_message(conn, stream_id, &req)?;
    flush_egress(conn, socket)?;

    let mut f = File::open(local).context("opening local for send")?;
    if offset > 0 {
        f.seek(SeekFrom::Start(offset))?;
    }

    let bar = make_bar(size, "upload");
    bar.set_position(offset);

    let mut sent: u64 = 0;
    let mut buf = vec![0u8; CHUNK];
    while sent < bytes_to_send {
        let want = (bytes_to_send - sent) as usize;
        let want = want.min(buf.len());
        f.read_exact(&mut buf[..want])
            .context("reading local chunk")?;
        let is_last = sent + want as u64 == bytes_to_send;

        // The whole batch is one stream_send_all call, but we still want
        // to flush egress periodically so the server actually sees the
        // bytes. Send in CHUNK-sized pieces with intermediate flushes.
        stream_send_all(conn, stream_id, &buf[..want], is_last)?;
        flush_egress(conn, socket)?;

        sent += want as u64;
        bar.set_position(offset + sent);

        // Pump any incoming acks so flow-control opens up.
        poll.poll(events, conn.timeout().or(Some(Duration::from_millis(20))))?;
        conn.on_timeout();
        handle_ingress(conn, socket, &mut [0u8; 65535])?;
        flush_egress(conn, socket)?;
    }
    bar.finish_and_clear();

    let resp = poll_response(conn, socket, poll, events, stream_id)?;
    match resp {
        Response::Ok => {
            println!("Uploaded {bytes_to_send} bytes to {remote} (verified)");
            Ok(())
        }
        Response::Err(e) => bail!("server refused Put: {} ({:?})", e.message, e.code),
        other => bail!("unexpected response to Put: {other:?}"),
    }
}

#[cfg(unix)]
fn unix_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}
#[cfg(not(unix))]
fn unix_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
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
            bail!("Connection closed");
        }
    }
}
