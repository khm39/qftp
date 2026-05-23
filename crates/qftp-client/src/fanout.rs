//! `qftp-client put-multi --to host1,host2,... LOCAL REMOTE_PATH`
//!
//! Upload one local file to N servers in parallel. Each target is
//! served by its own OS thread that runs the same connection +
//! upload path as one-shot mode; the threads run concurrently so the
//! wall-clock time is approximately `max(individual upload)`,
//! not `sum`. This is the QUIC angle the issue lists: cheap
//! connection setup means N independent connections actually beat
//! a serial scp loop.
//!
//! Failure modes:
//!   - `--strict`: one failure exits the process non-zero. Survivors
//!     finish; we don't try to roll them back.
//!   - default (best-effort): we keep going and report the survivor
//!     count at the end.

use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};

use crate::config::{self, Overrides};

#[derive(Debug)]
struct Outcome {
    host: String,
    ok: bool,
    elapsed_ms: u128,
    message: String,
}

pub fn run(
    local: &str,
    remote_path: &str,
    targets: &[String],
    strict: bool,
    overrides: &Overrides,
) -> Result<i32> {
    if targets.is_empty() {
        anyhow::bail!("put-multi: need at least one --to host");
    }
    let local_path = std::path::PathBuf::from(local);
    if !local_path.is_file() {
        anyhow::bail!("put-multi: not a regular file: {local}");
    }

    let results: Arc<Mutex<Vec<Outcome>>> = Arc::new(Mutex::new(Vec::with_capacity(targets.len())));
    let mut handles: Vec<(String, thread::JoinHandle<()>)> = Vec::with_capacity(targets.len());

    for host in targets {
        let host = host.clone();
        let local_path = local_path.clone();
        let remote_path = remote_path.to_string();
        let overrides = overrides.clone();
        let results = Arc::clone(&results);
        let host_for_handle = host.clone();
        let h = thread::Builder::new()
            .name(format!("fanout-{host}"))
            .spawn(move || {
                let t0 = Instant::now();
                let res = upload_to_host(&host, &local_path, &remote_path, &overrides);
                let elapsed_ms = t0.elapsed().as_millis();
                let outcome = match res {
                    Ok(()) => Outcome {
                        host: host.clone(),
                        ok: true,
                        elapsed_ms,
                        message: "ok".to_string(),
                    },
                    Err(e) => Outcome {
                        host: host.clone(),
                        ok: false,
                        elapsed_ms,
                        message: format!("{e:#}"),
                    },
                };
                results
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(outcome);
            })
            .context("spawn fanout worker")?;
        handles.push((host_for_handle, h));
    }

    for (host, h) in handles {
        if let Err(payload) = h.join() {
            // A worker that panicked never wrote its Outcome, so the
            // summary line below would silently undercount the targets.
            // Synthesize a failure Outcome here so the user sees one
            // row per --to host and can tell that something blew up.
            let msg = panic_payload_message(payload);
            results
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Outcome {
                    host,
                    ok: false,
                    elapsed_ms: 0,
                    message: format!("worker thread panicked: {msg}"),
                });
        }
    }
    let results = Arc::into_inner(results)
        .expect("all worker threads have been joined; this is the sole Arc owner")
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());

    let mut ok = 0;
    let mut fail = 0;
    let mut total_ms = 0u128;
    println!("put-multi results:");
    for o in &results {
        let status = if o.ok { "OK" } else { "FAIL" };
        println!(
            "  {status:5} {host:<32} {ms:>6} ms  {msg}",
            host = o.host,
            ms = o.elapsed_ms,
            msg = o.message
        );
        if o.ok {
            ok += 1;
        } else {
            fail += 1;
        }
        total_ms = total_ms.max(o.elapsed_ms);
    }
    println!(
        "summary: {ok} ok, {fail} fail, {n} total (wall-clock {total_ms} ms vs serial estimate {serial_ms} ms)",
        n = results.len(),
        serial_ms = results.iter().map(|o| o.elapsed_ms).sum::<u128>()
    );

    if strict && fail > 0 {
        return Ok(crate::oneshot::exit::DATA);
    }
    if ok == 0 {
        return Ok(crate::oneshot::exit::DATA);
    }
    Ok(crate::oneshot::exit::OK)
}

/// Best-effort extraction of a panic payload's message for inclusion
/// in the fanout summary. Mirrors what the default panic hook does
/// when it prints to stderr: `panic!("...")` uses `&'static str`, and
/// `panic!("...{}", x)` boxes a `String`.
fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "<non-string panic payload>".to_string()
}

fn upload_to_host(
    host: &str,
    local: &std::path::Path,
    remote_path: &str,
    overrides: &Overrides,
) -> Result<()> {
    // Build a qftp:// URL pointing at this host + path and reuse the
    // one-shot Put path; transfer::do_put hashes the body itself.
    let url = if !host.contains("://") {
        format!("qftp://{host}{remote_path}")
    } else {
        // Caller already passed a fully qualified URL; respect it.
        host.to_string()
    };
    let url_obj = config::parse_url(&url).with_context(|| format!("bad target URL {url}"))?;
    let host_port = config::format_host_port(&url_obj.host, url_obj.port);
    let path = url_obj.initial_path.unwrap_or_else(|| "/".to_string());
    let target = format!("qftp://{host_port}{path}");

    let spec = config::resolve(Some(&target), &config::ConfigFile::default(), overrides)
        .with_context(|| format!("resolve {target}"))?;

    // The actual upload reuses transfer::do_put via a hand-rolled
    // tiny client loop. We don't go through `oneshot::run` because
    // that one calls std::process::exit at the end.
    do_put_once(&spec, local, &path)
}

fn do_put_once(
    spec: &crate::config::ConnectionSpec,
    local: &std::path::Path,
    remote_path: &str,
) -> Result<()> {
    use qftp_common::protocol::Request;
    use qftp_common::transport::*;

    let crate::connect::Established {
        mut conn,
        socket,
        mut poll,
        mut events,
        ..
    } = crate::connect::establish(
        spec,
        "fanout",
        crate::connect::EstablishOpts::for_spec(spec),
    )?;

    let mut next_stream_id: u64 = 0;
    let put_stream = crate::proto::take_stream(&mut next_stream_id);
    crate::transfer::do_put(
        &mut conn,
        &socket,
        &mut poll,
        &mut events,
        put_stream,
        local,
        remote_path,
        0,
        false,
    )?;

    // Polite close.
    let quit_stream = crate::proto::take_stream(&mut next_stream_id);
    let _ = send_message(&mut conn, quit_stream, &Request::Quit);
    let _ = stream_send_all(&mut conn, quit_stream, &[], true);
    let _ = flush_egress(&mut conn, &socket);

    if let Some(dir) = crate::session_store::default_dir() {
        let _ = crate::session_store::save_from_conn(&dir, &spec.host, &conn);
    }

    Ok(())
}
