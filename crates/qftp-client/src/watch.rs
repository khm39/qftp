//! `qftp-client watch <local-dir> <remote-url>` — mirror filesystem
//! events under `<local-dir>` to the server in real time.
//!
//! - `notify` crate's recommended_watcher gives us inotify on Linux,
//!   FSEvents on macOS, and ReadDirectoryChangesW on Windows.
//! - Events are read off a channel, debounced for `debounce_ms`, and
//!   coalesced per-path (the last action wins, so a save→save→delete
//!   burst produces one `Rm`).
//! - The qftp connection is opened once and held for the lifetime of
//!   the watcher. On any transport error we drop it and reconnect
//!   with exponential backoff (1s → 2s → 4s → 8s → 16s → 30s cap).
//! - Ctrl-C / SIGTERM ends the loop cleanly after the current batch.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecursiveMode, Watcher};
use qftp_common::protocol::*;
use qftp_common::transport::*;

use crate::config::{self, ConnectionSpec, Overrides};
use crate::proto::{join_remote, Session};
use crate::transfer;

/// What we want done with one path after collapsing a burst of
/// inotify events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Upload,
    Delete,
}

pub fn run(local: &str, remote_url: &str, debounce_ms: u64, overrides: &Overrides) -> Result<i32> {
    let local_root = std::fs::canonicalize(local)
        .with_context(|| format!("watch: cannot canonicalize {local}"))?;
    if !local_root.is_dir() {
        return Err(anyhow!(
            "watch: {} is not a directory",
            local_root.display()
        ));
    }

    // Parse the remote URL. We hand the URL through the same resolver
    // the rest of the client uses so flags / aliases / TOFU behaviour
    // stay consistent.
    let url = config::parse_url(remote_url)
        .with_context(|| format!("watch: invalid remote URL {remote_url}"))?;
    let host_port = config::format_host_port(&url.host, url.port);
    let target = format!(
        "qftp://{host_port}{}",
        url.initial_path.as_deref().unwrap_or("/")
    );
    let spec = config::resolve(Some(&target), &config::ConfigFile::default(), overrides)?;
    let remote_prefix = url.initial_path.unwrap_or_else(|| "/".to_string());

    eprintln!(
        "watching {} -> {} (debounce {debounce_ms}ms; Ctrl-C to stop)",
        local_root.display(),
        target,
    );

    // Block SIGINT/SIGTERM on the main thread *before* spawning any
    // thread (notify watcher below, sigwait thread in install_sigint).
    // pthread_sigmask only affects the calling thread, and the block
    // is inherited by threads spawned afterwards — so every thread
    // alive at signal-delivery time has the signal blocked and it is
    // delivered deterministically to the sigwait thread instead of
    // triggering the default terminate action somewhere else.
    block_signals();

    // notify crate produces events on a channel.
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let _ = tx.send(ev);
        }
    })
    .context("failed to create filesystem watcher")?;
    watcher
        .watch(&local_root, RecursiveMode::Recursive)
        .with_context(|| format!("failed to watch {}", local_root.display()))?;

    let stop = install_sigint()?;

    let mut backoff = 1u64;
    while !stop.load(Ordering::Relaxed) {
        match run_session(&spec, &rx, &local_root, &remote_prefix, debounce_ms, &stop) {
            Ok(()) => {
                tracing::info!("watch: clean exit");
                break;
            }
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                tracing::warn!(error = %e, backoff_secs = backoff, "watch: connection lost; reconnecting");
                let mut slept = 0;
                while slept < backoff && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_secs(1));
                    slept += 1;
                }
                backoff = (backoff * 2).min(30);
            }
        }
    }
    Ok(0)
}

fn install_sigint() -> Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    ctrlc_handler(move || {
        s.store(true, Ordering::Relaxed);
    });
    Ok(stop)
}

/// Block SIGINT/SIGTERM on the current (main) thread. Must be called
/// before spawning the notify watcher and the sigwait thread so they
/// inherit the mask; otherwise a process-directed signal could be
/// delivered to an unblocked thread and terminate the process before
/// the stop flag is ever set.
fn block_signals() {
    #[cfg(unix)]
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

/// Tiny stand-in for the `ctrlc` crate: spawns a thread that blocks in
/// a raw `sigwait` for SIGINT/SIGTERM and runs `cb` once one arrives.
/// SIGINT/SIGTERM must already be blocked process-wide via
/// `block_signals` (called before any thread is spawned) so the signal
/// is steered to this dedicated thread rather than acted on elsewhere.
/// We keep the wrapper inline so qftp-client doesn't pull in another
/// crate (the server uses `signal_hook::flag::register` for the same
/// effect).
fn ctrlc_handler(cb: impl Fn() + Send + 'static) {
    #[cfg(unix)]
    {
        std::thread::spawn(move || unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::sigaddset(&mut set, libc::SIGTERM);
            let mut sig: i32 = 0;
            libc::sigwait(&set, &mut sig);
            cb();
        });
    }
    #[cfg(not(unix))]
    {
        // On non-Unix we degrade to "no Ctrl-C handling"; the OS
        // default will simply kill the process.
        let _ = cb;
    }
}

/// One full QUIC connection's worth of watching. Returns when the
/// stop flag fires or when something in transport / I/O goes wrong;
/// the caller then backs off and re-enters us.
fn run_session(
    spec: &ConnectionSpec,
    rx: &mpsc::Receiver<notify::Event>,
    local_root: &Path,
    remote_prefix: &str,
    debounce_ms: u64,
    stop: &AtomicBool,
) -> Result<()> {
    let crate::connect::Established {
        mut conn,
        socket,
        mut poll,
        mut events,
        ..
    } = crate::connect::establish(spec, "watch", crate::connect::EstablishOpts::for_spec(spec))?;
    let mut next_stream_id: u64 = 0;
    let mut pending: HashMap<PathBuf, Action> = HashMap::new();
    let mut last_event_at: Option<Instant> = None;

    // The watched root never changes for the lifetime of the session,
    // so canonicalize it once rather than on every debounce flush.
    let canonical_root = local_root
        .canonicalize()
        .with_context(|| format!("canonicalize watch root {}", local_root.display()))?;

    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        // Drain any new events with a short timeout so we can also
        // service the QUIC connection (and the stop flag).
        let wait = Duration::from_millis(debounce_ms.min(200));
        match rx.recv_timeout(wait) {
            Ok(ev) => {
                // notify reports a rename as two events on Linux: the
                // source as Modify(Name(From)) and the destination as
                // Modify(Name(To)). Mapping every Modify(_) to Upload
                // would leave the renamed-away source on the remote
                // forever (its Upload is skipped because the file is
                // gone), so split the rename modes out explicitly.
                let mut touched = false;
                match ev.kind {
                    EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                        // `paths` is [from, to]: the first is gone, the
                        // rest are new.
                        let mut it = ev.paths.into_iter();
                        if let Some(from) = it.next() {
                            pending.insert(from, Action::Delete);
                            touched = true;
                        }
                        for to in it {
                            pending.insert(to, Action::Upload);
                            touched = true;
                        }
                    }
                    EventKind::Modify(ModifyKind::Name(RenameMode::From))
                    | EventKind::Remove(_) => {
                        for p in ev.paths {
                            pending.insert(p, Action::Delete);
                            touched = true;
                        }
                    }
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for p in ev.paths {
                            // Last action per path wins.
                            pending.insert(p, Action::Upload);
                            touched = true;
                        }
                    }
                    _ => {}
                }
                if touched {
                    last_event_at = Some(Instant::now());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow!("watcher channel closed"));
            }
        }

        // Pump QUIC even if there's nothing to do — keep the
        // connection healthy.
        conn.on_timeout();
        let mut buf = [0u8; 65535];
        handle_ingress(&mut conn, &socket, &mut buf)?;
        flush_egress(&mut conn, &socket)?;
        if conn.is_closed() {
            return Err(anyhow!("server closed the connection"));
        }

        // Once `debounce_ms` has elapsed since the last event, flush
        // the pending map.
        let ready = match last_event_at {
            Some(t) if t.elapsed() >= Duration::from_millis(debounce_ms) => true,
            None => false,
            _ => false,
        };
        if !ready {
            continue;
        }

        // Notify follows symlinks under the watched tree on
        // Linux. A symlink planted inside `local_root` could point at
        // `/home/user/.ssh/` and be silently uploaded. Resolve each
        // event path through `canonicalize` and confirm the *real*
        // path is still under the canonical root before acting.
        for (path, action) in pending.drain() {
            let canonical = match path.canonicalize() {
                Ok(p) => p,
                Err(e) if matches!(action, Action::Delete) => {
                    // Removed paths can't be canonicalized — but their
                    // location can be, by taking the parent. If even
                    // the parent disappeared, just trust the strip
                    // prefix check; we're only sending an Rm.
                    path.parent()
                        .and_then(|p| p.canonicalize().ok())
                        .filter(|p| p.starts_with(&canonical_root))
                        .map(|_| path.clone())
                        .unwrap_or_else(|| {
                            tracing::warn!(error=%e, path=%path.display(),
                                "watch: cannot canonicalize delete target; skipping");
                            PathBuf::new()
                        })
                }
                Err(e) => {
                    tracing::warn!(error=%e, path=%path.display(),
                        "watch: cannot canonicalize event path; skipping");
                    continue;
                }
            };
            if canonical.as_os_str().is_empty() {
                continue;
            }
            if !canonical.starts_with(&canonical_root) {
                tracing::warn!(
                    path = %path.display(),
                    resolved = %canonical.display(),
                    "watch: ignoring event whose real path escapes the watched root (#115)"
                );
                continue;
            }
            let rel = match canonical.strip_prefix(&canonical_root) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let remote_path = join_remote(remote_prefix, rel);
            let mut session = Session {
                conn: &mut conn,
                socket: &socket,
                poll: &mut poll,
                events: &mut events,
                next_stream_id: &mut next_stream_id,
            };
            match action {
                Action::Upload => {
                    if !path.is_file() {
                        // create-then-delete arrived in the same
                        // window; skip silently.
                        continue;
                    }
                    let stream_id = session.take_stream();
                    if let Err(e) =
                        transfer::do_put(&mut session, stream_id, &path, &remote_path, 0, false)
                    {
                        tracing::warn!(error = %e, path = %path.display(), "watch: put failed");
                    } else {
                        tracing::info!(path = %remote_path, "watch: uploaded");
                    }
                }
                Action::Delete => {
                    let stream_id = session.take_stream();
                    let req = Request::Rm {
                        path: remote_path.clone(),
                    };
                    if let Err(e) = send_message(session.conn, stream_id, &req) {
                        tracing::warn!(error = %e, "watch: rm send failed");
                        return Err(anyhow!(e));
                    }
                    let _ = stream_send_all(session.conn, stream_id, &[], true);
                    flush_egress(session.conn, session.socket)?;
                    match session.poll_response(stream_id) {
                        Ok(Response::Ok) => {
                            tracing::info!(path = %remote_path, "watch: removed");
                        }
                        Ok(Response::Err(e)) => {
                            tracing::warn!(?e.code, msg = %e.message, "watch: rm rejected");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "watch: poll_response");
                            return Err(e);
                        }
                    }
                }
            }
        }
        last_event_at = None;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn block_signals_masks_sigint_and_sigterm() {
        // `block_signals` mutates the *calling* thread's mask, and cargo
        // reuses test threads, so snapshot the mask and restore it after
        // asserting to avoid leaking a blocked state into other tests.
        unsafe {
            let mut saved: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut saved);

            block_signals();

            let mut current: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current);

            let int_blocked = libc::sigismember(&current, libc::SIGINT) == 1;
            let term_blocked = libc::sigismember(&current, libc::SIGTERM) == 1;

            libc::pthread_sigmask(libc::SIG_SETMASK, &saved, std::ptr::null_mut());

            assert!(int_blocked, "block_signals must block SIGINT");
            assert!(term_blocked, "block_signals must block SIGTERM");
        }
    }
}
