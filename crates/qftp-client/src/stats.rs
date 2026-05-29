//! Process-global transfer counters surfaced via the REPL `stats`
//! command. Cheap AtomicU64s incremented from
//! `transfer::do_put` / `transfer::do_get`; printed on demand.
//!
//! Counters live for the lifetime of the client process, so a long
//! REPL session sees its full history. One-shot subcommands also
//! bump them but exit before anyone could ask, which is fine -- the
//! point of the feature is observability inside an interactive
//! session.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use qftp_common::util::{format_duration, format_size};

static STARTED_AT: OnceLock<Instant> = OnceLock::new();

static BYTES_UPLOADED: AtomicU64 = AtomicU64::new(0);
static BYTES_DOWNLOADED: AtomicU64 = AtomicU64::new(0);
static FILES_UPLOADED: AtomicU64 = AtomicU64::new(0);
static FILES_DOWNLOADED: AtomicU64 = AtomicU64::new(0);
static TRANSFERS_FAILED: AtomicU64 = AtomicU64::new(0);

/// Stamp the process start time. Called once from `main`. Safe to
/// call more than once -- subsequent calls are no-ops.
pub fn init() {
    let _ = STARTED_AT.set(Instant::now());
}

/// Record a successful upload of `bytes`. The caller is responsible
/// for only invoking this on the success path (post-checksum-ack).
pub fn record_upload(bytes: u64) {
    BYTES_UPLOADED.fetch_add(bytes, Ordering::Relaxed);
    FILES_UPLOADED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_download(bytes: u64) {
    BYTES_DOWNLOADED.fetch_add(bytes, Ordering::Relaxed);
    FILES_DOWNLOADED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_failure() {
    TRANSFERS_FAILED.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot used by the REPL renderer. We pull a single coherent set
/// of values rather than reading individual atomics in the format
/// string, mostly so the printout is internally consistent.
pub struct Snapshot {
    pub uptime: std::time::Duration,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub files_uploaded: u64,
    pub files_downloaded: u64,
    pub transfers_failed: u64,
}

pub fn snapshot() -> Snapshot {
    let started = STARTED_AT.get().copied().unwrap_or_else(Instant::now);
    Snapshot {
        uptime: started.elapsed(),
        bytes_uploaded: BYTES_UPLOADED.load(Ordering::Relaxed),
        bytes_downloaded: BYTES_DOWNLOADED.load(Ordering::Relaxed),
        files_uploaded: FILES_UPLOADED.load(Ordering::Relaxed),
        files_downloaded: FILES_DOWNLOADED.load(Ordering::Relaxed),
        transfers_failed: TRANSFERS_FAILED.load(Ordering::Relaxed),
    }
}

/// Print a human-readable summary of the snapshot to stdout. Output
/// format is stable enough to grep in tests but not a structured API.
pub fn print(s: &Snapshot) {
    let succeeded = s.files_uploaded + s.files_downloaded;
    let failed = s.transfers_failed;
    let attempted = succeeded + failed;
    let pct = if attempted == 0 {
        100.0
    } else {
        (succeeded as f64 / attempted as f64) * 100.0
    };
    println!("uptime:    {}", format_duration(s.uptime));
    println!("transfers: {succeeded} succeeded, {failed} failed ({pct:.0}%)");
    println!(
        "bytes:     up={}  down={}",
        format_size(s.bytes_uploaded),
        format_size(s.bytes_downloaded)
    );
    println!(
        "files:     {} uploaded, {} downloaded",
        s.files_uploaded, s.files_downloaded
    );
    if s.uptime.as_secs() > 0 {
        let up_rate = s.bytes_uploaded as f64 / s.uptime.as_secs_f64();
        let dn_rate = s.bytes_downloaded as f64 / s.uptime.as_secs_f64();
        println!(
            "avg rate:  up={}/s  down={}/s",
            format_size(up_rate as u64),
            format_size(dn_rate as u64)
        );
    }
}

