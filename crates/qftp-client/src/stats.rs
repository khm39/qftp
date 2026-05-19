//! Process-global transfer counters surfaced via the REPL `stats`
//! command (#80). Cheap AtomicU64s incremented from
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

/// `12 B` / `1.2 KB` / `3.4 MB` / `5.6 GB`. Matches the REPL `ls`
/// rendering style.
pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m{:02}s", secs / 3600, (secs / 60) % 60, secs % 60)
    }
}

/// Print a human-readable summary of the snapshot to stdout. Output
/// format is stable enough to grep in tests but not a structured API.
pub fn print(s: &Snapshot) {
    let total = s.files_uploaded + s.files_downloaded;
    let success = total;
    let failed = s.transfers_failed;
    let attempted = success + failed;
    let pct = if attempted == 0 {
        100.0
    } else {
        (success as f64 / attempted as f64) * 100.0
    };
    println!("uptime:    {}", format_duration(s.uptime));
    println!(
        "transfers: {success} succeeded, {failed} failed ({pct:.0}%)",
        success = success,
        failed = failed,
        pct = pct
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_thresholds() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn format_duration_rolls_over() {
        use std::time::Duration;
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(75)), "1m15s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h01m01s");
    }
}
