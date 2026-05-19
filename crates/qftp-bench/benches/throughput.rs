//! End-to-end qftp throughput benchmarks.
//!
//! Spawns a real `qftp-server` over loopback, then drives `qftp-client
//! put` / `qftp-client get` for a handful of file sizes under criterion.
//! The reported metric is wall-clock time per transfer; criterion
//! computes throughput from the `Throughput::Bytes` we set on each
//! group.
//!
//! Run with:
//!   cargo bench -p qftp-bench
//!
//! Override the size set with `QFTP_BENCH_SIZES` (comma-separated bytes
//! or `<n>K|M`), e.g. `QFTP_BENCH_SIZES=1M,16M,64M`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput};

use qftp_bench::{write_random_file, ServerFixture};

/// Default size sweep. Default goes up to 1 GiB so the steady-state
/// throughput dominates handshake cost; override with `QFTP_BENCH_SIZES`
/// for a faster smoke run.
const DEFAULT_SIZES: &[usize] = &[1 << 20, 16 << 20, 64 << 20, 256 << 20, 1024 << 20];

fn parse_sizes() -> Vec<usize> {
    let Ok(raw) = std::env::var("QFTP_BENCH_SIZES") else {
        return DEFAULT_SIZES.to_vec();
    };
    raw.split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            let (num, mul): (&str, usize) = match s.chars().last() {
                Some('K') | Some('k') => (&s[..s.len() - 1], 1 << 10),
                Some('M') | Some('m') => (&s[..s.len() - 1], 1 << 20),
                Some('G') | Some('g') => (&s[..s.len() - 1], 1 << 30),
                _ => (s, 1),
            };
            num.parse::<usize>().ok().map(|n| n * mul)
        })
        .collect()
}

fn human_size(n: usize) -> String {
    if n % (1 << 30) == 0 {
        format!("{}GiB", n >> 30)
    } else if n % (1 << 20) == 0 {
        format!("{}MiB", n >> 20)
    } else if n % (1 << 10) == 0 {
        format!("{}KiB", n >> 10)
    } else {
        format!("{n}B")
    }
}

fn bench_put(c: &mut Criterion, fixture: &ServerFixture, sizes: &[usize]) {
    let mut group = c.benchmark_group("put");
    group.sample_size(10);
    // Big files need longer measurement / warmup windows so criterion
    // doesn't print "Unable to complete N samples" or skew warmup to
    // a fraction of one transfer.
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(5));

    let counter = AtomicU64::new(0);

    for &size in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("upload", human_size(size)),
            &size,
            |b, &size| {
                // Pre-generate the local file once per benchmark
                // configuration (not per iteration). The cost of
                // building random bytes is not what we want to time.
                let local_dir = tempfile::tempdir().expect("local tempdir");
                let local_path: PathBuf = local_dir.path().join("payload.bin");
                write_random_file(&local_path, size).expect("stage local payload");
                let local_str = local_path.to_str().unwrap().to_string();

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    let server_anon = fixture.root.path().join("anonymous");
                    for _ in 0..iters {
                        let n = counter.fetch_add(1, Ordering::Relaxed);
                        let remote_name = format!("put-{n}.bin");
                        let remote = format!("/{remote_name}");
                        let script = format!("put {local_str} {remote}");
                        let start = Instant::now();
                        if let Err(e) = fixture.run_repl(&script) {
                            // Record failures (timeouts, errors) as the
                            // wall-clock spent on the failed iteration
                            // so the bench keeps going and the tail
                            // shows up in criterion's stats instead of
                            // crashing the entire harness.
                            eprintln!("warning: put iter {n}: {e}");
                        }
                        total += start.elapsed();
                        // Reclaim the just-uploaded file so a multi-GiB
                        // sweep doesn't exhaust the server's tempdir.
                        let _ = std::fs::remove_file(server_anon.join(&remote_name));
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

fn bench_get(c: &mut Criterion, fixture: &ServerFixture, sizes: &[usize]) {
    let mut group = c.benchmark_group("get");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(5));

    for &size in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("download", human_size(size)),
            &size,
            |b, &size| {
                // Stage the remote payload directly into the anonymous
                // user's home (the bench's users.toml maps the
                // anonymous user to `<root>/anonymous/`). The bench
                // owns the root, so this is just a filesystem write.
                let remote_name = format!("get-{}.bin", human_size(size));
                let server_dir = fixture.root.path().join("anonymous");
                std::fs::create_dir_all(&server_dir).expect("create anonymous home");
                let server_path = server_dir.join(&remote_name);
                write_random_file(&server_path, size).expect("stage server payload");

                let local_dir = tempfile::tempdir().expect("local tempdir");

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for i in 0..iters {
                        // Use a fresh local destination each iteration so
                        // the client doesn't trigger resume-from-offset.
                        let local_path = local_dir.path().join(format!("dst-{i}.bin"));
                        let local_str = local_path.to_str().unwrap().to_string();
                        let script = format!("get /{remote_name} {local_str}");
                        let start = Instant::now();
                        if let Err(e) = fixture.run_repl(&script) {
                            eprintln!("warning: get iter {i}: {e}");
                        }
                        total += start.elapsed();
                        let _ = std::fs::remove_file(&local_path);
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

fn main() {
    let sizes = parse_sizes();
    eprintln!(
        "qftp-bench: sizes = {}",
        sizes
            .iter()
            .map(|s| human_size(*s))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let fixture = ServerFixture::start().expect("start qftp-server fixture");
    eprintln!(
        "qftp-bench: server up at {} (root: {})",
        fixture.addr,
        fixture.root.path().display()
    );

    let mut c = Criterion::default().configure_from_args();
    bench_put(&mut c, &fixture, &sizes);
    bench_get(&mut c, &fixture, &sizes);
    c.final_summary();

    // fixture dropped here -> server killed.
}
