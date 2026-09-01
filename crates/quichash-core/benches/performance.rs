use std::hint::black_box;
use std::time::{Duration, Instant};

use quichash_core::database::DatabaseFormat;
use quichash_core::scan::ScanEngine;
use quichash_core::{Algorithm, NoopObserver, ScanOptions, hash_bytes, scan_folder};

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn measure(mut operation: impl FnMut(), iterations: usize) -> Duration {
    operation();
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        operation();
        samples.push(start.elapsed());
    }
    median(samples)
}

fn main() {
    let data = vec![0x5a_u8; 64 * 1024 * 1024];
    for algorithm in [Algorithm::Blake3, Algorithm::Sha256, Algorithm::Xxh3] {
        let elapsed = measure(
            || {
                black_box(hash_bytes(black_box(&data), &[algorithm]).unwrap());
            },
            9,
        );
        let mib_per_second = 64.0 / elapsed.as_secs_f64();
        println!(
            "hash/{:<8} {:>10.2} MiB/s (median {:?})",
            algorithm, mib_per_second, elapsed
        );
    }

    let directory = tempfile::tempdir().unwrap();
    let payload = vec![0x36_u8; 4096];
    let file_count = std::env::var("QUICHASH_BENCH_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000_usize);
    for index in 0..file_count {
        std::fs::write(
            directory.path().join(format!("file-{index:08}.bin")),
            &payload,
        )
        .unwrap();
    }
    let options = ScanOptions::new().with_parallel(true);
    let elapsed = measure(
        || {
            black_box(scan_folder(directory.path(), &options, &NoopObserver).unwrap());
        },
        5,
    );
    println!(
        "scan/4k-tree {:>10.0} files/s ({} files, median {:?})",
        file_count as f64 / elapsed.as_secs_f64(),
        file_count,
        elapsed
    );

    let output = directory.path().join("benchmark-output.qh");
    let engine = ScanEngine::with_parallel(true)
        .with_ignore(false)
        .with_format(DatabaseFormat::Quichash);
    let elapsed = measure(
        || {
            black_box(
                engine
                    .scan_directory(directory.path(), "blake3", &output)
                    .unwrap(),
            );
        },
        5,
    );
    println!(
        "scan/cli-path {:>10.0} files/s ({} files, median {:?})",
        file_count as f64 / elapsed.as_secs_f64(),
        file_count,
        elapsed
    );
}
