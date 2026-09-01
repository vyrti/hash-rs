use quichash_core::benchmark::{self, BenchmarkEngine};
use quichash_core::error::HashUtilityError;

/// Handle the benchmark command: run performance tests
pub fn handle_benchmark_command(size_mb: usize, json: bool) -> Result<(), HashUtilityError> {
    let engine = BenchmarkEngine::new();

    if !json {
        println!("Running benchmarks with {} MB of test data...", size_mb);
    }

    // Run benchmarks
    let results = engine.run_benchmarks(size_mb)?;

    // Output results based on format
    if json {
        #[derive(serde::Serialize)]
        struct BenchmarkOutput {
            results: Vec<benchmark::BenchmarkResult>,
            metadata: BenchmarkMetadata,
        }

        #[derive(serde::Serialize)]
        struct BenchmarkMetadata {
            timestamp: String,
            data_size_mb: usize,
            algorithm_count: usize,
        }

        let algorithm_count = results.len();
        let output = BenchmarkOutput {
            results,
            metadata: BenchmarkMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                data_size_mb: size_mb,
                algorithm_count,
            },
        };

        let json_output = serde_json::to_string_pretty(&output).map_err(|e| {
            HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            }
        })?;

        println!("{}", json_output);
    } else {
        // Display results in plain text
        display_benchmark_results(&results);
    }

    Ok(())
}

fn display_benchmark_results(results: &[benchmark::BenchmarkResult]) {
    if results.is_empty() {
        println!("No benchmark results to display.");
        return;
    }
    let mut sorted = results.to_vec();
    sorted.sort_by(|left, right| {
        right
            .throughput_mbps
            .partial_cmp(&left.throughput_mbps)
            .unwrap()
    });
    println!("\n{:<20} {:>15}", "Algorithm", "Throughput (MB/s)");
    println!("{}", "-".repeat(37));
    for result in sorted {
        println!("{:<20} {:>15.2}", result.algorithm, result.throughput_mbps);
    }
    println!();
}
