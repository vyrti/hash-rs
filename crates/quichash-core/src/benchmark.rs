//! Hash algorithm benchmarks.
// Measures hash algorithm performance

use crate::error::HashUtilityError;
use crate::hash::HashRegistry;
use std::time::{Duration, Instant};

/// Result of a benchmark run for a single algorithm
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchmarkResult {
    /// Algorithm name measured by the benchmark.
    pub algorithm: String,
    /// Computed throughput in mebibytes per second.
    pub throughput_mbps: f64,
}

/// Engine for benchmarking hash algorithms
pub struct BenchmarkEngine;

impl BenchmarkEngine {
    /// Create a new BenchmarkEngine
    pub fn new() -> Self {
        Self
    }

    /// Run benchmarks on all supported hash algorithms
    ///
    /// # Arguments
    /// * `data_size_mb` - Size of test data in megabytes (default: 100MB)
    ///
    /// # Returns
    /// Vector of BenchmarkResult containing throughput for each algorithm
    pub fn run_benchmarks(
        &self,
        data_size_mb: usize,
    ) -> Result<Vec<BenchmarkResult>, HashUtilityError> {
        // Generate test data
        let data_size_bytes = data_size_mb * 1024 * 1024;
        let test_data = generate_test_data(data_size_bytes);

        // Get list of all algorithms
        let algorithms = HashRegistry::list_algorithms();

        let mut results = Vec::new();

        // Benchmark each algorithm
        for algo_info in algorithms {
            match self.benchmark_algorithm(&algo_info.name, &test_data, data_size_mb) {
                Ok(result) => results.push(result),
                Err(e) => {
                    eprintln!("Warning: Failed to benchmark {}: {}", algo_info.name, e);
                    continue;
                }
            }
        }

        Ok(results)
    }

    /// Benchmark a single algorithm
    fn benchmark_algorithm(
        &self,
        algorithm: &str,
        test_data: &[u8],
        data_size_mb: usize,
    ) -> Result<BenchmarkResult, HashUtilityError> {
        // Get hasher for this algorithm
        let mut hasher =
            HashRegistry::get_hasher(algorithm).map_err(|e| HashUtilityError::BenchmarkFailed {
                algorithm: algorithm.to_string(),
                reason: e.to_string(),
            })?;

        // Measure time to hash the data
        let start = Instant::now();
        hasher.update(test_data);
        let _ = hasher.finalize();
        let duration = start.elapsed();

        // Calculate throughput in MB/s
        let throughput_mbps = calculate_throughput(data_size_mb, duration);

        Ok(BenchmarkResult {
            algorithm: algorithm.to_string(),
            throughput_mbps,
        })
    }

    /// Legacy display hook retained for API compatibility.
    ///
    /// The reusable core does not render terminal output. Consume the returned
    /// [`BenchmarkResult`] values in the embedding application.
    pub fn display_results(&self, results: &[BenchmarkResult]) {
        if results.is_empty() {
            println!("No benchmark results to display.");
            return;
        }

        // Sort results by throughput (descending)
        let mut sorted_results = results.to_vec();
        sorted_results.sort_by(|a, b| b.throughput_mbps.partial_cmp(&a.throughput_mbps).unwrap());

        // Print header
        println!("\n{:<20} {:>15}", "Algorithm", "Throughput (MB/s)");
        println!("{}", "-".repeat(37));

        // Print results
        for result in sorted_results {
            println!("{:<20} {:>15.2}", result.algorithm, result.throughput_mbps);
        }

        println!();
    }
}

impl Default for BenchmarkEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate test data of specified size
pub fn generate_test_data(size_bytes: usize) -> Vec<u8> {
    // Use a simple pattern to generate test data
    // This is faster than random data and sufficient for benchmarking
    let pattern = b"The quick brown fox jumps over the lazy dog. ";
    let pattern_len = pattern.len();

    let mut data = Vec::with_capacity(size_bytes);

    while data.len() < size_bytes {
        let remaining = size_bytes - data.len();
        if remaining >= pattern_len {
            data.extend_from_slice(pattern);
        } else {
            data.extend_from_slice(&pattern[..remaining]);
        }
    }

    data
}

/// Calculate throughput in MB/s
pub fn calculate_throughput(data_size_mb: usize, duration: Duration) -> f64 {
    let seconds = duration.as_secs_f64();
    if seconds > 0.0 {
        data_size_mb as f64 / seconds
    } else {
        0.0
    }
}

/// Backward-compatible error name for benchmark operations.
pub type BenchmarkError = HashUtilityError;
