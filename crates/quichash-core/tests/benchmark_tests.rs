use quichash_core::benchmark::{
    BenchmarkEngine, BenchmarkResult, calculate_throughput, generate_test_data,
};
use std::time::Duration;

#[test]
fn test_generate_test_data() {
    let data = generate_test_data(1024);
    assert_eq!(data.len(), 1024);
}

#[test]
fn test_generate_test_data_exact_pattern() {
    let pattern = b"The quick brown fox jumps over the lazy dog. ";
    let data = generate_test_data(pattern.len());
    assert_eq!(data.len(), pattern.len());
    assert_eq!(&data[..], pattern);
}

#[test]
fn test_generate_test_data_partial_pattern() {
    let size = 50;
    let data = generate_test_data(size);
    assert_eq!(data.len(), size);
}

#[test]
fn test_calculate_throughput() {
    let duration = Duration::from_secs(1);
    let throughput = calculate_throughput(100, duration);
    assert_eq!(throughput, 100.0);

    let duration = Duration::from_secs(2);
    let throughput = calculate_throughput(100, duration);
    assert_eq!(throughput, 50.0);
}

#[test]
fn test_calculate_throughput_subsecond() {
    let duration = Duration::from_millis(500);
    let throughput = calculate_throughput(100, duration);
    assert_eq!(throughput, 200.0);
}

#[test]
fn test_benchmark_engine_creation() {
    let _engine = BenchmarkEngine::new();
}

#[test]
fn test_run_benchmarks_small_data() {
    let engine = BenchmarkEngine::new();
    // Use 1MB for faster test
    let results = engine.run_benchmarks(1).unwrap();

    // Should have results for all algorithms
    assert!(!results.is_empty());

    // All throughput values should be positive
    for result in results {
        assert!(result.throughput_mbps > 0.0);
        assert!(!result.algorithm.is_empty());
    }
}

#[test]
fn test_benchmark_result_structure() {
    let result = BenchmarkResult {
        algorithm: "SHA-256".to_string(),
        throughput_mbps: 500.0,
    };

    assert_eq!(result.algorithm, "SHA-256");
    assert_eq!(result.throughput_mbps, 500.0);
}
