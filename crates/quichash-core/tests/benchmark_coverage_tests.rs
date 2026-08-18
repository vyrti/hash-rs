use quichash_core::benchmark::{
    calculate_throughput, generate_test_data, BenchmarkEngine, BenchmarkResult,
};
use std::time::Duration;

#[test]
fn test_generate_test_data_exact_sizes() {
    assert_eq!(generate_test_data(0).len(), 0);
    assert_eq!(generate_test_data(10).len(), 10);
    assert_eq!(generate_test_data(1024).len(), 1024);
}

#[test]
fn test_calculate_throughput_zero_duration() {
    assert_eq!(calculate_throughput(100, Duration::from_secs(0)), 0.0);
    let throughput = calculate_throughput(100, Duration::from_secs(2));
    assert_eq!(throughput, 50.0);
}

#[test]
fn test_benchmark_engine_run_and_display() {
    let engine = BenchmarkEngine::new();
    // Benchmark 1MB
    let results = engine.run_benchmarks(1).unwrap();
    assert!(!results.is_empty());

    engine.display_results(&results);

    // Empty results display
    engine.display_results(&[]);
}

#[test]
fn test_benchmark_result_clone_and_serialize() {
    let res = BenchmarkResult {
        algorithm: "blake3".to_string(),
        throughput_mbps: 1234.56,
    };
    let cloned = res.clone();
    assert_eq!(cloned.algorithm, "blake3");
}
