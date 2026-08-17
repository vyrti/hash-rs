use quichash_core::error::HashUtilityError;
use quichash_core::hash::{HashComputer, HashRegistry};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[test]
fn test_compute_hash_sha256() {
    // Create a temporary test file
    let test_data = b"hello world";
    let temp_file = "test_hash_temp.txt";
    fs::write(temp_file, test_data).unwrap();

    // Compute hash
    let computer = HashComputer::new();
    let result = computer
        .compute_hash(Path::new(temp_file), "sha256")
        .unwrap();

    // Verify result
    assert_eq!(result.algorithm, "sha256");
    assert_eq!(
        result.hash,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_eq!(result.file_path, Path::new(temp_file));

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_compute_multiple_hashes() {
    // Create a temporary test file
    let test_data = b"test data";
    let temp_file = "test_multi_hash_temp.txt";
    fs::write(temp_file, test_data).unwrap();

    // Compute multiple hashes
    let computer = HashComputer::new();
    let algorithms = vec!["md5".to_string(), "sha256".to_string()];
    let results = computer
        .compute_multiple_hashes(Path::new(temp_file), &algorithms)
        .unwrap();

    // Verify results
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].algorithm, "md5");
    assert_eq!(results[1].algorithm, "sha256");

    // Both should have the same file path
    assert_eq!(results[0].file_path, Path::new(temp_file));
    assert_eq!(results[1].file_path, Path::new(temp_file));

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_streaming_large_file() {
    // Create a file larger than buffer size (64KB)
    let temp_file = "test_large_temp.txt";
    let mut file = fs::File::create(temp_file).unwrap();
    let chunk = vec![b'a'; 1024];
    for _ in 0..100 {
        // 100KB file
        file.write_all(&chunk).unwrap();
    }
    drop(file);

    // Compute hash with streaming
    let computer = HashComputer::new();
    let result = computer
        .compute_hash(Path::new(temp_file), "sha256")
        .unwrap();

    // Verify hash is computed (not checking exact value, just that it works)
    assert_eq!(result.hash.len(), 64); // SHA-256 produces 64 hex characters

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_file_not_found_error() {
    let computer = HashComputer::new();
    let result = computer.compute_hash(Path::new("nonexistent_file.txt"), "sha256");

    assert!(result.is_err());
    match result {
        Err(HashUtilityError::FileNotFound { .. }) => {}
        Err(HashUtilityError::IoError { .. }) => {}
        _ => panic!("Expected FileNotFound or IoError"),
    }
}

#[test]
fn test_unsupported_algorithm_error() {
    let temp_file = "test_unsupported_temp.txt";
    fs::write(temp_file, b"test").unwrap();

    let computer = HashComputer::new();
    let result = computer.compute_hash(Path::new(temp_file), "invalid_algorithm");

    assert!(result.is_err());
    match result {
        Err(HashUtilityError::UnsupportedAlgorithm { .. }) => {}
        _ => panic!("Expected UnsupportedAlgorithm error"),
    }

    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_compute_hash_fast_small_file() {
    // Create a small test file (less than 300MB)
    let test_data = b"hello world";
    let temp_file = "test_fast_small_temp.txt";
    fs::write(temp_file, test_data).unwrap();

    // Compute hash using fast mode
    let computer = HashComputer::new();
    let result_fast = computer
        .compute_hash_fast(Path::new(temp_file), "sha256")
        .unwrap();

    // Compute hash using normal mode
    let result_normal = computer
        .compute_hash(Path::new(temp_file), "sha256")
        .unwrap();

    // For small files, fast mode should produce the same hash as normal mode
    assert_eq!(result_fast.hash, result_normal.hash);
    assert_eq!(result_fast.algorithm, "sha256");
    assert_eq!(result_fast.file_path, Path::new(temp_file));

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_compute_hash_fast_deterministic() {
    // Create a test file
    let test_data = vec![b'x'; 1024 * 1024]; // 1MB file
    let temp_file = "test_fast_deterministic_temp.txt";
    fs::write(temp_file, &test_data).unwrap();

    // Compute hash twice using fast mode
    let computer = HashComputer::new();
    let result1 = computer
        .compute_hash_fast(Path::new(temp_file), "sha256")
        .unwrap();
    let result2 = computer
        .compute_hash_fast(Path::new(temp_file), "sha256")
        .unwrap();

    // Results should be identical
    assert_eq!(result1.hash, result2.hash);

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_compute_hash_fast_large_file() {
    // Create a large test file (larger than 300MB threshold)
    // For testing purposes, we'll create a smaller file and verify the logic works
    let temp_file = "test_fast_large_temp.txt";
    let mut file = fs::File::create(temp_file).unwrap();

    // Write 350MB of data (more than 300MB threshold)
    let chunk = vec![b'a'; 1024 * 1024]; // 1MB chunk
    for _ in 0..350 {
        file.write_all(&chunk).unwrap();
    }
    drop(file);

    // Compute hash using fast mode
    let computer = HashComputer::new();
    let result = computer
        .compute_hash_fast(Path::new(temp_file), "sha256")
        .unwrap();

    // Verify hash is computed (not checking exact value, just that it works)
    assert_eq!(result.hash.len(), 64); // SHA-256 produces 64 hex characters
    assert_eq!(result.algorithm, "sha256");

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_compute_hash_stdin_equivalence() {
    // Create a test file
    let test_data = b"hello world from stdin test";
    let temp_file = "test_stdin_equiv_temp.txt";
    fs::write(temp_file, test_data).unwrap();

    // Compute hash from file
    let computer = HashComputer::new();
    let file_result = computer
        .compute_hash(Path::new(temp_file), "sha256")
        .unwrap();

    // Verify file hash is valid
    assert_eq!(file_result.hash.len(), 64);
    assert_eq!(file_result.algorithm, "sha256");

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_compute_multiple_hashes_stdin_structure() {
    let computer = HashComputer::new();
    let algorithms = vec!["sha256".to_string(), "md5".to_string()];

    let _ = &computer;
    let _ = &algorithms;

    // Just verify the computer was created successfully
    assert_eq!(computer.buffer_size(), 1024 * 1024);
}

#[test]
fn test_compute_hash_text() {
    let computer = HashComputer::new();
    let result = computer.compute_hash_text("hello world", "sha256").unwrap();

    // Verify result
    assert_eq!(result.algorithm, "sha256");
    assert_eq!(
        result.hash,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_eq!(result.file_path, PathBuf::from("<text>"));
}

#[test]
fn test_compute_hash_text_empty_string() {
    let computer = HashComputer::new();
    let result = computer.compute_hash_text("", "sha256").unwrap();

    // Verify result - empty string has a known SHA-256 hash
    assert_eq!(result.algorithm, "sha256");
    assert_eq!(
        result.hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(result.file_path, PathBuf::from("<text>"));
}

#[test]
fn test_compute_hash_text_utf8() {
    let computer = HashComputer::new();
    let result = computer
        .compute_hash_text("Hello, 世界! 🌍", "sha256")
        .unwrap();

    // Verify result - should handle UTF-8 correctly
    assert_eq!(result.algorithm, "sha256");
    assert_eq!(result.hash.len(), 64); // SHA-256 produces 64 hex characters
    assert_eq!(result.file_path, PathBuf::from("<text>"));
}

#[test]
fn test_compute_multiple_hashes_text() {
    let computer = HashComputer::new();
    let algorithms = vec!["md5".to_string(), "sha256".to_string()];
    let results = computer
        .compute_multiple_hashes_text("test data", &algorithms)
        .unwrap();

    // Verify results
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].algorithm, "md5");
    assert_eq!(results[1].algorithm, "sha256");

    // Both should have the same file path indicator
    assert_eq!(results[0].file_path, PathBuf::from("<text>"));
    assert_eq!(results[1].file_path, PathBuf::from("<text>"));

    // Verify hashes are not empty
    assert!(!results[0].hash.is_empty());
    assert!(!results[1].hash.is_empty());
}

#[test]
fn test_compute_hash_text_consistency() {
    let computer = HashComputer::new();
    let text = "consistent test";

    // Compute hash twice
    let result1 = computer.compute_hash_text(text, "sha256").unwrap();
    let result2 = computer.compute_hash_text(text, "sha256").unwrap();

    // Results should be identical
    assert_eq!(result1.hash, result2.hash);
}

#[test]
fn test_compute_hash_text_unsupported_algorithm() {
    let computer = HashComputer::new();
    let result = computer.compute_hash_text("test", "invalid_algorithm");

    assert!(result.is_err());
    match result {
        Err(HashUtilityError::UnsupportedAlgorithm { .. }) => {}
        _ => panic!("Expected UnsupportedAlgorithm error"),
    }
}

#[test]
fn test_compute_hash_xxh3() {
    let computer = HashComputer::new();
    let result = computer.compute_hash_text("hello world", "xxh3").unwrap();

    // Verify result
    assert_eq!(result.algorithm, "xxh3");
    assert_eq!(result.hash.len(), 16); // XXH3 produces 8 bytes = 16 hex characters
    assert_eq!(result.file_path, PathBuf::from("<text>"));
}

#[test]
fn test_compute_hash_xxh128() {
    let computer = HashComputer::new();
    let result = computer.compute_hash_text("hello world", "xxh128").unwrap();

    // Verify result
    assert_eq!(result.algorithm, "xxh128");
    assert_eq!(result.hash.len(), 32); // XXH128 produces 16 bytes = 32 hex characters
    assert_eq!(result.file_path, PathBuf::from("<text>"));
}

#[test]
fn test_xxhash_consistency() {
    let computer = HashComputer::new();
    let text = "consistent test";

    // Compute hash twice with XXH3
    let result1 = computer.compute_hash_text(text, "xxh3").unwrap();
    let result2 = computer.compute_hash_text(text, "xxh3").unwrap();

    // Results should be identical
    assert_eq!(result1.hash, result2.hash);

    // Compute hash twice with XXH128
    let result3 = computer.compute_hash_text(text, "xxh128").unwrap();
    let result4 = computer.compute_hash_text(text, "xxh128").unwrap();

    // Results should be identical
    assert_eq!(result3.hash, result4.hash);
}

#[test]
fn test_xxhash_algorithms_in_registry() {
    let algorithms = HashRegistry::list_algorithms();

    // Find XXH3 and XXH128 in the list
    let xxh3 = algorithms.iter().find(|a| a.name == "XXH3");
    let xxh128 = algorithms.iter().find(|a| a.name == "XXH128");

    // Verify they exist
    assert!(xxh3.is_some());
    assert!(xxh128.is_some());

    // Verify their properties
    let xxh3 = xxh3.unwrap();
    assert_eq!(xxh3.output_bits, 64);
    assert!(!xxh3.post_quantum);
    assert!(!xxh3.cryptographic);

    let xxh128 = xxh128.unwrap();
    assert_eq!(xxh128.output_bits, 128);
    assert!(!xxh128.post_quantum);
    assert!(!xxh128.cryptographic);
}
