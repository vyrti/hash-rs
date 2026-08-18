use quichash_core::hash::HashComputer;
use std::fs::File;
use std::io::Write;

#[test]
fn test_hash_computer_buffer_size_configuration() {
    let computer_default = HashComputer::new();
    assert_eq!(computer_default.buffer_size(), 1024 * 1024);

    let computer_custom = HashComputer::with_buffer_size(64 * 1024);
    assert_eq!(computer_custom.buffer_size(), 64 * 1024);
}

#[test]
fn test_hash_computer_compute_multiple_hashes_text() {
    let computer = HashComputer::new();
    let algorithms = vec!["blake3".to_string(), "sha256".to_string()];
    let results = computer
        .compute_multiple_hashes_text("hello world", &algorithms)
        .unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].algorithm, "blake3");
    assert_eq!(results[1].algorithm, "sha256");
    assert_eq!(results[0].file_path.to_str().unwrap(), "<text>");
}

#[test]
fn test_hash_computer_compute_multiple_hashes_file() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let mut file = File::create(temporary.path()).unwrap();
    file.write_all(b"test data content for hashing").unwrap();

    let computer = HashComputer::with_buffer_size(16);
    let algorithms = vec!["blake3".to_string(), "sha256".to_string()];
    let results = computer
        .compute_multiple_hashes(temporary.path(), &algorithms)
        .unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].file_path, temporary.path());
}

#[test]
fn test_hash_computer_compute_hash_fast_on_small_and_large_files() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let mut file = File::create(temporary.path()).unwrap();
    file.write_all(b"small content").unwrap();

    let computer = HashComputer::new();
    let result_small = computer
        .compute_hash_fast(temporary.path(), "blake3")
        .unwrap();
    assert_eq!(result_small.algorithm, "blake3");

    // Non-existent file error
    let missing_path = temporary.path().join("missing");
    assert!(computer.compute_hash_fast(&missing_path, "blake3").is_err());
}

#[test]
fn test_hash_computer_buffered_io_fallback() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let mut file = File::create(temporary.path()).unwrap();
    file.write_all(&vec![1u8; 10000]).unwrap();

    let computer = HashComputer::with_buffer_size(512);
    let res = computer
        .compute_hash_with_progress(temporary.path(), "sha256", true)
        .unwrap();
    assert_eq!(res.algorithm, "sha256");
}
