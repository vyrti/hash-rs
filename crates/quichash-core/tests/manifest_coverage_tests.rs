use quichash_core::hash::{Algorithm, HashMode};
use quichash_core::manifest::{scan_folder, verify_folder, Manifest, ScanOptions};
use quichash_core::operation::{FailurePolicy, NoopObserver};
use std::fs;
use std::path::Path;

#[test]
fn test_scan_options_builder_methods() {
    let options = ScanOptions::new()
        .with_algorithms(vec![Algorithm::Blake3, Algorithm::Sha256])
        .with_mode(HashMode::Sampled)
        .with_parallel(false)
        .with_hashignore(false)
        .with_failure_policy(FailurePolicy::Continue)
        .with_exclude(Some(Path::new("/tmp/excluded.txt").to_path_buf()));

    assert_eq!(options.algorithms.len(), 2);
    assert_eq!(options.mode, HashMode::Sampled);
    assert!(!options.parallel);
    assert!(!options.use_hashignore);
    assert_eq!(options.failure_policy, FailurePolicy::Continue);
    assert!(options.exclude.is_some());
}

#[test]
fn test_scan_folder_validation_errors() {
    let temporary = tempfile::tempdir().unwrap();

    // Empty algorithms
    let empty_opts = ScanOptions::new().with_algorithms(Vec::new());
    assert!(scan_folder(temporary.path(), &empty_opts, &NoopObserver).is_err());

    // Nonexistent folder
    let missing_path = temporary.path().join("does_not_exist");
    let valid_opts = ScanOptions::default();
    assert!(scan_folder(&missing_path, &valid_opts, &NoopObserver).is_err());

    // File passed as directory
    let file_path = temporary.path().join("file.txt");
    fs::write(&file_path, b"hello").unwrap();
    assert!(scan_folder(&file_path, &valid_opts, &NoopObserver).is_err());
}

#[test]
fn test_verify_folder_nonexistent_directory() {
    let manifest = Manifest::default();
    let missing_path = Path::new("/path/that/definitely/does/not/exist");
    assert!(verify_folder(
        &manifest,
        missing_path,
        FailurePolicy::FailFast,
        &NoopObserver
    )
    .is_err());
}

#[test]
fn test_scan_folder_continue_failure_policy() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("valid.txt"), b"good data").unwrap();

    let options = ScanOptions::default()
        .with_failure_policy(FailurePolicy::Continue)
        .with_parallel(false);
    let report = scan_folder(temporary.path(), &options, &NoopObserver).unwrap();

    assert_eq!(report.manifest.entries.len(), 1);
    assert_eq!(report.files_processed, 1);
}
