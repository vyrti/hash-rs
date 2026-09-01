use quichash_core::database::DatabaseFormat;
use quichash_core::scan::ScanEngine;
use std::fs;

#[test]
fn test_scan_engine_builder_options() {
    let engine = ScanEngine::new()
        .with_fast_mode(true)
        .with_ignore(false)
        .with_format(DatabaseFormat::Hashdeep)
        .with_excluded_output("/tmp/some_out.qh");

    assert!(
        engine
            .scan_directory(
                &std::path::PathBuf::from("/nonexistent"),
                "blake3",
                &std::path::PathBuf::from("/tmp/out")
            )
            .is_err()
    );
}

#[test]
fn test_scan_engine_sequential_and_hashdeep_format() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("a.txt"), b"apple").unwrap();
    fs::write(temporary.path().join("b.txt"), b"banana").unwrap();

    let output_file = temporary.path().join("database.hashdeep");
    let engine = ScanEngine::new()
        .with_format(DatabaseFormat::Hashdeep)
        .with_fast_mode(false);

    let stats = engine
        .scan_directory(temporary.path(), "sha256", &output_file)
        .unwrap();

    assert_eq!(stats.files_processed, 2);
    assert_eq!(stats.files_failed, 0);

    let contents = fs::read_to_string(&output_file).unwrap();
    assert!(contents.contains("HASHDEEP-1.0"));
    assert!(contents.contains("a.txt"));
    assert!(contents.contains("b.txt"));
}

#[test]
fn test_scan_engine_parallel_with_excluded_output() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("doc.txt"), b"data").unwrap();

    let output_file = temporary.path().join("hashes.qh");
    let excluded_extra = temporary.path().join("temp.qh");

    let engine = ScanEngine::with_parallel(true).with_excluded_output(&excluded_extra);

    let stats = engine
        .scan_directory(temporary.path(), "blake3", &output_file)
        .unwrap();

    assert_eq!(stats.files_processed, 1);
}
