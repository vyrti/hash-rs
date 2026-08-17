use quichash_core::error::HashUtilityError;
use quichash_core::verify::VerifyEngine;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn create_test_file(path: &Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

#[test]
fn checksum_files_verify_in_parallel_and_sequential_modes() {
    let temporary = tempfile::tempdir().unwrap();
    create_test_file(&temporary.path().join("match.txt"), b"hello");
    create_test_file(&temporary.path().join("changed.txt"), b"changed");
    create_test_file(&temporary.path().join("new.txt"), b"new");
    let checksum = temporary.path().join("checks.sha256");
    fs::write(
        &checksum,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  match.txt\n\
         0000000000000000000000000000000000000000000000000000000000000000 *changed.txt\n\
         1111111111111111111111111111111111111111111111111111111111111111 missing.txt\n",
    )
    .unwrap();

    for parallel in [false, true] {
        let report = VerifyEngine::with_parallel(parallel)
            .verify(&checksum, temporary.path())
            .unwrap();
        assert_eq!(report.matches, 1);
        assert_eq!(report.mismatches.len(), 1);
        assert_eq!(report.missing_files.len(), 1);
        assert_eq!(report.new_files.len(), 1);
        assert!(report.new_files[0].ends_with("new.txt"));
    }
}

#[test]
fn checksum_verification_rejects_unknown_extension() {
    let temporary = tempfile::tempdir().unwrap();
    let checksum = temporary.path().join("checks.digest");
    fs::write(
        &checksum,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  file.txt\n",
    )
    .unwrap();
    let error = VerifyEngine::new()
        .verify(&checksum, temporary.path())
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("cannot infer checksum algorithm"));
}

#[cfg(not(feature = "sha2"))]
#[test]
fn checksum_verification_reports_disabled_algorithm() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("file.txt"), b"hello").unwrap();
    let checksum = temporary.path().join("checks.sha256");
    fs::write(
        &checksum,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  file.txt\n",
    )
    .unwrap();
    let error = VerifyEngine::new()
        .verify(&checksum, temporary.path())
        .unwrap_err();
    assert!(matches!(
        error,
        HashUtilityError::AlgorithmUnavailable { .. }
    ));
}

#[test]
fn test_verify_all_matches() {
    // Create test directory structure
    let test_dir = "test_verify_matches";
    fs::create_dir_all(test_dir).unwrap();

    // Create test files
    create_test_file(&PathBuf::from(format!("{}/file1.txt", test_dir)), b"hello");
    create_test_file(&PathBuf::from(format!("{}/file2.txt", test_dir)), b"world");

    // Create database with correct hashes (SHA-256)
    let db_path = format!("{}/database.txt", test_dir);
    let mut db_file = fs::File::create(&db_path).unwrap();
    writeln!(db_file, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  sha256  normal  file1.txt").unwrap();
    writeln!(db_file, "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7  sha256  normal  file2.txt").unwrap();

    // Run verification
    let engine = VerifyEngine::new();
    let report = engine
        .verify(Path::new(&db_path), Path::new(test_dir))
        .unwrap();

    // Verify results
    assert_eq!(report.matches, 2);
    assert_eq!(report.mismatches.len(), 0);
    assert_eq!(report.missing_files.len(), 0);
    assert_eq!(report.new_files.len(), 0);

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_verify_with_mismatch() {
    // Create test directory
    let test_dir = "test_verify_mismatch";
    fs::create_dir_all(test_dir).unwrap();

    // Create test file
    create_test_file(
        &PathBuf::from(format!("{}/file1.txt", test_dir)),
        b"modified content",
    );

    // Create database with old hash
    let db_path = format!("{}/database.txt", test_dir);
    let mut db_file = fs::File::create(&db_path).unwrap();
    writeln!(db_file, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  sha256  normal  file1.txt").unwrap();

    // Run verification
    let engine = VerifyEngine::new();
    let report = engine
        .verify(Path::new(&db_path), Path::new(test_dir))
        .unwrap();

    // Verify results
    assert_eq!(report.matches, 0);
    assert_eq!(report.mismatches.len(), 1);
    assert_eq!(report.missing_files.len(), 0);
    assert_eq!(report.new_files.len(), 0);

    // Check mismatch details
    let mismatch = &report.mismatches[0];
    assert_eq!(
        mismatch.expected,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_ne!(mismatch.actual, mismatch.expected);

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_verify_with_missing_file() {
    // Create test directory
    let test_dir = "test_verify_missing";
    fs::create_dir_all(test_dir).unwrap();

    // Create database with file that doesn't exist
    let db_path = format!("{}/database.txt", test_dir);
    let mut db_file = fs::File::create(&db_path).unwrap();
    writeln!(db_file, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  sha256  normal  missing_file.txt").unwrap();

    // Run verification
    let engine = VerifyEngine::new();
    let report = engine
        .verify(Path::new(&db_path), Path::new(test_dir))
        .unwrap();

    // Verify results
    assert_eq!(report.matches, 0);
    assert_eq!(report.mismatches.len(), 0);
    assert_eq!(report.missing_files.len(), 1);
    assert_eq!(report.new_files.len(), 0);

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_verify_with_new_file() {
    // Create test directory
    let test_dir = "test_verify_new";
    fs::create_dir_all(test_dir).unwrap();

    // Create test file
    create_test_file(
        &PathBuf::from(format!("{}/new_file.txt", test_dir)),
        b"new content",
    );

    // Create empty database
    let db_path = format!("{}/database.txt", test_dir);
    let mut db_file = fs::File::create(&db_path).unwrap();
    writeln!(db_file, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  sha256  normal  dummy.txt").unwrap();

    // Run verification
    let engine = VerifyEngine::new();
    let report = engine
        .verify(Path::new(&db_path), Path::new(test_dir))
        .unwrap();

    // Verify results - should have 1 missing (dummy.txt) and 1 new (new_file.txt)
    assert_eq!(report.matches, 0);
    assert_eq!(report.mismatches.len(), 0);
    assert_eq!(report.missing_files.len(), 1);
    assert_eq!(report.new_files.len(), 1);

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_verify_mixed_results() {
    // Create test directory
    let test_dir = "test_verify_mixed";
    fs::create_dir_all(test_dir).unwrap();

    // Create test files
    create_test_file(&PathBuf::from(format!("{}/match.txt", test_dir)), b"hello");
    create_test_file(
        &PathBuf::from(format!("{}/mismatch.txt", test_dir)),
        b"modified",
    );
    create_test_file(&PathBuf::from(format!("{}/new.txt", test_dir)), b"new");

    // Create database
    let db_path = format!("{}/database.txt", test_dir);
    let mut db_file = fs::File::create(&db_path).unwrap();
    // match.txt - correct hash
    writeln!(db_file, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  sha256  normal  match.txt").unwrap();
    // mismatch.txt - wrong hash
    writeln!(db_file, "0000000000000000000000000000000000000000000000000000000000000000  sha256  normal  mismatch.txt").unwrap();
    // missing.txt - file doesn't exist
    writeln!(db_file, "1111111111111111111111111111111111111111111111111111111111111111  sha256  normal  missing.txt").unwrap();
    // new.txt is not in database

    // Run verification
    let engine = VerifyEngine::new();
    let report = engine
        .verify(Path::new(&db_path), Path::new(test_dir))
        .unwrap();

    // Verify results
    assert_eq!(report.matches, 1);
    assert_eq!(report.mismatches.len(), 1);
    assert_eq!(report.missing_files.len(), 1);
    assert_eq!(report.new_files.len(), 1);

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_verify_database_not_found() {
    let engine = VerifyEngine::new();
    let result = engine.verify(Path::new("nonexistent_database.txt"), Path::new("."));

    assert!(result.is_err());
    match result {
        Err(HashUtilityError::DatabaseNotFound { .. }) => {}
        _ => panic!("Expected DatabaseNotFound error"),
    }
}

#[test]
fn test_verify_directory_not_found() {
    // Create a temporary database file
    let db_path = "test_db_temp.txt";
    fs::write(db_path, "abc123  sha256  normal  file.txt\n").unwrap();

    let engine = VerifyEngine::new();
    let result = engine.verify(Path::new(db_path), Path::new("nonexistent_directory"));

    assert!(result.is_err());
    match result {
        Err(HashUtilityError::DirectoryNotFound { .. }) => {}
        _ => panic!("Expected DirectoryNotFound error"),
    }

    // Cleanup
    fs::remove_file(db_path).unwrap();
}

#[test]
fn test_collect_files_recursive() {
    // Create nested directory structure
    let test_dir = "test_verify_collect_files";
    fs::create_dir_all(format!("{}/subdir1", test_dir)).unwrap();
    fs::create_dir_all(format!("{}/subdir2", test_dir)).unwrap();

    create_test_file(&PathBuf::from(format!("{}/file1.txt", test_dir)), b"test");
    create_test_file(
        &PathBuf::from(format!("{}/subdir1/file2.txt", test_dir)),
        b"test",
    );
    create_test_file(
        &PathBuf::from(format!("{}/subdir2/file3.txt", test_dir)),
        b"test",
    );

    let engine = VerifyEngine::new();
    let files = engine.collect_files(Path::new(test_dir)).unwrap();

    // Should find all 3 files
    assert_eq!(files.len(), 3);

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}
