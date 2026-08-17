use quichash_core::compare::CompareEngine;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn test_compare_identical_databases() {
    // Create two identical databases
    let db1_path = "test_compare_identical_db1.txt";
    let db2_path = "test_compare_identical_db2.txt";

    let content = "hash1  sha256  normal  file1.txt\n\
                   hash2  sha256  normal  file2.txt\n\
                   hash3  sha256  normal  file3.txt\n";

    fs::write(db1_path, content).unwrap();
    fs::write(db2_path, content).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    assert_eq!(report.db1_total_files, 3);
    assert_eq!(report.db2_total_files, 3);
    assert_eq!(report.unchanged_files, 3);
    assert_eq!(report.changed_files.len(), 0);
    assert_eq!(report.removed_files.len(), 0);
    assert_eq!(report.added_files.len(), 0);
    assert_eq!(report.duplicates_db1.len(), 0);
    assert_eq!(report.duplicates_db2.len(), 0);

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}

#[test]
fn test_compare_with_changed_files() {
    let db1_path = "test_compare_changed_db1.txt";
    let db2_path = "test_compare_changed_db2.txt";

    let content1 = "hash1  sha256  normal  file1.txt\n\
                    hash2  sha256  normal  file2.txt\n\
                    hash3  sha256  normal  file3.txt\n";

    let content2 = "hash1  sha256  normal  file1.txt\n\
                    hash2_modified  sha256  normal  file2.txt\n\
                    hash3  sha256  normal  file3.txt\n";

    fs::write(db1_path, content1).unwrap();
    fs::write(db2_path, content2).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    assert_eq!(report.db1_total_files, 3);
    assert_eq!(report.db2_total_files, 3);
    assert_eq!(report.unchanged_files, 2);
    assert_eq!(report.changed_files.len(), 1);
    assert_eq!(report.removed_files.len(), 0);
    assert_eq!(report.added_files.len(), 0);

    let changed = &report.changed_files[0];
    assert_eq!(changed.path, PathBuf::from("file2.txt"));
    assert_eq!(changed.hash_db1, "hash2");
    assert_eq!(changed.hash_db2, "hash2_modified");

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}

#[test]
fn test_compare_with_removed_files() {
    let db1_path = "test_compare_removed_db1.txt";
    let db2_path = "test_compare_removed_db2.txt";

    let content1 = "hash1  sha256  normal  file1.txt\n\
                    hash2  sha256  normal  file2.txt\n\
                    hash3  sha256  normal  file3.txt\n";

    let content2 = "hash1  sha256  normal  file1.txt\n\
                    hash3  sha256  normal  file3.txt\n";

    fs::write(db1_path, content1).unwrap();
    fs::write(db2_path, content2).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    assert_eq!(report.db1_total_files, 3);
    assert_eq!(report.db2_total_files, 2);
    assert_eq!(report.unchanged_files, 2);
    assert_eq!(report.changed_files.len(), 0);
    assert_eq!(report.removed_files.len(), 1);
    assert_eq!(report.added_files.len(), 0);

    assert_eq!(report.removed_files[0], PathBuf::from("file2.txt"));

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}

#[test]
fn test_compare_with_added_files() {
    let db1_path = "test_compare_added_db1.txt";
    let db2_path = "test_compare_added_db2.txt";

    let content1 = "hash1  sha256  normal  file1.txt\n\
                    hash2  sha256  normal  file2.txt\n";

    let content2 = "hash1  sha256  normal  file1.txt\n\
                    hash2  sha256  normal  file2.txt\n\
                    hash3  sha256  normal  file3.txt\n";

    fs::write(db1_path, content1).unwrap();
    fs::write(db2_path, content2).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    assert_eq!(report.db1_total_files, 2);
    assert_eq!(report.db2_total_files, 3);
    assert_eq!(report.unchanged_files, 2);
    assert_eq!(report.changed_files.len(), 0);
    assert_eq!(report.removed_files.len(), 0);
    assert_eq!(report.added_files.len(), 1);

    assert_eq!(report.added_files[0], PathBuf::from("file3.txt"));

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}

#[test]
fn test_compare_with_duplicates() {
    let db1_path = "test_compare_duplicates_db1.txt";
    let db2_path = "test_compare_duplicates_db2.txt";

    // DB1 has duplicates: file1 and file2 have the same hash
    let content1 = "hash_duplicate  sha256  normal  file1.txt\n\
                    hash_duplicate  sha256  normal  file2.txt\n\
                    hash3  sha256  normal  file3.txt\n";

    // DB2 has different duplicates: file3 and file4 have the same hash
    let content2 = "hash1  sha256  normal  file1.txt\n\
                    hash2  sha256  normal  file2.txt\n\
                    hash_dup2  sha256  normal  file3.txt\n\
                    hash_dup2  sha256  normal  file4.txt\n";

    fs::write(db1_path, content1).unwrap();
    fs::write(db2_path, content2).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    assert_eq!(report.db1_total_files, 3);
    assert_eq!(report.db2_total_files, 4);
    assert_eq!(report.duplicates_db1.len(), 1);
    assert_eq!(report.duplicates_db2.len(), 1);

    // Check DB1 duplicates
    let dup1 = &report.duplicates_db1[0];
    assert_eq!(dup1.hash, "hash_duplicate");
    assert_eq!(dup1.count, 2);
    assert_eq!(dup1.paths.len(), 2);

    // Check DB2 duplicates
    let dup2 = &report.duplicates_db2[0];
    assert_eq!(dup2.hash, "hash_dup2");
    assert_eq!(dup2.count, 2);
    assert_eq!(dup2.paths.len(), 2);

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}
