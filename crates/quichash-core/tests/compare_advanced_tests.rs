use quichash_core::compare::CompareEngine;
use quichash_core::database::{DatabaseEntry, DatabaseHandler};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn test_compare_complex_scenario() {
    let db1_path = "test_compare_complex_db1.txt";
    let db2_path = "test_compare_complex_db2.txt";

    // Complex scenario with unchanged, changed, removed, added, and duplicates
    let content1 = "hash_unchanged  sha256  normal  unchanged.txt\n\
                    hash_old  sha256  normal  changed.txt\n\
                    hash_removed  sha256  normal  removed.txt\n\
                    hash_dup  sha256  normal  dup1.txt\n\
                    hash_dup  sha256  normal  dup2.txt\n";

    let content2 = "hash_unchanged  sha256  normal  unchanged.txt\n\
                    hash_new  sha256  normal  changed.txt\n\
                    hash_added  sha256  normal  added.txt\n\
                    hash_dup2  sha256  normal  dup3.txt\n\
                    hash_dup2  sha256  normal  dup4.txt\n\
                    hash_dup2  sha256  normal  dup5.txt\n";

    fs::write(db1_path, content1).unwrap();
    fs::write(db2_path, content2).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    assert_eq!(report.db1_total_files, 5);
    assert_eq!(report.db2_total_files, 6);
    assert_eq!(report.unchanged_files, 1);
    assert_eq!(report.changed_files.len(), 1);
    assert_eq!(report.removed_files.len(), 3); // removed.txt, dup1.txt, dup2.txt
    assert_eq!(report.added_files.len(), 4); // added.txt, dup3.txt, dup4.txt, dup5.txt
    assert_eq!(report.duplicates_db1.len(), 1);
    assert_eq!(report.duplicates_db2.len(), 1);

    // Check changed file
    let changed = &report.changed_files[0];
    assert_eq!(changed.path, PathBuf::from("changed.txt"));
    assert_eq!(changed.hash_db1, "hash_old");
    assert_eq!(changed.hash_db2, "hash_new");

    // Check duplicates
    assert_eq!(report.duplicates_db1[0].count, 2);
    assert_eq!(report.duplicates_db2[0].count, 3);

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}

#[test]
fn test_find_duplicates_no_duplicates() {
    let mut db = HashMap::new();
    db.insert(
        PathBuf::from("file1.txt"),
        DatabaseEntry {
            hash: "hash1".to_string(),
            algorithm: "sha256".to_string(),
            fast_mode: false,
        },
    );
    db.insert(
        PathBuf::from("file2.txt"),
        DatabaseEntry {
            hash: "hash2".to_string(),
            algorithm: "sha256".to_string(),
            fast_mode: false,
        },
    );

    let duplicates = CompareEngine::find_duplicates(&db);
    assert_eq!(duplicates.len(), 0);
}

#[test]
fn test_find_duplicates_with_duplicates() {
    let mut db = HashMap::new();
    db.insert(
        PathBuf::from("file1.txt"),
        DatabaseEntry {
            hash: "hash_dup".to_string(),
            algorithm: "sha256".to_string(),
            fast_mode: false,
        },
    );
    db.insert(
        PathBuf::from("file2.txt"),
        DatabaseEntry {
            hash: "hash_dup".to_string(),
            algorithm: "sha256".to_string(),
            fast_mode: false,
        },
    );
    db.insert(
        PathBuf::from("file3.txt"),
        DatabaseEntry {
            hash: "hash_unique".to_string(),
            algorithm: "sha256".to_string(),
            fast_mode: false,
        },
    );

    let duplicates = CompareEngine::find_duplicates(&db);
    assert_eq!(duplicates.len(), 1);

    let dup_group = &duplicates[0];
    assert_eq!(dup_group.hash, "hash_dup");
    assert_eq!(dup_group.count, 2);
    assert_eq!(dup_group.paths.len(), 2);
}

#[cfg(feature = "zstd")]
#[test]
fn test_compare_compressed_databases() {
    // Create two plain text databases
    let db1_plain = "test_compare_compressed_db1_plain.txt";
    let db2_plain = "test_compare_compressed_db2_plain.txt";

    let content1 = "hash1  sha256  normal  file1.txt\n\
                    hash2  sha256  normal  file2.txt\n\
                    hash3  sha256  normal  file3.txt\n";

    let content2 = "hash1  sha256  normal  file1.txt\n\
                    hash2_modified  sha256  normal  file2.txt\n\
                    hash3  sha256  normal  file3.txt\n\
                    hash4  sha256  normal  file4.txt\n";

    fs::write(db1_plain, content1).unwrap();
    fs::write(db2_plain, content2).unwrap();

    // Compress both databases
    let db1_compressed = DatabaseHandler::compress_database(Path::new(db1_plain)).unwrap();
    let db2_compressed = DatabaseHandler::compress_database(Path::new(db2_plain)).unwrap();

    // Test 1: Compare two compressed databases
    let engine = CompareEngine::new();
    let report = engine.compare(&db1_compressed, &db2_compressed).unwrap();

    assert_eq!(report.db1_total_files, 3);
    assert_eq!(report.db2_total_files, 4);
    assert_eq!(report.unchanged_files, 2);
    assert_eq!(report.changed_files.len(), 1);
    assert_eq!(report.added_files.len(), 1);

    // Test 2: Compare compressed vs plain text
    let report2 = engine
        .compare(&db1_compressed, Path::new(db2_plain))
        .unwrap();

    assert_eq!(report2.db1_total_files, 3);
    assert_eq!(report2.db2_total_files, 4);
    assert_eq!(report2.unchanged_files, 2);
    assert_eq!(report2.changed_files.len(), 1);

    // Test 3: Compare plain text vs compressed
    let report3 = engine
        .compare(Path::new(db1_plain), &db2_compressed)
        .unwrap();

    assert_eq!(report3.db1_total_files, 3);
    assert_eq!(report3.db2_total_files, 4);
    assert_eq!(report3.unchanged_files, 2);
    assert_eq!(report3.changed_files.len(), 1);

    // Cleanup
    fs::remove_file(db1_plain).unwrap();
    fs::remove_file(db2_plain).unwrap();
    fs::remove_file(db1_compressed).unwrap();
    fs::remove_file(db2_compressed).unwrap();
}

#[test]
fn test_compare_report_summary_correctness() {
    // Test that summary counts are mathematically consistent
    let db1_path = "test_compare_summary_db1.txt";
    let db2_path = "test_compare_summary_db2.txt";

    let content1 = "hash1  sha256  normal  unchanged.txt\n\
                    hash2  sha256  normal  changed.txt\n\
                    hash3  sha256  normal  removed.txt\n";

    let content2 = "hash1  sha256  normal  unchanged.txt\n\
                    hash_new  sha256  normal  changed.txt\n\
                    hash4  sha256  normal  added.txt\n";

    fs::write(db1_path, content1).unwrap();
    fs::write(db2_path, content2).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    // Verify mathematical consistency:
    // unchanged + changed + removed = db1_total
    assert_eq!(
        report.unchanged_files + report.changed_files.len() + report.removed_files.len(),
        report.db1_total_files
    );

    // unchanged + changed + added = db2_total
    assert_eq!(
        report.unchanged_files + report.changed_files.len() + report.added_files.len(),
        report.db2_total_files
    );

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}

#[test]
fn test_to_hashdeep_format() {
    let db1_path = "test_hashdeep_format_db1.txt";
    let db2_path = "test_hashdeep_format_db2.txt";

    let content1 = "hash1  sha256  normal  unchanged.txt\n\
                    hash_old  sha256  normal  changed.txt\n\
                    hash_removed  sha256  normal  removed.txt\n";

    let content2 = "hash1  sha256  normal  unchanged.txt\n\
                    hash_new  sha256  normal  changed.txt\n\
                    hash_added  sha256  normal  added.txt\n";

    fs::write(db1_path, content1).unwrap();
    fs::write(db2_path, content2).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    let hashdeep_output = report.to_hashdeep();

    // Verify audit failed header
    assert!(hashdeep_output.contains("hashdeep: Audit failed"));

    // Verify summary counts
    assert!(hashdeep_output.contains("Files matched: 1"));
    assert!(hashdeep_output.contains("Files modified: 1"));
    assert!(hashdeep_output.contains("New files found: 1"));
    assert!(hashdeep_output.contains("Known files not found: 1"));

    // Verify modified file entry with both hashes
    assert!(hashdeep_output.contains("Modified files:"));
    assert!(hashdeep_output.contains("changed.txt"));
    assert!(hashdeep_output.contains("Known hash:"));
    assert!(hashdeep_output.contains("hash_old"));
    assert!(hashdeep_output.contains("Computed hash:"));
    assert!(hashdeep_output.contains("hash_new"));

    // Verify new file entry
    assert!(hashdeep_output.contains("New files:"));
    assert!(hashdeep_output.contains("added.txt"));

    // Verify not found file entry
    assert!(hashdeep_output.contains("Known files not found:"));
    assert!(hashdeep_output.contains("removed.txt"));

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}

#[test]
fn test_to_hashdeep_format_audit_passed() {
    let db1_path = "test_hashdeep_audit_passed_db1.txt";
    let db2_path = "test_hashdeep_audit_passed_db2.txt";

    // Identical databases should result in audit passed
    let content = "hash1  sha256  normal  file1.txt\n\
                   hash2  sha256  normal  file2.txt\n";

    fs::write(db1_path, content).unwrap();
    fs::write(db2_path, content).unwrap();

    let engine = CompareEngine::new();
    let report = engine
        .compare(Path::new(db1_path), Path::new(db2_path))
        .unwrap();

    let hashdeep_output = report.to_hashdeep();

    // Verify audit passed
    assert!(hashdeep_output.contains("hashdeep: Audit passed"));
    assert!(!hashdeep_output.contains("hashdeep: Audit failed"));

    fs::remove_file(db1_path).unwrap();
    fs::remove_file(db2_path).unwrap();
}
