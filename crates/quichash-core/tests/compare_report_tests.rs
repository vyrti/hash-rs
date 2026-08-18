use quichash_core::compare::*;
use std::path::PathBuf;

fn sample_compare_report(has_differences: bool) -> CompareReport {
    let db1_info = DatabaseInfo {
        path: PathBuf::from("/tmp/db1.qh"),
        format: "quichash".to_string(),
        size_bytes: 1024 * 1024 * 5, // 5MB
        file_count: 10,
        modified: Some("2026-01-01T00:00:00Z".to_string()),
    };
    let db2_info = DatabaseInfo {
        path: PathBuf::from("/tmp/db2.qh"),
        format: "quichash".to_string(),
        size_bytes: 1024 * 1024 * 6, // 6MB
        file_count: 10,
        modified: Some("2026-01-02T00:00:00Z".to_string()),
    };

    if !has_differences {
        CompareReport {
            db1_info,
            db2_info,
            db1_total_files: 10,
            db2_total_files: 10,
            unchanged_files: 10,
            changed_files: Vec::new(),
            moved_files: Vec::new(),
            removed_files: Vec::new(),
            added_files: Vec::new(),
            duplicates_db1: Vec::new(),
            duplicates_db2: Vec::new(),
        }
    } else {
        CompareReport {
            db1_info,
            db2_info,
            db1_total_files: 10,
            db2_total_files: 10,
            unchanged_files: 6,
            changed_files: vec![ChangedFile {
                path: PathBuf::from("modified.txt"),
                hash_db1: "hash1".to_string(),
                hash_db2: "hash2".to_string(),
            }],
            moved_files: vec![MovedFile {
                from_path: PathBuf::from("old_name.txt"),
                to_path: PathBuf::from("new_name.txt"),
                hash: "samehash".to_string(),
            }],
            removed_files: vec![PathBuf::from("deleted.txt")],
            added_files: vec![PathBuf::from("created.txt")],
            duplicates_db1: vec![DuplicateGroup {
                hash: "dup1".to_string(),
                paths: vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")],
                count: 2,
            }],
            duplicates_db2: vec![DuplicateGroup {
                hash: "dup2".to_string(),
                paths: vec![PathBuf::from("c.txt"), PathBuf::from("d.txt")],
                count: 2,
            }],
        }
    }
}

#[test]
fn test_compare_report_display() {
    let report_clean = sample_compare_report(false);
    report_clean.display();

    let report_diff = sample_compare_report(true);
    report_diff.display();
}

#[test]
fn test_compare_report_to_plain_text() {
    let report = sample_compare_report(true);
    let text = report.to_plain_text();
    assert!(text.contains("Database Comparison Report"));
    assert!(text.contains("modified.txt"));
    assert!(text.contains("old_name.txt -> new_name.txt"));
    assert!(text.contains("deleted.txt"));
    assert!(text.contains("created.txt"));
}

#[test]
fn test_compare_report_to_hashdeep() {
    let report_clean = sample_compare_report(false);
    let hd_clean = report_clean.to_hashdeep();
    assert!(hd_clean.contains("hashdeep: Audit passed"));

    let report_diff = sample_compare_report(true);
    let hd_diff = report_diff.to_hashdeep();
    assert!(hd_diff.contains("hashdeep: Audit failed"));
    assert!(hd_diff.contains("modified.txt"));
    assert!(hd_diff.contains("Moved from"));
}

#[cfg(feature = "reporting")]
#[test]
fn test_compare_report_to_json() {
    let report = sample_compare_report(true);
    let json = report.to_json().unwrap();
    assert!(json.contains("\"unchanged_count\": 6"));
    assert!(json.contains("modified.txt"));
    assert!(json.contains("old_name.txt"));
    assert!(json.contains("new_name.txt"));
}
