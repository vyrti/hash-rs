use quichash_core::dedup::{DedupReport, DedupStats, DuplicateGroupWithSize};
use std::path::PathBuf;
use std::time::Duration;

#[test]
fn test_dedup_report_display_empty_and_populated() {
    let empty_report = DedupReport {
        stats: DedupStats {
            files_scanned: 0,
            files_failed: 0,
            total_bytes: 0,
            duplicate_groups: 0,
            duplicate_files: 0,
            wasted_space: 0,
            duration: Duration::from_secs(1),
        },
        duplicate_groups: Vec::new(),
    };
    empty_report.display();

    let populated_report = DedupReport {
        stats: DedupStats {
            files_scanned: 5,
            files_failed: 0,
            total_bytes: 2048,
            duplicate_groups: 1,
            duplicate_files: 2,
            wasted_space: 1024,
            duration: Duration::from_millis(500),
        },
        duplicate_groups: vec![DuplicateGroupWithSize {
            hash: "abc123".to_string(),
            paths: vec![PathBuf::from("/tmp/a.txt"), PathBuf::from("/tmp/b.txt")],
            count: 2,
            file_size: 1024,
            wasted_space: 1024,
        }],
    };
    populated_report.display();
}

#[cfg(feature = "reporting")]
#[test]
fn test_dedup_report_to_json() {
    let report = DedupReport {
        stats: DedupStats {
            files_scanned: 2,
            files_failed: 0,
            total_bytes: 100,
            duplicate_groups: 1,
            duplicate_files: 2,
            wasted_space: 50,
            duration: Duration::from_secs(2),
        },
        duplicate_groups: vec![DuplicateGroupWithSize {
            hash: "deadbeef".to_string(),
            paths: vec![PathBuf::from("a"), PathBuf::from("b")],
            count: 2,
            file_size: 50,
            wasted_space: 50,
        }],
    };

    let json = report.to_json().unwrap();
    assert!(json.contains("deadbeef"));
    assert!(json.contains("\"files_scanned\": 2"));
    assert!(json.contains("\"wasted_space\": 50"));
}
