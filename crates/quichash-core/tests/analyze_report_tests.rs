use quichash_core::analyze::{format_size, AnalyzeReport, AnalyzeStats, DuplicateGroup};
use std::path::PathBuf;

#[test]
fn test_analyze_format_size() {
    assert_eq!(format_size(500), "500 bytes");
    assert_eq!(format_size(1024), "1.00 KB");
    assert_eq!(format_size(1024 * 1024), "1.00 MB");
    assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    assert_eq!(format_size(1024 * 1024 * 1024 * 1024), "1.00 TB");
}

#[test]
fn test_analyze_report_to_plain_text() {
    let report = AnalyzeReport {
        database_path: PathBuf::from("/tmp/test.qh"),
        stats: AnalyzeStats {
            total_files: 10,
            unique_hashes: 8,
            duplicate_groups: 1,
            duplicate_files: 2,
            database_file_size: 512,
            database_format: "quichash".to_string(),
            algorithms: vec!["blake3".to_string()],
            fast_mode_files: 1,
            normal_mode_files: 9,
            total_file_size: Some(1024 * 1024 * 10),
            potential_savings: Some(1024 * 1024 * 2),
        },
        duplicate_groups: vec![DuplicateGroup {
            hash: "0123456789abcdef0123456789abcdef".to_string(),
            paths: vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")],
            count: 2,
            file_size: Some(1024 * 1024 * 2),
            wasted_space: Some(1024 * 1024 * 2),
        }],
    };

    let text = report.to_plain_text();
    assert!(text.contains("Database Analysis Report"));
    assert!(text.contains("quichash"));
    assert!(text.contains("blake3"));
    assert!(text.contains("Potential savings"));
    assert!(text.contains("a.txt"));
}

#[cfg(feature = "reporting")]
#[test]
fn test_analyze_report_to_json() {
    let report = AnalyzeReport {
        database_path: PathBuf::from("/tmp/test.qh"),
        stats: AnalyzeStats {
            total_files: 2,
            unique_hashes: 1,
            duplicate_groups: 1,
            duplicate_files: 2,
            database_file_size: 100,
            database_format: "quichash".to_string(),
            algorithms: vec!["sha256".to_string()],
            fast_mode_files: 0,
            normal_mode_files: 2,
            total_file_size: None,
            potential_savings: None,
        },
        duplicate_groups: vec![DuplicateGroup {
            hash: "abcd".to_string(),
            paths: vec![PathBuf::from("1.bin"), PathBuf::from("2.bin")],
            count: 2,
            file_size: None,
            wasted_space: None,
        }],
    };

    let json = report.to_json().unwrap();
    assert!(json.contains("\"total_files\": 2"));
    assert!(json.contains("sha256"));
    assert!(json.contains("1.bin"));
}
