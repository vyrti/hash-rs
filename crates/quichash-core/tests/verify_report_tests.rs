use quichash_core::verify::{Mismatch, VerifyReport};
use std::path::PathBuf;

#[test]
fn test_verify_report_display_all_good() {
    let report = VerifyReport {
        matches: 5,
        mismatches: Vec::new(),
        missing_files: Vec::new(),
        new_files: Vec::new(),
    };
    report.display();
}

#[test]
fn test_verify_report_display_with_all_issues() {
    let report = VerifyReport {
        matches: 2,
        mismatches: vec![Mismatch {
            path: PathBuf::from("a.txt"),
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        }],
        missing_files: vec![PathBuf::from("deleted.txt")],
        new_files: vec![PathBuf::from("added.txt")],
    };
    report.display();
}
