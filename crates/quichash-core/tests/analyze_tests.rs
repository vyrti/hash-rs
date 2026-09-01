use quichash_core::analyze::{AnalyzeEngine, format_size};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn test_analyze_quichash_format() {
    let db_path = "test_analyze_quichash.qh";
    let content = "hash1  sha256  normal  file1.txt\n\
                   hash2  sha256  normal  file2.txt\n\
                   hash1  sha256  normal  file1_copy.txt\n";
    fs::write(db_path, content).unwrap();

    let engine = AnalyzeEngine::new();
    let report = engine.analyze(Path::new(db_path)).unwrap();

    assert_eq!(report.stats.total_files, 3);
    assert_eq!(report.stats.unique_hashes, 2);
    assert_eq!(report.stats.duplicate_groups, 1);
    assert_eq!(report.stats.duplicate_files, 2);
    assert!(report.stats.total_file_size.is_none()); // QuicHash format has no sizes

    fs::remove_file(db_path).unwrap();
}

#[test]
fn test_analyze_hashdeep_format() {
    let db_path = "test_analyze_hashdeep.txt";
    let content = "%%%% HASHDEEP-1.0\n\
                   %%%% size,sha256,filename\n\
                   ## Invoked from: test\n\
                   ##\n\
                   1000,hash1,file1.txt\n\
                   2000,hash2,file2.txt\n\
                   1000,hash1,file1_copy.txt\n";
    fs::write(db_path, content).unwrap();

    let engine = AnalyzeEngine::new();
    let report = engine.analyze(Path::new(db_path)).unwrap();

    assert_eq!(report.stats.total_files, 3);
    assert_eq!(report.stats.unique_hashes, 2);
    assert_eq!(report.stats.duplicate_groups, 1);
    assert_eq!(report.stats.total_file_size, Some(4000)); // 1000 + 2000 + 1000
    assert_eq!(report.stats.potential_savings, Some(1000)); // One duplicate of 1000 bytes

    fs::remove_file(db_path).unwrap();
}

#[test]
fn test_analyze_hashdeep_format_with_commas_in_filename() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let content = "%%%% HASHDEEP-1.0\n\
                   %%%% size,sha256,filename\n\
                   ## Invoked from: test\n\
                   ##\n\
                   1000,hash1,file,one.txt\n\
                   1000,hash1,file,two.txt\n";
    fs::write(temporary.path(), content).unwrap();

    let report = AnalyzeEngine::new().analyze(temporary.path()).unwrap();
    assert_eq!(report.stats.total_files, 2);
    assert_eq!(report.stats.duplicate_groups, 1);
    assert_eq!(report.stats.total_file_size, Some(2000));
    assert!(
        report.duplicate_groups[0]
            .paths
            .contains(&PathBuf::from("file,one.txt"))
    );
    assert!(
        report.duplicate_groups[0]
            .paths
            .contains(&PathBuf::from("file,two.txt"))
    );
}

#[test]
fn test_format_size() {
    assert_eq!(format_size(500), "500 bytes");
    assert_eq!(format_size(1024), "1.00 KB");
    assert_eq!(format_size(1536), "1.50 KB");
    assert_eq!(format_size(1048576), "1.00 MB");
    assert_eq!(format_size(1073741824), "1.00 GB");
}
