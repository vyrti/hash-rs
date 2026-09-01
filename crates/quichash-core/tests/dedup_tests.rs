use crossbeam_channel::bounded;
use quichash_core::dedup::{DedupEngine, walk_directory_streaming};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[test]
fn test_walk_directory_streaming_skips_ignored_directory_patterns() {
    let temporary = tempfile::tempdir().unwrap();
    fs::create_dir_all(temporary.path().join("A/sub")).unwrap();
    fs::create_dir_all(temporary.path().join("B")).unwrap();
    fs::write(temporary.path().join(".hashignore"), b"A/\n").unwrap();
    fs::write(temporary.path().join("A/file1.txt"), b"one").unwrap();
    fs::write(temporary.path().join("A/sub/file2.txt"), b"two").unwrap();
    fs::write(temporary.path().join("B/file3.txt"), b"three").unwrap();

    let (sender, receiver) = bounded::<PathBuf>(16);
    let discovered = Arc::new(Mutex::new(0));
    walk_directory_streaming(temporary.path(), sender, Arc::clone(&discovered)).unwrap();
    let files: Vec<_> = receiver.iter().collect();

    assert_eq!(files.len(), 1);
    assert_eq!(*discovered.lock().unwrap(), 1);
    assert!(files[0].ends_with(Path::new("B").join("file3.txt")));
}

#[test]
fn test_dedup_engine_find_duplicates_parallel() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("f1.txt"), b"same content").unwrap();
    fs::write(temporary.path().join("f2.txt"), b"same content").unwrap();
    fs::write(temporary.path().join("f3.txt"), b"different content").unwrap();

    let engine = DedupEngine::new().with_parallel(true).with_fast_mode(false);
    let report = engine.find_duplicates(temporary.path()).unwrap();

    assert_eq!(report.stats.files_scanned, 3);
    assert_eq!(report.stats.files_failed, 0);
    assert_eq!(report.stats.duplicate_groups, 1);
    assert_eq!(report.stats.duplicate_files, 2);
    assert_eq!(report.stats.wasted_space, 12); // "same content" is 12 bytes
    assert_eq!(report.duplicate_groups.len(), 1);
    assert_eq!(report.duplicate_groups[0].count, 2);
    assert_eq!(report.duplicate_groups[0].file_size, 12);
}

#[test]
fn test_dedup_engine_find_duplicates_sequential() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("f1.txt"), b"dup").unwrap();
    fs::write(temporary.path().join("f2.txt"), b"dup").unwrap();
    fs::write(temporary.path().join("f3.txt"), b"dup").unwrap();

    let engine = DedupEngine::new().with_parallel(false);
    let report = engine.find_duplicates(temporary.path()).unwrap();

    assert_eq!(report.stats.files_scanned, 3);
    assert_eq!(report.stats.duplicate_groups, 1);
    assert_eq!(report.stats.duplicate_files, 3);
    assert_eq!(report.stats.wasted_space, 6); // 2 extra copies * 3 bytes
}

#[test]
fn test_dedup_engine_empty_and_nonexistent_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let engine = DedupEngine::new();
    let report = engine.find_duplicates(temporary.path()).unwrap();

    assert_eq!(report.stats.files_scanned, 0);
    assert_eq!(report.stats.duplicate_groups, 0);
    assert_eq!(report.stats.duplicate_files, 0);

    let nonexistent = temporary.path().join("does_not_exist");
    assert!(engine.find_duplicates(&nonexistent).is_err());
}

#[test]
fn test_dedup_engine_fast_mode() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("a.bin"), vec![42u8; 1024]).unwrap();
    fs::write(temporary.path().join("b.bin"), vec![42u8; 1024]).unwrap();

    let engine = DedupEngine::new().with_fast_mode(true).with_parallel(false);
    let report = engine.find_duplicates(temporary.path()).unwrap();

    assert_eq!(report.stats.files_scanned, 2);
    assert_eq!(report.stats.duplicate_groups, 1);
    assert_eq!(report.stats.duplicate_files, 2);
    assert_eq!(report.stats.wasted_space, 1024);
}
