use crossbeam_channel::bounded;
use quichash_core::dedup::walk_directory_streaming;
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
