use quichash_core::verify::VerifyEngine;
use std::fs;

#[test]
fn test_verify_engine_sequential_mode() {
    let temporary = tempfile::tempdir().unwrap();
    let file1 = temporary.path().join("a.txt");
    fs::write(&file1, b"hello").unwrap();

    let digest = quichash_core::hash_bytes(b"hello", &[quichash_core::Algorithm::Blake3])
        .unwrap()
        .remove(0);

    let db_path = temporary.path().join("hashes.qh");
    fs::write(
        &db_path,
        format!("{}  blake3  normal  a.txt\n", digest.to_hex()),
    )
    .unwrap();

    let engine = VerifyEngine::with_parallel(false);
    let report = engine.verify(&db_path, temporary.path()).unwrap();
    assert_eq!(report.matches, 1);
    assert_eq!(report.mismatches.len(), 0);
}

#[test]
fn test_verify_engine_fast_mode_entry() {
    let temporary = tempfile::tempdir().unwrap();
    let file1 = temporary.path().join("fast.txt");
    fs::write(&file1, b"content").unwrap();

    let db_path = temporary.path().join("fast.qh");
    fs::write(
        &db_path,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  blake3  fast  fast.txt\n",
    )
    .unwrap();

    let engine = VerifyEngine::new();
    let report = engine.verify(&db_path, temporary.path()).unwrap();
    // Since expected hash doesn't match recomputed fast hash
    assert_eq!(report.mismatches.len(), 1);
}

#[test]
fn test_verify_engine_missing_inputs() {
    let engine = VerifyEngine::new();
    let nonexistent_db = std::path::Path::new("/nonexistent/db.qh");
    let nonexistent_dir = std::path::Path::new("/nonexistent/dir");

    assert!(engine.verify(nonexistent_db, nonexistent_dir).is_err());
}
