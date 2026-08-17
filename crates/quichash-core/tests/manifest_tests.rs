use quichash_core::hash::{Algorithm, DigestValue, HashMode};
use quichash_core::manifest::{Manifest, ManifestEntry};

#[cfg(all(feature = "filesystem", feature = "sha2", feature = "blake3"))]
use quichash_core::manifest::{scan_folder, verify_folder, ScanOptions};
#[cfg(all(feature = "filesystem", feature = "sha2", feature = "blake3"))]
use quichash_core::operation::{FailurePolicy, NoopObserver};

#[test]
fn folder_digest_is_independent_of_input_order() {
    let digest = |path: &str, value: u8| ManifestEntry {
        relative_path: path.into(),
        size: 1,
        mode: HashMode::Full,
        digests: vec![DigestValue::from_bytes(Algorithm::Blake3, vec![value; 32]).unwrap()],
    };
    let left = Manifest {
        entries: vec![digest("b", 2), digest("a", 1)],
    };
    let right = Manifest {
        entries: vec![digest("a", 1), digest("b", 2)],
    };
    assert_eq!(
        left.folder_digests(&[Algorithm::Blake3]).unwrap(),
        right.folder_digests(&[Algorithm::Blake3]).unwrap()
    );
}

#[test]
fn rename_changes_folder_digest() {
    let entry = |path: &str| ManifestEntry {
        relative_path: path.into(),
        size: 3,
        mode: HashMode::Full,
        digests: vec![DigestValue::from_bytes(Algorithm::Blake3, vec![7; 32]).unwrap()],
    };
    let left = Manifest {
        entries: vec![entry("a")],
    };
    let right = Manifest {
        entries: vec![entry("b")],
    };
    assert_ne!(
        left.folder_digests(&[Algorithm::Blake3]).unwrap(),
        right.folder_digests(&[Algorithm::Blake3]).unwrap()
    );
}

#[test]
fn sampled_and_full_folder_digests_are_distinct() {
    let entry = |mode| ManifestEntry {
        relative_path: "file".into(),
        size: 3,
        mode,
        digests: vec![DigestValue::from_bytes(Algorithm::Blake3, vec![9; 32]).unwrap()],
    };
    let full = Manifest {
        entries: vec![entry(HashMode::Full)],
    };
    let sampled = Manifest {
        entries: vec![entry(HashMode::Sampled)],
    };
    assert_ne!(
        full.folder_digests(&[Algorithm::Blake3]).unwrap(),
        sampled.folder_digests(&[Algorithm::Blake3]).unwrap(),
    );
}

#[cfg(all(feature = "filesystem", feature = "sha2", feature = "blake3"))]
#[test]
fn folder_scan_and_multi_digest_verification() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("nested")).unwrap();
    std::fs::write(temporary.path().join("a.txt"), b"alpha").unwrap();
    std::fs::write(temporary.path().join("nested/b.txt"), b"beta").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("a.txt", temporary.path().join("ignored-link")).unwrap();

    let options = ScanOptions {
        algorithms: vec![Algorithm::Blake3, Algorithm::Sha256],
        parallel: true,
        ..ScanOptions::default()
    };
    let scanned = scan_folder(temporary.path(), &options, &NoopObserver).unwrap();
    assert_eq!(scanned.manifest.entries.len(), 2);
    assert!(scanned
        .manifest
        .entries
        .iter()
        .all(|entry| entry.digests.len() == 2));
    assert_eq!(scanned.folder_digests.len(), 2);

    let verified = verify_folder(
        &scanned.manifest,
        temporary.path(),
        FailurePolicy::FailFast,
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(verified.matches, 2);
    assert!(verified.mismatches.is_empty());

    std::fs::write(temporary.path().join("a.txt"), b"changed").unwrap();
    let verified = verify_folder(
        &scanned.manifest,
        temporary.path(),
        FailurePolicy::FailFast,
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(verified.mismatches.len(), 2);
}
