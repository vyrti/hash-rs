use quichash_core::database::{DatabaseFormat, DatabaseHandler};
use quichash_core::error::HashUtilityError;
use quichash_core::hash::Algorithm;
use quichash_core::manifest::{Manifest, ManifestEntry};
use quichash_core::operation::FailurePolicy;
#[cfg(feature = "zstd")]
use std::fs::File;
use std::fs::{self};
use std::path::{Path, PathBuf};

fn sample_manifest() -> Manifest {
    Manifest {
        entries: vec![ManifestEntry {
            relative_path: PathBuf::from("nested/file.txt"),
            size: 0,
            mode: quichash_core::hash::HashMode::Full,
            digests: vec![quichash_core::hash::DigestValue::from_bytes(
                Algorithm::Sha256,
                vec![2; 32],
            )
            .unwrap()],
        }],
    }
}

#[test]
fn checksum_extensions_map_to_every_supported_algorithm() {
    let cases = [
        ("checks.MD5", Algorithm::Md5),
        ("checks.sha1", Algorithm::Sha1),
        ("checks.sha-1", Algorithm::Sha1),
        ("checks.sha224", Algorithm::Sha224),
        ("checks.sha-224", Algorithm::Sha224),
        ("checks.sha256", Algorithm::Sha256),
        ("checks.sha-256", Algorithm::Sha256),
        ("checks.sha384", Algorithm::Sha384),
        ("checks.sha-384", Algorithm::Sha384),
        ("checks.sha512", Algorithm::Sha512),
        ("checks.sha-512", Algorithm::Sha512),
        ("checks.sha3-224", Algorithm::Sha3_224),
        ("checks.sha3-256", Algorithm::Sha3_256),
        ("checks.sha3-384", Algorithm::Sha3_384),
        ("checks.sha3-512", Algorithm::Sha3_512),
        ("checks.blake2b", Algorithm::Blake2b512),
        ("checks.blake2b-512", Algorithm::Blake2b512),
        ("checks.blake2s", Algorithm::Blake2s256),
        ("checks.blake2s-256", Algorithm::Blake2s256),
        ("checks.blake3", Algorithm::Blake3),
        ("checks.xxh3", Algorithm::Xxh3),
        ("checks.xxh128", Algorithm::Xxh128),
        ("checks.SHA256.ZST", Algorithm::Sha256),
        ("checks.sha256.zstd", Algorithm::Sha256),
    ];
    for (path, expected) in cases {
        assert_eq!(
            DatabaseHandler::checksum_algorithm_from_path(Path::new(path)),
            Some(expected),
            "{path}",
        );
    }
    assert_eq!(
        DatabaseHandler::checksum_algorithm_from_path(Path::new("checks.txt")),
        None,
    );
}

#[test]
fn checksum_manifest_reads_gnu_generic_and_escaped_rows() {
    let temporary = tempfile::tempdir().unwrap();
    let checksum = temporary.path().join("checks.sha256");
    let hash = "AB".repeat(32);
    fs::write(
        &checksum,
        format!(
            "# generated checksums\r\n\r\n{hash}  file with spaces.txt\r\n{hash} *binary.bin\n{hash}\tgeneric path.txt\n{hash}    generic multi-space.txt\n\\{hash}  path\\\\with\\\\slashes\\nand-newline.txt\n"
        ),
    )
    .unwrap();

    let manifest = DatabaseHandler::read_checksum_manifest(&checksum).unwrap();
    let paths: Vec<_> = manifest
        .entries
        .iter()
        .map(|entry| entry.relative_path.clone())
        .collect();
    assert!(paths.contains(&PathBuf::from("file with spaces.txt")));
    assert!(paths.contains(&PathBuf::from("binary.bin")));
    assert!(paths.contains(&PathBuf::from("generic path.txt")));
    assert!(paths.contains(&PathBuf::from("generic multi-space.txt")));
    assert!(paths.contains(&PathBuf::from("path\\with\\slashes\nand-newline.txt")));
    assert!(manifest.entries.iter().all(|entry| {
        entry.digests.len() == 1
            && entry.digests[0].algorithm == Algorithm::Sha256
            && entry.digests[0].to_hex() == hash.to_ascii_lowercase()
    }));
}

#[test]
fn checksum_manifest_is_strict_and_requires_known_extension() {
    let temporary = tempfile::tempdir().unwrap();
    let malformed = temporary.path().join("checks.sha256");
    fs::write(
        &malformed,
        format!("{}  valid.txt\nnot-a-checksum\n", "02".repeat(32)),
    )
    .unwrap();
    assert!(matches!(
        DatabaseHandler::read_checksum_manifest(&malformed),
        Err(HashUtilityError::DatabaseParseError { line: 2, .. })
    ));

    let empty = temporary.path().join("empty.md5");
    fs::write(&empty, "# no rows\n\n").unwrap();
    assert!(matches!(
        DatabaseHandler::read_checksum_manifest(&empty),
        Err(HashUtilityError::EmptyDatabase { .. })
    ));

    let unknown = temporary.path().join("checks.digest");
    fs::write(&unknown, format!("{} file.txt\n", "02".repeat(32))).unwrap();
    assert!(matches!(
        DatabaseHandler::read_checksum_manifest(&unknown),
        Err(HashUtilityError::InvalidArguments { .. })
    ));
    assert!(matches!(
        DatabaseHandler::verification_checksum_algorithm(&unknown),
        Err(HashUtilityError::InvalidArguments { .. })
    ));

    let short = temporary.path().join("short.sha256");
    fs::write(&short, "abcd  file.txt\n").unwrap();
    assert!(matches!(
        DatabaseHandler::read_checksum_manifest(&short),
        Err(HashUtilityError::DatabaseParseError { line: 1, .. })
    ));

    let non_hex = temporary.path().join("non-hex.sha256");
    fs::write(&non_hex, format!("{}  file.txt\n", "zz".repeat(32))).unwrap();
    assert!(matches!(
        DatabaseHandler::read_checksum_manifest(&non_hex),
        Err(HashUtilityError::DatabaseParseError { line: 1, .. })
    ));
}

#[cfg(feature = "zstd")]
#[test]
fn checksum_manifest_reads_compressed_input() {
    let temporary = tempfile::tempdir().unwrap();
    let checksum = temporary.path().join("checks.sha256.zst");
    let compressed = structured_zstd::encoding::compress_to_vec(
        format!("{}  file.txt\n", "02".repeat(32)).as_bytes(),
        structured_zstd::encoding::CompressionLevel::from_level(3),
    );
    fs::write(&checksum, compressed).unwrap();

    let manifest = DatabaseHandler::read_checksum_manifest(&checksum).unwrap();
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].digests[0].algorithm, Algorithm::Sha256);
}

#[test]
fn canonical_output_paths_replace_legacy_and_multiple_suffixes() {
    let cases = [
        ("hashes", "hashes.qh"),
        ("hashes.txt", "hashes.qh"),
        ("hashes.db", "hashes.qh"),
        ("hashes.qh", "hashes.qh"),
        ("hashes.backup.txt", "hashes.backup.qh"),
        ("hashes.txt.zst", "hashes.qh"),
        ("hashes.qh.zst", "hashes.qh"),
    ];
    for (requested, expected) in cases {
        assert_eq!(
            DatabaseHandler::canonical_output_path(
                Path::new(requested),
                DatabaseFormat::Quichash,
                false,
            )
            .unwrap(),
            PathBuf::from(expected),
        );
    }
    assert_eq!(
        DatabaseHandler::canonical_output_path(
            Path::new("hashes.txt.zst"),
            DatabaseFormat::Quichash,
            true,
        )
        .unwrap(),
        PathBuf::from("hashes.qh.zst"),
    );
    assert_eq!(
        DatabaseHandler::canonical_output_path(
            Path::new("hashes.txt"),
            DatabaseFormat::Hashdeep,
            false,
        )
        .unwrap(),
        PathBuf::from("hashes.hashdeep"),
    );
    assert!(DatabaseHandler::canonical_output_path(
        Path::new("hashes"),
        DatabaseFormat::Hashdeep,
        true,
    )
    .is_err());
}

#[test]
fn write_manifest_file_uses_canonical_quichash_path() {
    let temporary = tempfile::tempdir().unwrap();
    let requested = temporary.path().join("hashes.txt");
    let actual = DatabaseHandler::write_manifest_file(
        &requested,
        &sample_manifest(),
        DatabaseFormat::Quichash,
        false,
    )
    .unwrap();

    assert_eq!(actual, temporary.path().join("hashes.qh"));
    assert!(!requested.exists());
    assert_eq!(
        DatabaseHandler::read_manifest(&actual).unwrap(),
        sample_manifest()
    );
}

#[test]
fn legacy_uncompressed_extensions_are_read_by_content() {
    let temporary = tempfile::tempdir().unwrap();
    let quichash_row = format!("{}  sha256  normal  file.txt\n", "02".repeat(32));
    for name in ["legacy.txt", "legacy.db"] {
        let path = temporary.path().join(name);
        fs::write(&path, &quichash_row).unwrap();
        assert_eq!(
            DatabaseHandler::detect_format(&path).unwrap(),
            DatabaseFormat::Quichash,
        );
        assert_eq!(
            DatabaseHandler::read_manifest(&path).unwrap().entries.len(),
            1
        );
    }

    let hashdeep = temporary.path().join("legacy.hashdeep");
    fs::write(
        &hashdeep,
        format!(
            "%%%% HASHDEEP-1.0\n%%%% size,sha256,filename\n5,{},file.txt\n",
            "02".repeat(32)
        ),
    )
    .unwrap();
    assert_eq!(
        DatabaseHandler::detect_format(&hashdeep).unwrap(),
        DatabaseFormat::Hashdeep,
    );
}

#[test]
fn test_detect_format_quichash_with_commas_in_filename() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        temporary.path(),
        "abc123  sha256  normal  path/to/file,with,commas.txt\n",
    )
    .unwrap();

    assert_eq!(
        DatabaseHandler::detect_format(temporary.path()).unwrap(),
        DatabaseFormat::Quichash
    );
}

#[test]
fn test_parse_hashdeep_line_with_commas_in_filename() {
    let algorithms = vec!["sha256".to_owned()];
    let line = "123,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,path/to/file,with,commas.txt";
    let entries = DatabaseHandler::parse_hashdeep_line(line, &algorithms).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, PathBuf::from("path/to/file,with,commas.txt"));
    assert_eq!(entries[0].1.algorithm, "sha256");
}

#[test]
fn test_read_hashdeep_database_with_commas_in_filename() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        temporary.path(),
        "%%%% HASHDEEP-1.0\n%%%% size,sha256,filename\n123,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,path/to/file,with,commas.txt\n",
    )
    .unwrap();

    let database = DatabaseHandler::read_database(temporary.path()).unwrap();
    let entry = database
        .get(&PathBuf::from("path/to/file,with,commas.txt"))
        .unwrap();
    assert_eq!(entry.algorithm, "sha256");
}

#[test]
fn typed_hashdeep_round_trip_preserves_every_digest() {
    let manifest = Manifest {
        entries: vec![ManifestEntry {
            relative_path: PathBuf::from("nested/file.txt"),
            size: 5,
            mode: quichash_core::hash::HashMode::Full,
            digests: vec![
                quichash_core::hash::DigestValue::from_bytes(Algorithm::Md5, vec![1; 16]).unwrap(),
                quichash_core::hash::DigestValue::from_bytes(Algorithm::Sha256, vec![2; 32])
                    .unwrap(),
            ],
        }],
    };
    let temporary = tempfile::NamedTempFile::new().unwrap();
    {
        let mut file = std::fs::File::create(temporary.path()).unwrap();
        DatabaseHandler::write_manifest(&mut file, &manifest, DatabaseFormat::Hashdeep).unwrap();
    }
    let restored = DatabaseHandler::read_manifest(temporary.path()).unwrap();
    assert_eq!(restored, manifest);
}

#[test]
fn typed_quichash_rows_merge_by_path() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        temporary.path(),
        format!(
            "{}  md5  normal  file.txt\n{}  sha256  normal  file.txt\n",
            "01".repeat(16),
            "02".repeat(32),
        ),
    )
    .unwrap();
    let restored = DatabaseHandler::read_manifest(temporary.path()).unwrap();
    assert_eq!(restored.entries.len(), 1);
    assert_eq!(restored.entries[0].digests.len(), 2);
}

#[test]
fn typed_reader_is_fail_fast_by_default_and_can_collect_issues() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        temporary.path(),
        format!(
            "malformed\n{}  blake3  normal  valid.txt\n",
            "01".repeat(32),
        ),
    )
    .unwrap();
    assert!(DatabaseHandler::read_manifest(temporary.path()).is_err());
    let read =
        DatabaseHandler::read_manifest_with_policy(temporary.path(), FailurePolicy::Continue)
            .unwrap();
    assert_eq!(read.issues.len(), 1);
    assert_eq!(read.manifest.entries.len(), 1);
}
