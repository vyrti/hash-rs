use quichash_core::database::{DatabaseFormat, DatabaseHandler};
use quichash_core::hash::{Algorithm, DigestValue, HashMode};
use quichash_core::manifest::{Manifest, ManifestEntry};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn test_write_hashdeep_manifest() {
    let mut buffer = Vec::new();
    let manifest = Manifest {
        entries: vec![ManifestEntry {
            relative_path: PathBuf::from("sub/file.txt"),
            size: 1234,
            mode: HashMode::Full,
            digests: vec![DigestValue::from_bytes(Algorithm::Sha256, vec![1; 32]).unwrap()],
        }],
    };

    DatabaseHandler::write_manifest(&mut buffer, &manifest, DatabaseFormat::Hashdeep).unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert!(output.contains("HASHDEEP-1.0"));
    assert!(output.contains("sub/file.txt"));
}

#[test]
fn test_parse_hashdeep_line_edge_cases() {
    let algos = vec!["sha256".to_string()];

    // Empty line
    assert!(DatabaseHandler::parse_hashdeep_line("", &algos).is_none());

    // Comment line
    assert!(DatabaseHandler::parse_hashdeep_line("## some comment", &algos).is_none());

    // Header line
    assert!(DatabaseHandler::parse_hashdeep_line("%%%% HASHDEEP-1.0", &algos).is_none());

    // Invalid non-integer size
    assert!(
        DatabaseHandler::parse_hashdeep_line("not_a_number,hash123,path.txt", &algos).is_none()
    );

    // Insufficient columns
    assert!(DatabaseHandler::parse_hashdeep_line("1234,only_one_col", &algos).is_none());
}

#[test]
fn test_compress_database_nonexistent() {
    let missing_path = Path::new("/path/that/does/not/exist/db.qh");
    assert!(DatabaseHandler::compress_database(missing_path).is_err());
}

#[test]
fn test_read_database_corrupt_content() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        temporary.path(),
        b"random garbage that cannot be parsed as quichash",
    )
    .unwrap();

    let database = DatabaseHandler::read_database(temporary.path()).unwrap();
    assert!(database.is_empty());
}
