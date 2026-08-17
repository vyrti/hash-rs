use quichash_core::database::{DatabaseFormat, DatabaseHandler};
use quichash_core::hash::Algorithm;
use quichash_core::manifest::{Manifest, ManifestEntry};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
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

#[cfg(feature = "xz")]
#[test]
fn historical_xz_names_are_read_by_content() {
    fn write_xz(path: &Path, content: &[u8]) {
        let file = File::create(path).unwrap();
        let mut encoder = xz2::write::XzEncoder::new(file, 6);
        encoder.write_all(content).unwrap();
        encoder.finish().unwrap();
    }

    let temporary = tempfile::tempdir().unwrap();
    let quichash = temporary.path().join("legacy.txt.xz");
    write_xz(
        &quichash,
        format!("{}  sha256  normal  file.txt\n", "02".repeat(32)).as_bytes(),
    );
    assert_eq!(
        DatabaseHandler::detect_format(&quichash).unwrap(),
        DatabaseFormat::Quichash,
    );

    let hashdeep = temporary.path().join("historical.hashdeep.xz");
    write_xz(
        &hashdeep,
        format!(
            "%%%% HASHDEEP-1.0\n%%%% size,sha256,filename\n5,{},file.txt\n",
            "02".repeat(32)
        )
        .as_bytes(),
    );
    assert_eq!(
        DatabaseHandler::detect_format(&hashdeep).unwrap(),
        DatabaseFormat::Hashdeep,
    );

    let arbitrary = temporary.path().join("arbitrary-name.xz");
    write_xz(
        &arbitrary,
        format!("{}  sha256  normal  file.txt\n", "02".repeat(32)).as_bytes(),
    );
    assert_eq!(
        DatabaseHandler::read_manifest(&arbitrary)
            .unwrap()
            .entries
            .len(),
        1
    );
}

#[cfg(feature = "xz")]
#[test]
fn write_manifest_file_round_trips_canonical_compressed_output() {
    let temporary = tempfile::tempdir().unwrap();
    let requested = temporary.path().join("hashes.db");
    let actual = DatabaseHandler::write_manifest_file(
        &requested,
        &sample_manifest(),
        DatabaseFormat::Quichash,
        true,
    )
    .unwrap();

    assert_eq!(actual, temporary.path().join("hashes.qh.xz"));
    assert!(!temporary.path().join("hashes.qh").exists());
    assert_eq!(
        DatabaseHandler::read_manifest(&actual).unwrap(),
        sample_manifest()
    );
}

#[cfg(feature = "xz")]
#[test]
fn compression_failure_preserves_plain_quichash_database() {
    let temporary = tempfile::tempdir().unwrap();
    let plain = temporary.path().join("hashes.qh");
    fs::write(
        &plain,
        format!("{}  sha256  normal  file.txt\n", "02".repeat(32)),
    )
    .unwrap();
    fs::create_dir(temporary.path().join("hashes.qh.xz")).unwrap();

    assert!(DatabaseHandler::compress_database(&plain).is_err());
    assert!(plain.is_file());
}

#[cfg(feature = "xz")]
#[test]
fn compress_database_rejects_hashdeep_content() {
    let temporary = tempfile::tempdir().unwrap();
    let hashdeep = temporary.path().join("hashes.hashdeep");
    fs::write(
        &hashdeep,
        format!(
            "%%%% HASHDEEP-1.0\n%%%% size,sha256,filename\n5,{},file.txt\n",
            "02".repeat(32)
        ),
    )
    .unwrap();

    let error = DatabaseHandler::compress_database(&hashdeep).unwrap_err();
    assert!(error.to_string().contains("only QuicHash databases"));
    assert!(hashdeep.is_file());
    assert!(!temporary.path().join("hashes.qh.xz").exists());
}

#[cfg(not(feature = "xz"))]
#[test]
fn disabled_xz_feature_reports_error_and_preserves_plain_output() {
    let temporary = tempfile::tempdir().unwrap();
    let requested = temporary.path().join("hashes");
    assert!(DatabaseHandler::write_manifest_file(
        &requested,
        &sample_manifest(),
        DatabaseFormat::Quichash,
        true,
    )
    .is_err());
    assert!(temporary.path().join("hashes.qh").is_file());
    assert!(!temporary.path().join("hashes.qh.xz").exists());
}

#[test]
fn test_write_entry() {
    let mut buffer = Vec::new();
    let hash = "d41d8cd98f00b204e9800998ecf8427e";
    let algorithm = "md5";
    let fast_mode = false;
    let path = Path::new("./test/file.txt");

    DatabaseHandler::write_entry(&mut buffer, hash, algorithm, fast_mode, path).unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert_eq!(
        output,
        "d41d8cd98f00b204e9800998ecf8427e  md5  normal  ./test/file.txt\n"
    );
}

#[test]
fn test_write_multiple_entries() {
    let mut buffer = Vec::new();

    DatabaseHandler::write_entry(
        &mut buffer,
        "abc123",
        "sha256",
        false,
        Path::new("file1.txt"),
    )
    .unwrap();

    DatabaseHandler::write_entry(
        &mut buffer,
        "def456",
        "sha256",
        true,
        Path::new("file2.txt"),
    )
    .unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert_eq!(
        output,
        "abc123  sha256  normal  file1.txt\ndef456  sha256  fast  file2.txt\n"
    );
}

#[test]
fn test_parse_line_valid() {
    let line = "d41d8cd98f00b204e9800998ecf8427e  md5  normal  ./test/file.txt";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_some());
    let (hash, algorithm, fast_mode, path) = result.unwrap();
    assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(algorithm, "md5");
    assert!(!fast_mode);
    assert_eq!(path, PathBuf::from("./test/file.txt"));
}

#[test]
fn test_parse_line_with_spaces_in_path() {
    let line = "abc123  sha256  fast  ./path with spaces/file.txt";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_some());
    let (hash, algorithm, fast_mode, path) = result.unwrap();
    assert_eq!(hash, "abc123");
    assert_eq!(algorithm, "sha256");
    assert!(fast_mode);
    assert_eq!(path, PathBuf::from("./path with spaces/file.txt"));
}

#[test]
fn test_parse_line_malformed_missing_fields() {
    let line = "abc123  sha256  file.txt"; // Missing fast_mode field
    let result = DatabaseHandler::parse_line(line);

    // Should fail because we expect 4 fields
    assert!(result.is_none());
}

#[test]
fn test_parse_line_malformed_no_space() {
    let line = "abc123sha256normalfile.txt";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_none());
}

#[test]
fn test_parse_line_empty_hash() {
    let line = "  sha256  normal  file.txt";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_none());
}

#[test]
fn test_parse_line_empty_path() {
    let line = "abc123  sha256  normal  ";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_none());
}

#[test]
fn test_parse_line_invalid_fast_mode() {
    let line = "abc123  sha256  invalid  file.txt";
    let result = DatabaseHandler::parse_line(line);

    // Should fail because fast_mode must be "fast" or "normal"
    assert!(result.is_none());
}

#[test]
fn test_read_database() {
    // Create a temporary database file
    let temp_file = "test_db_temp.txt";
    let content = "d41d8cd98f00b204e9800998ecf8427e  md5  normal  ./empty.txt\n\
                   5d41402abc4b2a76b9719d911017c592  md5  normal  ./hello.txt\n\
                   098f6bcd4621d373cade4e832627b4f6  md5  fast  ./test/data.bin\n";
    fs::write(temp_file, content).unwrap();

    // Read database
    let database = DatabaseHandler::read_database(Path::new(temp_file)).unwrap();

    // Verify entries
    assert_eq!(database.len(), 3);

    let empty_entry = database.get(&PathBuf::from("./empty.txt")).unwrap();
    assert_eq!(empty_entry.hash, "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(empty_entry.algorithm, "md5");
    assert!(!empty_entry.fast_mode);

    let hello_entry = database.get(&PathBuf::from("./hello.txt")).unwrap();
    assert_eq!(hello_entry.hash, "5d41402abc4b2a76b9719d911017c592");
    assert_eq!(hello_entry.algorithm, "md5");
    assert!(!hello_entry.fast_mode);

    let data_entry = database.get(&PathBuf::from("./test/data.bin")).unwrap();
    assert_eq!(data_entry.hash, "098f6bcd4621d373cade4e832627b4f6");
    assert_eq!(data_entry.algorithm, "md5");
    assert!(data_entry.fast_mode);

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_read_database_with_empty_lines() {
    let temp_file = "test_db_empty_lines_temp.txt";
    let content = "abc123  sha256  normal  file1.txt\n\
                   \n\
                   def456  sha256  fast  file2.txt\n\
                   \n";
    fs::write(temp_file, content).unwrap();

    let database = DatabaseHandler::read_database(Path::new(temp_file)).unwrap();

    assert_eq!(database.len(), 2);
    assert!(database.contains_key(&PathBuf::from("file1.txt")));
    assert!(database.contains_key(&PathBuf::from("file2.txt")));

    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_read_database_with_malformed_lines() {
    let temp_file = "test_db_malformed_temp.txt";
    let content = "abc123  sha256  normal  file1.txt\n\
                   malformed line without proper format\n\
                   def456  sha256  fast  file2.txt\n";
    fs::write(temp_file, content).unwrap();

    // Should skip malformed line and continue
    let database = DatabaseHandler::read_database(Path::new(temp_file)).unwrap();

    assert_eq!(database.len(), 2);
    assert!(database.contains_key(&PathBuf::from("file1.txt")));
    assert!(database.contains_key(&PathBuf::from("file2.txt")));

    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_read_database_file_not_found() {
    let result = DatabaseHandler::read_database(Path::new("nonexistent_db.txt"));

    assert!(result.is_err());
}

#[test]
fn test_round_trip() {
    // Write entries to a buffer
    let mut buffer = Vec::new();
    DatabaseHandler::write_entry(
        &mut buffer,
        "hash1",
        "sha256",
        false,
        Path::new("file1.txt"),
    )
    .unwrap();
    DatabaseHandler::write_entry(&mut buffer, "hash2", "sha256", true, Path::new("file2.txt"))
        .unwrap();

    // Write buffer to file
    let temp_file = "test_round_trip_temp.txt";
    fs::write(temp_file, &buffer).unwrap();

    // Read back
    let database = DatabaseHandler::read_database(Path::new(temp_file)).unwrap();

    // Verify
    assert_eq!(database.len(), 2);

    let entry1 = database.get(&PathBuf::from("file1.txt")).unwrap();
    assert_eq!(entry1.hash, "hash1");
    assert_eq!(entry1.algorithm, "sha256");
    assert!(!entry1.fast_mode);

    let entry2 = database.get(&PathBuf::from("file2.txt")).unwrap();
    assert_eq!(entry2.hash, "hash2");
    assert_eq!(entry2.algorithm, "sha256");
    assert!(entry2.fast_mode);

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_parse_line_with_forward_slashes() {
    let line = "abc123  sha256  normal  path/to/file.txt";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_some());
    let (hash, algorithm, fast_mode, path) = result.unwrap();
    assert_eq!(hash, "abc123");
    assert_eq!(algorithm, "sha256");
    assert!(!fast_mode);
    // Path should be parsed correctly regardless of platform
    assert!(path.to_str().unwrap().contains("file.txt"));
}

#[test]
fn test_parse_line_with_backward_slashes() {
    let line = "abc123  sha256  fast  path\\to\\file.txt";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_some());
    let (hash, algorithm, fast_mode, path) = result.unwrap();
    assert_eq!(hash, "abc123");
    assert_eq!(algorithm, "sha256");
    assert!(fast_mode);
    // Path should be parsed correctly regardless of platform
    assert!(path.to_str().unwrap().contains("file.txt"));
}

#[test]
fn test_parse_line_with_mixed_slashes() {
    let line = "abc123  sha256  normal  path/to\\mixed/file.txt";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_some());
    let (hash, algorithm, fast_mode, path) = result.unwrap();
    assert_eq!(hash, "abc123");
    assert_eq!(algorithm, "sha256");
    assert!(!fast_mode);
    // Path should be parsed correctly with normalized separators
    assert!(path.to_str().unwrap().contains("file.txt"));
}

#[test]
fn test_read_database_with_mixed_separators() {
    let temp_file = "test_db_mixed_sep_temp.txt";
    // Create database with mixed path separators
    let content = "abc123  sha256  normal  path/to/file1.txt\n\
                   def456  sha256  fast  path\\to\\file2.txt\n\
                   ghi789  sha256  normal  path/to\\file3.txt\n";
    fs::write(temp_file, content).unwrap();

    let database = DatabaseHandler::read_database(Path::new(temp_file)).unwrap();

    // All paths should be parsed successfully
    assert_eq!(database.len(), 3);

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_parse_line_with_double_spaces_in_filename() {
    // Test case for filenames that contain two consecutive spaces
    let line = "abc123  sha256  normal  path/to/file  with  spaces.txt";
    let result = DatabaseHandler::parse_line(line);

    assert!(result.is_some());
    let (hash, algorithm, fast_mode, path) = result.unwrap();
    assert_eq!(hash, "abc123");
    assert_eq!(algorithm, "sha256");
    assert!(!fast_mode);
    // The filename should preserve the double spaces
    assert!(path.to_str().unwrap().contains("file  with  spaces.txt"));
}

#[test]
fn test_read_database_with_double_spaces_in_filenames() {
    let temp_file = "test_db_double_spaces_temp.txt";
    // Create database with filenames containing double spaces (like the Windows bug)
    let content = "39301d664174903a82a8e204ec9a0f72b1b672ab2ba42290ae7bb43ff4395142  blake3  normal  Lesson 07\\008. Lesson 7 Lab  Setting up Storage.en.srt\n\
                   479173443b0a33bb6ac48b381475250642351f20c603df5c9d3bb6424d023de3  blake3  normal  Lesson 07\\008. Lesson 7 Lab  Setting up Storage.mp4\n";
    fs::write(temp_file, content).unwrap();

    let database = DatabaseHandler::read_database(Path::new(temp_file)).unwrap();

    // Both entries should be parsed successfully
    assert_eq!(database.len(), 2);

    // Verify the entries exist with the correct filenames
    let found_srt = database.iter().any(|(path, _)| {
        path.to_str().unwrap().contains("Lesson 7 Lab") && path.to_str().unwrap().ends_with(".srt")
    });
    let found_mp4 = database.iter().any(|(path, _)| {
        path.to_str().unwrap().contains("Lesson 7 Lab") && path.to_str().unwrap().ends_with(".mp4")
    });

    assert!(found_srt, "Should find .srt file");
    assert!(found_mp4, "Should find .mp4 file");

    // Cleanup
    fs::remove_file(temp_file).unwrap();
}
