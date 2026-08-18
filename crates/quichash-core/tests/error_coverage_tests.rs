use quichash_core::error::HashUtilityError;
use std::io;
use std::path::PathBuf;

#[test]
fn test_all_error_variants_display() {
    let variants = vec![
        HashUtilityError::FileNotFound {
            path: PathBuf::from("foo.txt"),
        },
        HashUtilityError::DirectoryNotFound {
            path: PathBuf::from("dir"),
        },
        HashUtilityError::PermissionDenied {
            path: PathBuf::from("secret"),
            operation: "reading".to_string(),
        },
        HashUtilityError::IoError {
            path: Some(PathBuf::from("file")),
            operation: "writing".to_string(),
            source: io::Error::other("test io"),
        },
        HashUtilityError::IoError {
            path: None,
            operation: "connecting".to_string(),
            source: io::Error::other("test io"),
        },
        HashUtilityError::UnsupportedAlgorithm {
            algorithm: "magic128".to_string(),
        },
        HashUtilityError::AlgorithmUnavailable {
            algorithm: "sha3".to_string(),
            feature: "sha3",
        },
        HashUtilityError::InvalidDigest {
            algorithm: "blake3".to_string(),
            reason: "wrong length".to_string(),
        },
        HashUtilityError::HashComputationFailed {
            path: PathBuf::from("f"),
            algorithm: "md5".to_string(),
            reason: "corrupt".to_string(),
        },
        HashUtilityError::Cancelled,
        HashUtilityError::DatabaseNotFound {
            path: PathBuf::from("db.qh"),
        },
        HashUtilityError::DatabaseParseError {
            path: PathBuf::from("db.qh"),
            line: 42,
            reason: "bad syntax".to_string(),
        },
        HashUtilityError::DatabaseWriteError {
            path: PathBuf::from("out.qh"),
            reason: "disk full".to_string(),
        },
        HashUtilityError::EmptyDatabase {
            path: PathBuf::from("empty.qh"),
        },
        HashUtilityError::VerificationFailed {
            reason: "hash mismatch in 5 files".to_string(),
        },
        HashUtilityError::InvalidArguments {
            message: "mutually exclusive flags".to_string(),
        },
        HashUtilityError::MissingRequiredArgument {
            argument: "--directory".to_string(),
        },
        HashUtilityError::BenchmarkFailed {
            algorithm: "xxh3".to_string(),
            reason: "out of memory".to_string(),
        },
    ];

    for variant in variants {
        let display = format!("{}", variant);
        assert!(!display.is_empty());
    }
}

#[test]
fn test_from_io_error_direct_conversion() {
    let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broken");
    let err: HashUtilityError = io_err.into();
    assert!(matches!(err, HashUtilityError::IoError { .. }));
}
