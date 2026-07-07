// Centralized error handling module
// Provides comprehensive error types with context for all operations

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Main error type for the hash utility
/// Provides context-rich error messages with file paths and operations
#[derive(Debug)]
#[allow(dead_code)]
pub enum HashUtilityError {
    /// File system errors with context
    FileNotFound {
        path: PathBuf,
    },
    DirectoryNotFound {
        path: PathBuf,
    },
    PermissionDenied {
        path: PathBuf,
        operation: String,
    },
    IoError {
        path: Option<PathBuf>,
        operation: String,
        source: io::Error,
    },

    /// Hash computation errors
    UnsupportedAlgorithm {
        algorithm: String,
    },
    HashComputationFailed {
        path: PathBuf,
        algorithm: String,
        reason: String,
    },

    /// Database errors
    DatabaseNotFound {
        path: PathBuf,
    },
    DatabaseParseError {
        path: PathBuf,
        line: usize,
        reason: String,
    },
    DatabaseWriteError {
        path: PathBuf,
        reason: String,
    },
    EmptyDatabase {
        path: PathBuf,
    },

    /// Verification errors
    VerificationFailed {
        reason: String,
    },

    /// CLI errors
    InvalidArguments {
        message: String,
    },
    MissingRequiredArgument {
        argument: String,
    },

    /// Benchmark errors
    BenchmarkFailed {
        algorithm: String,
        reason: String,
    },
}

impl fmt::Display for HashUtilityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // File system errors
            HashUtilityError::FileNotFound { path } => {
                write!(f, "File not found: {}\n", path.display())?;
                write!(
                    f,
                    "Suggestion: Check that the file path is correct and the file exists"
                )
            }
            HashUtilityError::DirectoryNotFound { path } => {
                write!(f, "Directory not found: {}\n", path.display())?;
                write!(
                    f,
                    "Suggestion: Check that the directory path is correct and the directory exists"
                )
            }
            HashUtilityError::PermissionDenied { path, operation } => {
                write!(
                    f,
                    "Permission denied while {} file: {}\n",
                    operation,
                    path.display()
                )?;
                write!(
                    f,
                    "Suggestion: Check file permissions or run with appropriate privileges"
                )
            }
            HashUtilityError::IoError {
                path,
                operation,
                source,
            } => {
                if let Some(p) = path {
                    write!(
                        f,
                        "I/O error while {} file {}: {}\n",
                        operation,
                        p.display(),
                        source
                    )?;
                } else {
                    write!(f, "I/O error while {}: {}\n", operation, source)?;
                }
                write!(f, "Suggestion: Check file permissions and disk space")
            }

            // Hash computation errors
            HashUtilityError::UnsupportedAlgorithm { algorithm } => {
                write!(f, "Unsupported hash algorithm: {}\n", algorithm)?;
                write!(f, "Suggestion: Use --list to see available algorithms")
            }
            HashUtilityError::HashComputationFailed {
                path,
                algorithm,
                reason,
            } => {
                write!(
                    f,
                    "Failed to compute {} hash for {}: {}\n",
                    algorithm,
                    path.display(),
                    reason
                )?;
                write!(
                    f,
                    "Suggestion: Check that the file is readable and not corrupted"
                )
            }

            // Database errors
            HashUtilityError::DatabaseNotFound { path } => {
                write!(f, "Hash database file not found: {}\n", path.display())?;
                write!(
                    f,
                    "Suggestion: Create a database first using the 'scan' command"
                )
            }
            HashUtilityError::DatabaseParseError { path, line, reason } => {
                write!(
                    f,
                    "Error parsing database {} at line {}: {}\n",
                    path.display(),
                    line,
                    reason
                )?;
                write!(
                    f,
                    "Suggestion: Check that the database file format is correct (hash  filepath)"
                )
            }
            HashUtilityError::DatabaseWriteError { path, reason } => {
                write!(
                    f,
                    "Failed to write to database {}: {}\n",
                    path.display(),
                    reason
                )?;
                write!(f, "Suggestion: Check disk space and write permissions")
            }
            HashUtilityError::EmptyDatabase { path } => {
                write!(f, "Database file is empty: {}\n", path.display())?;
                write!(
                    f,
                    "Suggestion: Ensure the database contains at least one hash entry"
                )
            }

            // Verification errors
            HashUtilityError::VerificationFailed { reason } => {
                write!(f, "Verification failed: {}\n", reason)?;
                write!(
                    f,
                    "Suggestion: Check that the database and directory paths are correct"
                )
            }

            // CLI errors
            HashUtilityError::InvalidArguments { message } => {
                write!(f, "Invalid arguments: {}\n", message)?;
                write!(f, "Suggestion: Run with --help to see usage information")
            }
            HashUtilityError::MissingRequiredArgument { argument } => {
                write!(f, "Missing required argument: {}\n", argument)?;
                write!(f, "Suggestion: Run with --help to see required arguments")
            }

            // Benchmark errors
            HashUtilityError::BenchmarkFailed { algorithm, reason } => {
                write!(f, "Benchmark failed for {}: {}\n", algorithm, reason)?;
                write!(
                    f,
                    "Suggestion: Try running the benchmark again or with a smaller data size"
                )
            }
        }
    }
}

impl std::error::Error for HashUtilityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HashUtilityError::IoError { source, .. } => Some(source),
            _ => None,
        }
    }
}

// Conversion from io::Error with context
impl HashUtilityError {
    /// Create an IoError with context about the operation and optional path
    pub fn from_io_error(err: io::Error, operation: &str, path: Option<PathBuf>) -> Self {
        // Check for specific error kinds and provide more specific errors
        match err.kind() {
            io::ErrorKind::NotFound => {
                if let Some(p) = path {
                    if operation.contains("directory") || operation.contains("scan") {
                        HashUtilityError::DirectoryNotFound { path: p }
                    } else {
                        HashUtilityError::FileNotFound { path: p }
                    }
                } else {
                    HashUtilityError::IoError {
                        path: None,
                        operation: operation.to_string(),
                        source: err,
                    }
                }
            }
            io::ErrorKind::PermissionDenied => {
                if let Some(p) = path {
                    HashUtilityError::PermissionDenied {
                        path: p,
                        operation: operation.to_string(),
                    }
                } else {
                    HashUtilityError::IoError {
                        path: None,
                        operation: operation.to_string(),
                        source: err,
                    }
                }
            }
            _ => HashUtilityError::IoError {
                path,
                operation: operation.to_string(),
                source: err,
            },
        }
    }
}

// Default From implementation for io::Error (without context)
impl From<io::Error> for HashUtilityError {
    fn from(err: io::Error) -> Self {
        HashUtilityError::from_io_error(err, "unknown operation", None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_file_not_found_error_display() {
        let error = HashUtilityError::FileNotFound {
            path: PathBuf::from("/path/to/file.txt"),
        };
        let message = format!("{}", error);
        assert!(message.contains("File not found"));
        assert!(message.contains("/path/to/file.txt"));
        assert!(message.contains("Suggestion"));
    }

    #[test]
    fn test_unsupported_algorithm_error_display() {
        let error = HashUtilityError::UnsupportedAlgorithm {
            algorithm: "invalid-algo".to_string(),
        };
        let message = format!("{}", error);
        assert!(message.contains("Unsupported hash algorithm"));
        assert!(message.contains("invalid-algo"));
        assert!(message.contains("--list"));
    }

    #[test]
    fn test_database_not_found_error_display() {
        let error = HashUtilityError::DatabaseNotFound {
            path: PathBuf::from("hashes.txt"),
        };
        let message = format!("{}", error);
        assert!(message.contains("Hash database file not found"));
        assert!(message.contains("hashes.txt"));
        assert!(message.contains("scan"));
    }

    #[test]
    fn test_permission_denied_error_display() {
        let error = HashUtilityError::PermissionDenied {
            path: PathBuf::from("/protected/file.txt"),
            operation: "reading".to_string(),
        };
        let message = format!("{}", error);
        assert!(message.contains("Permission denied"));
        assert!(message.contains("reading"));
        assert!(message.contains("/protected/file.txt"));
    }

    #[test]
    fn test_io_error_with_path() {
        let io_err = io::Error::new(io::ErrorKind::Other, "disk full");
        let error = HashUtilityError::IoError {
            path: Some(PathBuf::from("output.txt")),
            operation: "writing".to_string(),
            source: io_err,
        };
        let message = format!("{}", error);
        assert!(message.contains("I/O error"));
        assert!(message.contains("writing"));
        assert!(message.contains("output.txt"));
    }

    #[test]
    fn test_io_error_without_path() {
        let io_err = io::Error::new(io::ErrorKind::Other, "unknown error");
        let error = HashUtilityError::IoError {
            path: None,
            operation: "processing".to_string(),
            source: io_err,
        };
        let message = format!("{}", error);
        assert!(message.contains("I/O error"));
        assert!(message.contains("processing"));
        // The message should not contain "file" followed by a path
        assert!(!message.contains("file /"));
        assert!(!message.contains("file:"));
    }

    #[test]
    fn test_from_io_error_not_found_file() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let error =
            HashUtilityError::from_io_error(io_err, "reading", Some(PathBuf::from("test.txt")));

        match error {
            HashUtilityError::FileNotFound { path } => {
                assert_eq!(path, PathBuf::from("test.txt"));
            }
            _ => panic!("Expected FileNotFound error"),
        }
    }

    #[test]
    fn test_from_io_error_not_found_directory() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "directory not found");
        let error = HashUtilityError::from_io_error(
            io_err,
            "scanning directory",
            Some(PathBuf::from("/test/dir")),
        );

        match error {
            HashUtilityError::DirectoryNotFound { path } => {
                assert_eq!(path, PathBuf::from("/test/dir"));
            }
            _ => panic!("Expected DirectoryNotFound error"),
        }
    }

    #[test]
    fn test_from_io_error_permission_denied() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let error = HashUtilityError::from_io_error(
            io_err,
            "writing",
            Some(PathBuf::from("protected.txt")),
        );

        match error {
            HashUtilityError::PermissionDenied { path, operation } => {
                assert_eq!(path, PathBuf::from("protected.txt"));
                assert_eq!(operation, "writing");
            }
            _ => panic!("Expected PermissionDenied error"),
        }
    }

    #[test]
    fn test_database_parse_error_display() {
        let error = HashUtilityError::DatabaseParseError {
            path: PathBuf::from("db.txt"),
            line: 42,
            reason: "invalid format".to_string(),
        };
        let message = format!("{}", error);
        assert!(message.contains("Error parsing database"));
        assert!(message.contains("db.txt"));
        assert!(message.contains("42"));
        assert!(message.contains("invalid format"));
    }

    #[test]
    fn test_hash_computation_failed_display() {
        let error = HashUtilityError::HashComputationFailed {
            path: PathBuf::from("data.bin"),
            algorithm: "SHA-256".to_string(),
            reason: "corrupted data".to_string(),
        };
        let message = format!("{}", error);
        assert!(message.contains("Failed to compute"));
        assert!(message.contains("SHA-256"));
        assert!(message.contains("data.bin"));
        assert!(message.contains("corrupted data"));
    }

    #[test]
    fn test_error_source() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test error");
        let error = HashUtilityError::IoError {
            path: None,
            operation: "test".to_string(),
            source: io_err,
        };

        assert!(error.source().is_some());
    }

    #[test]
    fn test_error_source_none() {
        let error = HashUtilityError::FileNotFound {
            path: PathBuf::from("test.txt"),
        };

        assert!(error.source().is_none());
    }
}
