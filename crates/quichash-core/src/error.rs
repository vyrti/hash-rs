//! Error handling for the reusable QuicHash core.
// Provides comprehensive error types with context for all operations

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Main error type for the hash utility
/// Provides context-rich error messages with file paths and operations
#[derive(Debug)]
pub enum HashUtilityError {
    /// A required file does not exist.
    FileNotFound {
        /// Missing file path.
        path: PathBuf,
    },
    /// A required directory does not exist.
    DirectoryNotFound {
        /// Missing directory path.
        path: PathBuf,
    },
    /// The process lacks permission for a filesystem operation.
    PermissionDenied {
        /// Path that could not be accessed.
        path: PathBuf,
        /// Operation attempted on the path.
        operation: String,
    },
    /// Other input/output failure with operation context.
    IoError {
        /// Related path, when one is available.
        path: Option<PathBuf>,
        /// Operation being performed when the error occurred.
        operation: String,
        /// Original I/O error.
        source: io::Error,
    },

    /// A string does not identify a supported algorithm.
    UnsupportedAlgorithm {
        /// Unrecognized algorithm name.
        algorithm: String,
    },
    /// A known algorithm was disabled at compile time.
    AlgorithmUnavailable {
        /// Canonical algorithm name.
        algorithm: String,
        /// Cargo feature required to enable the algorithm.
        feature: &'static str,
    },
    /// Digest text or bytes have an invalid value or length.
    InvalidDigest {
        /// Algorithm whose digest was being decoded.
        algorithm: String,
        /// Validation failure description.
        reason: String,
    },
    /// A file could not be hashed.
    HashComputationFailed {
        /// File being hashed.
        path: PathBuf,
        /// Requested algorithm.
        algorithm: String,
        /// Underlying failure description.
        reason: String,
    },

    /// Cooperative cancellation requested by an embedding application.
    Cancelled,

    /// A requested manifest database does not exist.
    DatabaseNotFound {
        /// Missing database path.
        path: PathBuf,
    },
    /// A manifest line could not be parsed.
    DatabaseParseError {
        /// Manifest path.
        path: PathBuf,
        /// One-based line number.
        line: usize,
        /// Parsing failure description.
        reason: String,
    },
    /// A manifest could not be written.
    DatabaseWriteError {
        /// Destination path.
        path: PathBuf,
        /// Write failure description.
        reason: String,
    },
    /// A manifest contained no usable entries.
    EmptyDatabase {
        /// Empty manifest path.
        path: PathBuf,
    },

    /// Verification could not be completed.
    VerificationFailed {
        /// Failure description.
        reason: String,
    },

    /// An operation received an invalid combination of arguments.
    InvalidArguments {
        /// Argument validation message.
        message: String,
    },
    /// A compatibility operation did not receive a required argument.
    MissingRequiredArgument {
        /// Name of the missing argument.
        argument: String,
    },

    /// An algorithm benchmark failed.
    BenchmarkFailed {
        /// Algorithm being measured.
        algorithm: String,
        /// Benchmark failure description.
        reason: String,
    },
}

impl fmt::Display for HashUtilityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // File system errors
            HashUtilityError::FileNotFound { path } => {
                writeln!(f, "File not found: {}", path.display())?;
                write!(
                    f,
                    "Suggestion: Check that the file path is correct and the file exists"
                )
            }
            HashUtilityError::DirectoryNotFound { path } => {
                writeln!(f, "Directory not found: {}", path.display())?;
                write!(
                    f,
                    "Suggestion: Check that the directory path is correct and the directory exists"
                )
            }
            HashUtilityError::PermissionDenied { path, operation } => {
                writeln!(
                    f,
                    "Permission denied while {} file: {}",
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
                    writeln!(
                        f,
                        "I/O error while {} file {}: {}",
                        operation,
                        p.display(),
                        source
                    )?;
                } else {
                    writeln!(f, "I/O error while {}: {}", operation, source)?;
                }
                write!(f, "Suggestion: Check file permissions and disk space")
            }

            // Hash computation errors
            HashUtilityError::UnsupportedAlgorithm { algorithm } => {
                writeln!(f, "Unsupported hash algorithm: {}", algorithm)?;
                write!(f, "Suggestion: Use --list to see available algorithms")
            }
            HashUtilityError::AlgorithmUnavailable { algorithm, feature } => {
                writeln!(f, "Hash algorithm '{}' is not compiled in", algorithm)?;
                write!(f, "Suggestion: Enable the '{}' Cargo feature", feature)
            }
            HashUtilityError::InvalidDigest { algorithm, reason } => {
                write!(f, "Invalid {} digest: {}", algorithm, reason)
            }
            HashUtilityError::HashComputationFailed {
                path,
                algorithm,
                reason,
            } => {
                writeln!(
                    f,
                    "Failed to compute {} hash for {}: {}",
                    algorithm,
                    path.display(),
                    reason
                )?;
                write!(
                    f,
                    "Suggestion: Check that the file is readable and not corrupted"
                )
            }
            HashUtilityError::Cancelled => write!(f, "Operation cancelled"),

            // Database errors
            HashUtilityError::DatabaseNotFound { path } => {
                writeln!(f, "Hash database file not found: {}", path.display())?;
                write!(
                    f,
                    "Suggestion: Create a database first using the 'scan' command"
                )
            }
            HashUtilityError::DatabaseParseError { path, line, reason } => {
                writeln!(
                    f,
                    "Error parsing database {} at line {}: {}",
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
                writeln!(
                    f,
                    "Failed to write to database {}: {}",
                    path.display(),
                    reason
                )?;
                write!(f, "Suggestion: Check disk space and write permissions")
            }
            HashUtilityError::EmptyDatabase { path } => {
                writeln!(f, "Database file is empty: {}", path.display())?;
                write!(
                    f,
                    "Suggestion: Ensure the database contains at least one hash entry"
                )
            }

            // Verification errors
            HashUtilityError::VerificationFailed { reason } => {
                writeln!(f, "Verification failed: {}", reason)?;
                write!(
                    f,
                    "Suggestion: Check that the database and directory paths are correct"
                )
            }

            // CLI errors
            HashUtilityError::InvalidArguments { message } => {
                writeln!(f, "Invalid arguments: {}", message)?;
                write!(f, "Suggestion: Run with --help to see usage information")
            }
            HashUtilityError::MissingRequiredArgument { argument } => {
                writeln!(f, "Missing required argument: {}", argument)?;
                write!(f, "Suggestion: Run with --help to see required arguments")
            }

            // Benchmark errors
            HashUtilityError::BenchmarkFailed { algorithm, reason } => {
                writeln!(f, "Benchmark failed for {}: {}", algorithm, reason)?;
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
    /// Convert an [`io::Error`] while retaining operation and path context.
    ///
    /// `NotFound` and `PermissionDenied` errors are promoted to their more
    /// specific variants when a path is supplied.
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
