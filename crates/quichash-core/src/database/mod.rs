//! QuicHash and hashdeep manifest formats.
// Reads and writes plain text hash database files

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::HashUtilityError;
use crate::hash::Algorithm;
use crate::manifest::Manifest;
use crate::operation::FailurePolicy;

pub(crate) mod checksum;
pub(crate) mod compression;
pub(crate) mod hashdeep;
pub(crate) mod manifest_io;
pub(crate) mod quichash;

pub(crate) use hashdeep::HashdeepRecord;

/// Database entry with metadata
#[derive(Debug, Clone)]
pub struct DatabaseEntry {
    /// Lowercase hexadecimal digest.
    pub hash: String,
    /// Algorithm name recorded in the row.
    pub algorithm: String,
    /// Whether the digest was created with sampled hashing.
    pub fast_mode: bool,
}

/// Database format type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DatabaseFormat {
    /// QuicHash format: hash  algorithm  fast_mode  filepath
    Quichash,
    /// Hashdeep format: size,hash1,hash2,...,filename
    Hashdeep,
}

/// Malformed input line retained while reading with a continue policy.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DatabaseIssue {
    /// One-based source line number.
    pub line: usize,
    /// Explanation of why the line could not be parsed.
    pub message: String,
}

/// Typed manifest and non-fatal parsing issues returned together.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ManifestRead {
    /// Successfully parsed and canonicalized manifest entries.
    pub manifest: Manifest,
    /// Malformed lines skipped under [`FailurePolicy::Continue`].
    pub issues: Vec<DatabaseIssue>,
}

/// Handler for reading and writing hash database files
pub struct DatabaseHandler;

impl DatabaseHandler {
    /// Infer a checksum algorithm from a path's file extension.
    pub fn checksum_algorithm_from_path(path: &Path) -> Option<Algorithm> {
        checksum::checksum_algorithm_from_path(path)
    }

    /// Check if a path corresponds to a supported checksum format for verification.
    pub fn verification_checksum_algorithm(
        path: &Path,
    ) -> Result<Option<Algorithm>, HashUtilityError> {
        checksum::verification_checksum_algorithm(path)
    }

    /// Read a conventional two-column checksum file for verification.
    pub fn read_checksum_manifest(path: &Path) -> Result<Manifest, HashUtilityError> {
        checksum::read_checksum_manifest(path)
    }

    /// Return the canonical output path for a database.
    pub fn canonical_output_path(
        requested_path: &Path,
        format: DatabaseFormat,
        compressed: bool,
    ) -> Result<PathBuf, HashUtilityError> {
        compression::canonical_output_path(requested_path, format, compressed)
    }

    /// Write a manifest to its canonical database path.
    pub fn write_manifest_file(
        requested_path: &Path,
        manifest: &Manifest,
        format: DatabaseFormat,
        compressed: bool,
    ) -> Result<PathBuf, HashUtilityError> {
        manifest_io::write_manifest_file(requested_path, manifest, format, compressed)
    }

    /// Check if a path has .zst or .zstd extension (compressed database)
    pub fn is_compressed(path: &Path) -> bool {
        compression::is_compressed(path)
    }

    /// Compress a database file with Zstandard.
    pub fn compress_database(input_path: &Path) -> Result<PathBuf, HashUtilityError> {
        compression::compress_database(input_path)
    }

    /// Detect the format of a database file by reading its first few lines
    pub fn detect_format(path: &Path) -> Result<DatabaseFormat, HashUtilityError> {
        manifest_io::detect_format(path)
    }

    /// Write a single hash entry to the output writer
    pub fn write_entry(
        writer: &mut impl Write,
        hash: &str,
        algorithm: &str,
        fast_mode: bool,
        path: &Path,
    ) -> std::io::Result<()> {
        quichash::write_entry(writer, hash, algorithm, fast_mode, path)
    }

    /// Write hashdeep format header
    pub fn write_hashdeep_header(
        writer: &mut impl Write,
        algorithms: &[String],
    ) -> std::io::Result<()> {
        hashdeep::write_hashdeep_header(writer, algorithms)
    }

    /// Write a single entry in hashdeep format
    pub fn write_hashdeep_entry(
        writer: &mut impl Write,
        size: u64,
        hashes: &[String],
        path: &Path,
    ) -> std::io::Result<()> {
        hashdeep::write_hashdeep_entry(writer, size, hashes, path)
    }

    /// Read a hash database file and parse it into a HashMap
    pub fn read_database(path: &Path) -> Result<HashMap<PathBuf, DatabaseEntry>, HashUtilityError> {
        manifest_io::read_database(path)
    }

    /// Read every digest from a QuicHash or hashdeep manifest.
    pub fn read_manifest(path: &Path) -> Result<Manifest, HashUtilityError> {
        manifest_io::read_manifest(path)
    }

    /// Read a typed manifest, optionally retaining malformed-line issues.
    pub fn read_manifest_with_policy(
        path: &Path,
        failure_policy: FailurePolicy,
    ) -> Result<ManifestRead, HashUtilityError> {
        manifest_io::read_manifest_with_policy(path, failure_policy)
    }

    /// Write every manifest digest in QuicHash or hashdeep format.
    pub fn write_manifest(
        writer: &mut impl Write,
        manifest: &Manifest,
        format: DatabaseFormat,
    ) -> std::io::Result<()> {
        manifest_io::write_manifest(writer, manifest, format)
    }

    /// Parse a single line from a QuicHash database file.
    pub fn parse_line(line: &str) -> Option<(String, String, bool, PathBuf)> {
        quichash::parse_line(line)
    }

    /// Parse a single line from a hashdeep database file.
    pub fn parse_hashdeep_line(
        line: &str,
        algorithms: &[String],
    ) -> Option<Vec<(PathBuf, DatabaseEntry)>> {
        hashdeep::parse_hashdeep_line(line, algorithms)
    }

    pub(crate) fn parse_hashdeep_record(
        line: &str,
        expected_hash_count: Option<usize>,
    ) -> Option<HashdeepRecord> {
        hashdeep::parse_hashdeep_record(line, expected_hash_count)
    }
}
