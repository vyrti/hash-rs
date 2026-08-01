//! Standard and hashdeep manifest formats.
// Reads and writes plain text hash database files

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "xz")]
use xz2::read::XzDecoder;
#[cfg(feature = "xz")]
use xz2::write::XzEncoder;

use crate::error::HashUtilityError;
use crate::hash::{Algorithm, DigestValue, HashMode};
use crate::manifest::{Manifest, ManifestEntry};
use crate::operation::FailurePolicy;
use crate::path_utils;

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
    /// Standard format: hash  algorithm  fast_mode  filepath
    Standard,
    /// Hashdeep format: size,hash1,hash2,...,filename
    Hashdeep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HashdeepRecord {
    pub(crate) size: u64,
    pub(crate) hashes: Vec<String>,
    pub(crate) filename: String,
}

/// Handler for reading and writing hash database files
pub struct DatabaseHandler;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
/// Malformed input line retained while reading with a continue policy.
pub struct DatabaseIssue {
    /// One-based source line number.
    pub line: usize,
    /// Explanation of why the line could not be parsed.
    pub message: String,
}

#[derive(Clone, Debug, serde::Serialize)]
/// Typed manifest and non-fatal parsing issues returned together.
pub struct ManifestRead {
    /// Successfully parsed and canonicalized manifest entries.
    pub manifest: Manifest,
    /// Malformed lines skipped under [`FailurePolicy::Continue`].
    pub issues: Vec<DatabaseIssue>,
}

impl DatabaseHandler {
    /// Check if a path has .xz extension (compressed database)
    pub fn is_compressed(path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext == "xz")
            .unwrap_or(false)
    }

    /// Compress a database file with LZMA.
    ///
    /// Creates a sibling path with an `.xz` suffix and returns that path. When
    /// the `xz` feature is disabled, this returns an explanatory error.
    #[cfg(feature = "xz")]
    pub fn compress_database(input_path: &Path) -> Result<PathBuf, HashUtilityError> {
        // Read the input file
        let input_file = File::open(input_path).map_err(|e| {
            HashUtilityError::from_io_error(
                e,
                "opening database for compression",
                Some(input_path.to_path_buf()),
            )
        })?;

        // Create output path with .xz extension
        let output_path = input_path.with_extension(format!(
            "{}.xz",
            input_path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("txt")
        ));

        // Create compressed output file
        let output_file = File::create(&output_path).map_err(|e| {
            HashUtilityError::from_io_error(
                e,
                "creating compressed database",
                Some(output_path.clone()),
            )
        })?;

        // Create LZMA encoder with compression level 6 (good balance of speed and compression)
        let mut encoder = XzEncoder::new(output_file, 6);

        // Copy data through the encoder
        let mut reader = BufReader::new(input_file);
        std::io::copy(&mut reader, &mut encoder).map_err(|e| {
            HashUtilityError::from_io_error(
                e,
                "compressing database",
                Some(input_path.to_path_buf()),
            )
        })?;

        // Finish compression
        encoder.finish().map_err(|e| {
            HashUtilityError::from_io_error(e, "finalizing compression", Some(output_path.clone()))
        })?;

        Ok(output_path)
    }

    #[cfg(not(feature = "xz"))]
    /// Return an error explaining that XZ support was compiled out.
    pub fn compress_database(input_path: &Path) -> Result<PathBuf, HashUtilityError> {
        Err(HashUtilityError::InvalidArguments {
            message: format!(
                "XZ compression for '{}' requires the 'xz' Cargo feature",
                input_path.display()
            ),
        })
    }

    /// Open a database file, automatically decompressing if it has .xz extension
    fn open_database_reader(path: &Path) -> Result<Box<dyn BufRead>, HashUtilityError> {
        let file = File::open(path).map_err(|e| {
            HashUtilityError::from_io_error(e, "opening database", Some(path.to_path_buf()))
        })?;

        if Self::is_compressed(path) {
            #[cfg(feature = "xz")]
            {
                let decoder = XzDecoder::new(file);
                Ok(Box::new(BufReader::new(decoder)))
            }
            #[cfg(not(feature = "xz"))]
            {
                let _ = file;
                Err(HashUtilityError::InvalidArguments {
                    message: format!(
                        "reading '{}' requires the 'xz' Cargo feature",
                        path.display()
                    ),
                })
            }
        } else {
            // Read normally
            Ok(Box::new(BufReader::new(file)))
        }
    }

    /// Detect the format of a database file by reading its first few lines
    pub fn detect_format(path: &Path) -> Result<DatabaseFormat, HashUtilityError> {
        let reader = Self::open_database_reader(path)?;

        for line_result in reader.lines().take(10) {
            let line = line_result.map_err(|e| {
                HashUtilityError::from_io_error(e, "reading database", Some(path.to_path_buf()))
            })?;

            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }

            // Check for hashdeep header (starts with %)
            if trimmed.starts_with('%') {
                return Ok(DatabaseFormat::Hashdeep);
            }

            // Prefer a valid standard row so a comma in its filename does not
            // incorrectly select the hashdeep parser.
            if Self::parse_line(trimmed).is_some() {
                return Ok(DatabaseFormat::Standard);
            }

            if Self::parse_hashdeep_record(trimmed, None).is_some() {
                return Ok(DatabaseFormat::Hashdeep);
            }

            if trimmed.contains("  ") {
                return Ok(DatabaseFormat::Standard);
            }
        }

        // Default to standard format if we can't determine
        Ok(DatabaseFormat::Standard)
    }
    /// Write a single hash entry to the output writer
    /// Format: `<hash>  <algorithm>  <fast_mode>  <filepath>` (two spaces between fields)
    pub fn write_entry(
        writer: &mut impl Write,
        hash: &str,
        algorithm: &str,
        fast_mode: bool,
        path: &Path,
    ) -> io::Result<()> {
        let fast_str = if fast_mode { "fast" } else { "normal" };
        writeln!(
            writer,
            "{}  {}  {}  {}",
            hash,
            algorithm,
            fast_str,
            path.display()
        )
    }

    /// Write hashdeep format header
    /// Includes metadata and column definitions
    pub fn write_hashdeep_header(writer: &mut impl Write, algorithms: &[String]) -> io::Result<()> {
        writeln!(writer, "%%%% HASHDEEP-1.0")?;
        writeln!(writer, "%%%% size,{},filename", algorithms.join(","))?;
        writeln!(writer, "## Invoked from: hash utility")?;
        writeln!(writer, "## $ hash scan --format hashdeep")?;
        writeln!(writer, "##")?;
        Ok(())
    }

    /// Write a single entry in hashdeep format
    /// Format: size,hash1,hash2,...,filename
    pub fn write_hashdeep_entry(
        writer: &mut impl Write,
        size: u64,
        hashes: &[String],
        path: &Path,
    ) -> io::Result<()> {
        write!(writer, "{}", size)?;
        for hash in hashes {
            write!(writer, ",{}", hash)?;
        }
        writeln!(writer, ",{}", path.display())
    }

    /// Read a hash database file and parse it into a HashMap
    /// Maps file paths to their database entries (hash, algorithm, fast_mode)
    /// Malformed lines are skipped with a warning to stderr
    /// Auto-detects format (standard or hashdeep)
    pub fn read_database(path: &Path) -> Result<HashMap<PathBuf, DatabaseEntry>, HashUtilityError> {
        let format = Self::detect_format(path)?;

        match format {
            DatabaseFormat::Standard => Self::read_standard_database(path),
            DatabaseFormat::Hashdeep => Self::read_hashdeep_database(path),
        }
    }

    /// Read every digest from a standard or hashdeep manifest.
    ///
    /// Format is detected automatically. This method is fail-fast; use
    /// [`Self::read_manifest_with_policy`] to retain malformed-line issues.
    pub fn read_manifest(path: &Path) -> Result<Manifest, HashUtilityError> {
        Ok(Self::read_manifest_with_policy(path, FailurePolicy::FailFast)?.manifest)
    }

    /// Read a typed manifest, optionally retaining malformed-line issues.
    ///
    /// Standard rows for the same path are merged, and every declared hashdeep
    /// digest column is retained. The returned manifest is canonicalized.
    pub fn read_manifest_with_policy(
        path: &Path,
        failure_policy: FailurePolicy,
    ) -> Result<ManifestRead, HashUtilityError> {
        use std::collections::BTreeMap;

        let format = Self::detect_format(path)?;
        let reader = Self::open_database_reader(path)?;
        let mut entries: BTreeMap<PathBuf, ManifestEntry> = BTreeMap::new();
        let mut issues = Vec::new();
        let mut hashdeep_algorithms = Vec::new();
        for (index, line_result) in reader.lines().enumerate() {
            let line_number = index + 1;
            let line = line_result.map_err(|error| {
                HashUtilityError::from_io_error(error, "reading database", Some(path.to_owned()))
            })?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("##") {
                continue;
            }
            if format == DatabaseFormat::Hashdeep && trimmed.starts_with("%%%%") {
                if let Some(fields) = trimmed.split_whitespace().find(|field| field.contains(',')) {
                    let columns: Vec<_> = fields.split(',').collect();
                    if columns.len() >= 3
                        && columns[0] == "size"
                        && columns.last() == Some(&"filename")
                    {
                        hashdeep_algorithms = columns[1..columns.len() - 1]
                            .iter()
                            .map(|name| name.parse::<Algorithm>())
                            .collect::<Result<Vec<_>, _>>()?;
                    }
                }
                continue;
            }
            if trimmed.starts_with('%') || trimmed.starts_with('#') {
                continue;
            }
            let parsed = match format {
                DatabaseFormat::Standard => Self::parse_manifest_standard(&line),
                DatabaseFormat::Hashdeep => {
                    Self::parse_manifest_hashdeep(&line, &hashdeep_algorithms)
                }
            };
            match parsed {
                Ok((path, size, mode, digests)) => {
                    let entry = entries
                        .entry(path.clone())
                        .or_insert_with(|| ManifestEntry {
                            relative_path: path,
                            size,
                            mode,
                            digests: Vec::new(),
                        });
                    if entry.size == 0 {
                        entry.size = size;
                    }
                    for digest in digests {
                        if let Some(existing) = entry
                            .digests
                            .iter_mut()
                            .find(|item| item.algorithm == digest.algorithm)
                        {
                            *existing = digest;
                        } else {
                            entry.digests.push(digest);
                        }
                    }
                }
                Err(reason) if failure_policy == FailurePolicy::Continue => {
                    issues.push(DatabaseIssue {
                        line: line_number,
                        message: reason,
                    });
                }
                Err(reason) => {
                    return Err(HashUtilityError::DatabaseParseError {
                        path: path.to_owned(),
                        line: line_number,
                        reason,
                    });
                }
            }
        }
        let mut manifest = Manifest {
            entries: entries.into_values().collect(),
        };
        manifest.canonicalize();
        Ok(ManifestRead { manifest, issues })
    }

    /// Write every manifest digest in standard or hashdeep format.
    ///
    /// Standard output contains one row per digest. Hashdeep output contains
    /// one row per file and a column for every algorithm present in the
    /// manifest.
    pub fn write_manifest(
        writer: &mut impl Write,
        manifest: &Manifest,
        format: DatabaseFormat,
    ) -> io::Result<()> {
        let mut manifest = manifest.clone();
        manifest.canonicalize();
        match format {
            DatabaseFormat::Standard => {
                for entry in &manifest.entries {
                    for digest in &entry.digests {
                        Self::write_entry(
                            writer,
                            &digest.to_hex(),
                            digest.algorithm.canonical_name(),
                            entry.mode == HashMode::Sampled,
                            &entry.relative_path,
                        )?;
                    }
                }
            }
            DatabaseFormat::Hashdeep => {
                let mut algorithms: Vec<_> = manifest
                    .entries
                    .iter()
                    .flat_map(|entry| entry.digests.iter().map(|digest| digest.algorithm))
                    .collect();
                algorithms.sort();
                algorithms.dedup();
                let names: Vec<_> = algorithms
                    .iter()
                    .map(|algorithm| algorithm.canonical_name().to_owned())
                    .collect();
                Self::write_hashdeep_header(writer, &names)?;
                for entry in &manifest.entries {
                    let hashes: Vec<_> = algorithms
                        .iter()
                        .map(|algorithm| {
                            entry
                                .digests
                                .iter()
                                .find(|digest| digest.algorithm == *algorithm)
                                .map(DigestValue::to_hex)
                                .unwrap_or_default()
                        })
                        .collect();
                    Self::write_hashdeep_entry(writer, entry.size, &hashes, &entry.relative_path)?;
                }
            }
        }
        Ok(())
    }

    fn parse_manifest_standard(
        line: &str,
    ) -> Result<(PathBuf, u64, HashMode, Vec<DigestValue>), String> {
        let (hash, algorithm, fast, path) = Self::parse_line(line)
            .ok_or_else(|| "expected '<hash>  <algorithm>  <mode>  <path>'".to_owned())?;
        let algorithm = algorithm
            .parse::<Algorithm>()
            .map_err(|error| error.to_string())?;
        let digest = DigestValue::from_hex(algorithm, &hash).map_err(|error| error.to_string())?;
        Ok((
            path,
            0,
            if fast {
                HashMode::Sampled
            } else {
                HashMode::Full
            },
            vec![digest],
        ))
    }

    fn parse_manifest_hashdeep(
        line: &str,
        declared_algorithms: &[Algorithm],
    ) -> Result<(PathBuf, u64, HashMode, Vec<DigestValue>), String> {
        let expected_hash_count =
            (!declared_algorithms.is_empty()).then_some(declared_algorithms.len());
        let record = Self::parse_hashdeep_record(line, expected_hash_count)
            .ok_or_else(|| "expected 'size,hash...,filename'".to_owned())?;
        let path = path_utils::parse_database_path(&record.filename);
        let hashes = record.hashes;
        let algorithms = if declared_algorithms.len() == hashes.len() {
            declared_algorithms.to_vec()
        } else {
            hashes
                .iter()
                .map(|hash| {
                    Self::infer_algorithm_from_hash(hash)
                        .parse::<Algorithm>()
                        .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let digests = algorithms
            .into_iter()
            .zip(&hashes)
            .filter_map(|(algorithm, hash)| {
                (!hash.is_empty()).then_some(
                    DigestValue::from_hex(algorithm, hash).map_err(|error| error.to_string()),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        if digests.is_empty() {
            return Err("row contains no hashes".to_owned());
        }
        Ok((path, record.size, HashMode::Full, digests))
    }

    /// Read a standard format database file
    fn read_standard_database(
        path: &Path,
    ) -> Result<HashMap<PathBuf, DatabaseEntry>, HashUtilityError> {
        let reader = Self::open_database_reader(path)?;
        let mut database = HashMap::new();

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(|e| {
                HashUtilityError::from_io_error(e, "reading database", Some(path.to_path_buf()))
            })?;

            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            // Parse line: split on two spaces
            match Self::parse_line(&line) {
                Some((hash, algorithm, fast_mode, file_path)) => {
                    database.insert(
                        file_path,
                        DatabaseEntry {
                            hash,
                            algorithm,
                            fast_mode,
                        },
                    );
                }
                None => {
                    // Warn about malformed line but continue processing (Requirement 2.4)
                    eprintln!(
                        "Warning: Skipping malformed line {} in database {}: {}",
                        line_num + 1,
                        path.display(),
                        line
                    );
                }
            }
        }

        Ok(database)
    }

    /// Parse a single line from the database file
    /// Expected format: `<hash>  <algorithm>  <fast_mode>  <filepath>` (two spaces between fields)
    /// Returns None if the line is malformed
    /// Handles both forward and backward slashes in paths
    /// Note: Filenames may contain two spaces, so we only split on the first 3 delimiters
    fn parse_line(line: &str) -> Option<(String, String, bool, PathBuf)> {
        // Split on two spaces, but only for the first 3 fields
        // The rest is the filename (which may contain two spaces)
        let parts: Vec<&str> = line.splitn(4, "  ").collect();

        if parts.len() == 4 {
            let hash = parts[0].trim();
            let algorithm = parts[1].trim();
            let fast_mode_str = parts[2].trim();
            let path_str = parts[3];

            // Parse fast_mode
            let fast_mode = match fast_mode_str {
                "fast" => true,
                "normal" => false,
                _ => return None, // Invalid fast_mode value
            };

            // Validate that all fields are not empty
            if !hash.is_empty() && !algorithm.is_empty() && !path_str.is_empty() {
                // Use path_utils to parse the path with proper separator handling
                let path = path_utils::parse_database_path(path_str);
                return Some((hash.to_string(), algorithm.to_string(), fast_mode, path));
            }
        }

        None
    }

    /// Read a hashdeep format database file
    /// Format: size,hash1,hash2,...,filename
    /// Header lines start with %
    /// Note: For files with multiple hashes, only the first hash is stored
    fn read_hashdeep_database(
        path: &Path,
    ) -> Result<HashMap<PathBuf, DatabaseEntry>, HashUtilityError> {
        let reader = Self::open_database_reader(path)?;
        let mut database = HashMap::new();
        let mut hash_algorithms = Vec::new();

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(|e| {
                HashUtilityError::from_io_error(e, "reading database", Some(path.to_path_buf()))
            })?;

            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }

            // Skip comment lines (## ...) - these are part of the standard hashdeep format
            if trimmed.starts_with('#') {
                continue;
            }

            // Parse header lines
            if trimmed.starts_with('%') {
                // Extract algorithm information from header
                // Format: %%%% HASHDEEP-1.0
                // %%%% size,md5,sha256,filename
                if trimmed.starts_with("%%%%") && trimmed.contains(',') {
                    // Parse the algorithm list from header
                    let header_parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if header_parts.len() >= 2 {
                        let fields = header_parts[1];
                        let field_list: Vec<&str> = fields.split(',').collect();
                        // First field is size, last is filename, middle are hash algorithms
                        if field_list.len() >= 3 {
                            hash_algorithms = field_list[1..field_list.len() - 1]
                                .iter()
                                .map(|s| s.to_string())
                                .collect();
                        }
                    }
                }
                continue;
            }

            // Parse data lines
            match Self::parse_hashdeep_line(&line, &hash_algorithms) {
                Some(entries) => {
                    // Only use the first hash entry for each file
                    // (hashdeep can have multiple hashes per file, but our verify engine expects one)
                    if let Some((file_path, entry)) = entries.into_iter().next() {
                        database.insert(file_path, entry);
                    }
                }
                None => {
                    eprintln!(
                        "Warning: Skipping malformed line {} in hashdeep database {}: {}",
                        line_num + 1,
                        path.display(),
                        trimmed
                    );
                }
            }
        }

        Ok(database)
    }

    /// Parse a single hashdeep format line
    /// Format: size,hash1,hash2,...,filename
    /// Returns multiple entries (one per hash algorithm)
    fn parse_hashdeep_line(
        line: &str,
        algorithms: &[String],
    ) -> Option<Vec<(PathBuf, DatabaseEntry)>> {
        let expected_hash_count = (!algorithms.is_empty()).then_some(algorithms.len());
        let record = Self::parse_hashdeep_record(line, expected_hash_count)?;
        let path = path_utils::parse_database_path(&record.filename);
        let hashes = record.hashes;

        let mut entries = Vec::new();

        // If we have algorithm names from header, use them
        if !algorithms.is_empty() && algorithms.len() == hashes.len() {
            for (i, hash) in hashes.into_iter().enumerate() {
                if !hash.is_empty() {
                    entries.push((
                        path.clone(),
                        DatabaseEntry {
                            hash,
                            algorithm: algorithms[i].clone(),
                            fast_mode: false,
                        },
                    ));
                }
            }
        } else {
            // No header or mismatch - try to infer algorithm from hash length
            for hash in hashes {
                if !hash.is_empty() {
                    let algorithm = Self::infer_algorithm_from_hash(&hash);
                    entries.push((
                        path.clone(),
                        DatabaseEntry {
                            hash,
                            algorithm,
                            fast_mode: false,
                        },
                    ));
                }
            }
        }

        if entries.is_empty() {
            None
        } else {
            Some(entries)
        }
    }

    pub(crate) fn parse_hashdeep_record(
        line: &str,
        expected_hash_count: Option<usize>,
    ) -> Option<HashdeepRecord> {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 3 {
            return None;
        }

        let size = parts[0].trim().parse().ok()?;
        let filename_index = match expected_hash_count {
            Some(hash_count) => {
                let index = 1 + hash_count;
                (parts.len() > index).then_some(index)?
            }
            None => {
                let remainder = &parts[1..];
                let hash_count = remainder
                    .iter()
                    .take_while(|field| Self::is_hashdeep_hash_field(field))
                    .count();
                if hash_count == 0 {
                    return None;
                }
                if hash_count == remainder.len() {
                    parts.len() - 1
                } else {
                    1 + hash_count
                }
            }
        };

        let hashes: Vec<String> = parts[1..filename_index]
            .iter()
            .map(|part| part.trim().to_owned())
            .collect();
        if hashes.is_empty() || hashes.iter().any(String::is_empty) {
            return None;
        }

        let filename = parts[filename_index..].join(",");
        if filename.is_empty() {
            return None;
        }

        Some(HashdeepRecord {
            size,
            hashes,
            filename,
        })
    }

    /// Infer hash algorithm from hash string length
    fn infer_algorithm_from_hash(hash: &str) -> String {
        match hash.len() {
            32 => "md5".to_string(),
            40 => "sha1".to_string(),
            56 => "sha224".to_string(),
            64 => "sha256".to_string(),
            96 => "sha384".to_string(),
            128 => "sha512".to_string(),
            _ => "unknown".to_string(),
        }
    }

    fn is_hashdeep_hash_field(field: &str) -> bool {
        let trimmed = field.trim();
        matches!(trimmed.len(), 16 | 32 | 40 | 56 | 64 | 96 | 128)
            && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_detect_format_standard_with_commas_in_filename() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temporary.path(),
            "abc123  sha256  normal  path/to/file,with,commas.txt\n",
        )
        .unwrap();

        assert_eq!(
            DatabaseHandler::detect_format(temporary.path()).unwrap(),
            DatabaseFormat::Standard
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
                mode: HashMode::Full,
                digests: vec![
                    DigestValue {
                        algorithm: Algorithm::Md5,
                        bytes: vec![1; 16],
                    },
                    DigestValue {
                        algorithm: Algorithm::Sha256,
                        bytes: vec![2; 32],
                    },
                ],
            }],
        };
        let temporary = tempfile::NamedTempFile::new().unwrap();
        {
            let mut file = std::fs::File::create(temporary.path()).unwrap();
            DatabaseHandler::write_manifest(&mut file, &manifest, DatabaseFormat::Hashdeep)
                .unwrap();
        }
        let restored = DatabaseHandler::read_manifest(temporary.path()).unwrap();
        assert_eq!(restored, manifest);
    }

    #[test]
    fn typed_standard_rows_merge_by_path() {
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
        assert_eq!(fast_mode, false);
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
        assert_eq!(fast_mode, true);
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
        assert_eq!(empty_entry.fast_mode, false);

        let hello_entry = database.get(&PathBuf::from("./hello.txt")).unwrap();
        assert_eq!(hello_entry.hash, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(hello_entry.algorithm, "md5");
        assert_eq!(hello_entry.fast_mode, false);

        let data_entry = database.get(&PathBuf::from("./test/data.bin")).unwrap();
        assert_eq!(data_entry.hash, "098f6bcd4621d373cade4e832627b4f6");
        assert_eq!(data_entry.algorithm, "md5");
        assert_eq!(data_entry.fast_mode, true);

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
        assert_eq!(entry1.fast_mode, false);

        let entry2 = database.get(&PathBuf::from("file2.txt")).unwrap();
        assert_eq!(entry2.hash, "hash2");
        assert_eq!(entry2.algorithm, "sha256");
        assert_eq!(entry2.fast_mode, true);

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
        assert_eq!(fast_mode, false);
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
        assert_eq!(fast_mode, true);
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
        assert_eq!(fast_mode, false);
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
        assert_eq!(fast_mode, false);
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
            path.to_str().unwrap().contains("Lesson 7 Lab")
                && path.to_str().unwrap().ends_with(".srt")
        });
        let found_mp4 = database.iter().any(|(path, _)| {
            path.to_str().unwrap().contains("Lesson 7 Lab")
                && path.to_str().unwrap().ends_with(".mp4")
        });

        assert!(found_srt, "Should find .srt file");
        assert!(found_mp4, "Should find .mp4 file");

        // Cleanup
        fs::remove_file(temp_file).unwrap();
    }
}
