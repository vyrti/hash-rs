use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::error::HashUtilityError;
use crate::hash::{Algorithm, DigestValue, HashMode};
use crate::path_utils;

use super::DatabaseEntry;

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

pub(crate) fn read_standard_database_from(
    mut reader: Box<dyn BufRead>,
    path: &Path,
) -> Result<HashMap<PathBuf, DatabaseEntry>, HashUtilityError> {
    let mut database = HashMap::new();
    let mut line = String::new();
    let mut line_num = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(|error| {
            HashUtilityError::from_io_error(error, "reading database", Some(path.to_owned()))
        })? == 0
        {
            break;
        }
        line_num += 1;
        let record = line.strip_suffix('\n').unwrap_or(&line);
        let record = record.strip_suffix('\r').unwrap_or(record);

        // Skip empty lines
        if record.trim().is_empty() {
            continue;
        }

        // Parse line: split on two spaces
        match parse_line(record) {
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
                    line_num,
                    path.display(),
                    record
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
pub(crate) fn parse_line(line: &str) -> Option<(String, String, bool, PathBuf)> {
    // Split on two spaces, but only for the first 3 fields
    // The rest is the filename (which may contain two spaces)
    let mut parts = line.splitn(4, "  ");
    if let (Some(hash), Some(algorithm), Some(fast_mode_str), Some(path_str)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    {
        let hash = hash.trim();
        let algorithm = algorithm.trim();
        let fast_mode_str = fast_mode_str.trim();

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

pub(crate) fn parse_manifest_standard(
    line: &str,
) -> Result<(PathBuf, u64, HashMode, Vec<DigestValue>), String> {
    let (hash, algorithm, fast, path) = parse_line(line)
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
