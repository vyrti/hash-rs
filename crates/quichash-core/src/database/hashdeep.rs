use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::error::HashUtilityError;
use crate::hash::{Algorithm, DigestValue, HashMode};
use crate::path_utils;

use super::DatabaseEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HashdeepRecord {
    pub(crate) size: u64,
    pub(crate) hashes: Vec<String>,
    pub(crate) filename: String,
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

pub(crate) fn read_hashdeep_database_from(
    mut reader: Box<dyn BufRead>,
    path: &Path,
) -> Result<HashMap<PathBuf, DatabaseEntry>, HashUtilityError> {
    let mut database = HashMap::new();
    let mut hash_algorithms = Vec::new();
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

        let trimmed = record.trim();

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
        match parse_hashdeep_line(record, &hash_algorithms) {
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
                    line_num,
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
pub(crate) fn parse_hashdeep_line(
    line: &str,
    algorithms: &[String],
) -> Option<Vec<(PathBuf, DatabaseEntry)>> {
    let expected_hash_count = (!algorithms.is_empty()).then_some(algorithms.len());
    let record = parse_hashdeep_record(line, expected_hash_count)?;
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
                let algorithm = infer_algorithm_from_hash(&hash);
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
    if let Some(hash_count) = expected_hash_count {
        let mut fields = line.splitn(hash_count + 2, ',');
        let size = fields.next()?.trim().parse().ok()?;
        let mut hashes = Vec::with_capacity(hash_count);
        for _ in 0..hash_count {
            let hash = fields.next()?.trim();
            if hash.is_empty() {
                return None;
            }
            hashes.push(hash.to_owned());
        }
        let filename = fields.next()?.to_owned();
        if filename.is_empty() {
            return None;
        }
        return Some(HashdeepRecord {
            size,
            hashes,
            filename,
        });
    }

    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() < 3 {
        return None;
    }

    let size = parts[0].trim().parse().ok()?;
    let filename_index = {
        let remainder = &parts[1..];
        let hash_count = remainder
            .iter()
            .take_while(|field| is_hashdeep_hash_field(field))
            .count();
        if hash_count == 0 {
            return None;
        }
        if hash_count == remainder.len() {
            parts.len() - 1
        } else {
            1 + hash_count
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

pub(crate) fn parse_manifest_hashdeep(
    line: &str,
    declared_algorithms: &[Algorithm],
) -> Result<(PathBuf, u64, HashMode, Vec<DigestValue>), String> {
    let expected_hash_count =
        (!declared_algorithms.is_empty()).then_some(declared_algorithms.len());
    let record = parse_hashdeep_record(line, expected_hash_count)
        .ok_or_else(|| "expected 'size,hash...,filename'".to_owned())?;
    let path = path_utils::parse_database_path(&record.filename);
    let hashes = record.hashes;

    let algorithms = if declared_algorithms.len() == hashes.len() {
        declared_algorithms.to_vec()
    } else {
        hashes
            .iter()
            .map(|hash| {
                infer_algorithm_from_hash(hash)
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

/// Infer hash algorithm from hash string length
pub(crate) fn infer_algorithm_from_hash(hash: &str) -> String {
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

pub(crate) fn is_hashdeep_hash_field(field: &str) -> bool {
    let trimmed = field.trim();
    matches!(trimmed.len(), 16 | 32 | 40 | 56 | 64 | 96 | 128)
        && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
}
